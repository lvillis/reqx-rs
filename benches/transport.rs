use std::hint::black_box;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_util::{future::join_all, stream};
use http::header::{CONTENT_LENGTH, HeaderValue};
use reqx::prelude::{HttpClient, RetryPolicy};
use tokio::runtime::Runtime;

#[derive(Clone)]
struct ResponseSpec {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ResponseSpec {
    fn new(
        status: u16,
        headers: Vec<(impl Into<String>, impl Into<String>)>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            body: body.into(),
        }
    }
}

struct BenchmarkServer {
    base_url: String,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl BenchmarkServer {
    fn start(response: ResponseSpec) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind benchmark server");
        let authority = listener
            .local_addr()
            .expect("read benchmark server address");
        listener
            .set_nonblocking(true)
            .expect("set benchmark listener nonblocking");

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);

        let join = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stop_for_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let stop_for_connection = Arc::clone(&stop_for_thread);
                        let response = response.clone();
                        workers.push(thread::spawn(move || {
                            handle_connection(stream, response, stop_for_connection);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }

            for worker in workers {
                let _ = worker.join();
            }
        });

        Self {
            base_url: format!("http://{authority}"),
            stop,
            join: Some(join),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for BenchmarkServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_connection(mut stream: TcpStream, response: ResponseSpec, stop: Arc<AtomicBool>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    while !stop.load(Ordering::Relaxed) {
        match read_http_message(&mut stream) {
            Ok(true) => {
                if write_http_response(&mut stream, &response).is_err() {
                    break;
                }
            }
            Ok(false) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
}

fn read_http_message(stream: &mut TcpStream) -> std::io::Result<bool> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];

    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return if raw.is_empty() {
                Ok(false)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before full request",
                ))
            };
        }

        raw.extend_from_slice(&chunk[..read]);

        let Some(header_end) = find_header_end(&raw) else {
            continue;
        };

        let content_length = parse_content_length(&raw[..header_end]);
        let expected_total = header_end + 4 + content_length;

        while raw.len() < expected_total {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before request body",
                ));
            }
            raw.extend_from_slice(&chunk[..read]);
        }

        return Ok(true);
    }
}

fn parse_content_length(raw_headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(raw_headers);
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
            && let Ok(parsed) = value.trim().parse::<usize>()
        {
            return parsed;
        }
    }
    0
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_http_response(stream: &mut TcpStream, response: &ResponseSpec) -> std::io::Result<()> {
    let mut raw = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
        response.status,
        status_text(response.status),
        response.body.len()
    )
    .into_bytes();

    for (name, value) in &response.headers {
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }

    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&response.body);

    stream.write_all(&raw)?;
    stream.flush()
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn benchmark_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build benchmark runtime")
}

fn benchmark_client(base_url: &str) -> HttpClient {
    HttpClient::builder(base_url)
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .pool_max_idle_per_host(64)
        .build()
}

fn bench_small_get_latency(c: &mut Criterion) {
    let server = BenchmarkServer::start(ResponseSpec::new(
        200,
        vec![("Content-Type", "application/json")],
        br#"{"ok":true}"#,
    ));
    let runtime = benchmark_runtime();
    let client = benchmark_client(server.base_url());

    let mut group = c.benchmark_group("small_get_latency");
    group.sample_size(80);
    group.bench_function("get_200_json", |b| {
        b.to_async(&runtime).iter(|| async {
            let response = client
                .get("/v1/ping")
                .send()
                .await
                .expect("small get request should succeed");
            black_box(response.status());
        });
    });
    group.finish();
}

fn bench_concurrent_get_throughput(c: &mut Criterion) {
    let server = BenchmarkServer::start(ResponseSpec::new(
        200,
        vec![("Content-Type", "application/json")],
        br#"{"ok":true}"#,
    ));
    let runtime = benchmark_runtime();
    let client = Arc::new(benchmark_client(server.base_url()));

    let mut group = c.benchmark_group("concurrent_get_throughput");
    group.sample_size(40);

    for concurrency in [8_usize, 32, 64] {
        group.throughput(Throughput::Elements(concurrency as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &concurrency,
            |b, &concurrency| {
                let client = Arc::clone(&client);
                b.to_async(&runtime).iter(|| {
                    let client = Arc::clone(&client);
                    async move {
                        let requests = (0..concurrency).map(|_| client.get("/v1/ping").send());
                        let responses = join_all(requests).await;
                        for response in responses {
                            black_box(
                                response
                                    .expect("concurrent get request should succeed")
                                    .status(),
                            );
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_upload_modes(c: &mut Criterion) {
    const PAYLOAD_BYTES: usize = 256 * 1024;
    const CHUNK_BYTES: usize = 16 * 1024;

    let server = BenchmarkServer::start(ResponseSpec::new(
        200,
        Vec::<(String, String)>::new(),
        b"ok",
    ));
    let runtime = benchmark_runtime();
    let client = Arc::new(benchmark_client(server.base_url()));

    let payload = Bytes::from(vec![b'x'; PAYLOAD_BYTES]);
    let payload_len_header =
        HeaderValue::from_str(&PAYLOAD_BYTES.to_string()).expect("valid content-length header");
    let stream_chunks: Vec<Bytes> = payload
        .chunks(CHUNK_BYTES)
        .map(Bytes::copy_from_slice)
        .collect();

    let mut group = c.benchmark_group("upload_256k");
    group.sample_size(40);
    group.throughput(Throughput::Bytes(PAYLOAD_BYTES as u64));

    group.bench_function("buffered", |b| {
        let client = Arc::clone(&client);
        let payload = payload.clone();
        let payload_len_header = payload_len_header.clone();
        b.to_async(&runtime).iter(|| {
            let client = Arc::clone(&client);
            let payload = payload.clone();
            let payload_len_header = payload_len_header.clone();
            async move {
                let response = client
                    .post("/v1/upload")
                    .header(CONTENT_LENGTH, payload_len_header)
                    .body_bytes(payload)
                    .send()
                    .await
                    .expect("buffered upload should succeed");
                black_box(response.status());
            }
        });
    });

    group.bench_function("streamed", |b| {
        let client = Arc::clone(&client);
        let payload_len_header = payload_len_header.clone();
        let stream_chunks = stream_chunks.clone();
        b.to_async(&runtime).iter(|| {
            let client = Arc::clone(&client);
            let payload_len_header = payload_len_header.clone();
            let stream_chunks = stream_chunks.clone();
            async move {
                let body_stream =
                    stream::iter(stream_chunks.into_iter().map(Ok::<Bytes, std::io::Error>));
                let response = client
                    .post("/v1/upload")
                    .header(CONTENT_LENGTH, payload_len_header)
                    .body_stream(body_stream)
                    .send()
                    .await
                    .expect("stream upload should succeed");
                black_box(response.status());
            }
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8));
    targets = bench_small_get_latency, bench_concurrent_get_throughput, bench_upload_modes
);
criterion_main!(benches);
