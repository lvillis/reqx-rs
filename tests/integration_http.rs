#![cfg(feature = "_async")]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_util::stream;
use http::header::{CONTENT_LENGTH, HeaderName, HeaderValue};
use reqx::advanced::{
    AdaptiveConcurrencyPolicy, Interceptor, Observer, RateLimitPolicy, RequestContext,
    RetryBudgetPolicy, ServerThrottleScope, StatusPolicy,
};
use reqx::prelude::{Client, Error, RedirectPolicy, RetryPolicy};
use reqx::{ErrorCode, TimeoutPhase};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWrite};

#[derive(Clone)]
struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
}

impl MockResponse {
    fn new(
        status: u16,
        headers: Vec<(impl Into<String>, impl Into<String>)>,
        body: impl Into<String>,
        delay: Duration,
    ) -> Self {
        Self::new_bytes(status, headers, body.into().into_bytes(), delay)
    }

    fn new_bytes(
        status: u16,
        headers: Vec<(impl Into<String>, impl Into<String>)>,
        body: impl Into<Vec<u8>>,
        delay: Duration,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            body: body.into(),
            delay,
        }
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct MockServer {
    base_url: String,
    served: Arc<AtomicUsize>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    join: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start(responses: Vec<MockResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("read local address");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");

        let served = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let served_clone = Arc::clone(&served);
        let captured_clone = Arc::clone(&captured);

        let join = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let mut response_index = 0;

            while response_index < responses.len() && std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Ok(request) = read_request(&mut stream) {
                            captured_clone
                                .lock()
                                .expect("lock captured requests")
                                .push(request);
                        }

                        served_clone.fetch_add(1, Ordering::SeqCst);
                        let response = &responses[response_index];
                        response_index += 1;

                        if !response.delay.is_zero() {
                            thread::sleep(response.delay);
                        }

                        let _ = write_response(&mut stream, response);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url: format!("http://{address}"),
            served,
            captured,
            join: Some(join),
        }
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .expect("lock captured requests")
            .clone()
    }

    fn served_count(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Clone)]
struct ThrottleObserver {
    scopes: Arc<Mutex<Vec<ServerThrottleScope>>>,
}

impl Observer for ThrottleObserver {
    fn on_server_throttle(
        &self,
        _context: &RequestContext,
        scope: ServerThrottleScope,
        _delay: Duration,
    ) {
        self.scopes.lock().expect("lock scopes").push(scope);
    }
}

struct FailingAsyncWriter;

impl AsyncWrite for FailingAsyncWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let _ = self;
        Poll::Ready(Err(std::io::Error::other("writer failed")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self;
        Poll::Ready(Ok(()))
    }
}

struct SplitBodyServer {
    base_url: String,
    join: Option<JoinHandle<()>>,
}

impl SplitBodyServer {
    fn start(
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        body_delay: Duration,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind split body server");
        let address = listener
            .local_addr()
            .expect("read split body server address");
        listener
            .set_nonblocking(true)
            .expect("set split body listener nonblocking");

        let join = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = read_request(&mut stream);

                        let mut head = format!(
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                            status,
                            status_text(status),
                            body.len()
                        );
                        for (name, value) in &headers {
                            head.push_str(name);
                            head.push_str(": ");
                            head.push_str(value);
                            head.push_str("\r\n");
                        }
                        head.push_str("\r\n");

                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.flush();
                        if !body_delay.is_zero() {
                            thread::sleep(body_delay);
                        }
                        let _ = stream.write_all(&body);
                        let _ = stream.flush();
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url: format!("http://{address}"),
            join: Some(join),
        }
    }
}

impl Drop for SplitBodyServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct ChunkedBodyServer {
    base_url: String,
    join: Option<JoinHandle<()>>,
}

impl ChunkedBodyServer {
    fn start(
        status: u16,
        headers: Vec<(String, String)>,
        chunks: Vec<Vec<u8>>,
        chunk_delay: Duration,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind chunked body server");
        let address = listener
            .local_addr()
            .expect("read chunked body server address");
        listener
            .set_nonblocking(true)
            .expect("set chunked body listener nonblocking");

        let join = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = read_request(&mut stream);

                        let total_len: usize = chunks.iter().map(Vec::len).sum();
                        let mut head = format!(
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                            status,
                            status_text(status),
                            total_len
                        );
                        for (name, value) in &headers {
                            head.push_str(name);
                            head.push_str(": ");
                            head.push_str(value);
                            head.push_str("\r\n");
                        }
                        head.push_str("\r\n");

                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.flush();
                        for chunk in &chunks {
                            if !chunk_delay.is_zero() {
                                thread::sleep(chunk_delay);
                            }
                            let _ = stream.write_all(chunk);
                            let _ = stream.flush();
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url: format!("http://{address}"),
            join: Some(join),
        }
    }
}

impl Drop for ChunkedBodyServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Clone)]
struct SplitBodyResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    body_delay: Duration,
}

impl SplitBodyResponse {
    fn new(
        status: u16,
        headers: Vec<(impl Into<String>, impl Into<String>)>,
        body: impl Into<Vec<u8>>,
        body_delay: Duration,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            body: body.into(),
            body_delay,
        }
    }
}

struct SplitBodySequenceServer {
    base_url: String,
    served: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
}

impl SplitBodySequenceServer {
    fn start(responses: Vec<SplitBodyResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind split body sequence server");
        let address = listener
            .local_addr()
            .expect("read split body sequence server address");
        listener
            .set_nonblocking(true)
            .expect("set split body sequence listener nonblocking");

        let served = Arc::new(AtomicUsize::new(0));
        let served_clone = Arc::clone(&served);

        let join = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut accepted = 0usize;
            let mut workers = Vec::new();
            while accepted < responses.len() && std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let response = responses[accepted].clone();
                        let served = Arc::clone(&served_clone);
                        accepted += 1;
                        workers.push(thread::spawn(move || {
                            let _ = read_request(&mut stream);
                            served.fetch_add(1, Ordering::SeqCst);

                            let mut head = format!(
                                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                response.status,
                                status_text(response.status),
                                response.body.len()
                            );
                            for (name, value) in &response.headers {
                                head.push_str(name);
                                head.push_str(": ");
                                head.push_str(value);
                                head.push_str("\r\n");
                            }
                            head.push_str("\r\n");

                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.flush();
                            if !response.body_delay.is_zero() {
                                thread::sleep(response.body_delay);
                            }
                            let _ = stream.write_all(&response.body);
                            let _ = stream.flush();
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }

            for worker in workers {
                let _ = worker.join();
            }
        });

        Self {
            base_url: format!("http://{address}"),
            served,
            join: Some(join),
        }
    }

    fn served_count(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

impl Drop for SplitBodySequenceServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;

    let mut raw = Vec::new();
    loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if find_header_end(&raw).is_some() {
            break;
        }
    }

    let header_end = find_header_end(&raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed request without header terminator",
        )
    })?;

    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line")
    })?;
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts.next().unwrap_or_default().to_owned();
    let path = request_line_parts.next().unwrap_or_default().to_owned();

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = raw[header_end + 4..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: &MockResponse) -> std::io::Result<()> {
    let body = &response.body;
    let mut raw = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        status_text(response.status),
        body.len()
    );
    for (name, value) in &response.headers {
        raw.push_str(name);
        raw.push_str(": ");
        raw.push_str(value);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");

    stream.write_all(raw.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .expect("write gzip source bytes should succeed");
    encoder.finish().expect("finish gzip stream should succeed")
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.array_windows::<4>()
        .position(|window| window == b"\r\n\r\n")
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_post_with_idempotency_key_then_succeeds() {
    let server = MockServer::start(vec![
        MockResponse::new(503, vec![("Retry-After", "0")], "busy", Duration::ZERO),
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            r#"{"ok":true}"#,
            Duration::ZERO,
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(3)
                .base_backoff(Duration::from_millis(1))
                .max_backoff(Duration::from_millis(5))
                .jitter_ratio(0.0),
        )
        .build()
        .expect("client should build");

    let response_json: Value = client
        .post("/v1/items")
        .idempotency_key("item-001")
        .expect("set idempotency key")
        .json(&json!({ "name": "demo" }))
        .expect("serialize payload")
        .send_json()
        .await
        .expect("request should succeed after retry");

    assert_eq!(response_json["ok"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(server.served_count(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.headers.contains_key("idempotency-key"))
    );
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("content-type")
                == Some(&"application/json".to_owned()))
    );
    assert!(requests.iter().all(|request| !request.body.is_empty()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_without_idempotency_key_does_not_retry() {
    let server = MockServer::start(vec![MockResponse::new(
        500,
        Vec::<(String, String)>::new(),
        "fail",
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(3)
                .base_backoff(Duration::from_millis(1))
                .max_backoff(Duration::from_millis(5))
                .jitter_ratio(0.0),
        )
        .build()
        .expect("client should build");

    let error = client
        .post("/v1/items")
        .json(&json!({ "name": "demo" }))
        .expect("serialize payload")
        .send()
        .await
        .expect_err("500 should be returned as HttpStatus error without retry");

    match error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 500),
        other => panic!("unexpected error: {other}"),
    }

    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.served_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_timeout_reports_transport_phase() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        r#"{"ok":true}"#,
        Duration::from_millis(120),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(20))
        .retry_policy(RetryPolicy::disabled())
        .metrics_enabled(true)
        .build()
        .expect("client should build");

    let error = client
        .get("/slow")
        .send()
        .await
        .expect_err("slow response should timeout in transport phase");

    match error {
        Error::Timeout { phase, .. } => assert_eq!(phase, TimeoutPhase::Transport),
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/slow");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decodes_gzip_response_and_sets_accept_encoding() {
    let body = gzip_bytes(br#"{"ok":true}"#);
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![
            ("Content-Type", "application/json"),
            ("Content-Encoding", "gzip"),
        ],
        body,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response: Value = client
        .get("/gzip")
        .send_json()
        .await
        .expect("gzip response should be transparently decoded");
    assert_eq!(response["ok"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get("accept-encoding")
            .map(String::as_str),
        Some("gzip, br, deflate, zstd")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffered_request_accept_encoding_can_be_disabled_per_request() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        r#"{"ok":true}"#,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response: Value = client
        .get("/no-auto-accept-encoding")
        .auto_accept_encoding(false)
        .send_json()
        .await
        .expect("request should succeed");
    assert_eq!(response["ok"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers.get("accept-encoding"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_empty_body_with_content_encoding_is_not_decoded() {
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Type", "text/plain"), ("Content-Encoding", "zstd")],
        Vec::<u8>::new(),
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .request(http::Method::HEAD, "/head-empty")
        .send()
        .await
        .expect("head response should not attempt to decode empty body");
    assert_eq!(response.status().as_u16(), 200);
    assert!(response.body().is_empty());
    assert_eq!(
        response
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("zstd")
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "HEAD");
    assert_eq!(
        requests[0].headers.get("accept-encoding"),
        None,
        "HEAD should not auto inject Accept-Encoding"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_stream_into_response_with_content_encoding_empty_body_succeeds() {
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Type", "text/plain"), ("Content-Encoding", "zstd")],
        Vec::<u8>::new(),
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .request(http::Method::HEAD, "/head-stream-empty")
        .send_stream()
        .await
        .expect("head stream should succeed")
        .into_response_limited(1024)
        .await
        .expect("empty head stream should not decode");

    assert_eq!(response.status().as_u16(), 200);
    assert!(response.body().is_empty());
    assert_eq!(
        response
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("zstd")
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "HEAD");
    assert_eq!(requests[0].headers.get("accept-encoding"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decoded_gzip_response_still_respects_max_body_limit() {
    let expanded = vec![b'a'; 16 * 1024];
    let body = gzip_bytes(&expanded);
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
        body,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .max_response_body_bytes(512)
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/gzip-too-large")
        .send()
        .await
        .expect_err("decoded payload should still honor response size limit");

    match error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            actual_bytes,
            ..
        } => {
            assert_eq!(limit_bytes, 512);
            assert!(actual_bytes > limit_bytes);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_http_status_error_strips_decoded_encoding_headers() {
    let body = gzip_bytes(br#"{"error":"bad-request"}"#);
    let server = MockServer::start(vec![MockResponse::new_bytes(
        400,
        vec![
            ("Content-Type", "application/json"),
            ("Content-Encoding", "gzip"),
        ],
        body,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/gzip-http-status-buffered")
        .send()
        .await
        .expect_err("non-success request should return HttpStatus error");

    match error {
        Error::HttpStatus {
            status,
            headers,
            body,
            ..
        } => {
            assert_eq!(status, 400);
            assert_eq!(body, r#"{"error":"bad-request"}"#);
            assert!(
                headers.get("content-encoding").is_none(),
                "decoded error headers should not keep content-encoding"
            );
            assert!(
                headers.get("content-length").is_none(),
                "decoded error headers should not keep original content-length"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_into_response_limited_respects_decode_limit() {
    let expanded = vec![b'b'; 16 * 1024];
    let body = gzip_bytes(&expanded);
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
        body,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/gzip-stream-too-large")
        .send_stream()
        .await
        .expect("send_stream should succeed");
    let error = streamed
        .into_response_limited(512)
        .await
        .expect_err("decoded stream payload should still honor response size limit");

    match error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            actual_bytes,
            ..
        } => {
            assert_eq!(limit_bytes, 512);
            assert!(actual_bytes > limit_bytes);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_keeps_raw_bytes_and_decode_is_explicit() {
    let server = MockServer::start(vec![
        MockResponse::new_bytes(
            200,
            vec![
                ("Content-Type", "application/octet-stream"),
                ("Content-Encoding", "gzip"),
            ],
            b"not-valid-gzip".to_vec(),
            Duration::ZERO,
        ),
        MockResponse::new_bytes(
            200,
            vec![
                ("Content-Type", "application/octet-stream"),
                ("Content-Encoding", "gzip"),
            ],
            b"not-valid-gzip".to_vec(),
            Duration::ZERO,
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/gzip-stream-raw")
        .send_stream()
        .await
        .expect("send_stream should succeed");
    let raw = streamed
        .into_bytes_limited(1024)
        .await
        .expect("stream read should return raw bytes");
    assert_eq!(raw.as_ref(), b"not-valid-gzip");

    let streamed = client
        .get("/gzip-stream-raw")
        .send_stream()
        .await
        .expect("send_stream should succeed");
    let error = streamed
        .into_response_limited(1024)
        .await
        .expect_err("decode should happen only in explicit buffered conversion");

    match error {
        Error::DecodeContentEncoding {
            encoding,
            method,
            uri,
            ..
        } => {
            assert_eq!(encoding.to_ascii_lowercase(), "gzip");
            assert_eq!(method.as_str(), "GET");
            assert!(uri.contains("/gzip-stream-raw"));
        }
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].headers.get("accept-encoding"), None);
    assert_eq!(requests[1].headers.get("accept-encoding"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_http_status_error_strips_decoded_encoding_headers() {
    let body = gzip_bytes(br#"{"error":"bad-request"}"#);
    let server = MockServer::start(vec![MockResponse::new_bytes(
        400,
        vec![
            ("Content-Type", "application/json"),
            ("Content-Encoding", "gzip"),
        ],
        body,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/gzip-http-status")
        .send_stream()
        .await
        .expect_err("non-success stream request should return HttpStatus error");

    match error {
        Error::HttpStatus {
            status,
            headers,
            body,
            ..
        } => {
            assert_eq!(status, 400);
            assert_eq!(body, r#"{"error":"bad-request"}"#);
            assert!(
                headers.get("content-encoding").is_none(),
                "decoded error headers should not keep content-encoding"
            );
            assert!(
                headers.get("content-length").is_none(),
                "decoded error headers should not keep original content-length"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_accept_encoding_can_be_opted_in_per_request() {
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Type", "application/octet-stream")],
        b"ok".to_vec(),
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let _ = client
        .get("/stream-opt-in")
        .auto_accept_encoding(true)
        .send_stream()
        .await
        .expect("stream request should succeed");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get("accept-encoding")
            .map(String::as_str),
        Some("gzip, br, deflate, zstd")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_uri_exposes_raw_and_redacted_variants() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        r#"{"ok":true}"#,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let stream = client
        .get("/v1/list?list-type=2&uploads=")
        .send_stream()
        .await
        .expect("stream request should succeed");

    assert_eq!(stream.status().as_u16(), 200);
    assert!(stream.uri_raw().contains("/v1/list?"));
    assert!(stream.uri_raw().contains("list-type=2"));
    assert!(stream.uri_raw().contains("uploads="));

    assert!(stream.uri_redacted().contains("/v1/list"));
    assert!(!stream.uri_redacted().contains('?'));
    assert!(!stream.uri_redacted().contains("list-type=2"));
    assert!(!stream.uri_redacted().contains("uploads="));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/list?list-type=2&uploads=");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_drop_marks_canceled_and_releases_in_flight() {
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Type", "application/octet-stream")],
        b"stream-body".to_vec(),
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .metrics_enabled(true)
        .build()
        .expect("client should build");

    let stream = client
        .get("/stream-drop")
        .send_stream()
        .await
        .expect("stream request should succeed");

    let in_flight_metrics = client.metrics_snapshot();
    assert_eq!(in_flight_metrics.requests.started, 1);
    assert_eq!(in_flight_metrics.requests.succeeded, 0);
    assert_eq!(in_flight_metrics.requests.failed, 0);
    assert_eq!(in_flight_metrics.requests.canceled, 0);
    assert_eq!(in_flight_metrics.requests.in_flight, 1);

    drop(stream);
    tokio::task::yield_now().await;

    let canceled_metrics = client.metrics_snapshot();
    assert_eq!(canceled_metrics.requests.started, 1);
    assert_eq!(canceled_metrics.requests.succeeded, 0);
    assert_eq!(canceled_metrics.requests.failed, 0);
    assert_eq!(canceled_metrics.requests.canceled, 1);
    assert_eq!(canceled_metrics.requests.in_flight, 0);
    assert!(canceled_metrics.errors.by_code.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_auto_accept_encoding_can_be_enabled_at_client_level() {
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Type", "application/octet-stream")],
        b"ok".to_vec(),
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .stream_auto_accept_encoding(true)
        .build()
        .expect("client should build");

    let _ = client
        .get("/stream-client-opt-in")
        .send_stream()
        .await
        .expect("stream request should succeed");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get("accept-encoding")
            .map(String::as_str),
        Some("gzip, br, deflate, zstd")
    );
}

#[derive(Serialize)]
struct SearchParams<'a> {
    topic: &'a str,
    page: u32,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_helpers_append_encoded_query_pairs() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        r#"{"ok":true}"#,
        Duration::ZERO,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response: Value = client
        .get("/v1/search?existing=true")
        .query_pair("q", "rust sdk")
        .query_pairs([("lang", "zh"), ("sort", "desc")])
        .query(&SearchParams {
            topic: "network",
            page: 2,
        })
        .expect("query serialization should succeed")
        .send_json()
        .await
        .expect("request should succeed");
    assert_eq!(response["ok"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let path = &requests[0].path;
    let query_text = path
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default();
    let query_map: BTreeMap<String, String> = url::form_urlencoded::parse(query_text.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(query_map.get("existing"), Some(&"true".to_owned()));
    assert_eq!(query_map.get("q"), Some(&"rust sdk".to_owned()));
    assert_eq!(query_map.get("lang"), Some(&"zh".to_owned()));
    assert_eq!(query_map.get("sort"), Some(&"desc".to_owned()));
    assert_eq!(query_map.get("topic"), Some(&"network".to_owned()));
    assert_eq!(query_map.get("page"), Some(&"2".to_owned()));
}

#[derive(Serialize)]
struct LoginPayload<'a> {
    username: &'a str,
    password: &'a str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn form_helper_sets_content_type_and_encoded_body() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        Vec::<(String, String)>::new(),
        "ok",
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .post("/v1/login")
        .form(&LoginPayload {
            username: "alice@example.com",
            password: "p@ss word",
        })
        .expect("form serialization should succeed")
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(response.status().as_u16(), 200);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("content-type"),
        Some(&"application/x-www-form-urlencoded".to_owned())
    );
    let body = String::from_utf8_lossy(&requests[0].body);
    let body_map: BTreeMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(
        body_map.get("username"),
        Some(&"alice@example.com".to_owned())
    );
    assert_eq!(body_map.get("password"), Some(&"p@ss word".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_stream_uploads_chunked_data_with_declared_length() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        Vec::<(String, String)>::new(),
        "ok",
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let body_stream = stream::iter(vec![
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"hello ")),
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"world")),
    ]);

    let response = client
        .post("/v1/upload")
        .header(CONTENT_LENGTH, http::HeaderValue::from_static("11"))
        .body_stream(body_stream)
        .send()
        .await
        .expect("stream upload should succeed");
    assert_eq!(response.status().as_u16(), 200);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"hello world".to_vec());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_rate_limit_applies_between_parallel_requests() {
    let server = MockServer::start(vec![
        MockResponse::new(200, Vec::<(String, String)>::new(), "ok-1", Duration::ZERO),
        MockResponse::new(200, Vec::<(String, String)>::new(), "ok-2", Duration::ZERO),
    ]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(20.0)
                .burst(1),
        )
        .build()
        .expect("client should build");

    let started = Instant::now();
    let client_a = client.clone();
    let client_b = client.clone();
    let (first, second) = tokio::join!(client_a.get("/a").send(), client_b.get("/b").send());

    let first = first.expect("first request should succeed");
    let second = second.expect("second request should succeed");
    assert_eq!(first.status().as_u16(), 200);
    assert_eq!(second.status().as_u16(), 200);
    assert!(
        started.elapsed() >= Duration::from_millis(45),
        "rate limiter should introduce spacing between requests"
    );
    assert_eq!(server.served_count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_after_429_backpressures_following_request() {
    let server = MockServer::start(vec![
        MockResponse::new(429, vec![("Retry-After", "1")], "busy", Duration::ZERO),
        MockResponse::new(200, Vec::<(String, String)>::new(), "ok", Duration::ZERO),
    ]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .build()
        .expect("client should build");

    let first_error = client
        .get("/throttled")
        .send()
        .await
        .expect_err("first request should return 429");
    match first_error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected first error: {other}"),
    }

    let started = Instant::now();
    let second = client
        .get("/recovered")
        .send()
        .await
        .expect("second request should succeed after retry-after delay");
    assert_eq!(second.status().as_u16(), 200);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "retry-after should backpressure the next request"
    );
    assert_eq!(server.served_count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_after_429_auto_scope_throttles_same_host_only() {
    let server_a = MockServer::start(vec![
        MockResponse::new(429, vec![("Retry-After", "1")], "busy", Duration::ZERO),
        MockResponse::new(200, Vec::<(String, String)>::new(), "ok-a", Duration::ZERO),
    ]);
    let server_b = MockServer::start(vec![MockResponse::new(
        200,
        Vec::<(String, String)>::new(),
        "ok-b",
        Duration::ZERO,
    )]);

    let host_b_url = format!("{}/other-host", server_b.base_url);

    let client = Client::builder(server_a.base_url.clone())
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .per_host_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .build()
        .expect("client should build");

    let first_error = client
        .get("/throttled")
        .send()
        .await
        .expect_err("first request should return 429");
    match first_error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected first error: {other}"),
    }

    let cross_host_started = Instant::now();
    let cross_host = client
        .get(host_b_url.clone())
        .send()
        .await
        .expect("other host request should not be backpressured in auto scope");
    assert_eq!(cross_host.status().as_u16(), 200);
    assert!(
        cross_host_started.elapsed() < Duration::from_millis(250),
        "cross-host request should not inherit host-a retry-after backpressure"
    );

    let same_host_started = Instant::now();
    let same_host = client
        .get("/recovered-a")
        .send()
        .await
        .expect("same host request should eventually succeed");
    assert_eq!(same_host.status().as_u16(), 200);
    assert!(
        same_host_started.elapsed() >= Duration::from_millis(900),
        "same host should be backpressured by retry-after"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_after_429_global_scope_backpressures_other_hosts() {
    let server_a = MockServer::start(vec![MockResponse::new(
        429,
        vec![("Retry-After", "1")],
        "busy",
        Duration::ZERO,
    )]);
    let server_b = MockServer::start(vec![MockResponse::new(
        200,
        Vec::<(String, String)>::new(),
        "ok-b",
        Duration::ZERO,
    )]);
    let host_b_url = format!("{}/other-host", server_b.base_url);

    let client = Client::builder(server_a.base_url.clone())
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .per_host_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .server_throttle_scope(ServerThrottleScope::Global)
        .build()
        .expect("client should build");

    let first_error = client
        .get("/throttled")
        .send()
        .await
        .expect_err("first request should return 429");
    match first_error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected first error: {other}"),
    }

    let cross_host_started = Instant::now();
    let cross_host = client
        .get(host_b_url)
        .send()
        .await
        .expect("cross-host request should still succeed");
    assert_eq!(cross_host.status().as_u16(), 200);
    assert!(
        cross_host_started.elapsed() >= Duration::from_millis(900),
        "global scope should backpressure requests for other hosts"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_after_429_observer_receives_resolved_scope() {
    let server = MockServer::start(vec![MockResponse::new(
        429,
        vec![("Retry-After", "1"), ("X-RateLimit-Scope", "global")],
        "busy",
        Duration::ZERO,
    )]);
    let scopes = Arc::new(Mutex::new(Vec::new()));
    let observer = ThrottleObserver {
        scopes: Arc::clone(&scopes),
    };

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .per_host_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .server_throttle_scope(ServerThrottleScope::Auto)
        .observer(observer)
        .build()
        .expect("client should build");

    let error = client
        .get("/throttled-scope")
        .send()
        .await
        .expect_err("request should return 429");
    match error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected error: {other}"),
    }

    let recorded = scopes.lock().expect("lock scopes").clone();
    assert_eq!(recorded, vec![ServerThrottleScope::Global]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_after_429_observer_receives_scope_without_rate_limiter() {
    let server = MockServer::start(vec![MockResponse::new(
        429,
        vec![("Retry-After", "1"), ("X-RateLimit-Scope", "global")],
        "busy",
        Duration::ZERO,
    )]);
    let scopes = Arc::new(Mutex::new(Vec::new()));
    let observer = ThrottleObserver {
        scopes: Arc::clone(&scopes),
    };

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .server_throttle_scope(ServerThrottleScope::Auto)
        .observer(observer)
        .build()
        .expect("client should build");

    let error = client
        .get("/throttled-scope")
        .send()
        .await
        .expect_err("request should return 429");
    match error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected error: {other}"),
    }

    let recorded = scopes.lock().expect("lock scopes").clone();
    assert_eq!(recorded, vec![ServerThrottleScope::Global]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_body_timeout_reports_phase_and_metrics() {
    let server = SplitBodyServer::start(
        200,
        vec![("Content-Type".to_owned(), "application/json".to_owned())],
        br#"{"ok":true}"#.to_vec(),
        Duration::from_millis(250),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(100))
        .retry_policy(RetryPolicy::disabled())
        .metrics_enabled(true)
        .build()
        .expect("client should build");

    let error = client
        .get("/slow-body")
        .send()
        .await
        .expect_err("slow body read should timeout in response body phase");
    match error {
        Error::Timeout { phase, .. } => assert_eq!(phase, TimeoutPhase::ResponseBody),
        other => panic!("unexpected error variant: {other}"),
    }

    let metrics = client.metrics_snapshot();
    assert_eq!(metrics.requests.started, 1);
    assert_eq!(metrics.requests.succeeded, 0);
    assert_eq!(metrics.requests.failed, 1);
    assert_eq!(metrics.timeouts.transport, 0);
    assert_eq!(metrics.timeouts.response_body, 1);
    assert_eq!(metrics.requests.in_flight, 0);
    assert_eq!(
        metrics
            .errors
            .by_timeout_phase
            .get(&TimeoutPhase::ResponseBody),
        Some(&1_u64)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_body_timeout_maps_to_deadline_exceeded_when_total_timeout_is_exhausted() {
    let server = SplitBodyServer::start(
        200,
        vec![("Content-Type".to_owned(), "application/json".to_owned())],
        br#"{"ok":true}"#.to_vec(),
        Duration::from_millis(180),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(400))
        .total_timeout(Duration::from_millis(120))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/slow-body-total-timeout")
        .send()
        .await
        .expect_err("slow body read should stop at the total timeout deadline");
    match error {
        Error::DeadlineExceeded { method, uri, .. } => {
            assert_eq!(method.as_str(), "GET");
            assert!(uri.contains("/slow-body-total-timeout"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_copy_to_writer_reports_response_body_timeout() {
    let server = SplitBodySequenceServer::start(vec![
        SplitBodyResponse::new(
            200,
            vec![("Content-Type", "application/octet-stream")],
            b"delayed".to_vec(),
            Duration::from_millis(120),
        ),
        SplitBodyResponse::new(
            200,
            vec![("Content-Type", "application/octet-stream")],
            b"delayed".to_vec(),
            Duration::from_millis(120),
        ),
    ]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(20))
        .retry_policy(RetryPolicy::disabled())
        .metrics_enabled(true)
        .build()
        .expect("client should build");

    let stream = client
        .get("/slow-stream-copy")
        .send_stream()
        .await
        .expect("stream request should return headers");
    let mut sink = tokio::io::sink();
    let error = stream
        .copy_to_writer(&mut sink)
        .await
        .expect_err("slow stream copy should timeout");
    match error {
        Error::Timeout { phase, uri, .. } => {
            assert_eq!(phase, TimeoutPhase::ResponseBody);
            assert!(uri.contains("/slow-stream-copy"));
        }
        other => panic!("unexpected error variant: {other}"),
    }

    let stream = client
        .get("/slow-stream-copy-limited")
        .send_stream()
        .await
        .expect("stream request should return headers");
    let mut sink = tokio::io::sink();
    let error = stream
        .copy_to_writer_limited(&mut sink, 1024)
        .await
        .expect_err("slow stream limited copy should timeout");
    match error {
        Error::Timeout { phase, uri, .. } => {
            assert_eq!(phase, TimeoutPhase::ResponseBody);
            assert!(uri.contains("/slow-stream-copy-limited"));
        }
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(server.served_count(), 2);
    let metrics = client.metrics_snapshot();
    assert_eq!(metrics.requests.started, 2);
    assert_eq!(metrics.requests.succeeded, 0);
    assert_eq!(metrics.requests.failed, 2);
    assert_eq!(metrics.timeouts.response_body, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_copy_to_writer_reports_write_body_error() {
    let server = SplitBodyServer::start(
        200,
        vec![(
            "Content-Type".to_owned(),
            "application/octet-stream".to_owned(),
        )],
        b"writer-fail".to_vec(),
        Duration::ZERO,
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(100))
        .retry_policy(RetryPolicy::disabled())
        .metrics_enabled(true)
        .build()
        .expect("client should build");

    let stream = client
        .get("/stream-copy-write-fail")
        .send_stream()
        .await
        .expect("stream request should return headers");
    let mut writer = FailingAsyncWriter;
    let error = stream
        .copy_to_writer(&mut writer)
        .await
        .expect_err("writer failure should surface as write_body");
    match error {
        Error::WriteBody { method, uri, .. } => {
            assert_eq!(method.as_str(), "GET");
            assert!(uri.contains("/stream-copy-write-fail"));
        }
        other => panic!("unexpected error variant: {other}"),
    }

    let metrics = client.metrics_snapshot();
    assert_eq!(metrics.requests.failed, 1);
    assert_eq!(metrics.errors.write_body, 1);
    assert_eq!(metrics.errors.by_code.get(&ErrorCode::WriteBody), Some(&1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_copy_to_writer_respects_total_timeout_deadline() {
    let server = ChunkedBodyServer::start(
        200,
        vec![(
            "Content-Type".to_owned(),
            "application/octet-stream".to_owned(),
        )],
        vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()],
        Duration::from_millis(90),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(400))
        .total_timeout(Duration::from_millis(220))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let stream = client
        .get("/stream-total-timeout")
        .send_stream()
        .await
        .expect("stream request should return headers");
    let mut sink = tokio::io::sink();
    let error = stream
        .copy_to_writer(&mut sink)
        .await
        .expect_err("stream copy should stop at total timeout deadline");
    match error {
        Error::DeadlineExceeded { uri, .. } => {
            assert!(uri.contains("/stream-total-timeout"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_large_deadline_slack_does_not_shorten_total_timeout() {
    let server = SplitBodyServer::start(
        200,
        vec![(
            "Content-Type".to_owned(),
            "application/octet-stream".to_owned(),
        )],
        b"ok".to_vec(),
        Duration::from_millis(80),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(400))
        .total_timeout(Duration::from_millis(250))
        .stream_deadline_slack(Duration::from_secs(5))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let body = client
        .get("/stream-large-deadline-slack")
        .send_stream()
        .await
        .expect("stream request should return headers")
        .into_bytes_limited(64)
        .await
        .expect("large classification slack must not shorten the actual deadline");

    assert_eq!(body, Bytes::from_static(b"ok"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_large_deadline_slack_does_not_reclassify_body_timeout() {
    let server = SplitBodyServer::start(
        200,
        vec![(
            "Content-Type".to_owned(),
            "application/octet-stream".to_owned(),
        )],
        b"slow".to_vec(),
        Duration::from_millis(180),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(100))
        .total_timeout(Duration::from_millis(500))
        .stream_deadline_slack(Duration::from_millis(450))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/stream-large-deadline-slack-timeout")
        .send_stream()
        .await
        .expect("stream request should return headers")
        .into_bytes_limited(64)
        .await
        .expect_err("body timeout should remain classified as response body timeout");

    match error {
        Error::Timeout { phase, .. } => assert_eq!(phase, TimeoutPhase::ResponseBody),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_into_body_collect_reports_response_body_timeout() {
    let server = SplitBodyServer::start(
        200,
        vec![(
            "Content-Type".to_owned(),
            "application/octet-stream".to_owned(),
        )],
        b"delayed".to_vec(),
        Duration::from_millis(120),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(20))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let stream = client
        .get("/slow-stream-collect")
        .send_stream()
        .await
        .expect("stream request should return headers");
    let mut stream = stream;
    let mut body = Vec::new();
    let error = stream
        .read_to_end(&mut body)
        .await
        .expect_err("reading a delayed stream body should timeout");
    let error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
        .expect("stream read should wrap reqx::Error");
    match error {
        Error::Timeout { phase, uri, .. } => {
            assert_eq!(*phase, TimeoutPhase::ResponseBody);
            assert!(uri.contains("/slow-stream-collect"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_stream_retries_on_non_success_response_body_timeout() {
    let server = SplitBodySequenceServer::start(vec![
        SplitBodyResponse::new(
            503,
            Vec::<(String, String)>::new(),
            b"busy".to_vec(),
            Duration::from_millis(320),
        ),
        SplitBodyResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            br#"{"ok":true}"#.to_vec(),
            Duration::ZERO,
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(120))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(2)
                .base_backoff(Duration::from_millis(1))
                .max_backoff(Duration::from_millis(1))
                .jitter_ratio(0.0),
        )
        .build()
        .expect("client should build");

    let stream = client
        .get("/stream-timeout-then-retry")
        .send_stream()
        .await
        .expect("stream request should succeed after retry");
    let response = stream
        .into_response_limited(1024)
        .await
        .expect("stream response should decode");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(server.served_count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decode_content_encoding_error_is_classified() {
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Encoding", "x-custom")],
        b"abc".to_vec(),
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(200))
        .retry_policy(RetryPolicy::disabled())
        .metrics_enabled(true)
        .build()
        .expect("client should build");

    let error = client
        .get("/bad-encoding")
        .send()
        .await
        .expect_err("unknown content-encoding should fail");
    match error {
        Error::DecodeContentEncoding { encoding, .. } => {
            assert_eq!(encoding, "x-custom");
        }
        other => panic!("unexpected error variant: {other}"),
    }

    let metrics = client.metrics_snapshot();
    assert_eq!(metrics.requests.started, 1);
    assert_eq!(metrics.requests.failed, 1);
    assert_eq!(
        metrics
            .errors
            .by_code
            .get(&ErrorCode::DecodeContentEncoding),
        Some(&1_u64)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_snapshot_tracks_success_and_error_buckets() {
    let server = MockServer::start(vec![
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            r#"{"ok":true}"#,
            Duration::ZERO,
        ),
        MockResponse::new(503, Vec::<(String, String)>::new(), "busy", Duration::ZERO),
        MockResponse::new(
            200,
            vec![("Content-Type", "text/plain")],
            "0123456789abcdef",
            Duration::ZERO,
        ),
    ]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .metrics_enabled(true)
        .build()
        .expect("client should build");

    let first: Value = client
        .get("/ok")
        .send_json()
        .await
        .expect("first request should succeed");
    assert_eq!(first["ok"], Value::Bool(true));

    let second_error = client
        .get("/status-503")
        .send()
        .await
        .expect_err("second request should return http status error");
    match second_error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 503),
        other => panic!("unexpected error: {other}"),
    }

    let third_error = client
        .get("/large")
        .max_response_body_bytes(4)
        .send()
        .await
        .expect_err("third request should exceed body limit");
    match third_error {
        Error::ResponseBodyTooLarge { limit_bytes, .. } => assert_eq!(limit_bytes, 4),
        other => panic!("unexpected error: {other}"),
    }

    let metrics = client.metrics_snapshot();
    assert_eq!(metrics.requests.started, 3);
    assert_eq!(metrics.requests.succeeded, 1);
    assert_eq!(metrics.requests.failed, 2);
    assert_eq!(metrics.requests.canceled, 0);
    assert_eq!(metrics.requests.retries, 0);
    assert_eq!(metrics.errors.http_status, 1);
    assert_eq!(metrics.errors.response_body_too_large, 1);
    assert_eq!(metrics.responses.status_counts.get(&200), Some(&1_u64));
    assert_eq!(metrics.responses.status_counts.get(&503), Some(&1_u64));
    assert_eq!(metrics.errors.by_http_status.get(&503), Some(&1_u64));
    assert_eq!(
        metrics.errors.by_code.get(&ErrorCode::ResponseBodyTooLarge),
        Some(&1_u64)
    );
    assert_eq!(metrics.requests.in_flight, 0);
    assert_eq!(metrics.latency.samples, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_snapshot_is_noop_when_metrics_disabled() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        r#"{"ok":true}"#,
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let _response = client
        .get("/metrics-disabled")
        .send()
        .await
        .expect("request should succeed");

    let metrics = client.metrics_snapshot();
    assert_eq!(metrics.requests.started, 0);
    assert_eq!(metrics.requests.succeeded, 0);
    assert_eq!(metrics.requests.failed, 0);
    assert_eq!(metrics.requests.canceled, 0);
    assert_eq!(metrics.requests.retries, 0);
    assert_eq!(metrics.latency.samples, 0);
    assert!(metrics.responses.status_counts.is_empty());
    assert!(metrics.errors.by_code.is_empty());
    assert!(metrics.errors.by_timeout_phase.is_empty());
    assert!(metrics.errors.by_transport_kind.is_empty());
    assert!(metrics.errors.by_http_status.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_budget_is_credited_by_non_retryable_send_response() {
    let server = MockServer::start(vec![
        MockResponse::new(
            404,
            Vec::<(String, String)>::new(),
            "not-found",
            Duration::ZERO,
        ),
        MockResponse::new(503, Vec::<(String, String)>::new(), "busy", Duration::ZERO),
        MockResponse::new(200, Vec::<(String, String)>::new(), "ok", Duration::ZERO),
    ]);

    let client = Client::builder(server.base_url.clone())
        .default_status_policy(StatusPolicy::Response)
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(2)
                .base_backoff(Duration::from_millis(1))
                .max_backoff(Duration::from_millis(1))
                .jitter_ratio(0.0),
        )
        .retry_budget_policy(
            RetryBudgetPolicy::standard()
                .window(Duration::from_secs(60))
                .retry_ratio(1.0)
                .min_retries_per_window(0),
        )
        .request_timeout(Duration::from_millis(300))
        .build()
        .expect("client should build");

    let first = client
        .get("/status-404")
        .send()
        .await
        .expect("404 should be returned as response");
    assert_eq!(first.status().as_u16(), 404);

    let second = client
        .get("/status-503-then-200")
        .send()
        .await
        .expect("retry budget should allow one retry after 404 credit");
    assert_eq!(second.status().as_u16(), 200);
    assert_eq!(server.served_count(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn build_rejects_invalid_adaptive_concurrency_policy() {
    let result = Client::builder("https://api.example.com")
        .adaptive_concurrency_policy(
            AdaptiveConcurrencyPolicy::standard()
                .min_limit(10)
                .initial_limit(8)
                .max_limit(5),
        )
        .build();

    let error = match result {
        Ok(_) => panic!("invalid adaptive concurrency policy should fail"),
        Err(error) => error,
    };

    match error {
        Error::InvalidAdaptiveConcurrencyPolicy {
            min_limit,
            initial_limit,
            max_limit,
            ..
        } => {
            assert_eq!(min_limit, 10);
            assert_eq!(initial_limit, 8);
            assert_eq!(max_limit, 5);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_policy_follows_relative_location() {
    let server = MockServer::start(vec![
        MockResponse::new(
            302,
            vec![("Location", "/v1/new")],
            "redirect",
            Duration::ZERO,
        ),
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            r#"{"ok":true}"#,
            Duration::ZERO,
        ),
    ]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let body: Value = client
        .get("/v1/old")
        .send_json()
        .await
        .expect("redirect should be followed");
    assert_eq!(body["ok"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1/old");
    assert_eq!(requests[1].path, "/v1/new");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_post_302_rewrites_to_get_and_drops_body() {
    let server = MockServer::start(vec![
        MockResponse::new(
            302,
            vec![("Location", "/v1/new")],
            "redirect",
            Duration::ZERO,
        ),
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            r#"{"ok":true}"#,
            Duration::ZERO,
        ),
    ]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let body: Value = client
        .post("/v1/old")
        .json(&json!({ "name": "demo" }))
        .expect("json serialization should succeed")
        .send_json()
        .await
        .expect("redirect should be followed");
    assert_eq!(body["ok"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[1].method, "GET");
    assert!(requests[1].body.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_303_allows_non_replayable_stream_body_when_method_changes_to_get() {
    let server = MockServer::start(vec![
        MockResponse::new(
            303,
            vec![("Location", "/v1/new")],
            "redirect",
            Duration::ZERO,
        ),
        MockResponse::new(
            200,
            vec![("Content-Type", "text/plain")],
            "ok",
            Duration::ZERO,
        ),
    ]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let response = client
        .post("/v1/old")
        .body_stream(stream::once(async {
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"payload"))
        }))
        .send()
        .await
        .expect("303 redirect should be followed even for non-replayable body");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text_lossy(), "ok");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[1].method, "GET");
    assert!(requests[1].body.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_307_rejects_non_replayable_stream_body() {
    let server = MockServer::start(vec![MockResponse::new(
        307,
        vec![("Location", "/v1/new")],
        "redirect",
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .post("/v1/old")
        .body_stream(stream::once(async {
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"payload"))
        }))
        .send()
        .await
        .expect_err("307 redirect should fail for non-replayable body");

    match error {
        Error::RedirectBodyNotReplayable { .. } => {}
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_invalid_location_redacts_sensitive_tokens_in_error() {
    let server = MockServer::start(vec![MockResponse::new(
        302,
        vec![(
            "Location",
            "https://example.com:invalid/v1/new?token=secret#frag",
        )],
        "redirect",
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/old")
        .send()
        .await
        .expect_err("invalid redirect location should fail");
    let display = error.to_string();
    assert!(!display.contains("token=secret"));
    assert!(!display.contains("#frag"));

    match error {
        Error::InvalidRedirectLocation { location, .. } => {
            assert_eq!(location, "https://example.com:invalid/v1/new");
        }
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_http_location_with_userinfo_is_rejected() {
    let server = MockServer::start(vec![MockResponse::new(
        302,
        vec![(
            "Location",
            "https://user:pass@example.com/v1/new?token=secret",
        )],
        "redirect",
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/userinfo-redirect")
        .send()
        .await
        .expect_err("redirect with userinfo should fail");

    match error {
        Error::InvalidRedirectLocation { location, .. } => {
            assert_eq!(location, "https://example.com/v1/new");
        }
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absolute_request_uri_with_userinfo_is_rejected() {
    let client = Client::builder("https://api.example.com")
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("https://user:pass@example.com/v1/items?token=secret")
        .send()
        .await
        .expect_err("absolute request URI with userinfo should be rejected");

    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://example.com/v1/items");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_non_http_location_is_rejected() {
    let server = MockServer::start(vec![MockResponse::new(
        302,
        vec![("Location", "mailto:user:pass@example.com?subject=secret")],
        "redirect",
        Duration::ZERO,
    )]);
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/non-http-redirect")
        .send()
        .await
        .expect_err("non-http redirect location should fail");
    let display = error.to_string();
    assert!(!display.contains("user:pass"));
    assert!(!display.contains("subject=secret"));

    match error {
        Error::InvalidRedirectLocation { location, .. } => {
            assert_eq!(location, "mailto:<redacted>@example.com");
        }
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
}

struct HeaderInjectingInterceptor {
    request_hits: Arc<AtomicUsize>,
    response_hits: Arc<AtomicUsize>,
    error_hits: Arc<AtomicUsize>,
}

impl Interceptor for HeaderInjectingInterceptor {
    fn on_request(&self, _context: &RequestContext, headers: &mut http::HeaderMap) {
        self.request_hits.fetch_add(1, Ordering::SeqCst);
        headers.insert(
            HeaderName::from_static("x-interceptor"),
            HeaderValue::from_static("active"),
        );
    }

    fn on_response(
        &self,
        _context: &RequestContext,
        _status: http::StatusCode,
        _headers: &http::HeaderMap,
    ) {
        self.response_hits.fetch_add(1, Ordering::SeqCst);
    }

    fn on_error(&self, _context: &RequestContext, _error: &Error) {
        self.error_hits.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interceptor_can_mutate_headers_and_observe_lifecycle() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        r#"{"ok":true}"#,
        Duration::ZERO,
    )]);

    let request_hits = Arc::new(AtomicUsize::new(0));
    let response_hits = Arc::new(AtomicUsize::new(0));
    let error_hits = Arc::new(AtomicUsize::new(0));
    let interceptor = Arc::new(HeaderInjectingInterceptor {
        request_hits: Arc::clone(&request_hits),
        response_hits: Arc::clone(&response_hits),
        error_hits: Arc::clone(&error_hits),
    });

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .interceptor_arc(interceptor)
        .build()
        .expect("client should build");

    let body: Value = client
        .get("/v1/interceptor")
        .send_json()
        .await
        .expect("request should succeed");
    assert_eq!(body["ok"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/interceptor");
    assert_eq!(
        requests[0].headers.get("x-interceptor").map(String::as_str),
        Some("active")
    );
    assert_eq!(request_hits.load(Ordering::SeqCst), 1);
    assert_eq!(response_hits.load(Ordering::SeqCst), 1);
    assert_eq!(error_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interceptor_on_error_is_invoked_for_decode_failure() {
    let server = MockServer::start(vec![MockResponse::new_bytes(
        200,
        vec![("Content-Encoding", "x-custom")],
        b"abc".to_vec(),
        Duration::ZERO,
    )]);

    let request_hits = Arc::new(AtomicUsize::new(0));
    let response_hits = Arc::new(AtomicUsize::new(0));
    let error_hits = Arc::new(AtomicUsize::new(0));
    let interceptor = Arc::new(HeaderInjectingInterceptor {
        request_hits: Arc::clone(&request_hits),
        response_hits: Arc::clone(&response_hits),
        error_hits: Arc::clone(&error_hits),
    });

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .interceptor_arc(interceptor)
        .build()
        .expect("client should build");

    let error = client
        .get("/decode-fail")
        .send()
        .await
        .expect_err("unknown content-encoding should fail");
    match error {
        Error::DecodeContentEncoding { encoding, .. } => assert_eq!(encoding, "x-custom"),
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(request_hits.load(Ordering::SeqCst), 1);
    assert_eq!(response_hits.load(Ordering::SeqCst), 0);
    assert_eq!(error_hits.load(Ordering::SeqCst), 1);
}
