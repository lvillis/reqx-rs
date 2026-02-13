#![cfg(feature = "_blocking")]

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use http::header::{HeaderName, HeaderValue};
use reqx::blocking::Client;
use reqx::prelude::{Error, RedirectPolicy, RetryPolicy, TlsRootStore};
use reqx::{
    AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, Interceptor, RateLimitPolicy, RequestContext,
    RetryBudgetPolicy, ServerThrottleScope, StatusPolicy, TimeoutPhase,
};
use serde_json::Value;

#[derive(Clone)]
struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponse {
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

    fn served_count(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .expect("lock captured requests")
            .clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
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

fn update_max(max: &AtomicUsize, value: usize) {
    let mut current = max.load(Ordering::SeqCst);
    while value > current {
        match max.compare_exchange(current, value, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

struct CountingServer {
    authority: String,
    served: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
}

impl CountingServer {
    fn start(expected_requests: usize, response: MockResponse, response_delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counting server");
        let authority = listener
            .local_addr()
            .expect("read counting server address")
            .to_string();
        listener
            .set_nonblocking(true)
            .expect("set counting listener nonblocking");

        let served = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let response = Arc::new(response);
        let served_clone = Arc::clone(&served);
        let active_clone = Arc::clone(&active);
        let max_active_clone = Arc::clone(&max_active);

        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut workers = Vec::new();

            while Instant::now() < deadline {
                if served_clone.load(Ordering::SeqCst) >= expected_requests {
                    break;
                }

                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let served = Arc::clone(&served_clone);
                        let active = Arc::clone(&active_clone);
                        let max_active = Arc::clone(&max_active_clone);
                        let response = Arc::clone(&response);

                        workers.push(thread::spawn(move || {
                            let now_active = active.fetch_add(1, Ordering::SeqCst) + 1;
                            update_max(&max_active, now_active);

                            if !response_delay.is_zero() {
                                thread::sleep(response_delay);
                            }

                            let _ = read_request(&mut stream);
                            let _ = write_response(&mut stream, &response);

                            served.fetch_add(1, Ordering::SeqCst);
                            active.fetch_sub(1, Ordering::SeqCst);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }

            for worker in workers {
                let _ = worker.join();
            }
        });

        Self {
            authority,
            served,
            max_active,
            join: Some(join),
        }
    }

    fn authority(&self) -> &str {
        &self.authority
    }

    fn served_count(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    fn max_active(&self) -> usize {
        self.max_active.load(Ordering::SeqCst)
    }
}

impl Drop for CountingServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
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

#[test]
fn blocking_get_json_succeeds_and_sets_accept_encoding() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        br#"{"ok":true}"#.to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .build()
        .expect("client should build");

    let body: Value = client
        .get("/v1/ping")
        .send_json()
        .expect("blocking json call should succeed");

    assert_eq!(body["ok"], true);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/v1/ping");
    assert_eq!(requests[0].body, Vec::<u8>::new());
    assert_eq!(
        requests[0]
            .headers
            .get("accept-encoding")
            .map(String::as_str),
        Some("gzip, br, deflate, zstd")
    );
}

#[test]
fn blocking_buffered_request_accept_encoding_can_be_disabled_per_request() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        br#"{"ok":true}"#.to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let body: Value = client
        .get("/v1/no-auto-accept-encoding")
        .auto_accept_encoding(false)
        .send_json()
        .expect("request should succeed");
    assert_eq!(body["ok"], true);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers.get("accept-encoding"), None);
}

#[test]
fn blocking_head_empty_body_with_content_encoding_is_not_decoded() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "text/plain"), ("Content-Encoding", "zstd")],
        Vec::<u8>::new(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .request(http::Method::HEAD, "/v1/head-empty")
        .send()
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
    assert_eq!(requests[0].headers.get("accept-encoding"), None);
}

#[test]
fn blocking_head_stream_into_response_with_content_encoding_empty_body_succeeds() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "text/plain"), ("Content-Encoding", "zstd")],
        Vec::<u8>::new(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .request(http::Method::HEAD, "/v1/head-stream-empty")
        .send_stream()
        .expect("head stream should succeed")
        .into_response_limited(1024)
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

#[test]
fn blocking_body_reader_accepts_send_non_sync_reader() {
    #[derive(Default)]
    struct NonSyncReader {
        data: Vec<u8>,
        pos: std::cell::Cell<usize>,
    }

    impl Read for NonSyncReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let start = self.pos.get();
            if start >= self.data.len() {
                return Ok(0);
            }
            let remaining = &self.data[start..];
            let to_copy = remaining.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
            self.pos.set(start + to_copy);
            Ok(to_copy)
        }
    }

    let client = Client::builder("http://127.0.0.1")
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let _request = client.post("/v1/upload").body_reader(NonSyncReader {
        data: b"payload".to_vec(),
        ..NonSyncReader::default()
    });
}

#[test]
fn blocking_retries_idempotent_post_then_succeeds() {
    let server = MockServer::start(vec![
        MockResponse::new(
            503,
            vec![("Content-Type", "application/json")],
            b"{}".to_vec(),
        ),
        MockResponse::new(
            201,
            vec![("Content-Type", "application/json")],
            br#"{"id":"item-1"}"#.to_vec(),
        ),
    ]);

    let retry_policy = RetryPolicy::standard()
        .max_attempts(3)
        .base_backoff(Duration::from_millis(5))
        .max_backoff(Duration::from_millis(5))
        .jitter_ratio(0.0);

    let client = Client::builder(server.base_url.clone())
        .retry_policy(retry_policy)
        .request_timeout(Duration::from_secs(1))
        .build()
        .expect("client should build");

    let response: Value = client
        .post("/v1/items")
        .idempotency_key("create-item-1")
        .expect("set idempotency key")
        .json(&serde_json::json!({ "name": "demo" }))
        .expect("serialize body")
        .send_json()
        .expect("blocking request should succeed after retry");

    assert_eq!(response["id"], "item-1");
    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_global_rate_limit_applies_between_requests() {
    let server = MockServer::start(vec![
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok-1".to_vec()),
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok-2".to_vec()),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(20.0)
                .burst(1),
        )
        .build()
        .expect("client should build");

    let started = Instant::now();
    let first = client
        .get("/v1/rate-a")
        .send()
        .expect("first request succeeds");
    let second = client
        .get("/v1/rate-b")
        .send()
        .expect("second request succeeds");
    assert_eq!(first.status().as_u16(), 200);
    assert_eq!(second.status().as_u16(), 200);
    assert!(
        started.elapsed() >= Duration::from_millis(45),
        "rate limiter should introduce spacing between requests"
    );
    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_retry_after_429_backpressures_following_request() {
    let server = MockServer::start(vec![
        MockResponse::new(429, vec![("Retry-After", "1")], b"busy".to_vec()),
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok".to_vec()),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .build()
        .expect("client should build");

    let first = client
        .get("/v1/throttled")
        .send()
        .expect_err("first request should return 429");
    match first {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected first error: {other}"),
    }

    let started = Instant::now();
    let second = client
        .get("/v1/recovered")
        .send()
        .expect("second request should succeed");
    assert_eq!(second.status().as_u16(), 200);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "retry-after should backpressure the next request"
    );
    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_retry_after_429_auto_scope_throttles_same_host_only() {
    let server_a = MockServer::start(vec![
        MockResponse::new(429, vec![("Retry-After", "1")], b"busy".to_vec()),
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok-a".to_vec()),
    ]);
    let server_b = MockServer::start(vec![MockResponse::new(
        200,
        Vec::<(String, String)>::new(),
        b"ok-b".to_vec(),
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

    let first = client
        .get("/v1/throttled")
        .send()
        .expect_err("first request should return 429");
    match first {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected first error: {other}"),
    }

    let cross_host_started = Instant::now();
    let cross_host = client
        .get(host_b_url)
        .send()
        .expect("cross-host request should not be backpressured in auto scope");
    assert_eq!(cross_host.status().as_u16(), 200);
    assert!(
        cross_host_started.elapsed() < Duration::from_millis(250),
        "cross-host request should not inherit host-a retry-after backpressure"
    );

    let same_host_started = Instant::now();
    let same_host = client
        .get("/v1/recovered-a")
        .send()
        .expect("same host request should eventually succeed");
    assert_eq!(same_host.status().as_u16(), 200);
    assert!(
        same_host_started.elapsed() >= Duration::from_millis(900),
        "same host should be backpressured by retry-after"
    );
}

#[test]
fn blocking_retry_after_429_global_scope_backpressures_other_hosts() {
    let server_a = MockServer::start(vec![MockResponse::new(
        429,
        vec![("Retry-After", "1")],
        b"busy".to_vec(),
    )]);
    let server_b = MockServer::start(vec![MockResponse::new(
        200,
        Vec::<(String, String)>::new(),
        b"ok-b".to_vec(),
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

    let first = client
        .get("/v1/throttled")
        .send()
        .expect_err("first request should return 429");
    match first {
        Error::HttpStatus { status, .. } => assert_eq!(status, 429),
        other => panic!("unexpected first error: {other}"),
    }

    let cross_host_started = Instant::now();
    let cross_host = client
        .get(host_b_url)
        .send()
        .expect("cross-host request should succeed");
    assert_eq!(cross_host.status().as_u16(), 200);
    assert!(
        cross_host_started.elapsed() >= Duration::from_millis(900),
        "global scope should backpressure requests for other hosts"
    );
}

#[test]
fn blocking_max_in_flight_enforces_single_active_request() {
    let server = CountingServer::start(
        3,
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok".to_vec()),
        Duration::from_millis(120),
    );
    let client = Arc::new(
        Client::builder(format!("http://{}", server.authority()))
            .max_in_flight(1)
            .request_timeout(Duration::from_millis(800))
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client should build"),
    );
    let barrier = Arc::new(Barrier::new(4));

    let started = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..3 {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            client
                .get("/slow")
                .send()
                .map(|response| response.status().as_u16())
        }));
    }
    barrier.wait();

    for worker in workers {
        let status = worker
            .join()
            .expect("join spawned request")
            .expect("request should succeed");
        assert_eq!(status, 200);
    }

    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(server.served_count(), 3);
    assert_eq!(server.max_active(), 1);
}

#[test]
fn blocking_max_in_flight_per_host_limits_each_host_independently() {
    let server_a = CountingServer::start(
        2,
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok-a".to_vec()),
        Duration::from_millis(120),
    );
    let server_b = CountingServer::start(
        2,
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok-b".to_vec()),
        Duration::from_millis(120),
    );
    let client = Arc::new(
        Client::builder(format!("http://{}", server_a.authority()))
            .max_in_flight_per_host(1)
            .request_timeout(Duration::from_millis(800))
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client should build"),
    );
    let server_b_url = format!("http://{}/host-b", server_b.authority());
    let barrier = Arc::new(Barrier::new(5));

    let started = Instant::now();
    let mut workers = Vec::new();
    for idx in 0..4 {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        let path = if idx % 2 == 0 {
            "/host-a".to_owned()
        } else {
            server_b_url.clone()
        };
        workers.push(thread::spawn(move || {
            barrier.wait();
            client
                .get(path)
                .send()
                .map(|response| response.status().as_u16())
        }));
    }
    barrier.wait();

    for worker in workers {
        let status = worker
            .join()
            .expect("join spawned request")
            .expect("request should succeed");
        assert_eq!(status, 200);
    }

    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(220));
    assert!(
        elapsed < Duration::from_millis(460),
        "per-host run took too long: {elapsed:?}"
    );
    assert_eq!(server_a.served_count(), 2);
    assert_eq!(server_b.served_count(), 2);
    assert_eq!(server_a.max_active(), 1);
    assert_eq!(server_b.max_active(), 1);
}

#[test]
fn blocking_max_in_flight_queue_wait_respects_total_timeout_deadline() {
    let server = CountingServer::start(
        1,
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok".to_vec()),
        Duration::ZERO,
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .max_in_flight(1)
        .request_timeout(Duration::from_millis(800))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let held_stream = client
        .get("/hold-global-permit")
        .send_stream()
        .expect("first stream should acquire and hold the global permit");

    let error = client
        .get("/queued-behind-global-permit")
        .total_timeout(Duration::from_millis(80))
        .send()
        .expect_err("queued request should stop waiting once total_timeout is exhausted");
    match error {
        Error::DeadlineExceeded { uri, .. } => {
            assert!(uri.contains("/queued-behind-global-permit"));
        }
        other => panic!("unexpected error variant: {other}"),
    }

    drop(held_stream);
    assert_eq!(server.served_count(), 1);
}

#[test]
fn blocking_total_timeout_includes_global_queue_wait_before_send_loop() {
    let server = CountingServer::start(
        2,
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok".to_vec()),
        Duration::from_millis(120),
    );
    let client = Arc::new(
        Client::builder(format!("http://{}", server.authority()))
            .max_in_flight(1)
            .request_timeout(Duration::from_millis(500))
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client should build"),
    );

    let held_stream = client
        .get("/hold-global-permit-for-total-timeout")
        .send_stream()
        .expect("first stream should acquire and hold the global permit");

    let queued_client = Arc::clone(&client);
    let queued = thread::spawn(move || {
        queued_client
            .get("/queued-total-timeout")
            .total_timeout(Duration::from_millis(220))
            .send()
    });

    thread::sleep(Duration::from_millis(140));
    drop(held_stream);

    let error = queued
        .join()
        .expect("join queued request")
        .expect_err("request should honor total_timeout including global queue wait");
    match error {
        Error::DeadlineExceeded { uri, .. } => {
            assert!(uri.contains("/queued-total-timeout"));
        }
        Error::Timeout {
            timeout_ms, uri, ..
        } => {
            assert!(uri.contains("/queued-total-timeout"));
            assert!(
                timeout_ms < 220,
                "remaining timeout should be bounded by elapsed queue wait"
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_adaptive_concurrency_queue_wait_respects_total_timeout_deadline() {
    let server = CountingServer::start(
        1,
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok".to_vec()),
        Duration::from_millis(260),
    );
    let client = Arc::new(
        Client::builder(format!("http://{}", server.authority()))
            .adaptive_concurrency_policy(
                AdaptiveConcurrencyPolicy::standard()
                    .min_limit(1)
                    .initial_limit(1)
                    .max_limit(1),
            )
            .request_timeout(Duration::from_millis(700))
            .retry_policy(RetryPolicy::disabled())
            .build()
            .expect("client should build"),
    );

    let barrier = Arc::new(Barrier::new(2));
    let first_client = Arc::clone(&client);
    let first_barrier = Arc::clone(&barrier);
    let first = thread::spawn(move || {
        first_barrier.wait();
        first_client
            .get("/adaptive-first")
            .send()
            .map(|response| response.status().as_u16())
    });
    barrier.wait();
    thread::sleep(Duration::from_millis(20));

    let error = client
        .get("/adaptive-second")
        .total_timeout(Duration::from_millis(80))
        .send()
        .expect_err("queued adaptive request should stop waiting at total_timeout");
    match error {
        Error::DeadlineExceeded { uri, .. } => {
            assert!(uri.contains("/adaptive-second"));
        }
        other => panic!("unexpected error variant: {other}"),
    }

    let first_status = first
        .join()
        .expect("join first request")
        .expect("first request should succeed");
    assert_eq!(first_status, 200);
    assert_eq!(server.served_count(), 1);
}

#[test]
fn blocking_retry_budget_exhausted_stops_retry_loop_early() {
    let server = MockServer::start(vec![
        MockResponse::new(
            503,
            vec![("Content-Type", "application/json")],
            b"{}".to_vec(),
        ),
        MockResponse::new(
            503,
            vec![("Content-Type", "application/json")],
            b"{}".to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(5)
                .base_backoff(Duration::from_millis(1))
                .max_backoff(Duration::from_millis(2))
                .jitter_ratio(0.0),
        )
        .retry_budget_policy(
            RetryBudgetPolicy::standard()
                .window(Duration::from_secs(1))
                .retry_ratio(0.0)
                .min_retries_per_window(1),
        )
        .request_timeout(Duration::from_secs(1))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/budget")
        .send()
        .expect_err("retry budget should stop retries after one retry");

    match error {
        Error::RetryBudgetExhausted { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_retry_budget_is_credited_by_non_retryable_status_response_mode() {
    let server = MockServer::start(vec![
        MockResponse::new(404, Vec::<(String, String)>::new(), b"not-found".to_vec()),
        MockResponse::new(503, Vec::<(String, String)>::new(), b"busy".to_vec()),
        MockResponse::new(200, Vec::<(String, String)>::new(), b"ok".to_vec()),
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
        .request_timeout(Duration::from_secs(1))
        .build()
        .expect("client should build");

    let first = client
        .get("/v1/status-404")
        .send()
        .expect("404 should be returned as response");
    assert_eq!(first.status().as_u16(), 404);

    let second = client
        .get("/v1/status-503-then-200")
        .send()
        .expect("retry budget should allow one retry after 404 credit");
    assert_eq!(second.status().as_u16(), 200);
    assert_eq!(server.served_count(), 3);
}

#[test]
fn blocking_build_rejects_invalid_adaptive_concurrency_policy() {
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

#[test]
fn blocking_circuit_breaker_short_circuits_after_opening() {
    let server = MockServer::start(vec![MockResponse::new(
        503,
        vec![("Content-Type", "application/json")],
        b"{}".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .retry_policy(RetryPolicy::disabled())
        .circuit_breaker_policy(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_secs(30))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
        )
        .request_timeout(Duration::from_secs(1))
        .build()
        .expect("client should build");

    let first = client
        .get("/v1/open")
        .send()
        .expect_err("first request should return 503");
    match first {
        Error::HttpStatus { status, .. } => assert_eq!(status, 503),
        other => panic!("unexpected first error: {other}"),
    }

    let second = client
        .get("/v1/open")
        .send()
        .expect_err("second request should be rejected by circuit");
    match second {
        Error::CircuitOpen { .. } => {}
        other => panic!("unexpected second error: {other}"),
    }

    assert_eq!(server.served_count(), 1);
}

#[test]
fn blocking_circuit_breaker_error_mode_does_not_open_on_non_success_buffered() {
    let server = MockServer::start(vec![
        MockResponse::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
        ),
        MockResponse::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .retry_policy(RetryPolicy::disabled())
        .circuit_breaker_policy(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_secs(30))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
        )
        .request_timeout(Duration::from_millis(400))
        .build()
        .expect("client should build");

    let first = client
        .get("/v1/error-mode-buffered")
        .send()
        .expect_err("first non-success request should return an http status error");
    match first {
        Error::HttpStatus { status, .. } => assert_eq!(status, 404),
        other => panic!("unexpected first error: {other}"),
    }

    let second = client
        .get("/v1/error-mode-buffered")
        .send()
        .expect_err("second non-success request should not be short-circuited");
    match second {
        Error::HttpStatus { status, .. } => assert_eq!(status, 404),
        other => panic!("unexpected second error: {other}"),
    }

    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_circuit_breaker_response_mode_does_not_open_on_non_success_buffered() {
    let server = MockServer::start(vec![
        MockResponse::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
        ),
        MockResponse::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .retry_policy(RetryPolicy::disabled())
        .circuit_breaker_policy(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_secs(30))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
        )
        .request_timeout(Duration::from_millis(400))
        .build()
        .expect("client should build");

    let first = client
        .get("/v1/response-mode-buffered")
        .send_with_status()
        .expect("first non-success response should be returned");
    assert_eq!(first.status(), http::StatusCode::NOT_FOUND);

    let second = client
        .get("/v1/response-mode-buffered")
        .send_with_status()
        .expect("second non-success response should be returned");
    assert_eq!(second.status(), http::StatusCode::NOT_FOUND);

    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_circuit_breaker_response_mode_does_not_open_on_non_success_stream() {
    let server = MockServer::start(vec![
        MockResponse::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
        ),
        MockResponse::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .retry_policy(RetryPolicy::disabled())
        .circuit_breaker_policy(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_secs(30))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
        )
        .request_timeout(Duration::from_millis(400))
        .build()
        .expect("client should build");

    let first = client
        .get("/v1/response-mode-stream")
        .send_stream_with_status()
        .expect("first non-success stream should be returned");
    assert_eq!(first.status(), http::StatusCode::NOT_FOUND);

    let second = client
        .get("/v1/response-mode-stream")
        .send_stream_with_status()
        .expect("second non-success stream should be returned");
    assert_eq!(second.status(), http::StatusCode::NOT_FOUND);

    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_tls_root_store_specific_without_roots_returns_tls_config_error() {
    let result = Client::builder("https://api.example.com")
        .tls_root_store(TlsRootStore::Specific)
        .build();
    let error = match result {
        Ok(_) => panic!("specific root store without roots should fail"),
        Err(error) => error,
    };

    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::Specific"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_build_rejects_invalid_base_url_early() {
    let result = Client::builder("ftp://api.example.com").build();
    let error = match result {
        Ok(_) => panic!("non-http base url should fail at build time"),
        Err(error) => error,
    };

    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "ftp://api.example.com/");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_build_rejects_base_url_with_query() {
    let result = Client::builder("https://api.example.com/v1?token=abc").build();
    let error = match result {
        Ok(_) => panic!("base url with query should fail at build time"),
        Err(error) => error,
    };

    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com/v1");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_tls_root_store_system_accepts_custom_roots() {
    let custom_der = rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .next()
        .map(|certificate| certificate.as_ref().to_vec());
    let Some(custom_der) = custom_der else {
        return;
    };

    let result = Client::builder("https://api.example.com")
        .tls_root_store(TlsRootStore::System)
        .tls_root_ca_der(custom_der)
        .build();
    result.expect("system root store should allow appending custom roots");
}

#[test]
fn blocking_custom_root_ca_requires_explicit_root_store() {
    let result = Client::builder("https://api.example.com")
        .tls_root_ca_der([1_u8, 2, 3, 4])
        .build();
    let error = match result {
        Ok(_) => panic!("custom root ca should require an explicit root store"),
        Err(error) => error,
    };

    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::System"));
            assert!(message.contains("TlsRootStore::Specific"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_response_body_limit_returns_specific_error() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "text/plain")],
        b"0123456789".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .max_response_body_bytes(4)
        .request_timeout(Duration::from_secs(1))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/large")
        .send()
        .expect_err("response body should exceed max size");

    match error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            actual_bytes,
            ..
        } => {
            assert_eq!(limit_bytes, 4);
            assert!(actual_bytes > limit_bytes);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_send_stream_downloads_body_and_status() {
    let payload = b"blocking-stream-ok".to_vec();
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/octet-stream")],
        payload.clone(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/v1/stream")
        .send_stream()
        .expect("stream request should succeed");
    assert_eq!(streamed.status().as_u16(), 200);
    assert_eq!(streamed.method().as_str(), "GET");
    assert!(streamed.uri().contains("/v1/stream"));

    let body = streamed
        .into_bytes_limited(1024)
        .expect("stream body read should succeed");
    assert_eq!(body.to_vec(), payload);
}

#[test]
fn blocking_send_stream_limit_violation_uses_response_body_too_large_error() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/octet-stream")],
        b"0123456789".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/v1/stream-large")
        .send_stream()
        .expect("stream request should succeed");
    let error = streamed
        .into_bytes_limited(4)
        .expect_err("stream body should exceed max size");

    match error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            actual_bytes,
            method,
            uri,
        } => {
            assert_eq!(limit_bytes, 4);
            assert!(actual_bytes > limit_bytes);
            assert_eq!(method.as_str(), "GET");
            assert!(uri.contains("/v1/stream-large"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_send_stream_maps_body_timeout_to_response_body_phase() {
    let server = SplitBodyServer::start(
        200,
        vec![("Content-Type".to_owned(), "text/plain".to_owned())],
        b"delayed".to_vec(),
        Duration::from_millis(180),
    );

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(80))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/v1/slow-stream")
        .send_stream()
        .expect("headers should be read before timeout");
    let error = streamed
        .into_bytes_limited(1024)
        .expect_err("body read should time out");

    match error {
        Error::Timeout {
            phase, method, uri, ..
        } => {
            assert_eq!(phase, TimeoutPhase::ResponseBody);
            assert_eq!(method.as_str(), "GET");
            assert!(uri.contains("/v1/slow-stream"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_buffered_response_body_timeout_maps_to_deadline_exceeded_when_total_timeout_is_exhausted()
 {
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
        .get("/v1/slow-body-total-timeout")
        .send()
        .expect_err("slow body read should stop at the total timeout deadline");
    match error {
        Error::DeadlineExceeded { method, uri, .. } => {
            assert_eq!(method.as_str(), "GET");
            assert!(uri.contains("/v1/slow-body-total-timeout"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn blocking_send_stream_respects_total_timeout_deadline() {
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

    let streamed = client
        .get("/v1/stream-total-timeout")
        .send_stream()
        .expect("stream request should return headers");
    let error = streamed
        .into_bytes_limited(1024)
        .expect_err("stream read should stop at total timeout deadline");

    match error {
        Error::DeadlineExceeded { uri, .. } => {
            assert!(uri.contains("/v1/stream-total-timeout"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_send_http_status_error_strips_decoded_encoding_headers() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(br#"{"error":"bad-request"}"#)
        .expect("write gzip source bytes should succeed");
    let body = encoder.finish().expect("finish gzip stream should succeed");
    let server = MockServer::start(vec![MockResponse::new(
        400,
        vec![
            ("Content-Type", "application/json"),
            ("Content-Encoding", "gzip"),
        ],
        body,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/gzip-http-status-buffered")
        .send()
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

#[test]
fn blocking_send_stream_keeps_raw_bytes_and_decode_is_explicit() {
    let server = MockServer::start(vec![
        MockResponse::new(
            200,
            vec![
                ("Content-Type", "application/octet-stream"),
                ("Content-Encoding", "gzip"),
            ],
            b"not-valid-gzip".to_vec(),
        ),
        MockResponse::new(
            200,
            vec![
                ("Content-Type", "application/octet-stream"),
                ("Content-Encoding", "gzip"),
            ],
            b"not-valid-gzip".to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/v1/decode-error")
        .send_stream()
        .expect("stream request should succeed");
    let raw = streamed
        .into_bytes_limited(1024)
        .expect("stream read should return raw compressed bytes");
    assert_eq!(raw.as_ref(), b"not-valid-gzip");

    let streamed = client
        .get("/v1/decode-error")
        .send_stream()
        .expect("stream request should succeed");
    let error = streamed
        .into_response_limited(1024)
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
            assert!(uri.contains("/v1/decode-error"));
        }
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].headers.get("accept-encoding"), None);
    assert_eq!(requests[1].headers.get("accept-encoding"), None);
}

#[test]
fn blocking_send_stream_http_status_error_strips_decoded_encoding_headers() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(br#"{"error":"bad-request"}"#)
        .expect("write gzip source bytes should succeed");
    let body = encoder.finish().expect("finish gzip stream should succeed");
    let server = MockServer::start(vec![MockResponse::new(
        400,
        vec![
            ("Content-Type", "application/json"),
            ("Content-Encoding", "gzip"),
        ],
        body,
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/gzip-http-status")
        .send_stream()
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

#[test]
fn blocking_send_stream_accept_encoding_can_be_opted_in_per_request() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/octet-stream")],
        b"ok".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let _ = client
        .get("/v1/stream-opt-in")
        .auto_accept_encoding(true)
        .send_stream()
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

#[test]
fn blocking_stream_auto_accept_encoding_can_be_enabled_at_client_level() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/octet-stream")],
        b"ok".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .stream_auto_accept_encoding(true)
        .build()
        .expect("client should build");

    let _ = client
        .get("/v1/stream-client-opt-in")
        .send_stream()
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

#[test]
fn blocking_download_to_writer_writes_stream_without_buffering() {
    let payload = b"writer-stream-ok".to_vec();
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/octet-stream")],
        payload.clone(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let mut output = Vec::new();
    let written = client
        .get("/v1/download-writer")
        .download_to_writer(&mut output)
        .expect("download_to_writer should succeed");
    assert_eq!(written as usize, payload.len());
    assert_eq!(output, payload);
}

#[test]
fn blocking_download_to_writer_limited_maps_limit_error() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/octet-stream")],
        b"0123456789".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let mut output = Vec::new();
    let error = client
        .get("/v1/download-limit")
        .download_to_writer_limited(&mut output, 4)
        .expect_err("download_to_writer_limited should enforce max bytes");

    match error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            method,
            uri,
            ..
        } => {
            assert_eq!(limit_bytes, 4);
            assert_eq!(method.as_str(), "GET");
            assert!(uri.contains("/v1/download-limit"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_redirect_policy_follows_relative_location() {
    let server = MockServer::start(vec![
        MockResponse::new(302, vec![("Location", "/v1/new")], b"redirect".to_vec()),
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            br#"{"ok":true}"#.to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let body: Value = client
        .get("/v1/old")
        .send_json()
        .expect("redirect should be followed");
    assert_eq!(body["ok"], true);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1/old");
    assert_eq!(requests[1].path, "/v1/new");
}

#[test]
fn blocking_redirect_post_302_rewrites_to_get_and_drops_body() {
    let server = MockServer::start(vec![
        MockResponse::new(302, vec![("Location", "/v1/new")], b"redirect".to_vec()),
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            br#"{"ok":true}"#.to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let body: Value = client
        .post("/v1/old")
        .json(&serde_json::json!({ "name": "demo" }))
        .expect("serialize body")
        .send_json()
        .expect("redirect should be followed");
    assert_eq!(body["ok"], true);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[1].method, "GET");
    assert!(requests[1].body.is_empty());
}

#[test]
fn blocking_redirect_303_allows_non_replayable_reader_body_when_method_changes_to_get() {
    let server = MockServer::start(vec![
        MockResponse::new(303, vec![("Location", "/v1/new")], b"redirect".to_vec()),
        MockResponse::new(200, vec![("Content-Type", "text/plain")], b"ok".to_vec()),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let response = client
        .post("/v1/old")
        .body_reader(Cursor::new(b"payload".to_vec()))
        .send()
        .expect("303 redirect should be followed even for non-replayable body");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text_lossy(), "ok");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[1].method, "GET");
    assert!(requests[1].body.is_empty());
}

#[test]
fn blocking_redirect_307_rejects_non_replayable_reader_body() {
    let server = MockServer::start(vec![MockResponse::new(
        307,
        vec![("Location", "/v1/new")],
        b"redirect".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .post("/v1/old")
        .body_reader(Cursor::new(b"payload".to_vec()))
        .send()
        .expect_err("307 redirect should fail for non-replayable body");

    match error {
        Error::RedirectBodyNotReplayable { .. } => {}
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
}

#[test]
fn blocking_redirect_invalid_location_redacts_sensitive_tokens_in_error() {
    let server = MockServer::start(vec![MockResponse::new(
        302,
        vec![(
            "Location",
            "https://example.com:invalid/v1/new?token=secret#frag",
        )],
        b"redirect".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/old")
        .send()
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

#[test]
fn blocking_redirect_http_location_with_userinfo_is_rejected() {
    let server = MockServer::start(vec![MockResponse::new(
        302,
        vec![(
            "Location",
            "https://user:pass@example.com/v1/new?token=secret",
        )],
        b"redirect".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/userinfo-redirect")
        .send()
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

#[test]
fn blocking_redirect_non_http_location_is_rejected() {
    let server = MockServer::start(vec![MockResponse::new(
        302,
        vec![("Location", "mailto:user:pass@example.com?subject=secret")],
        b"redirect".to_vec(),
    )]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/non-http-redirect")
        .send()
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

#[test]
fn blocking_absolute_request_uri_with_userinfo_is_rejected() {
    let client = Client::builder("https://api.example.com")
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("https://user:pass@example.com/v1/items?token=secret")
        .send()
        .expect_err("absolute request URI with userinfo should be rejected");

    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://example.com/v1/items");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_redirect_policy_none_returns_301_without_following_in_response_mode() {
    let server = MockServer::start(vec![
        MockResponse::new(301, vec![("Location", "/v1/new")], b"redirect".to_vec()),
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            br#"{"ok":true}"#.to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::none())
        .default_status_policy(StatusPolicy::Response)
        .build()
        .expect("client should build");

    let response = client
        .get("/v1/old")
        .send()
        .expect("request should return 301");
    assert_eq!(response.status().as_u16(), 301);
    assert_eq!(response.text_lossy(), "redirect");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/old");
}

#[test]
fn blocking_redirect_policy_none_returns_http_status_error_without_following() {
    let server = MockServer::start(vec![
        MockResponse::new(301, vec![("Location", "/v1/new")], b"redirect".to_vec()),
        MockResponse::new(
            200,
            vec![("Content-Type", "application/json")],
            br#"{"ok":true}"#.to_vec(),
        ),
    ]);

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::none())
        .default_status_policy(StatusPolicy::Error)
        .build()
        .expect("client should build");

    let error = client
        .get("/v1/old")
        .send()
        .expect_err("request should return status error");

    match error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 301),
        other => panic!("unexpected error: {other}"),
    }

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/old");
}

struct BlockingHeaderInterceptor {
    request_hits: Arc<AtomicUsize>,
    response_hits: Arc<AtomicUsize>,
    error_hits: Arc<AtomicUsize>,
}

impl Interceptor for BlockingHeaderInterceptor {
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

#[test]
fn blocking_interceptor_can_mutate_headers_and_observe_lifecycle() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/json")],
        br#"{"ok":true}"#.to_vec(),
    )]);

    let request_hits = Arc::new(AtomicUsize::new(0));
    let response_hits = Arc::new(AtomicUsize::new(0));
    let error_hits = Arc::new(AtomicUsize::new(0));
    let interceptor = Arc::new(BlockingHeaderInterceptor {
        request_hits: Arc::clone(&request_hits),
        response_hits: Arc::clone(&response_hits),
        error_hits: Arc::clone(&error_hits),
    });

    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .interceptor_arc(interceptor)
        .build()
        .expect("client should build");

    let body: Value = client
        .get("/v1/interceptor")
        .send_json()
        .expect("request should succeed");
    assert_eq!(body["ok"], true);

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
