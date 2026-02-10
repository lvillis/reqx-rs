#![cfg(feature = "_blocking")]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use http::header::{HeaderName, HeaderValue};
use reqx::blocking::HttpClient;
use reqx::prelude::{
    CircuitBreakerPolicy, HttpClientError, HttpInterceptor, RateLimitPolicy, RedirectPolicy,
    RequestContext, RetryBudgetPolicy, RetryPolicy, ServerThrottleScope, TimeoutPhase,
    TlsRootStore,
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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .build();

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
    assert!(
        requests[0]
            .headers
            .get("accept-encoding")
            .is_some_and(|value| value.contains("gzip"))
    );
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

    let client = HttpClient::builder(server.base_url.clone())
        .retry_policy(retry_policy)
        .request_timeout(Duration::from_secs(1))
        .build();

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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(20.0)
                .burst(1),
        )
        .build();

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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(2))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(500.0)
                .burst(50),
        )
        .build();

    let first = client
        .get("/v1/throttled")
        .send()
        .expect_err("first request should return 429");
    match first {
        HttpClientError::HttpStatus { status, .. } => assert_eq!(status, 429),
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

    let client = HttpClient::builder(server_a.base_url.clone())
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
        .build();

    let first = client
        .get("/v1/throttled")
        .send()
        .expect_err("first request should return 429");
    match first {
        HttpClientError::HttpStatus { status, .. } => assert_eq!(status, 429),
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

    let client = HttpClient::builder(server_a.base_url.clone())
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
        .build();

    let first = client
        .get("/v1/throttled")
        .send()
        .expect_err("first request should return 429");
    match first {
        HttpClientError::HttpStatus { status, .. } => assert_eq!(status, 429),
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

    let client = HttpClient::builder(server.base_url.clone())
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
        .build();

    let error = client
        .get("/v1/budget")
        .send()
        .expect_err("retry budget should stop retries after one retry");

    match error {
        HttpClientError::RetryBudgetExhausted { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(server.served_count(), 2);
}

#[test]
fn blocking_circuit_breaker_short_circuits_after_opening() {
    let server = MockServer::start(vec![MockResponse::new(
        503,
        vec![("Content-Type", "application/json")],
        b"{}".to_vec(),
    )]);

    let client = HttpClient::builder(server.base_url.clone())
        .retry_policy(RetryPolicy::disabled())
        .circuit_breaker_policy(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_secs(30))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
        )
        .request_timeout(Duration::from_secs(1))
        .build();

    let first = client
        .get("/v1/open")
        .send()
        .expect_err("first request should return 503");
    match first {
        HttpClientError::HttpStatus { status, .. } => assert_eq!(status, 503),
        other => panic!("unexpected first error: {other}"),
    }

    let second = client
        .get("/v1/open")
        .send()
        .expect_err("second request should be rejected by circuit");
    match second {
        HttpClientError::CircuitOpen { .. } => {}
        other => panic!("unexpected second error: {other}"),
    }

    assert_eq!(server.served_count(), 1);
}

#[test]
fn blocking_tls_root_store_specific_without_roots_returns_tls_config_error() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_root_store(TlsRootStore::Specific)
        .try_build();
    let error = match result {
        Ok(_) => panic!("specific root store without roots should fail"),
        Err(error) => error,
    };

    match error {
        HttpClientError::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::Specific"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_try_build_rejects_invalid_base_url_early() {
    let result = HttpClient::builder("ftp://api.example.com").try_build();
    let error = match result {
        Ok(_) => panic!("non-http base url should fail at build time"),
        Err(error) => error,
    };

    match error {
        HttpClientError::InvalidUri { uri } => {
            assert_eq!(uri, "ftp://api.example.com");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_tls_root_store_system_rejects_custom_roots() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_root_store(TlsRootStore::System)
        .tls_root_ca_der([1_u8, 2, 3, 4])
        .try_build();
    let error = match result {
        Ok(_) => panic!("system root store should reject custom roots"),
        Err(error) => error,
    };

    match error {
        HttpClientError::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::Specific"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn blocking_custom_root_ca_requires_specific_root_store() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_root_ca_der([1_u8, 2, 3, 4])
        .try_build();
    let error = match result {
        Ok(_) => panic!("custom root ca should require specific root store"),
        Err(error) => error,
    };

    match error {
        HttpClientError::TlsConfig { message, .. } => {
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

    let client = HttpClient::builder(server.base_url.clone())
        .max_response_body_bytes(4)
        .request_timeout(Duration::from_secs(1))
        .build();

    let error = client
        .get("/v1/large")
        .send()
        .expect_err("response body should exceed max size");

    match error {
        HttpClientError::ResponseBodyTooLarge {
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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build();

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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build();

    let streamed = client
        .get("/v1/stream-large")
        .send_stream()
        .expect("stream request should succeed");
    let error = streamed
        .into_bytes_limited(4)
        .expect_err("stream body should exceed max size");

    match error {
        HttpClientError::ResponseBodyTooLarge {
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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(80))
        .retry_policy(RetryPolicy::disabled())
        .build();

    let streamed = client
        .get("/v1/slow-stream")
        .send_stream()
        .expect("headers should be read before timeout");
    let error = streamed
        .into_bytes_limited(1024)
        .expect_err("body read should time out");

    match error {
        HttpClientError::Timeout {
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
fn blocking_send_stream_maps_decode_error_consistently() {
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![
            ("Content-Type", "application/octet-stream"),
            ("Content-Encoding", "gzip"),
        ],
        b"not-valid-gzip".to_vec(),
    )]);

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build();

    let streamed = client
        .get("/v1/decode-error")
        .send_stream()
        .expect("stream request should succeed");
    let error = streamed
        .into_bytes_limited(1024)
        .expect_err("invalid gzip body should fail decoding");

    match error {
        HttpClientError::DecodeContentEncoding {
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
}

#[test]
fn blocking_download_to_writer_writes_stream_without_buffering() {
    let payload = b"writer-stream-ok".to_vec();
    let server = MockServer::start(vec![MockResponse::new(
        200,
        vec![("Content-Type", "application/octet-stream")],
        payload.clone(),
    )]);

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build();

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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build();

    let mut output = Vec::new();
    let error = client
        .get("/v1/download-limit")
        .download_to_writer_limited(&mut output, 4)
        .expect_err("download_to_writer_limited should enforce max bytes");

    match error {
        HttpClientError::ResponseBodyTooLarge {
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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .redirect_policy(RedirectPolicy::limited(3))
        .build();

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

struct BlockingHeaderInterceptor {
    request_hits: Arc<AtomicUsize>,
    response_hits: Arc<AtomicUsize>,
    error_hits: Arc<AtomicUsize>,
}

impl HttpInterceptor for BlockingHeaderInterceptor {
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

    fn on_error(&self, _context: &RequestContext, _error: &HttpClientError) {
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

    let client = HttpClient::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .interceptor_arc(interceptor)
        .build();

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
