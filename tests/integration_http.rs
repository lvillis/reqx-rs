#![cfg(feature = "_async")]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use futures_util::stream;
use http::header::{CONTENT_LENGTH, HeaderName, HeaderValue};
use reqx::prelude::{
    Client, Error, HttpInterceptor, RateLimitPolicy, RedirectPolicy, RequestContext, RetryPolicy,
    ServerThrottleScope, TimeoutPhase,
};
use serde::Serialize;
use serde_json::{Value, json};

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
    raw.windows(4).position(|window| window == b"\r\n\r\n")
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
async fn response_body_timeout_reports_phase_and_metrics() {
    let server = SplitBodyServer::start(
        200,
        vec![("Content-Type".to_owned(), "application/json".to_owned())],
        br#"{"ok":true}"#.to_vec(),
        Duration::from_millis(120),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_millis(20))
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
    assert_eq!(metrics.requests_started, 1);
    assert_eq!(metrics.requests_succeeded, 0);
    assert_eq!(metrics.requests_failed, 1);
    assert_eq!(metrics.timeout_transport, 0);
    assert_eq!(metrics.timeout_response_body, 1);
    assert_eq!(metrics.in_flight, 0);
    assert_eq!(
        metrics.error_counts.get("timeout:response_body"),
        Some(&1_u64)
    );
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
    assert_eq!(metrics.requests_started, 1);
    assert_eq!(metrics.requests_failed, 1);
    assert_eq!(
        metrics.error_counts.get("decode_content_encoding"),
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
    assert_eq!(metrics.requests_started, 3);
    assert_eq!(metrics.requests_succeeded, 1);
    assert_eq!(metrics.requests_failed, 2);
    assert_eq!(metrics.retries, 0);
    assert_eq!(metrics.http_status_errors, 1);
    assert_eq!(metrics.response_body_too_large, 1);
    assert_eq!(metrics.status_counts.get(&200), Some(&1_u64));
    assert_eq!(metrics.status_counts.get(&503), Some(&1_u64));
    assert_eq!(metrics.error_counts.get("http_status:503"), Some(&1_u64));
    assert_eq!(
        metrics.error_counts.get("response_body_too_large"),
        Some(&1_u64)
    );
    assert_eq!(metrics.in_flight, 0);
    assert_eq!(metrics.latency_samples, 3);
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
    assert_eq!(metrics.requests_started, 0);
    assert_eq!(metrics.requests_succeeded, 0);
    assert_eq!(metrics.requests_failed, 0);
    assert_eq!(metrics.retries, 0);
    assert_eq!(metrics.latency_samples, 0);
    assert!(metrics.status_counts.is_empty());
    assert!(metrics.error_counts.is_empty());
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

struct HeaderInjectingInterceptor {
    request_hits: Arc<AtomicUsize>,
    response_hits: Arc<AtomicUsize>,
    error_hits: Arc<AtomicUsize>,
}

impl HttpInterceptor for HeaderInjectingInterceptor {
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
