#![cfg(feature = "_blocking")]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use reqx::blocking::HttpClient;
use reqx::prelude::{HttpClientError, RetryPolicy};
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
