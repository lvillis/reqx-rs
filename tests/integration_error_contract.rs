#![cfg(any(feature = "_async", feature = "_blocking"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use reqx::prelude::{Error, ErrorCode};

struct OneShotServer {
    base_url: String,
    join: Option<JoinHandle<()>>,
}

impl OneShotServer {
    fn start(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind one-shot server");
        listener
            .set_nonblocking(true)
            .expect("set one-shot listener nonblocking");
        let address = listener
            .local_addr()
            .expect("read one-shot listener address");

        let join = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = read_request_headers(&mut stream);

                        let mut response_head = format!(
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                            status,
                            status_text(status),
                            body.len()
                        );
                        for (name, value) in &headers {
                            response_head.push_str(name);
                            response_head.push_str(": ");
                            response_head.push_str(value);
                            response_head.push_str("\r\n");
                        }
                        response_head.push_str("\r\n");

                        let _ = stream.write_all(response_head.as_bytes());
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

impl Drop for OneShotServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_request_headers(stream: &mut std::net::TcpStream) -> std::io::Result<()> {
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
    Ok(())
}

fn assert_error_contract(error: &Error, expected: ErrorCode, expected_code: &str) {
    assert_eq!(error.code(), expected);
    assert_eq!(error.code().as_str(), expected_code);
}

#[test]
fn error_display_does_not_include_response_body_payloads() {
    let secret = "token=super-secret-value";
    let status_error = Error::HttpStatus {
        status: 503,
        method: http::Method::GET,
        uri: "https://example.com/private".to_owned(),
        headers: Box::new(http::HeaderMap::new()),
        body: secret.to_owned(),
    };
    let status_text = status_error.to_string();
    assert!(
        !status_text.contains(secret),
        "http status display should not leak response body"
    );
    match status_error {
        Error::HttpStatus { body, .. } => assert_eq!(body, secret),
        other => panic!("unexpected error variant: {other}"),
    }

    let source = serde_json::from_slice::<serde_json::Value>(b"{not-json")
        .expect_err("invalid json should produce a decode error");
    let decode_error = Error::DeserializeJson {
        source,
        body: secret.to_owned(),
    };
    let decode_text = decode_error.to_string();
    assert!(
        !decode_text.contains(secret),
        "json decode display should not leak response body"
    );
    match decode_error {
        Error::DeserializeJson { body, .. } => assert_eq!(body, secret),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[derive(Clone)]
struct CountingObserver {
    started: Arc<AtomicUsize>,
    retries: Arc<AtomicUsize>,
}

impl reqx::Observer for CountingObserver {
    fn on_request_start(&self, _context: &reqx::RequestContext) {
        self.started.fetch_add(1, Ordering::Relaxed);
    }

    fn on_retry_scheduled(
        &self,
        _context: &reqx::RequestContext,
        _decision: &reqx::RetryDecision,
        _delay: Duration,
    ) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "_async")]
async fn async_get_error(status: u16, body: Vec<u8>, max_response_body_bytes: usize) -> Error {
    use reqx::prelude::{Client, RetryPolicy};

    let server = OneShotServer::start(
        status,
        vec![(
            "content-type".to_owned(),
            "application/octet-stream".to_owned(),
        )],
        body,
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .max_response_body_bytes(max_response_body_bytes)
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");
    let error = client
        .get("/case")
        .send()
        .await
        .expect_err("request should return an error for this scenario");
    drop(server);
    error
}

#[cfg(feature = "_blocking")]
fn blocking_get_error(status: u16, body: Vec<u8>, max_response_body_bytes: usize) -> Error {
    use reqx::blocking::Client;
    use reqx::prelude::RetryPolicy;

    let server = OneShotServer::start(
        status,
        vec![(
            "content-type".to_owned(),
            "application/octet-stream".to_owned(),
        )],
        body,
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .max_response_body_bytes(max_response_body_bytes)
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");
    let error = client
        .get("/case")
        .send()
        .expect_err("request should return an error for this scenario");
    drop(server);
    error
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_error_code_contract_status_and_body_limit() {
    let status_error = async_get_error(503, b"unavailable".to_vec(), 1024).await;
    assert_error_contract(&status_error, ErrorCode::HttpStatus, "http_status");

    let too_large_error = async_get_error(200, vec![b'x'; 32], 4).await;
    assert_error_contract(
        &too_large_error,
        ErrorCode::ResponseBodyTooLarge,
        "response_body_too_large",
    );
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_http_status_error_carries_response_headers() {
    use reqx::prelude::{Client, RetryPolicy};

    let server = OneShotServer::start(
        503,
        vec![
            ("retry-after".to_owned(), "3".to_owned()),
            ("x-amz-request-id".to_owned(), "req-123".to_owned()),
        ],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/case")
        .send()
        .await
        .expect_err("request should return http status error");
    assert_eq!(error.status_code(), Some(503));
    assert_eq!(error.request_id(), Some("req-123"));
    assert_eq!(
        error.retry_after(SystemTime::UNIX_EPOCH),
        Some(Duration::from_secs(3))
    );
    match error {
        Error::HttpStatus {
            status, headers, ..
        } => {
            assert_eq!(status, 503);
            assert_eq!(
                headers
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok()),
                Some("3")
            );
            assert_eq!(
                headers
                    .get("x-amz-request-id")
                    .and_then(|value| value.to_str().ok()),
                Some("req-123")
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_error_code_contract_status_and_body_limit() {
    let status_error = blocking_get_error(503, b"unavailable".to_vec(), 1024);
    assert_error_contract(&status_error, ErrorCode::HttpStatus, "http_status");

    let too_large_error = blocking_get_error(200, vec![b'x'; 32], 4);
    assert_error_contract(
        &too_large_error,
        ErrorCode::ResponseBodyTooLarge,
        "response_body_too_large",
    );
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_http_status_error_carries_response_headers() {
    use reqx::blocking::Client;
    use reqx::prelude::RetryPolicy;

    let server = OneShotServer::start(
        503,
        vec![
            ("retry-after".to_owned(), "3".to_owned()),
            ("x-amz-request-id".to_owned(), "req-123".to_owned()),
        ],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/case")
        .send()
        .expect_err("request should return http status error");
    assert_eq!(error.status_code(), Some(503));
    assert_eq!(error.request_id(), Some("req-123"));
    assert_eq!(
        error.retry_after(SystemTime::UNIX_EPOCH),
        Some(Duration::from_secs(3))
    );
    match error {
        Error::HttpStatus {
            status, headers, ..
        } => {
            assert_eq!(status, 503);
            assert_eq!(
                headers
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok()),
                Some("3")
            );
            assert_eq!(
                headers
                    .get("x-amz-request-id")
                    .and_then(|value| value.to_str().ok()),
                Some("req-123")
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_send_with_status_returns_response_for_non_success() {
    use reqx::prelude::{Client, RetryPolicy};

    let server = OneShotServer::start(
        503,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .get("/case")
        .send_with_status()
        .await
        .expect("non-success should be returned as response");
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(response.text_lossy(), "unavailable");
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_client_default_status_policy_response_returns_non_success() {
    use reqx::StatusPolicy;
    use reqx::prelude::{Client, RetryPolicy};

    let server = OneShotServer::start(
        503,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .default_status_policy(StatusPolicy::Response)
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .get("/case")
        .send()
        .await
        .expect("non-success should be returned as response by default");
    assert_eq!(response.status().as_u16(), 503);
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_send_with_status_returns_response_for_non_success() {
    use reqx::blocking::Client;
    use reqx::prelude::RetryPolicy;

    let server = OneShotServer::start(
        503,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .get("/case")
        .send_with_status()
        .expect("non-success should be returned as response");
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(response.text_lossy(), "unavailable");
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_client_default_status_policy_response_returns_non_success() {
    use reqx::StatusPolicy;
    use reqx::blocking::Client;
    use reqx::prelude::RetryPolicy;

    let server = OneShotServer::start(
        503,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .default_status_policy(StatusPolicy::Response)
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .get("/case")
        .send()
        .expect("non-success should be returned as response by default");
    assert_eq!(response.status().as_u16(), 503);
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_send_stream_with_status_returns_stream_for_non_success() {
    use reqx::prelude::{Client, RetryPolicy};

    let server = OneShotServer::start(
        503,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let stream = client
        .get("/case")
        .send_stream_with_status()
        .await
        .expect("non-success should be returned as stream");
    assert_eq!(stream.status().as_u16(), 503);
    let response = stream
        .into_response_limited(1024)
        .await
        .expect("stream should be readable");
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(response.text_lossy(), "unavailable");
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_endpoint_selector_can_override_base_url() {
    use reqx::RoundRobinEndpointSelector;
    use reqx::prelude::Client;

    let server = OneShotServer::start(
        200,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"ok".to_vec(),
    );
    let selector = RoundRobinEndpointSelector::new([server.base_url.clone()]);
    let client = Client::builder("http://invalid.local")
        .endpoint_selector(selector)
        .build()
        .expect("client should build");

    let response = client
        .get("/case")
        .send()
        .await
        .expect("request should use selector endpoint");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text_lossy(), "ok");
}

#[cfg(feature = "_async")]
#[tokio::test(flavor = "current_thread")]
async fn async_observer_receives_request_start_event() {
    use reqx::prelude::{Client, RetryPolicy};

    let server = OneShotServer::start(
        200,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"ok".to_vec(),
    );
    let started = Arc::new(AtomicUsize::new(0));
    let retries = Arc::new(AtomicUsize::new(0));
    let observer = CountingObserver {
        started: Arc::clone(&started),
        retries: Arc::clone(&retries),
    };
    let client = Client::builder(server.base_url.clone())
        .retry_policy(RetryPolicy::disabled())
        .observer(observer)
        .build()
        .expect("client should build");

    let response = client
        .get("/case")
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(started.load(Ordering::Relaxed), 1);
    assert_eq!(retries.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_send_stream_with_status_returns_stream_for_non_success() {
    use reqx::blocking::Client;
    use reqx::prelude::RetryPolicy;

    let server = OneShotServer::start(
        503,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"unavailable".to_vec(),
    );
    let client = Client::builder(server.base_url.clone())
        .request_timeout(Duration::from_secs(1))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let stream = client
        .get("/case")
        .send_stream_with_status()
        .expect("non-success should be returned as stream");
    assert_eq!(stream.status().as_u16(), 503);
    let response = stream
        .into_response_limited(1024)
        .expect("stream should be readable");
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(response.text_lossy(), "unavailable");
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_endpoint_selector_can_override_base_url() {
    use reqx::RoundRobinEndpointSelector;
    use reqx::blocking::Client;

    let server = OneShotServer::start(
        200,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"ok".to_vec(),
    );
    let selector = RoundRobinEndpointSelector::new([server.base_url.clone()]);
    let client = Client::builder("http://invalid.local")
        .endpoint_selector(selector)
        .build()
        .expect("client should build");

    let response = client
        .get("/case")
        .send()
        .expect("request should use selector endpoint");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text_lossy(), "ok");
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_observer_receives_request_start_event() {
    use reqx::blocking::Client;
    use reqx::prelude::RetryPolicy;

    let server = OneShotServer::start(
        200,
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"ok".to_vec(),
    );
    let started = Arc::new(AtomicUsize::new(0));
    let retries = Arc::new(AtomicUsize::new(0));
    let observer = CountingObserver {
        started: Arc::clone(&started),
        retries: Arc::clone(&retries),
    };
    let client = Client::builder(server.base_url.clone())
        .retry_policy(RetryPolicy::disabled())
        .observer(observer)
        .build()
        .expect("client should build");

    let response = client.get("/case").send().expect("request should succeed");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(started.load(Ordering::Relaxed), 1);
    assert_eq!(retries.load(Ordering::Relaxed), 0);
}

#[cfg(all(feature = "_async", feature = "_blocking"))]
#[tokio::test(flavor = "current_thread")]
async fn async_and_blocking_error_codes_are_consistent() {
    let async_status_error = async_get_error(503, b"unavailable".to_vec(), 1024).await;
    let blocking_status_error = blocking_get_error(503, b"unavailable".to_vec(), 1024);

    assert_eq!(async_status_error.code(), blocking_status_error.code());
    assert_eq!(async_status_error.code(), ErrorCode::HttpStatus);

    let async_large_error = async_get_error(200, vec![b'x'; 32], 4).await;
    let blocking_large_error = blocking_get_error(200, vec![b'x'; 32], 4);

    assert_eq!(async_large_error.code(), blocking_large_error.code());
    assert_eq!(async_large_error.code(), ErrorCode::ResponseBodyTooLarge);
}
