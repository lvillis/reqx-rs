#![cfg(feature = "_async")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use http::Uri;
use http_body_util::BodyExt;
use reqx::prelude::{Client, Error, RedirectPolicy, RetryPolicy};
use reqx::{CircuitBreakerPolicy, RetryBudgetPolicy, RetryClassifier, RetryDecision};
use tokio::io::sink;

#[derive(Clone)]
struct ResponseSpec {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
}

impl ResponseSpec {
    fn new(
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

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
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

fn read_http_message(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut raw = Vec::new();
    loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);

        if let Some(header_end) = find_header_end(&raw) {
            let content_length = parse_content_length(&raw[..header_end]);
            let expected_total = header_end + 4 + content_length;
            if raw.len() >= expected_total {
                break;
            }
        }
    }

    Ok(raw)
}

fn write_http_response(stream: &mut TcpStream, response: &ResponseSpec) -> std::io::Result<()> {
    let mut raw = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
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
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

struct NeverRetryClassifier;

impl RetryClassifier for NeverRetryClassifier {
    fn should_retry(&self, _decision: &RetryDecision) -> bool {
        false
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
    fn start(expected_requests: usize, response: ResponseSpec) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counting server");
        let authority = listener
            .local_addr()
            .expect("read local address")
            .to_string();
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");

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

                            if !response.delay.is_zero() {
                                thread::sleep(response.delay);
                            }

                            let _ = read_http_message(&mut stream);
                            let _ = write_http_response(&mut stream, &response);

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

    fn wait_for_served_count(&self, expected: usize, timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        loop {
            let observed = self.served_count();
            if observed >= expected || Instant::now() >= deadline {
                return observed;
            }
            thread::sleep(Duration::from_millis(5));
        }
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

struct ConnectProxyServer {
    uri: String,
    tunnel_targets: Arc<Mutex<Vec<String>>>,
    forward_targets: Arc<Mutex<Vec<String>>>,
    proxy_authorization_values: Arc<Mutex<Vec<String>>>,
    join: Option<JoinHandle<()>>,
}

impl ConnectProxyServer {
    fn start(expected_connections: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy server");
        let authority = listener
            .local_addr()
            .expect("read proxy address")
            .to_string();
        listener
            .set_nonblocking(true)
            .expect("set proxy listener nonblocking");

        let tunnel_targets = Arc::new(Mutex::new(Vec::new()));
        let forward_targets = Arc::new(Mutex::new(Vec::new()));
        let proxy_authorization_values = Arc::new(Mutex::new(Vec::new()));
        let tunnel_targets_clone = Arc::clone(&tunnel_targets);
        let forward_targets_clone = Arc::clone(&forward_targets);
        let proxy_authorization_values_clone = Arc::clone(&proxy_authorization_values);

        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut workers = Vec::new();
            let mut accepted = 0;

            while Instant::now() < deadline && accepted < expected_connections {
                match listener.accept() {
                    Ok((stream, _)) => {
                        accepted += 1;
                        let tunnel_targets = Arc::clone(&tunnel_targets_clone);
                        let forward_targets = Arc::clone(&forward_targets_clone);
                        let proxy_authorization_values =
                            Arc::clone(&proxy_authorization_values_clone);
                        workers.push(thread::spawn(move || {
                            handle_proxy_connection(
                                stream,
                                tunnel_targets,
                                forward_targets,
                                proxy_authorization_values,
                            );
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
            uri: format!("http://{authority}"),
            tunnel_targets,
            forward_targets,
            proxy_authorization_values,
            join: Some(join),
        }
    }

    fn uri(&self) -> &str {
        &self.uri
    }

    fn tunnel_targets(&self) -> Vec<String> {
        lock_unpoisoned(&self.tunnel_targets).clone()
    }

    fn forward_targets(&self) -> Vec<String> {
        lock_unpoisoned(&self.forward_targets).clone()
    }

    fn proxy_authorization_values(&self) -> Vec<String> {
        lock_unpoisoned(&self.proxy_authorization_values).clone()
    }
}

impl Drop for ConnectProxyServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_proxy_connection(
    mut client: TcpStream,
    tunnel_targets: Arc<Mutex<Vec<String>>>,
    forward_targets: Arc<Mutex<Vec<String>>>,
    proxy_authorization_values: Arc<Mutex<Vec<String>>>,
) {
    if let Ok(proxy_request) = read_http_message(&mut client)
        && let Some(header_end) = find_header_end(&proxy_request)
    {
        let text = String::from_utf8_lossy(&proxy_request[..header_end]);
        for line in text.split("\r\n").skip(1) {
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("proxy-authorization")
            {
                lock_unpoisoned(&proxy_authorization_values).push(value.trim().to_owned());
            }
        }
        let mut line_parts = text
            .split("\r\n")
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let method = line_parts.next().unwrap_or_default();
        let target = line_parts.next().unwrap_or_default().to_owned();
        if target.is_empty() {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }

        if method == "CONNECT" {
            lock_unpoisoned(&tunnel_targets).push(target.clone());

            let mut upstream = match TcpStream::connect(&target) {
                Ok(stream) => stream,
                Err(_) => {
                    let _ =
                        client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                    return;
                }
            };

            let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");

            if let Ok(request) = read_http_message(&mut client) {
                let _ = upstream.write_all(&request);
                let _ = upstream.flush();
                if let Ok(response) = read_http_message(&mut upstream) {
                    let _ = client.write_all(&response);
                    let _ = client.flush();
                }
            }
            return;
        }

        let parsed_target = match target.parse::<Uri>() {
            Ok(uri) => uri,
            Err(_) => {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        };
        let Some(host) = parsed_target.host() else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        let port = parsed_target.port_u16().unwrap_or(80);
        let authority = format!("{host}:{port}");
        lock_unpoisoned(&forward_targets).push(authority.clone());

        let mut upstream = match TcpStream::connect(&authority) {
            Ok(stream) => stream,
            Err(_) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        };

        let _ = upstream.write_all(&proxy_request);
        let _ = upstream.flush();
        if let Ok(response) = read_http_message(&mut upstream) {
            let _ = client.write_all(&response);
            let _ = client.flush();
        }
    }
}

struct RawTcpServer {
    authority: String,
    accepted: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
}

impl RawTcpServer {
    fn start(expected_connections: usize, payload: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind raw server");
        let authority = listener.local_addr().expect("read raw address").to_string();
        listener
            .set_nonblocking(true)
            .expect("set raw listener nonblocking");

        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_clone = Arc::clone(&accepted);

        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(4);
            while Instant::now() < deadline {
                if accepted_clone.load(Ordering::SeqCst) >= expected_connections {
                    break;
                }

                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accepted_clone.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.write_all(&payload);
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            authority,
            accepted,
            join: Some(join),
        }
    }

    fn authority(&self) -> &str {
        &self.authority
    }

    fn accepted_count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for RawTcpServer {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_forwards_http_request_via_absolute_form() {
    let upstream = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "text/plain")],
            b"proxy-ok".to_vec(),
            Duration::ZERO,
        ),
    );
    let proxy = ConnectProxyServer::start(1);

    let proxy_uri: Uri = proxy.uri().parse().expect("parse proxy uri");
    let client = Client::builder(format!("http://{}", upstream.authority()))
        .http_proxy(proxy_uri)
        .request_timeout(Duration::from_millis(500))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .get("/through-proxy")
        .send()
        .await
        .expect("proxy request should succeed");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text_lossy(), "proxy-ok");
    assert_eq!(upstream.served_count(), 1);

    let tunnel_targets = proxy.tunnel_targets();
    assert!(tunnel_targets.is_empty());
    let forward_targets = proxy.forward_targets();
    assert_eq!(forward_targets.len(), 1);
    assert_eq!(forward_targets[0], upstream.authority());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_authorization_header_is_forwarded() {
    let upstream = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "text/plain")],
            b"proxy-auth-ok".to_vec(),
            Duration::ZERO,
        ),
    );
    let proxy = ConnectProxyServer::start(1);
    let proxy_uri: Uri = proxy.uri().parse().expect("parse proxy uri");

    let client = Client::builder(format!("http://{}", upstream.authority()))
        .http_proxy(proxy_uri)
        .try_proxy_authorization("Basic dXNlcjpwYXNz")
        .expect("valid proxy authorization header")
        .request_timeout(Duration::from_millis(500))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .get("/proxy-auth")
        .send()
        .await
        .expect("request through proxy should succeed");
    assert_eq!(response.status().as_u16(), 200);

    let proxy_auth_values = proxy.proxy_authorization_values();
    assert_eq!(proxy_auth_values.len(), 1);
    assert_eq!(proxy_auth_values[0], "Basic dXNlcjpwYXNz");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_proxy_bypasses_proxy_for_matching_host() {
    let upstream = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "text/plain")],
            b"direct-ok".to_vec(),
            Duration::ZERO,
        ),
    );
    let proxy = ConnectProxyServer::start(0);
    let proxy_uri: Uri = proxy.uri().parse().expect("parse proxy uri");

    let client = Client::builder(format!("http://{}", upstream.authority()))
        .http_proxy(proxy_uri)
        .no_proxy(["127.0.0.1"])
        .request_timeout(Duration::from_millis(500))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let response = client
        .get("/no-proxy")
        .send()
        .await
        .expect("request should bypass proxy and succeed");
    assert_eq!(response.status().as_u16(), 200);

    assert_eq!(upstream.served_count(), 1);
    assert!(proxy.tunnel_targets().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_in_flight_enforces_single_active_request() {
    let server = CountingServer::start(
        3,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"ok".to_vec(),
            Duration::from_millis(120),
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .max_in_flight(1)
        .request_timeout(Duration::from_millis(800))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let cloned = client.clone();
        tasks.push(tokio::spawn(async move {
            cloned
                .get("/slow")
                .send()
                .await
                .map(|response| response.status().as_u16())
        }));
    }

    for task in tasks {
        let status = task
            .await
            .expect("join spawned request")
            .expect("request should succeed");
        assert_eq!(status, 200);
    }

    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(server.served_count(), 3);
    assert_eq!(server.max_active(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_in_flight_stream_holds_permit_until_stream_is_dropped() {
    let server = CountingServer::start(
        2,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"ok".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .max_in_flight(1)
        .request_timeout(Duration::from_millis(800))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let first_stream = client
        .get("/stream-hold")
        .send_stream()
        .await
        .expect("first stream request should succeed");

    let started = Instant::now();
    let cloned = client.clone();
    let second = tokio::spawn(async move {
        cloned
            .get("/stream-after-drop")
            .send()
            .await
            .map(|response| response.status().as_u16())
    });

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        !second.is_finished(),
        "second request should remain queued while first stream is alive"
    );

    drop(first_stream);

    let status = second
        .await
        .expect("join spawned request")
        .expect("second request should succeed");
    assert_eq!(status, 200);
    assert!(
        started.elapsed() >= Duration::from_millis(120),
        "second request should wait until stream drop before acquiring permit"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_in_flight_per_host_limits_each_host_independently() {
    let server_a = CountingServer::start(
        2,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"ok-a".to_vec(),
            Duration::from_millis(120),
        ),
    );
    let server_b = CountingServer::start(
        2,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"ok-b".to_vec(),
            Duration::from_millis(120),
        ),
    );

    let client = Client::builder(format!("http://{}", server_a.authority()))
        .max_in_flight_per_host(1)
        .request_timeout(Duration::from_millis(800))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");
    let server_b_port = server_b
        .authority()
        .rsplit(':')
        .next()
        .expect("server authority should include port");

    let started = Instant::now();
    let mut tasks = Vec::new();
    for idx in 0..4 {
        let cloned = client.clone();
        let path = if idx % 2 == 0 {
            "/host-a".to_owned()
        } else {
            format!("http://localhost:{server_b_port}/host-b")
        };
        tasks.push(tokio::spawn(async move {
            cloned
                .get(path)
                .send()
                .await
                .map(|response| response.status().as_u16())
        }));
    }

    for task in tasks {
        let status = task
            .await
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_in_flight_per_host_distinguishes_same_host_different_ports() {
    let server_a = CountingServer::start(
        2,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"ok-a".to_vec(),
            Duration::from_millis(120),
        ),
    );
    let server_b = CountingServer::start(
        2,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"ok-b".to_vec(),
            Duration::from_millis(120),
        ),
    );

    let client = Client::builder(format!("http://{}", server_a.authority()))
        .max_in_flight_per_host(1)
        .request_timeout(Duration::from_millis(800))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");
    let server_b_url = format!("http://{}/host-b", server_b.authority());

    let started = Instant::now();
    let mut tasks = Vec::new();
    for idx in 0..4 {
        let cloned = client.clone();
        let path = if idx % 2 == 0 {
            "/host-a".to_owned()
        } else {
            server_b_url.clone()
        };
        tasks.push(tokio::spawn(async move {
            cloned
                .get(path)
                .send()
                .await
                .map(|response| response.status().as_u16())
        }));
    }

    for task in tasks {
        let status = task
            .await
            .expect("join spawned request")
            .expect("request should succeed");
        assert_eq!(status, 200);
    }

    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(220),
        "per-authority requests should still serialize per target: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(460),
        "requests to different ports should not share one per-host limiter: {elapsed:?}"
    );

    assert_eq!(server_a.served_count(), 2);
    assert_eq!(server_b.served_count(), 2);
    assert_eq!(server_a.max_active(), 1);
    assert_eq!(server_b.max_active(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_in_flight_per_host_applies_to_redirect_target_host() {
    let target = CountingServer::start(
        4,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"ok-target".to_vec(),
            Duration::from_millis(120),
        ),
    );
    let target_location = format!("http://{}/target", target.authority());
    let redirect_headers = vec![("Location".to_owned(), target_location)];
    let source_a = CountingServer::start(
        2,
        ResponseSpec::new(
            302,
            redirect_headers.clone(),
            Vec::<u8>::new(),
            Duration::ZERO,
        ),
    );
    let source_b = CountingServer::start(
        2,
        ResponseSpec::new(302, redirect_headers, Vec::<u8>::new(), Duration::ZERO),
    );

    let client = Client::builder(format!("http://{}", source_a.authority()))
        .max_in_flight_per_host(1)
        .request_timeout(Duration::from_millis(800))
        .redirect_policy(RedirectPolicy::follow())
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");
    let source_b_url = format!("http://{}", source_b.authority());

    let started = Instant::now();
    let mut tasks = Vec::new();
    for idx in 0..4 {
        let cloned = client.clone();
        let path = if idx % 2 == 0 {
            "/from-source-a".to_owned()
        } else {
            format!("{source_b_url}/from-source-b")
        };
        tasks.push(tokio::spawn(async move {
            cloned
                .get(path)
                .send()
                .await
                .map(|response| response.status().as_u16())
        }));
    }

    for task in tasks {
        let status = task
            .await
            .expect("join spawned request")
            .expect("request should succeed");
        assert_eq!(status, 200);
    }

    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(420),
        "redirect target host should be serialized by per-host limiter: {elapsed:?}"
    );
    assert_eq!(target.served_count(), 4);
    assert_eq!(target.max_active(), 1);
    assert_eq!(source_a.served_count(), 2);
    assert_eq!(source_b.served_count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn total_timeout_interrupts_retry_loop_with_retry_after() {
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            503,
            vec![("Retry-After", "1")],
            b"busy".to_vec(),
            Duration::ZERO,
        ),
    );

    let client = Client::builder(format!("http://{}", server.authority()))
        .request_timeout(Duration::from_millis(400))
        .total_timeout(Duration::from_millis(300))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(3)
                .base_backoff(Duration::from_millis(1))
                .max_backoff(Duration::from_millis(3))
                .jitter_ratio(0.0),
        )
        .build()
        .expect("client should build");

    let error = client
        .get("/busy")
        .send()
        .await
        .expect_err("total timeout should stop retry loop");

    match error {
        Error::DeadlineExceeded { .. } => {}
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(server.served_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_response_body_limit_returns_specific_error() {
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            Vec::<(String, String)>::new(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .max_response_body_bytes(8)
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/large")
        .send()
        .await
        .expect_err("response body should exceed max bytes");
    match error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            actual_bytes,
            ..
        } => {
            assert_eq!(limit_bytes, 8);
            assert!(actual_bytes > limit_bytes);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_classifier_can_disable_retries() {
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            503,
            Vec::<(String, String)>::new(),
            b"busy".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(3)
                .retry_classifier(Arc::new(NeverRetryClassifier)),
        )
        .request_timeout(Duration::from_millis(400))
        .build()
        .expect("client should build");

    let error = client
        .get("/disabled-retry")
        .send()
        .await
        .expect_err("custom classifier should disable retries");
    match error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 503),
        other => panic!("unexpected error variant: {other}"),
    }
    assert_eq!(
        server.wait_for_served_count(1, Duration::from_millis(200)),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permissive_retry_eligibility_retries_post_without_idempotency_key() {
    let server = CountingServer::start(
        2,
        ResponseSpec::new(
            503,
            Vec::<(String, String)>::new(),
            b"busy".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .allow_non_idempotent_retries(true)
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(2)
                .base_backoff(Duration::from_millis(1))
                .max_backoff(Duration::from_millis(5))
                .jitter_ratio(0.0),
        )
        .request_timeout(Duration::from_millis(400))
        .build()
        .expect("client should build");

    let error = client
        .post("/post-no-key")
        .body("payload")
        .send()
        .await
        .expect_err("server always returns 503");
    match error {
        Error::HttpStatus { status, .. } => assert_eq!(status, 503),
        other => panic!("unexpected error variant: {other}"),
    }
    assert_eq!(
        server.wait_for_served_count(2, Duration::from_millis(200)),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_budget_exhausted_stops_retry_loop_early() {
    let server = CountingServer::start(
        2,
        ResponseSpec::new(
            503,
            Vec::<(String, String)>::new(),
            b"busy".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
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
        .request_timeout(Duration::from_millis(400))
        .build()
        .expect("client should build");

    let error = client
        .get("/budget")
        .send()
        .await
        .expect_err("retry budget should stop retries after one retry");

    match error {
        Error::RetryBudgetExhausted { .. } => {}
        other => panic!("unexpected error variant: {other}"),
    }
    assert_eq!(
        server.wait_for_served_count(2, Duration::from_millis(200)),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn circuit_breaker_short_circuits_after_opening() {
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            503,
            Vec::<(String, String)>::new(),
            b"busy".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
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
        .get("/open")
        .send()
        .await
        .expect_err("first request should return 503");
    match first {
        Error::HttpStatus { status, .. } => assert_eq!(status, 503),
        other => panic!("unexpected first error variant: {other}"),
    }

    let second = client
        .get("/open")
        .send()
        .await
        .expect_err("second request should be rejected by circuit");
    match second {
        Error::CircuitOpen { .. } => {}
        other => panic!("unexpected second error variant: {other}"),
    }

    assert_eq!(
        server.wait_for_served_count(1, Duration::from_millis(200)),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn circuit_breaker_response_mode_does_not_open_on_non_success_buffered() {
    let server = CountingServer::start(
        2,
        ResponseSpec::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
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
        .get("/response-mode-buffered")
        .send_with_status()
        .await
        .expect("first non-success response should be returned");
    assert_eq!(first.status(), http::StatusCode::NOT_FOUND);

    let second = client
        .get("/response-mode-buffered")
        .send_with_status()
        .await
        .expect("second non-success response should be returned");
    assert_eq!(second.status(), http::StatusCode::NOT_FOUND);

    assert_eq!(
        server.wait_for_served_count(2, Duration::from_millis(200)),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn circuit_breaker_response_mode_does_not_open_on_non_success_stream() {
    let server = CountingServer::start(
        2,
        ResponseSpec::new(
            404,
            vec![("Content-Type", "application/json")],
            br#"{"error":"not-found"}"#.to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
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
        .get("/response-mode-stream")
        .send_stream_with_status()
        .await
        .expect("first non-success stream should be returned");
    assert_eq!(first.status(), http::StatusCode::NOT_FOUND);

    let second = client
        .get("/response-mode-stream")
        .send_stream_with_status()
        .await
        .expect("second non-success stream should be returned");
    assert_eq!(second.status(), http::StatusCode::NOT_FOUND);

    assert_eq!(
        server.wait_for_served_count(2, Duration::from_millis(200)),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_path_returns_transport_error_on_non_tls_server() {
    let raw_server = RawTcpServer::start(
        1,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    );
    let client = Client::builder(format!("https://{}", raw_server.authority()))
        .request_timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let error = client
        .get("/tls-required")
        .send()
        .await
        .expect_err("non-tls server should fail https transport");

    match error {
        Error::Transport { uri, .. } => {
            assert!(uri.starts_with("https://"));
        }
        other => panic!("unexpected error variant: {other}"),
    }

    assert_eq!(raw_server.accepted_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_stream_downloads_body_without_buffered_send_path() {
    let payload = b"stream-response-body".to_vec();
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "application/octet-stream")],
            payload.clone(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/stream-body")
        .send_stream()
        .await
        .expect("send_stream should succeed");
    assert_eq!(streamed.status().as_u16(), 200);

    let collected = streamed
        .into_body()
        .collect()
        .await
        .expect("stream body collect should succeed");
    assert_eq!(collected.to_bytes().to_vec(), payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_stream_into_response_limited_returns_buffered_response() {
    let payload = b"{\"ok\":true}".to_vec();
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "application/json")],
            payload,
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/stream-buffer")
        .send_stream()
        .await
        .expect("send_stream should succeed");
    let buffered = streamed
        .into_response_limited(1024)
        .await
        .expect("into_response_limited should succeed");

    assert_eq!(buffered.status().as_u16(), 200);
    assert_eq!(buffered.text_lossy(), "{\"ok\":true}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_stream_into_response_limited_enforces_limit_with_consistent_error() {
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "application/octet-stream")],
            b"0123456789".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let streamed = client
        .get("/stream-over-limit")
        .send_stream()
        .await
        .expect("send_stream should succeed");
    let error = streamed
        .into_response_limited(4)
        .await
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
            assert_eq!(method, http::Method::GET);
            assert!(uri.contains("/stream-over-limit"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn download_to_writer_transfers_stream_bytes() {
    let payload = b"writer-stream-async".to_vec();
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "application/octet-stream")],
            payload.clone(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let mut output = sink();
    let written = client
        .get("/stream-to-writer")
        .download_to_writer(&mut output)
        .await
        .expect("download_to_writer should succeed");
    assert_eq!(written as usize, payload.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn download_to_writer_limited_enforces_limit_with_consistent_error() {
    let server = CountingServer::start(
        1,
        ResponseSpec::new(
            200,
            vec![("Content-Type", "application/octet-stream")],
            b"0123456789".to_vec(),
            Duration::ZERO,
        ),
    );
    let client = Client::builder(format!("http://{}", server.authority()))
        .request_timeout(Duration::from_millis(400))
        .retry_policy(RetryPolicy::disabled())
        .build()
        .expect("client should build");

    let mut output = sink();
    let error = client
        .get("/stream-to-writer-limit")
        .download_to_writer_limited(&mut output, 4)
        .await
        .expect_err("download_to_writer_limited should enforce max bytes");
    match error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            method,
            uri,
            ..
        } => {
            assert_eq!(limit_bytes, 4);
            assert_eq!(method, http::Method::GET);
            assert!(uri.contains("/stream-to-writer-limit"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}
