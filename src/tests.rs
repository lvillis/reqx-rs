use std::collections::BTreeMap;
use std::io::Write;
use std::time::{Duration, SystemTime};

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::body::decode_content_encoded_body;
use crate::client::{HttpClient, TlsBackend};
use crate::error::{HttpClientError, HttpClientErrorCode};
use crate::proxy::{NoProxyRule, normalize_tunnel_target_uri};
use crate::response::HttpResponse;
use crate::retry::{RetryPolicy, request_supports_retry};
use crate::util::{
    append_query_pairs, bounded_retry_delay, ensure_accept_encoding, join_base_path,
    parse_retry_after, redact_uri_for_logs, resolve_uri,
};

#[test]
fn join_base_path_handles_slashes() {
    assert_eq!(
        join_base_path("https://api.example.com/v1/", "/users"),
        "https://api.example.com/v1/users"
    );
}

#[test]
fn resolve_uri_keeps_absolute_uri() {
    let (uri_text, uri) = resolve_uri("https://api.example.com/v1", "https://x.test/a")
        .expect("absolute uri should parse");
    assert_eq!(uri_text, "https://x.test/a");
    assert_eq!(uri.to_string(), "https://x.test/a");
}

#[test]
fn normalize_tunnel_target_uri_sets_https_default_port() {
    let uri: http::Uri = "https://api.example.com/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(
        normalized.to_string(),
        "https://api.example.com:443/v1/users"
    );
}

#[test]
fn normalize_tunnel_target_uri_sets_http_default_port() {
    let uri: http::Uri = "http://api.example.com/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(normalized.to_string(), "http://api.example.com:80/v1/users");
}

#[test]
fn normalize_tunnel_target_uri_keeps_explicit_port() {
    let uri: http::Uri = "https://api.example.com:9443/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(
        normalized.to_string(),
        "https://api.example.com:9443/v1/users"
    );
}

#[test]
fn redact_uri_for_logs_masks_telegram_token() {
    let redacted = redact_uri_for_logs(
        "https://api.telegram.org/bot123456:AAABBBCCCDDDEE/getUpdates?offset=10",
    );
    assert_eq!(
        redacted,
        "https://api.telegram.org/bot%3Credacted%3E/getUpdates"
    );
}

#[test]
fn redact_uri_for_logs_masks_userinfo() {
    let redacted = redact_uri_for_logs("http://user:pass@proxy.example.com:7890/path");
    assert_eq!(redacted, "http://proxy.example.com:7890/path");
}

#[test]
fn append_query_pairs_merges_existing_query_and_fragment() {
    let query_pairs = vec![
        ("name".to_owned(), "alice bob".to_owned()),
        ("page".to_owned(), "2".to_owned()),
    ];
    let merged = append_query_pairs("/v1/users?active=true#section", &query_pairs);
    assert!(merged.starts_with("/v1/users?"));
    assert!(merged.ends_with("#section"));

    let query_text = merged
        .split_once('?')
        .and_then(|(_, right)| right.split_once('#').map(|(query, _)| query))
        .unwrap_or_default();
    let parsed: BTreeMap<String, String> = url::form_urlencoded::parse(query_text.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(parsed.get("active"), Some(&"true".to_owned()));
    assert_eq!(parsed.get("name"), Some(&"alice bob".to_owned()));
    assert_eq!(parsed.get("page"), Some(&"2".to_owned()));
}

#[test]
fn append_query_pairs_handles_absolute_url() {
    let query_pairs = vec![
        ("topic".to_owned(), "rust sdk".to_owned()),
        ("lang".to_owned(), "zh".to_owned()),
    ];
    let merged = append_query_pairs("https://api.example.com/search?q=hello", &query_pairs);
    let parsed = url::Url::parse(&merged).expect("merged url should parse");
    let parsed_query: BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|pair| (pair.0.into_owned(), pair.1.into_owned()))
        .collect();
    assert_eq!(parsed_query.get("q"), Some(&"hello".to_owned()));
    assert_eq!(parsed_query.get("topic"), Some(&"rust sdk".to_owned()));
    assert_eq!(parsed_query.get("lang"), Some(&"zh".to_owned()));
}

#[test]
fn response_json_decode_error_contains_body() {
    let response = HttpResponse::new(
        http::StatusCode::OK,
        http::HeaderMap::new(),
        bytes::Bytes::from_static(b"not-json"),
    );
    let error = response
        .json::<serde_json::Value>()
        .expect_err("invalid json should return error");
    match error {
        HttpClientError::Deserialize { body, .. } => assert_eq!(body, "not-json"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn retry_policy_backoff_is_capped() {
    let retry_policy = RetryPolicy::standard()
        .base_backoff(Duration::from_millis(100))
        .max_backoff(Duration::from_millis(250))
        .jitter_ratio(0.0);
    assert_eq!(
        retry_policy.backoff_for_retry(1),
        Duration::from_millis(100)
    );
    assert_eq!(
        retry_policy.backoff_for_retry(2),
        Duration::from_millis(200)
    );
    assert_eq!(
        retry_policy.backoff_for_retry(3),
        Duration::from_millis(250)
    );
}

#[test]
fn post_without_idempotency_key_is_not_retryable() {
    let headers = http::HeaderMap::new();
    assert!(!request_supports_retry(&http::Method::POST, &headers));
}

#[test]
fn post_with_idempotency_key_is_retryable() {
    let mut headers = http::HeaderMap::new();
    headers.insert("idempotency-key", http::HeaderValue::from_static("abc"));
    assert!(request_supports_retry(&http::Method::POST, &headers));
}

#[test]
fn parse_retry_after_header_seconds() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("5"),
    );
    assert_eq!(
        parse_retry_after(&headers, SystemTime::UNIX_EPOCH),
        Some(Duration::from_secs(5))
    );
}

#[test]
fn parse_retry_after_header_http_date() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let retry_at = now + Duration::from_secs(30);
    let mut headers = http::HeaderMap::new();
    let retry_at_text = httpdate::fmt_http_date(retry_at);
    headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_str(&retry_at_text).expect("valid retry-after date"),
    );
    assert_eq!(
        parse_retry_after(&headers, now),
        Some(Duration::from_secs(30))
    );
}

#[test]
fn bounded_retry_delay_respects_total_timeout() {
    let start = std::time::Instant::now();
    let retry_delay = Duration::from_millis(100);
    let total_timeout = Some(Duration::from_millis(100));
    assert_eq!(bounded_retry_delay(retry_delay, total_timeout, start), None);
}

#[test]
fn error_code_maps_expected_variant() {
    let error = HttpClientError::InvalidUri {
        uri: "bad://uri".to_owned(),
    };
    assert_eq!(error.code(), HttpClientErrorCode::InvalidUri);
    assert_eq!(error.code().as_str(), "invalid_uri");
}

#[test]
fn no_proxy_rule_matches_domain_and_subdomain() {
    let rule = NoProxyRule::parse(".example.com").expect("valid rule");
    assert!(rule.matches("example.com"));
    assert!(rule.matches("api.example.com"));
    assert!(!rule.matches("another.com"));
}

#[test]
fn ensure_accept_encoding_sets_default_when_absent() {
    let mut headers = http::HeaderMap::new();
    ensure_accept_encoding(&mut headers);
    assert_eq!(
        headers
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip, br, deflate, zstd")
    );
}

#[test]
fn decode_content_encoded_body_decodes_gzip_payload() {
    let source = br#"{"ok":true}"#;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(source)
        .expect("write gzip source bytes should succeed");
    let compressed = encoder.finish().expect("finish gzip stream should succeed");

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("gzip"),
    );
    let decoded = decode_content_encoded_body(bytes::Bytes::from(compressed), &headers)
        .expect("gzip payload should decode");
    assert_eq!(decoded.as_ref(), source);
}

#[test]
fn decode_content_encoded_body_rejects_unknown_encoding() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("x-custom"),
    );
    let error = decode_content_encoded_body(bytes::Bytes::from_static(b"abc"), &headers)
        .expect_err("unknown content-encoding should fail");
    assert_eq!(error.0, "x-custom");
}

#[cfg(feature = "tls-rustls-ring")]
#[test]
fn selecting_rustls_ring_backend_builds_when_feature_enabled() {
    let client = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .try_build()
        .expect("rustls ring backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsRing);
}

#[cfg(not(feature = "tls-rustls-ring"))]
#[test]
fn selecting_rustls_ring_backend_returns_unavailable_when_feature_disabled() {
    let error = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .try_build()
        .expect_err("rustls ring backend should be unavailable when feature is disabled");
    match error {
        HttpClientError::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsRing.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "tls-rustls-aws-lc-rs")]
#[test]
fn selecting_rustls_aws_lc_backend_builds_when_feature_enabled() {
    let client = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .try_build()
        .expect("rustls aws-lc-rs backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsAwsLcRs);
}

#[cfg(not(feature = "tls-rustls-aws-lc-rs"))]
#[test]
fn selecting_rustls_aws_lc_backend_returns_unavailable_when_feature_disabled() {
    let error = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .try_build()
        .expect_err("rustls aws-lc-rs backend should be unavailable when feature is disabled");
    match error {
        HttpClientError::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsAwsLcRs.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "tls-native")]
#[test]
fn selecting_native_tls_backend_builds_when_feature_enabled() {
    let client = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .try_build()
        .expect("native tls backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::NativeTls);
}

#[cfg(not(feature = "tls-native"))]
#[test]
fn selecting_native_tls_backend_returns_unavailable_when_feature_disabled() {
    let error = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .try_build()
        .expect_err("native tls backend should be unavailable when feature is disabled");
    match error {
        HttpClientError::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::NativeTls.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}
