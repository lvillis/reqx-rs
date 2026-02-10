use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::time::{Duration, SystemTime};

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::body::decode_content_encoded_body;
use crate::client::HttpClient;
use crate::error::{HttpClientError, HttpClientErrorCode, TimeoutPhase, TransportErrorKind};
use crate::proxy::{NoProxyRule, normalize_tunnel_target_uri};
use crate::response::HttpResponse;
use crate::retry::{RetryDecision, RetryPolicy, request_supports_retry};
use crate::tls::{TlsBackend, TlsRootStore};
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
fn retry_policy_can_filter_transport_error_kinds() {
    let retry_policy =
        RetryPolicy::standard().retryable_transport_error_kinds([TransportErrorKind::Connect]);
    let connect_decision = RetryDecision {
        attempt: 1,
        max_attempts: 3,
        method: http::Method::GET,
        uri: "https://example.com".to_owned(),
        status: None,
        transport_error_kind: Some(TransportErrorKind::Connect),
        timeout_phase: None,
        response_body_read_error: false,
    };
    let dns_decision = RetryDecision {
        transport_error_kind: Some(TransportErrorKind::Dns),
        ..connect_decision.clone()
    };

    assert!(retry_policy.should_retry_decision(&connect_decision));
    assert!(!retry_policy.should_retry_decision(&dns_decision));
}

#[test]
fn retry_policy_status_retry_window_caps_followup_attempts() {
    let retry_policy = RetryPolicy::standard()
        .retryable_status_codes([429_u16, 503_u16])
        .status_retry_window(429, 2);
    let first_429 = RetryDecision {
        attempt: 1,
        max_attempts: 5,
        method: http::Method::GET,
        uri: "https://example.com/rate".to_owned(),
        status: Some(http::StatusCode::TOO_MANY_REQUESTS),
        transport_error_kind: None,
        timeout_phase: None,
        response_body_read_error: false,
    };
    let second_429 = RetryDecision {
        attempt: 2,
        ..first_429.clone()
    };
    let third_503 = RetryDecision {
        attempt: 3,
        status: Some(http::StatusCode::SERVICE_UNAVAILABLE),
        ..first_429.clone()
    };

    assert!(retry_policy.should_retry_decision(&first_429));
    assert!(!retry_policy.should_retry_decision(&second_429));
    assert!(retry_policy.should_retry_decision(&third_503));
}

#[test]
fn retry_policy_timeout_and_read_body_windows_are_configurable() {
    let retry_policy = RetryPolicy::standard()
        .retryable_timeout_phases([TimeoutPhase::Transport])
        .timeout_retry_window(TimeoutPhase::Transport, 2)
        .response_body_read_retry_window(2);
    let transport_timeout_first = RetryDecision {
        attempt: 1,
        max_attempts: 5,
        method: http::Method::GET,
        uri: "https://example.com/timeout".to_owned(),
        status: None,
        transport_error_kind: None,
        timeout_phase: Some(TimeoutPhase::Transport),
        response_body_read_error: false,
    };
    let transport_timeout_second = RetryDecision {
        attempt: 2,
        ..transport_timeout_first.clone()
    };
    let response_timeout = RetryDecision {
        timeout_phase: Some(TimeoutPhase::ResponseBody),
        ..transport_timeout_first.clone()
    };
    let read_body_first = RetryDecision {
        attempt: 1,
        timeout_phase: None,
        response_body_read_error: true,
        ..transport_timeout_first.clone()
    };
    let read_body_second = RetryDecision {
        attempt: 2,
        ..read_body_first.clone()
    };

    assert!(retry_policy.should_retry_decision(&transport_timeout_first));
    assert!(!retry_policy.should_retry_decision(&transport_timeout_second));
    assert!(!retry_policy.should_retry_decision(&response_timeout));
    assert!(retry_policy.should_retry_decision(&read_body_first));
    assert!(!retry_policy.should_retry_decision(&read_body_second));
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
fn error_code_contract_table_is_stable() {
    let codes = HttpClientErrorCode::all();
    assert_eq!(codes.len(), 25);

    let names: Vec<&str> = codes.iter().map(|code| code.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "invalid_uri",
            "serialize_json",
            "serialize_query",
            "serialize_form",
            "request_build",
            "transport",
            "timeout",
            "deadline_exceeded",
            "read_body",
            "response_body_too_large",
            "http_status",
            "deserialize",
            "invalid_header_name",
            "invalid_header_value",
            "decode_content_encoding",
            "concurrency_limit_closed",
            "tls_backend_unavailable",
            "tls_backend_init",
            "tls_config",
            "retry_budget_exhausted",
            "circuit_open",
            "missing_redirect_location",
            "invalid_redirect_location",
            "redirect_limit_exceeded",
            "redirect_body_not_replayable",
        ]
    );

    let unique: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(unique.len(), names.len());
}

#[test]
fn error_code_maps_tls_config_variant() {
    let error = HttpClientError::TlsConfig {
        backend: "native-tls",
        message: "bad cert".to_owned(),
    };
    assert_eq!(error.code(), HttpClientErrorCode::TlsConfig);
    assert_eq!(error.code().as_str(), "tls_config");
}

#[test]
fn error_code_maps_redirect_limit_exceeded_variant() {
    let error = HttpClientError::RedirectLimitExceeded {
        max_redirects: 3,
        method: http::Method::GET,
        uri: "https://example.com/a".to_owned(),
    };
    assert_eq!(error.code(), HttpClientErrorCode::RedirectLimitExceeded);
    assert_eq!(error.code().as_str(), "redirect_limit_exceeded");
}

#[test]
fn error_code_maps_retry_budget_exhausted_variant() {
    let error = HttpClientError::RetryBudgetExhausted {
        method: http::Method::GET,
        uri: "https://example.com/retry-budget".to_owned(),
    };
    assert_eq!(error.code(), HttpClientErrorCode::RetryBudgetExhausted);
    assert_eq!(error.code().as_str(), "retry_budget_exhausted");
}

#[test]
fn error_code_maps_circuit_open_variant() {
    let error = HttpClientError::CircuitOpen {
        method: http::Method::GET,
        uri: "https://example.com/circuit".to_owned(),
        retry_after_ms: 1000,
    };
    assert_eq!(error.code(), HttpClientErrorCode::CircuitOpen);
    assert_eq!(error.code().as_str(), "circuit_open");
}

#[test]
fn invalid_tls_root_ca_pem_returns_tls_config_error() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_root_ca_pem("not-a-pem-certificate")
        .try_build();
    let error = match result {
        Ok(_) => panic!("invalid root ca pem should fail"),
        Err(error) => error,
    };
    match error {
        HttpClientError::TlsConfig { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn tls_root_store_specific_without_roots_returns_tls_config_error() {
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
fn custom_root_ca_requires_specific_root_store() {
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
fn rustls_backend_rejects_pkcs12_identity_configuration() {
    #[cfg(feature = "async-tls-rustls-ring")]
    let backend = Some(TlsBackend::RustlsRing);
    #[cfg(all(
        not(feature = "async-tls-rustls-ring"),
        feature = "async-tls-rustls-aws-lc-rs"
    ))]
    let backend = Some(TlsBackend::RustlsAwsLcRs);
    #[cfg(all(
        not(feature = "async-tls-rustls-ring"),
        not(feature = "async-tls-rustls-aws-lc-rs")
    ))]
    let backend: Option<TlsBackend> = None;

    let Some(backend) = backend else {
        return;
    };

    let result = HttpClient::builder("https://api.example.com")
        .tls_backend(backend)
        .tls_client_identity_pkcs12(vec![0x30, 0x82], "secret")
        .try_build();
    let error = match result {
        Ok(_) => panic!("rustls should reject pkcs12 identity"),
        Err(error) => error,
    };

    match error {
        HttpClientError::TlsConfig { message, .. } => {
            assert!(message.contains("PKCS#12 identity"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn native_tls_invalid_pkcs12_identity_returns_tls_config_error() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_client_identity_pkcs12(vec![1, 2, 3, 4], "secret")
        .try_build();
    let error = match result {
        Ok(_) => panic!("invalid native tls identity should fail"),
        Err(error) => error,
    };
    match error {
        HttpClientError::TlsConfig { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn native_tls_webpki_root_store_is_rejected() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_root_store(TlsRootStore::WebPki)
        .try_build();
    let error = match result {
        Ok(_) => panic!("native tls should reject webpki root store"),
        Err(error) => error,
    };
    match error {
        HttpClientError::TlsConfig { message, .. } => {
            assert!(message.contains("TlsRootStore::WebPki"));
        }
        other => panic!("unexpected error: {other}"),
    }
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

#[cfg(feature = "async-tls-rustls-ring")]
#[test]
fn selecting_rustls_ring_backend_builds_when_feature_enabled() {
    let client = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .try_build()
        .expect("rustls ring backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsRing);
}

#[cfg(not(feature = "async-tls-rustls-ring"))]
#[test]
fn selecting_rustls_ring_backend_returns_unavailable_when_feature_disabled() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .try_build();
    let error = match result {
        Ok(_) => panic!("rustls ring backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        HttpClientError::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsRing.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-rustls-aws-lc-rs")]
#[test]
fn selecting_rustls_aws_lc_backend_builds_when_feature_enabled() {
    let client = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .try_build()
        .expect("rustls aws-lc-rs backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsAwsLcRs);
}

#[cfg(not(feature = "async-tls-rustls-aws-lc-rs"))]
#[test]
fn selecting_rustls_aws_lc_backend_returns_unavailable_when_feature_disabled() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .try_build();
    let error = match result {
        Ok(_) => panic!("rustls aws-lc-rs backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        HttpClientError::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsAwsLcRs.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn selecting_native_tls_backend_builds_when_feature_enabled() {
    let client = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .try_build()
        .expect("native tls backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::NativeTls);
}

#[cfg(not(feature = "async-tls-native"))]
#[test]
fn selecting_native_tls_backend_returns_unavailable_when_feature_disabled() {
    let result = HttpClient::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .try_build();
    let error = match result {
        Ok(_) => panic!("native tls backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        HttpClientError::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::NativeTls.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}
