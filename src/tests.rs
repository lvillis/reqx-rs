use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::time::{Duration, SystemTime};

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::body::{DecodeContentEncodingError, decode_content_encoded_body_limited};
use crate::client::Client;
use crate::content_encoding::should_decode_content_encoded_body;
use crate::error::{Error, ErrorCode, TimeoutPhase, TransportErrorKind};
use crate::proxy::{NoProxyRule, normalize_tunnel_target_uri};
use crate::response::Response;
use crate::retry::{RetryDecision, RetryPolicy, request_supports_retry};
use crate::tls::{TlsBackend, TlsRootStore};
use crate::util::{
    append_query_pairs, bounded_retry_delay, default_port, ensure_accept_encoding_async,
    join_base_path, parse_retry_after, rate_limit_bucket_key, redact_uri_for_logs, resolve_uri,
    same_origin,
};
use crate::{AdvancedConfig, ClientProfile, StatusPolicy};

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
fn resolve_uri_keeps_absolute_uri_with_uppercase_scheme() {
    let (uri_text, uri) = resolve_uri("https://api.example.com/v1", "HTTPS://x.test/a")
        .expect("absolute uri with uppercase scheme should parse");
    assert_eq!(uri_text, "HTTPS://x.test/a");
    assert_eq!(uri.host().expect("host should be present"), "x.test",);
}

#[test]
fn resolve_uri_rejects_non_http_absolute_uri() {
    let error = resolve_uri("https://api.example.com/v1", "ftp://x.test/a")
        .expect_err("non-http absolute uri should be rejected");
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "ftp://x.test/a");
        }
        other => panic!("unexpected error variant: {other}"),
    }
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
fn normalize_tunnel_target_uri_handles_uppercase_scheme() {
    let uri: http::Uri = "HTTPS://api.example.com/v1/users"
        .parse()
        .expect("uri should parse");
    let normalized = normalize_tunnel_target_uri(uri);
    assert_eq!(normalized.host(), Some("api.example.com"));
    assert_eq!(normalized.port_u16(), Some(443));
    assert!(
        normalized
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    );
}

#[test]
fn default_port_handles_uppercase_scheme() {
    let https: http::Uri = "HTTPS://api.example.com/path"
        .parse()
        .expect("uri should parse");
    let http: http::Uri = "HTTP://api.example.com/path"
        .parse()
        .expect("uri should parse");
    assert_eq!(default_port(&https), Some(443));
    assert_eq!(default_port(&http), Some(80));
}

#[test]
fn rate_limit_bucket_key_uses_default_port_for_uppercase_scheme() {
    let uri: http::Uri = "HTTPS://api.example.com/path"
        .parse()
        .expect("uri should parse");
    assert_eq!(
        rate_limit_bucket_key(&uri).as_deref(),
        Some("api.example.com:443")
    );
}

#[test]
fn same_origin_handles_uppercase_scheme() {
    let left: http::Uri = "HTTPS://api.example.com/path"
        .parse()
        .expect("left uri should parse");
    let right: http::Uri = "https://api.example.com:443/other"
        .parse()
        .expect("right uri should parse");
    assert!(same_origin(&left, &right));
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
    let response = Response::new(
        http::StatusCode::OK,
        http::HeaderMap::new(),
        bytes::Bytes::from_static(b"not-json"),
    );
    let error = response
        .json::<serde_json::Value>()
        .expect_err("invalid json should return error");
    match error {
        Error::DeserializeJson { body, .. } => assert_eq!(body, "not-json"),
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
fn retry_policy_standard_skips_tls_and_other_transport_errors() {
    let retry_policy = RetryPolicy::standard();
    let tls_decision = RetryDecision {
        attempt: 1,
        max_attempts: 3,
        method: http::Method::GET,
        uri: "https://example.com/tls".to_owned(),
        status: None,
        transport_error_kind: Some(TransportErrorKind::Tls),
        timeout_phase: None,
        response_body_read_error: false,
    };
    let other_decision = RetryDecision {
        transport_error_kind: Some(TransportErrorKind::Other),
        ..tls_decision.clone()
    };

    assert!(!retry_policy.should_retry_decision(&tls_decision));
    assert!(!retry_policy.should_retry_decision(&other_decision));
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
    let error = Error::InvalidUri {
        uri: "bad://uri".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::InvalidUri);
    assert_eq!(error.code().as_str(), "invalid_uri");
}

#[test]
fn error_code_contract_table_is_stable() {
    let codes = ErrorCode::all();
    assert_eq!(codes.len(), 26);

    let names: Vec<&str> = codes.iter().map(|code| code.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "invalid_uri",
            "invalid_no_proxy_rule",
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
            "deserialize_json",
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
    let error = Error::TlsConfig {
        backend: "native-tls",
        message: "bad cert".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::TlsConfig);
    assert_eq!(error.code().as_str(), "tls_config");
}

#[test]
fn error_code_maps_redirect_limit_exceeded_variant() {
    let error = Error::RedirectLimitExceeded {
        max_redirects: 3,
        method: http::Method::GET,
        uri: "https://example.com/a".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::RedirectLimitExceeded);
    assert_eq!(error.code().as_str(), "redirect_limit_exceeded");
}

#[test]
fn error_code_maps_retry_budget_exhausted_variant() {
    let error = Error::RetryBudgetExhausted {
        method: http::Method::GET,
        uri: "https://example.com/retry-budget".to_owned(),
    };
    assert_eq!(error.code(), ErrorCode::RetryBudgetExhausted);
    assert_eq!(error.code().as_str(), "retry_budget_exhausted");
}

#[test]
fn error_code_maps_circuit_open_variant() {
    let error = Error::CircuitOpen {
        method: http::Method::GET,
        uri: "https://example.com/circuit".to_owned(),
        retry_after_ms: 1000,
    };
    assert_eq!(error.code(), ErrorCode::CircuitOpen);
    assert_eq!(error.code().as_str(), "circuit_open");
}

#[test]
fn invalid_tls_root_ca_pem_returns_tls_config_error() {
    let result = Client::builder("https://api.example.com")
        .tls_root_ca_pem("not-a-pem-certificate")
        .build();
    let error = match result {
        Ok(_) => panic!("invalid root ca pem should fail"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_invalid_base_url_early() {
    let result = Client::builder("not-a-valid-base-url").build();
    let error = match result {
        Ok(_) => panic!("invalid base url should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "not-a-valid-base-url");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_non_http_base_url_scheme() {
    let result = Client::builder("ftp://api.example.com").build();
    let error = match result {
        Ok(_) => panic!("non-http base url should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "ftp://api.example.com");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_query() {
    let result = Client::builder("https://api.example.com/v1?token=abc").build();
    let error = match result {
        Ok(_) => panic!("base url with query should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com/v1?token=abc");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_fragment() {
    let result = Client::builder("https://api.example.com/v1#anchor").build();
    let error = match result {
        Ok(_) => panic!("base url with fragment should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://api.example.com/v1#anchor");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_userinfo() {
    let result = Client::builder("https://user:pass@api.example.com/v1").build();
    let error = match result {
        Ok(_) => panic!("base url with userinfo should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, "https://user:pass@api.example.com/v1");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn build_rejects_base_url_with_surrounding_whitespace() {
    let result = Client::builder(" https://api.example.com/v1 ").build();
    let error = match result {
        Ok(_) => panic!("base url with surrounding whitespace should fail at build time"),
        Err(error) => error,
    };
    match error {
        Error::InvalidUri { uri } => {
            assert_eq!(uri, " https://api.example.com/v1 ");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn client_profile_and_advanced_config_compose() {
    let client = Client::builder("https://api.example.com")
        .profile(ClientProfile::LowLatency)
        .advanced(
            AdvancedConfig::default()
                .with_request_timeout(Duration::from_secs(4))
                .with_total_timeout(Duration::from_secs(9))
                .with_max_response_body_bytes(16 * 1024)
                .with_default_status_policy(StatusPolicy::Response),
        )
        .build()
        .expect("client should build with profile and advanced config");
    assert_eq!(client.default_status_policy(), StatusPolicy::Response);
}

#[test]
fn tls_root_store_specific_without_roots_returns_tls_config_error() {
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
fn custom_root_ca_requires_specific_root_store() {
    let result = Client::builder("https://api.example.com")
        .tls_root_ca_der([1_u8, 2, 3, 4])
        .build();
    let error = match result {
        Ok(_) => panic!("custom root ca should require specific root store"),
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

    let result = Client::builder("https://api.example.com")
        .tls_backend(backend)
        .tls_client_identity_pkcs12(vec![0x30, 0x82], "secret")
        .build();
    let error = match result {
        Ok(_) => panic!("rustls should reject pkcs12 identity"),
        Err(error) => error,
    };

    match error {
        Error::TlsConfig { message, .. } => {
            assert!(message.contains("PKCS#12 identity"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn native_tls_invalid_pkcs12_identity_returns_tls_config_error() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_client_identity_pkcs12(vec![1, 2, 3, 4], "secret")
        .build();
    let error = match result {
        Ok(_) => panic!("invalid native tls identity should fail"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn native_tls_webpki_root_store_is_rejected() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .tls_root_store(TlsRootStore::WebPki)
        .build();
    let error = match result {
        Ok(_) => panic!("native tls should reject webpki root store"),
        Err(error) => error,
    };
    match error {
        Error::TlsConfig { message, .. } => {
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
fn no_proxy_rule_parses_bracketed_ipv6_with_port() {
    let rule = NoProxyRule::parse("[::1]:8080").expect("valid ipv6 rule");
    assert!(rule.matches("::1"));
    assert!(!rule.matches("::2"));
}

#[test]
fn no_proxy_rule_keeps_plain_ipv6_without_port() {
    let rule = NoProxyRule::parse("2001:db8::1").expect("valid ipv6 rule");
    assert!(rule.matches("2001:db8::1"));
    assert!(!rule.matches("2001:db8::2"));
}

#[test]
fn try_add_no_proxy_rejects_invalid_rule() {
    let result = Client::builder("https://api.example.com").try_add_no_proxy("[::1]not-a-port");
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
    match error {
        Error::InvalidNoProxyRule { rule } => assert_eq!(rule, "[::1]not-a-port"),
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn try_no_proxy_rejects_invalid_rule() {
    let result =
        Client::builder("https://api.example.com").try_no_proxy(["example.com", "[::1]not-a-port"]);
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
}

#[cfg(feature = "_blocking")]
#[test]
fn blocking_try_add_no_proxy_rejects_invalid_rule() {
    let result = crate::blocking::Client::builder("https://api.example.com")
        .try_add_no_proxy("[::1]not-a-port");
    let error = match result {
        Ok(_) => panic!("invalid no_proxy rule should fail"),
        Err(error) => error,
    };

    assert_eq!(error.code(), ErrorCode::InvalidNoProxyRule);
}

#[test]
fn ensure_accept_encoding_sets_default_when_absent() {
    let mut headers = http::HeaderMap::new();
    ensure_accept_encoding_async(&http::Method::GET, &mut headers);
    assert_eq!(
        headers
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip, br, deflate, zstd")
    );
}

#[test]
fn ensure_accept_encoding_skips_default_for_head() {
    let mut headers = http::HeaderMap::new();
    ensure_accept_encoding_async(&http::Method::HEAD, &mut headers);
    assert!(
        headers.get(http::header::ACCEPT_ENCODING).is_none(),
        "HEAD should not auto-negotiate content-encoding"
    );
}

#[test]
fn should_decode_content_encoded_body_only_when_body_semantics_allow() {
    assert!(!should_decode_content_encoded_body(
        &http::Method::HEAD,
        http::StatusCode::OK,
        32
    ));
    assert!(!should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::NO_CONTENT,
        32
    ));
    assert!(!should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::NOT_MODIFIED,
        32
    ));
    assert!(!should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::OK,
        0
    ));
    assert!(should_decode_content_encoded_body(
        &http::Method::GET,
        http::StatusCode::OK,
        32
    ));
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
    let decoded =
        decode_content_encoded_body_limited(bytes::Bytes::from(compressed), &headers, 1024)
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
    let error =
        decode_content_encoded_body_limited(bytes::Bytes::from_static(b"abc"), &headers, 64)
            .expect_err("unknown content-encoding should fail");
    match error {
        DecodeContentEncodingError::Decode { encoding, .. } => assert_eq!(encoding, "x-custom"),
        other => panic!("unexpected decode error: {other:?}"),
    }
}

#[test]
fn decode_content_encoded_body_limited_rejects_expanded_payload() {
    let source = vec![b'a'; 16 * 1024];
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&source)
        .expect("write gzip source bytes should succeed");
    let compressed = encoder.finish().expect("finish gzip stream should succeed");

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_ENCODING,
        http::HeaderValue::from_static("gzip"),
    );
    let error = decode_content_encoded_body_limited(bytes::Bytes::from(compressed), &headers, 512)
        .expect_err("expanded payload should exceed decode limit");
    match error {
        DecodeContentEncodingError::TooLarge { actual_bytes } => {
            assert!(actual_bytes > 512);
        }
        other => panic!("unexpected decode error: {other:?}"),
    }
}

#[cfg(feature = "async-tls-rustls-ring")]
#[test]
fn selecting_rustls_ring_backend_builds_when_feature_enabled() {
    let client = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .build()
        .expect("rustls ring backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsRing);
}

#[cfg(not(feature = "async-tls-rustls-ring"))]
#[test]
fn selecting_rustls_ring_backend_returns_unavailable_when_feature_disabled() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsRing)
        .build();
    let error = match result {
        Ok(_) => panic!("rustls ring backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        Error::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsRing.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-rustls-aws-lc-rs")]
#[test]
fn selecting_rustls_aws_lc_backend_builds_when_feature_enabled() {
    let client = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .build()
        .expect("rustls aws-lc-rs backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::RustlsAwsLcRs);
}

#[cfg(not(feature = "async-tls-rustls-aws-lc-rs"))]
#[test]
fn selecting_rustls_aws_lc_backend_returns_unavailable_when_feature_disabled() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::RustlsAwsLcRs)
        .build();
    let error = match result {
        Ok(_) => panic!("rustls aws-lc-rs backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        Error::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::RustlsAwsLcRs.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[cfg(feature = "async-tls-native")]
#[test]
fn selecting_native_tls_backend_builds_when_feature_enabled() {
    let client = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .build()
        .expect("native tls backend should build when feature is enabled");
    assert_eq!(client.tls_backend(), TlsBackend::NativeTls);
}

#[cfg(not(feature = "async-tls-native"))]
#[test]
fn selecting_native_tls_backend_returns_unavailable_when_feature_disabled() {
    let result = Client::builder("https://api.example.com")
        .tls_backend(TlsBackend::NativeTls)
        .build();
    let error = match result {
        Ok(_) => panic!("native tls backend should be unavailable when feature is disabled"),
        Err(error) => error,
    };
    match error {
        Error::TlsBackendUnavailable { backend } => {
            assert_eq!(backend, TlsBackend::NativeTls.as_str());
        }
        other => panic!("unexpected error: {other}"),
    }
}
