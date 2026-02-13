#[cfg(feature = "otel")]
mod enabled {
    use std::sync::Arc;
    use std::time::Duration;

    use http::Method;
    use http::Uri;
    use opentelemetry::KeyValue;
    use opentelemetry::global;
    use opentelemetry::metrics::{Counter, Histogram};
    use opentelemetry::trace::{Span, SpanKind, Tracer};

    use crate::error::Error;
    use crate::extensions::OtelPathNormalizer;

    #[derive(Clone, Debug, Default)]
    pub(crate) struct OtelTelemetry {
        inner: Option<Arc<OtelInner>>,
    }

    struct OtelInner {
        client_name: Arc<str>,
        path_normalizer: Arc<dyn OtelPathNormalizer>,
        tracer: global::BoxedTracer,
        requests_started: Counter<u64>,
        requests_succeeded: Counter<u64>,
        requests_failed: Counter<u64>,
        retries: Counter<u64>,
        request_latency_ms: Histogram<f64>,
    }

    impl std::fmt::Debug for OtelInner {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("OtelInner")
                .field("client_name", &self.client_name)
                .finish_non_exhaustive()
        }
    }

    #[derive(Debug, Default)]
    pub(crate) struct OtelRequestSpan {
        span: Option<global::BoxedSpan>,
    }

    impl OtelTelemetry {
        pub(crate) fn enabled_with_path_normalizer(
            client_name: impl Into<String>,
            path_normalizer: Arc<dyn OtelPathNormalizer>,
        ) -> Self {
            let meter = global::meter("reqx");
            let tracer = global::tracer("reqx");
            let client_name = Arc::<str>::from(client_name.into());
            Self {
                inner: Some(Arc::new(OtelInner {
                    client_name,
                    path_normalizer,
                    tracer,
                    requests_started: meter
                        .u64_counter("reqx.request.started")
                        .with_description("Total started HTTP requests")
                        .build(),
                    requests_succeeded: meter
                        .u64_counter("reqx.request.succeeded")
                        .with_description("Total successful HTTP requests")
                        .build(),
                    requests_failed: meter
                        .u64_counter("reqx.request.failed")
                        .with_description("Total failed HTTP requests")
                        .build(),
                    retries: meter
                        .u64_counter("reqx.request.retries")
                        .with_description("Total retry attempts")
                        .build(),
                    request_latency_ms: meter
                        .f64_histogram("reqx.request.duration.ms")
                        .with_unit("ms")
                        .with_description("End-to-end request latency in milliseconds")
                        .build(),
                })),
            }
        }

        pub(crate) fn disabled() -> Self {
            Self::default()
        }

        pub(crate) fn record_request_started(&self) {
            let Some(inner) = &self.inner else {
                return;
            };
            inner.requests_started.add(1, &base_attributes(inner));
        }

        pub(crate) fn record_request_succeeded(&self, status: u16) {
            let Some(inner) = &self.inner else {
                return;
            };
            let attributes = [
                KeyValue::new("reqx.client", inner.client_name.to_string()),
                KeyValue::new("http.response.status_code", i64::from(status)),
            ];
            inner.requests_succeeded.add(1, &attributes);
        }

        pub(crate) fn record_request_failed(&self, error: &Error) {
            let Some(inner) = &self.inner else {
                return;
            };
            let attributes = [
                KeyValue::new("reqx.client", inner.client_name.to_string()),
                KeyValue::new("error.type", error.code().as_str().to_owned()),
            ];
            inner.requests_failed.add(1, &attributes);
        }

        pub(crate) fn record_retry(&self) {
            let Some(inner) = &self.inner else {
                return;
            };
            inner.retries.add(1, &base_attributes(inner));
        }

        pub(crate) fn record_request_latency(&self, latency: Duration) {
            let Some(inner) = &self.inner else {
                return;
            };
            inner
                .request_latency_ms
                .record(latency.as_secs_f64() * 1000.0, &base_attributes(inner));
        }

        pub(crate) fn start_request_span(
            &self,
            method: &Method,
            uri: &str,
            stream: bool,
        ) -> OtelRequestSpan {
            let Some(inner) = &self.inner else {
                return OtelRequestSpan::default();
            };

            let operation = if stream {
                "reqx.http.request.stream"
            } else {
                "reqx.http.request"
            };
            let mut span = inner
                .tracer
                .span_builder(operation)
                .with_kind(SpanKind::Client)
                .start(&inner.tracer);
            for attribute in request_span_attributes(
                &inner.client_name,
                inner.path_normalizer.as_ref(),
                method,
                uri,
            ) {
                span.set_attribute(attribute);
            }

            OtelRequestSpan { span: Some(span) }
        }

        pub(crate) fn finish_request_span_success(
            &self,
            mut request_span: OtelRequestSpan,
            status: u16,
        ) {
            let Some(span) = request_span.span.as_mut() else {
                return;
            };
            span.set_attribute(KeyValue::new(
                "http.response.status_code",
                i64::from(status),
            ));
            if let Some(mut span) = request_span.span.take() {
                span.end();
            }
        }

        pub(crate) fn finish_request_span_error(
            &self,
            mut request_span: OtelRequestSpan,
            error: &Error,
        ) {
            let Some(span) = request_span.span.as_mut() else {
                return;
            };
            for attribute in error_span_attributes(error) {
                span.set_attribute(attribute);
            }
            if let Some(mut span) = request_span.span.take() {
                span.end();
            }
        }
    }

    fn request_span_attributes(
        client_name: &str,
        path_normalizer: &dyn OtelPathNormalizer,
        method: &Method,
        uri: &str,
    ) -> Vec<KeyValue> {
        let mut attributes = Vec::with_capacity(6);
        attributes.push(KeyValue::new("reqx.client", client_name.to_owned()));
        attributes.push(KeyValue::new(
            "http.request.method",
            method.as_str().to_owned(),
        ));
        if let Ok(parsed) = uri.parse::<Uri>() {
            if let Some(scheme) = parsed.scheme_str() {
                attributes.push(KeyValue::new("url.scheme", scheme.to_owned()));
            }
            if let Some(host) = parsed.host() {
                attributes.push(KeyValue::new("server.address", host.to_owned()));
            }
            if let Some(port) = parsed.port_u16() {
                attributes.push(KeyValue::new("server.port", i64::from(port)));
            }
            let path = path_normalizer.normalize_path(parsed.path());
            if !path.is_empty() {
                attributes.push(KeyValue::new("url.path", path));
            }
        }
        attributes
    }

    fn error_span_attributes(error: &Error) -> [KeyValue; 1] {
        [KeyValue::new(
            "error.type",
            error.code().as_str().to_owned(),
        )]
    }

    fn base_attributes(inner: &OtelInner) -> [KeyValue; 1] {
        [KeyValue::new("reqx.client", inner.client_name.to_string())]
    }

    #[cfg(test)]
    mod tests {
        use super::{error_span_attributes, request_span_attributes};
        use crate::error::{Error, TimeoutPhase};
        use crate::extensions::{OtelPathNormalizer, StandardOtelPathNormalizer};

        struct FixedPathNormalizer;

        impl OtelPathNormalizer for FixedPathNormalizer {
            fn normalize_path(&self, _path: &str) -> String {
                "/normalized".to_owned()
            }
        }

        #[test]
        fn request_span_attributes_do_not_include_url_full() {
            let attributes = request_span_attributes(
                "sdk",
                &FixedPathNormalizer,
                &http::Method::GET,
                "https://api.example.com/v1/orders/123?token=secret",
            );
            let keys = attributes
                .iter()
                .map(|item| item.key.as_str())
                .collect::<Vec<_>>();
            assert!(keys.contains(&"reqx.client"));
            assert!(keys.contains(&"http.request.method"));
            assert!(keys.contains(&"url.path"));
            assert!(!keys.contains(&"url.full"));

            let normalized = attributes
                .iter()
                .find(|item| item.key.as_str() == "url.path")
                .map(|item| item.value.to_string());
            assert_eq!(normalized.as_deref(), Some("/normalized"));
        }

        #[test]
        fn error_span_attributes_include_error_type_only() {
            let error = Error::Timeout {
                phase: TimeoutPhase::Transport,
                timeout_ms: 10,
                method: http::Method::GET,
                uri: "https://api.example.com/v1/items".to_owned(),
            };
            let attributes = error_span_attributes(&error);
            let keys = attributes
                .iter()
                .map(|item| item.key.as_str())
                .collect::<Vec<_>>();
            assert!(keys.contains(&"error.type"));
            assert!(!keys.contains(&"error.message"));
        }

        #[test]
        fn standard_path_normalizer_reduces_dynamic_segments() {
            let normalizer = StandardOtelPathNormalizer;
            let normalized = normalizer.normalize_path(
                "/v1/orders/123456789012/items/550e8400-e29b-41d4-a716-446655440000",
            );
            assert_eq!(normalized, "/v1/orders/:int/items/:uuid");
        }
    }
}

#[cfg(not(feature = "otel"))]
mod enabled {
    use std::sync::Arc;
    use std::time::Duration;

    use http::Method;

    use crate::error::Error;
    use crate::extensions::OtelPathNormalizer;

    #[derive(Clone, Debug, Default)]
    pub(crate) struct OtelTelemetry;

    #[derive(Debug, Default)]
    pub(crate) struct OtelRequestSpan;

    impl OtelTelemetry {
        pub(crate) fn enabled_with_path_normalizer(
            _client_name: impl Into<String>,
            _path_normalizer: Arc<dyn OtelPathNormalizer>,
        ) -> Self {
            Self
        }

        pub(crate) fn disabled() -> Self {
            Self
        }

        pub(crate) fn record_request_started(&self) {}

        pub(crate) fn record_request_succeeded(&self, _status: u16) {}

        pub(crate) fn record_request_failed(&self, _error: &Error) {}

        pub(crate) fn record_retry(&self) {}

        pub(crate) fn record_request_latency(&self, _latency: Duration) {}

        pub(crate) fn start_request_span(
            &self,
            _method: &Method,
            _uri: &str,
            _stream: bool,
        ) -> OtelRequestSpan {
            OtelRequestSpan
        }

        pub(crate) fn finish_request_span_success(
            &self,
            _request_span: OtelRequestSpan,
            _status: u16,
        ) {
        }

        pub(crate) fn finish_request_span_error(
            &self,
            _request_span: OtelRequestSpan,
            _error: &Error,
        ) {
        }
    }
}

pub(crate) use enabled::{OtelRequestSpan, OtelTelemetry};
