#[cfg(feature = "otel")]
mod enabled {
    use std::sync::Arc;
    use std::time::Duration;

    use http::Method;
    use opentelemetry::KeyValue;
    use opentelemetry::global;
    use opentelemetry::metrics::{Counter, Histogram};
    use opentelemetry::trace::{Span, SpanKind, Tracer};

    use crate::error::HttpClientError;

    #[derive(Clone, Debug, Default)]
    pub(crate) struct OtelTelemetry {
        inner: Option<Arc<OtelInner>>,
    }

    #[derive(Debug)]
    struct OtelInner {
        client_name: Arc<str>,
        tracer: global::BoxedTracer,
        requests_started: Counter<u64>,
        requests_succeeded: Counter<u64>,
        requests_failed: Counter<u64>,
        retries: Counter<u64>,
        request_latency_ms: Histogram<f64>,
    }

    #[derive(Debug, Default)]
    pub(crate) struct OtelRequestSpan {
        span: Option<global::BoxedSpan>,
    }

    impl OtelTelemetry {
        pub(crate) fn enabled(client_name: impl Into<String>) -> Self {
            let meter = global::meter("reqx");
            let tracer = global::tracer("reqx");
            let client_name = Arc::<str>::from(client_name.into());
            Self {
                inner: Some(Arc::new(OtelInner {
                    client_name,
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

        pub(crate) fn record_request_failed(&self, error: &HttpClientError) {
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
            span.set_attribute(KeyValue::new("reqx.client", inner.client_name.to_string()));
            span.set_attribute(KeyValue::new(
                "http.request.method",
                method.as_str().to_owned(),
            ));
            span.set_attribute(KeyValue::new("url.full", uri.to_owned()));

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
            error: &HttpClientError,
        ) {
            let Some(span) = request_span.span.as_mut() else {
                return;
            };
            span.set_attribute(KeyValue::new(
                "error.type",
                error.code().as_str().to_owned(),
            ));
            span.set_attribute(KeyValue::new("error.message", error.to_string()));
            if let Some(mut span) = request_span.span.take() {
                span.end();
            }
        }
    }

    fn base_attributes(inner: &OtelInner) -> [KeyValue; 1] {
        [KeyValue::new("reqx.client", inner.client_name.to_string())]
    }
}

#[cfg(not(feature = "otel"))]
mod enabled {
    use std::time::Duration;

    use http::Method;

    use crate::error::HttpClientError;

    #[derive(Clone, Debug, Default)]
    pub(crate) struct OtelTelemetry;

    #[derive(Debug, Default)]
    pub(crate) struct OtelRequestSpan;

    impl OtelTelemetry {
        pub(crate) fn enabled(_client_name: impl Into<String>) -> Self {
            Self
        }

        pub(crate) fn disabled() -> Self {
            Self
        }

        pub(crate) fn record_request_started(&self) {}

        pub(crate) fn record_request_succeeded(&self, _status: u16) {}

        pub(crate) fn record_request_failed(&self, _error: &HttpClientError) {}

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
            _error: &HttpClientError,
        ) {
        }
    }
}

pub(crate) use enabled::{OtelRequestSpan, OtelTelemetry};
