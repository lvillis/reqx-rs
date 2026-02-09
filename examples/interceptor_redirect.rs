use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use reqx::prelude::{
    HttpClient, HttpClientError, HttpInterceptor, RedirectPolicy, RequestContext, RetryPolicy,
};

struct TraceInterceptor;

impl HttpInterceptor for TraceInterceptor {
    fn on_request(&self, _context: &RequestContext, headers: &mut http::HeaderMap) {
        headers.insert(
            HeaderName::from_static("x-sdk-trace"),
            HeaderValue::from_static("reqx-example"),
        );
    }

    fn on_response(
        &self,
        context: &RequestContext,
        status: http::StatusCode,
        _headers: &http::HeaderMap,
    ) {
        println!(
            "response: method={} uri={} status={} attempt={} redirects={}",
            context.method(),
            context.uri(),
            status,
            context.attempt(),
            context.redirect_count()
        );
    }

    fn on_error(&self, context: &RequestContext, error: &HttpClientError) {
        eprintln!(
            "error: method={} uri={} code={} err={error}",
            context.method(),
            context.uri(),
            error.code().as_str(),
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://httpbin.org")
        .connect_timeout(Duration::from_secs(2))
        .request_timeout(Duration::from_secs(4))
        .total_timeout(Duration::from_secs(8))
        .redirect_policy(RedirectPolicy::limited(5))
        .retry_policy(RetryPolicy::standard())
        .interceptor(TraceInterceptor)
        .build();

    let response = client.get("/redirect-to?url=%2Fget").send().await?;
    println!("final status={}", response.status());
    Ok(())
}
