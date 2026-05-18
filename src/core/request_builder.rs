use std::time::Duration;

use http::{HeaderMap, Method};

use crate::config::RequestTimeoutConfig;
use crate::policy::{RedirectPolicy, StatusPolicy};
use crate::retry::RetryPolicy;
use crate::util::append_query_pairs;

#[derive(Default)]
pub(crate) struct RequestExecutionOverrides {
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) max_response_body_bytes: Option<usize>,
    pub(crate) retry_policy: Option<RetryPolicy>,
    pub(crate) redirect_policy: Option<RedirectPolicy>,
    pub(crate) status_policy: Option<StatusPolicy>,
    pub(crate) auto_accept_encoding: Option<bool>,
}

impl RequestExecutionOverrides {
    fn with_forced_status_policy(mut self, forced_status_policy: Option<StatusPolicy>) -> Self {
        self.status_policy = forced_status_policy.or(self.status_policy);
        self
    }
}

pub(crate) struct RequestExecutionOptions {
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) retry_policy: Option<RetryPolicy>,
    pub(crate) max_response_body_bytes: Option<usize>,
    pub(crate) redirect_policy: Option<RedirectPolicy>,
    pub(crate) status_policy: Option<StatusPolicy>,
    pub(crate) auto_accept_encoding: Option<bool>,
}

pub(crate) struct RequestExecutionDefaults<'a> {
    pub(crate) request_timeout: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) retry_policy: &'a RetryPolicy,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) status_policy: StatusPolicy,
    pub(crate) auto_accept_encoding: bool,
}

pub(crate) struct EffectiveRequestExecutionOptions {
    pub(crate) request_timeout: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) retry_policy: RetryPolicy,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) status_policy: StatusPolicy,
    pub(crate) auto_accept_encoding: bool,
}

impl RequestExecutionOptions {
    pub(crate) fn resolve(
        self,
        defaults: RequestExecutionDefaults<'_>,
    ) -> crate::Result<EffectiveRequestExecutionOptions> {
        let request_timeout = self.request_timeout.unwrap_or(defaults.request_timeout);
        let total_timeout = self.total_timeout.or(defaults.total_timeout);
        RequestTimeoutConfig {
            request_timeout,
            total_timeout,
        }
        .validate()?;

        let retry_policy = self
            .retry_policy
            .unwrap_or_else(|| defaults.retry_policy.clone());
        retry_policy.validate()?;

        Ok(EffectiveRequestExecutionOptions {
            request_timeout,
            total_timeout,
            retry_policy,
            max_response_body_bytes: self
                .max_response_body_bytes
                .unwrap_or(defaults.max_response_body_bytes),
            redirect_policy: self.redirect_policy.unwrap_or(defaults.redirect_policy),
            status_policy: self.status_policy.unwrap_or(defaults.status_policy),
            auto_accept_encoding: self
                .auto_accept_encoding
                .unwrap_or(defaults.auto_accept_encoding),
        })
    }
}

impl From<RequestExecutionOverrides> for RequestExecutionOptions {
    fn from(overrides: RequestExecutionOverrides) -> Self {
        Self {
            request_timeout: overrides.request_timeout,
            total_timeout: overrides.total_timeout,
            max_response_body_bytes: overrides.max_response_body_bytes,
            retry_policy: overrides.retry_policy,
            redirect_policy: overrides.redirect_policy,
            status_policy: overrides.status_policy,
            auto_accept_encoding: overrides.auto_accept_encoding,
        }
    }
}

pub(crate) struct PreparedRequest<'a, ClientRef, Body, ExecutionOptions> {
    pub(crate) client: &'a ClientRef,
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Body>,
    pub(crate) execution_options: ExecutionOptions,
}

pub(crate) struct RequestPreparation<'a, ClientRef, Body> {
    pub(crate) client: &'a ClientRef,
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) query_pairs: Vec<(String, String)>,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Body>,
    pub(crate) execution_overrides: RequestExecutionOverrides,
}

impl<'a, ClientRef, Body> RequestPreparation<'a, ClientRef, Body> {
    pub(crate) fn prepare<ExecutionOptions, F>(
        self,
        forced_status_policy: Option<StatusPolicy>,
        build_execution_options: F,
    ) -> PreparedRequest<'a, ClientRef, Body, ExecutionOptions>
    where
        F: FnOnce(RequestExecutionOverrides) -> ExecutionOptions,
    {
        PreparedRequest {
            client: self.client,
            method: self.method,
            path: append_query_pairs(&self.path, &self.query_pairs),
            headers: self.headers,
            body: self.body,
            execution_options: build_execution_options(
                self.execution_overrides
                    .with_forced_status_policy(forced_status_policy),
            ),
        }
    }
}
