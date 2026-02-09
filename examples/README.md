# reqx Examples

All examples are scenario-focused and runnable.

Run any example:

```bash
cargo run --example <name>
```

## Recommended Learning Path

1. `basic_json` - Base client, retries, JSON send/receive.
2. `request_helpers` - Query, form, and header helpers.
3. `request_overrides` - Per-request timeout and retry overrides.
4. `error_handling` - Pattern match `HttpClientError` + stable `error.code()`.
5. `metrics_snapshot` - Read runtime metrics counters.
6. `streaming` - Stream upload and stream response body.
7. `concurrency_limits` - `max_in_flight` behavior under parallel load.
8. `resilience_controls` - Retry budget, circuit breaker, and adaptive concurrency.
9. `rate_limit_429` - Global/per-host rate limiting with `429 Retry-After` backpressure.
10. `retry_classifier` - Custom `RetryClassifier`.
11. `proxy_and_no_proxy` - Proxy routing and bypass rules.
12. `tls_backends` - Runtime TLS backend selection.
13. `custom_ca_mtls` - Custom root CA and mTLS identity setup.
14. `interceptor_redirect` - Interceptor hooks with bounded redirect following.
15. `blocking_basic` - Blocking client (`reqx::blocking`) on top of `ureq`.

## Example Index

| Example                 | Focus                                               | Run                                      |
|-------------------------|-----------------------------------------------------|------------------------------------------|
| `basic_json.rs`         | Standard SDK request flow with JSON                 | `cargo run --example basic_json`         |
| `request_helpers.rs`    | `.query()`, `.form()`, default/request headers      | `cargo run --example request_helpers`    |
| `request_overrides.rs`  | Override timeout/retry at request level             | `cargo run --example request_overrides`  |
| `error_handling.rs`     | Match error variants and print error codes          | `cargo run --example error_handling`     |
| `metrics_snapshot.rs`   | Observe requests/retries/status/error counters      | `cargo run --example metrics_snapshot`   |
| `streaming.rs`          | `body_stream()` upload and `send_stream()` download | `cargo run --example streaming`          |
| `concurrency_limits.rs` | Demonstrate serialized execution with limiter       | `cargo run --example concurrency_limits` |
| `resilience_controls.rs` | Configure retry budget, circuit breaker, and adaptive concurrency | `cargo run --example resilience_controls` |
| `rate_limit_429.rs`    | Configure global/per-host rate limits and 429 backpressure | `cargo run --example rate_limit_429` |
| `retry_classifier.rs`   | Plug in custom retry classifier logic               | `cargo run --example retry_classifier`   |
| `proxy_and_no_proxy.rs` | Configure proxy auth and `no_proxy` rules           | `cargo run --example proxy_and_no_proxy` |
| `tls_backends.rs`       | Choose TLS backend based on enabled features        | `cargo run --example tls_backends`       |
| `custom_ca_mtls.rs`     | Configure custom CA trust and mTLS client identity  | `cargo run --example custom_ca_mtls`     |
| `interceptor_redirect.rs` | Interceptor lifecycle hooks + redirect policy      | `cargo run --example interceptor_redirect` |
| `blocking_basic.rs`     | Blocking request flow with sync transport           | `cargo run --example blocking_basic --no-default-features -F blocking-tls-rustls-ring` |

## Feature-Specific TLS Runs

Use `native-tls`:

```bash
cargo run --example tls_backends --no-default-features -F async-tls-native
```

Use `rustls + aws-lc-rs`:

```bash
cargo run --example tls_backends --no-default-features -F async-tls-rustls-aws-lc-rs
```

Use blocking sync client (`ureq + rustls`):

```bash
cargo run --example blocking_basic --no-default-features -F blocking-tls-rustls-ring
```
