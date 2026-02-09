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
8. `retry_classifier` - Custom `RetryClassifier`.
9. `proxy_and_no_proxy` - Proxy routing and bypass rules.
10. `tls_backends` - Runtime TLS backend selection.

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
| `retry_classifier.rs`   | Plug in custom retry classifier logic               | `cargo run --example retry_classifier`   |
| `proxy_and_no_proxy.rs` | Configure proxy auth and `no_proxy` rules           | `cargo run --example proxy_and_no_proxy` |
| `tls_backends.rs`       | Choose TLS backend based on enabled features        | `cargo run --example tls_backends`       |

## Feature-Specific TLS Runs

Use `native-tls`:

```bash
cargo run --example tls_backends --no-default-features -F tls-native
```

Use `rustls + aws-lc-rs`:

```bash
cargo run --example tls_backends --no-default-features -F tls-rustls-aws-lc-rs
```
