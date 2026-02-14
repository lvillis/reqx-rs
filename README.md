# reqx

[![crates.io](https://img.shields.io/crates/v/reqx.svg)](https://crates.io/crates/reqx)
[![docs.rs](https://docs.rs/reqx/badge.svg)](https://docs.rs/reqx)
[![CI](https://github.com/lvillis/reqx-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/lvillis/reqx-rs/actions/workflows/ci.yaml)
[![license](https://img.shields.io/crates/l/reqx.svg)](LICENSE)

![reqx transport banner](assets/reqx-banner.svg)

`reqx` is an HTTP transport client for Rust API SDK libraries.

It focuses on SDK transport concerns: retries, timeout phases, idempotency, proxy routing, structured errors, and metrics.

## For SDK Authors

- Start with a profile: `ClientProfile::StandardSdk`, `ClientProfile::LowLatency`, or `ClientProfile::HighThroughput`.
- Fine-tune with `AdvancedConfig` only when required.
- Keep strict behavior with `StatusPolicy::Error` (default), or opt into response-first mode with
  `StatusPolicy::Response`.
- For multi-endpoint SDKs, plug in an `EndpointSelector` (for example `RoundRobinEndpointSelector`).
- Hook transport events through `Observer` for retries and server-throttle telemetry.

## Install

```bash
cargo add reqx
```

Use `native-tls`:

```bash
cargo add reqx --no-default-features -F async-native-tls
```

Use `rustls` (alias to `async-tls-rustls-ring`):

```bash
cargo add reqx --no-default-features -F async-rustls
```

Use `rustls + aws-lc-rs`:

```bash
cargo add reqx --no-default-features -F async-tls-rustls-aws-lc-rs
```

Use blocking client with `ureq + rustls(ring)`:

```bash
cargo add reqx --no-default-features -F blocking-rustls
```

Use blocking client with `ureq + native-tls`:

```bash
cargo add reqx --no-default-features -F blocking-native-tls
```

## TLS Backends

- feature contract:
  - enable at least one transport mode
  - for each enabled mode (`async` / `blocking`), enable exactly one TLS backend
  - enabling both `async` and `blocking` is supported
- async backends (default mode):
  - `async-tls-rustls-ring` (default)
  - `async-tls-rustls-aws-lc-rs`
  - `async-tls-native`
- blocking backends (`ureq`):
  - `blocking-tls-rustls-ring`
  - `blocking-tls-rustls-aws-lc-rs`
  - `blocking-tls-native`
- ergonomic aliases:
  - `async-rustls` -> `async-tls-rustls-ring`
  - `async-native-tls` -> `async-tls-native`
  - `blocking-rustls` -> `blocking-tls-rustls-ring`
  - `blocking-native-tls` -> `blocking-tls-native`
- runtime selection via `tls_backend(TlsBackend::...)`
- build-time mismatch returns structured error from `build()`
- trust store selection via `tls_root_store(TlsRootStore::BackendDefault | WebPki | System | Specific)`
- `BackendDefault` follows each backend's default trust roots; set `System` explicitly for enterprise/private PKI environments
- custom root CA: `tls_root_store(TlsRootStore::Specific)` + `tls_root_ca_pem(...)` / `tls_root_ca_der(...)`
- mTLS identity:
  - PEM chain + key: `tls_client_identity_pem(...)` (async + sync)
  - PKCS#12: `tls_client_identity_pkcs12(...)` (async `async-tls-native`)

## Quick Start

```rust
use std::time::Duration;

use reqx::prelude::{Client, RetryPolicy};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CreateItemResponse {
    id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://api.example.com")
        .client_name("example-sdk")
        .request_timeout(Duration::from_secs(3))
        .total_timeout(Duration::from_secs(8))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(3)
                .base_backoff(Duration::from_millis(100))
                .max_backoff(Duration::from_millis(800)),
        )
        .build()?;

    let created: CreateItemResponse = client
        .post("/v1/items")
        .idempotency_key("create-item-001")?
        .json(&serde_json::json!({ "name": "demo" }))?
        .send_json()
        .await?;

    println!("created id={}", created.id);
    Ok(())
}
```

## Blocking Quick Start

```rust
use std::time::Duration;

use reqx::blocking::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://api.example.com")
        .request_timeout(Duration::from_secs(3))
        .total_timeout(Duration::from_secs(8))
        .build()?;

    let response = client.get("/v1/items").send()?;
    println!("status={}", response.status());
    Ok(())
}
```

## Core Capabilities

- global defaults + per-request overrides
- profile presets (`ClientProfile`) + explicit overrides (`AdvancedConfig`)
- idempotency-aware retries
- retry budget + circuit breaker + adaptive concurrency controls
- global/per-host rate limiting with `429 Retry-After` backpressure
- request-level and client-level status handling (`StatusPolicy`)
- bounded redirect following (`RedirectPolicy`)
- transport timeout + response-body timeout + total deadline
- separate connect timeout (`connect_timeout(...)`)
- streaming upload and streaming response path
- stream `copy_to_writer*` / `into_bytes_limited` keep raw bytes (wire semantics)
- explicit buffered conversion (`send()`, `into_response_limited`, `into_json_limited`) decodes
  `gzip`, `br`, `deflate`, `zstd` for both async and blocking
- proxy support with auth and `no_proxy`
- interceptor hooks for SDK concerns (`Interceptor`)
- response body size limit
- structured error variants + machine error codes
- stable status-error metadata helpers: `status_code()`, `response_headers()`, `retry_after()`, `request_id()`
- metrics snapshot for retries, latency, status and error buckets
- observer hooks (`Observer`) for request-start, retry scheduling, and server throttling

## Examples

- Full index: `examples/README.md`
- `cargo run --example basic_json`
- `cargo run --example request_helpers`
- `cargo run --example request_overrides`
- `cargo run --example profile_and_observer`
- `cargo run --example error_handling`
- `cargo run --example metrics_snapshot`
- `cargo run --example streaming`
- `cargo run --example concurrency_limits`
- `cargo run --example resilience_controls`
- `cargo run --example rate_limit_429`
- `cargo run --example retry_classifier`
- `cargo run --example proxy_and_no_proxy`
- `cargo run --example tls_backends`
- `cargo run --example custom_ca_mtls`
- `cargo run --example interceptor_redirect`
- `cargo run --example blocking_basic --no-default-features -F blocking-tls-rustls-ring`

## Release Checklist

- `just ci`
- `just feature-matrix`
- `just feature-contract`
- `just docsrs-check`
- `just release-check`

## Error Model

Common `Error` variants:

- `Transport { kind, .. }`
- `Timeout { phase, .. }`
- `DeadlineExceeded { .. }`
- `HttpStatus { status, body, .. }`
- `DecodeContentEncoding { .. }`
- `DeserializeJson { .. }`

Use `error.code()` for stable machine-readable classification.
