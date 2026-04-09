set shell := ["bash", "-euo", "pipefail", "-c"]

patch:
    cargo release patch --no-publish --execute

publish:
    cargo publish

ci:
    cargo fmt --all --check
    cargo clippy --all-targets --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring,otel -- -D warnings
    cargo +nightly rustdoc --lib --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring -- --cfg docsrs
    cargo test --doc --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring,otel
    cargo nextest run --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring,otel

bench:
    cargo bench --bench transport
