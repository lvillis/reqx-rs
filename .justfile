set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

list:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

check:
    cargo check

check-all:
    cargo check --all-targets --all-features

examples:
    cargo check --examples

examples-all:
    cargo check --examples --all-features

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test --all-features

feature-matrix:
    cargo test --tests --no-default-features --features async-tls-rustls-ring
    cargo check --lib --tests --no-default-features --features async-tls-rustls-aws-lc-rs
    cargo check --lib --tests --no-default-features --features async-tls-native
    cargo test --tests --no-default-features --features blocking-tls-rustls-ring
    cargo check --lib --tests --no-default-features --features blocking-tls-rustls-aws-lc-rs
    cargo check --lib --tests --no-default-features --features blocking-tls-native
    cargo check --lib --tests --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring

docsrs-check:
    cargo +nightly rustdoc --lib --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring -- --cfg docsrs

bench:
    cargo bench --bench transport

private-guard:
    @if git ls-files | grep -E '^(\\.docs|\\.cargo)/' >/dev/null; then \
      echo "error: tracked private paths detected (.docs or .cargo)"; \
      exit 1; \
    fi

ci: private-guard fmt-check check-all examples-all clippy test

package:
    cargo package

publish-dry-run:
    cargo publish --dry-run

release-check: ci package publish-dry-run

changelog:
    git cliff -o CHANGELOG.md

patch:
    cargo release patch --no-publish --execute

minor:
    cargo release minor --no-publish --execute

major:
    cargo release major --no-publish --execute
