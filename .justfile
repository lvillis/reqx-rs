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
    cargo check --all-targets --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring,otel

examples:
    cargo check --examples

examples-all:
    cargo check --examples --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring,otel

clippy:
    cargo clippy --all-targets --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring,otel -- -D warnings

test:
    cargo test --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring,otel

feature-matrix:
    cargo test --tests --no-default-features --features async-tls-rustls-ring
    cargo test --tests --no-default-features --features async-tls-rustls-aws-lc-rs
    cargo test --tests --no-default-features --features async-tls-native
    cargo test --tests --no-default-features --features blocking-tls-rustls-ring
    cargo test --tests --no-default-features --features blocking-tls-rustls-aws-lc-rs
    cargo test --tests --no-default-features --features blocking-tls-native
    cargo check --lib --tests --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring

feature-contract:
    cargo check --lib --no-default-features --features async-rustls
    cargo check --lib --no-default-features --features async-native-tls
    cargo check --lib --no-default-features --features blocking-rustls
    cargo check --lib --no-default-features --features blocking-native-tls
    @bash -euo pipefail -c '\
      expect_fail() { \
        local features="$1"; \
        if cargo check --lib --no-default-features --features "$features" >/dev/null 2>&1; then \
          echo "error: expected feature set to fail, but it passed: $features"; \
          exit 1; \
        fi; \
      }; \
      expect_fail "async-tls-rustls-ring,async-tls-rustls-aws-lc-rs"; \
      expect_fail "async-tls-rustls-ring,async-tls-native"; \
      expect_fail "async-tls-rustls-aws-lc-rs,async-tls-native"; \
      expect_fail "async-rustls,async-native-tls"; \
      expect_fail "blocking-tls-rustls-ring,blocking-tls-rustls-aws-lc-rs"; \
      expect_fail "blocking-tls-rustls-ring,blocking-tls-native"; \
      expect_fail "blocking-tls-rustls-aws-lc-rs,blocking-tls-native"; \
      expect_fail "blocking-rustls,blocking-native-tls"; \
    '

docsrs-check:
    cargo +nightly rustdoc --lib --no-default-features --features async-tls-rustls-ring,blocking-tls-rustls-ring -- --cfg docsrs

bench:
    cargo bench --bench transport

private-guard:
    @if git ls-files | grep -E '^(\\.docs|\\.cargo)/' >/dev/null; then \
      echo "error: tracked private paths detected (.docs or .cargo)"; \
      exit 1; \
    fi

ci: private-guard fmt-check check-all examples-all clippy docsrs-check test

package:
    cargo package

publish-dry-run:
    cargo publish --dry-run

release-check: ci feature-matrix feature-contract package publish-dry-run

changelog:
    git cliff -o CHANGELOG.md

patch:
    cargo release patch --no-publish --execute

minor:
    cargo release minor --no-publish --execute

major:
    cargo release major --no-publish --execute
