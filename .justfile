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

changelog:
    git cliff -o CHANGELOG.md

patch:
    cargo release patch --no-publish --execute

minor:
    cargo release minor --no-publish --execute

major:
    cargo release major --no-publish --execute
