## [0.1.29] - 2026-03-20

### 🐛 Bug Fixes

- Enable rustls tls12 in published builds

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.29
## [0.1.28] - 2026-03-20

### 🚀 Features

- Add async TLS version bounds and improve TLS error reporting

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.28
## [0.1.27] - 2026-03-06

### 🐛 Bug Fixes

- Tighten stream deadline timeout classification

### 🚜 Refactor

- Type metrics errors and inject resilience clocks
- Unify internal time controls and expose stream deadline slack
- Tighten control-clock semantics and deadline classification

### ⚙️ Miscellaneous Tasks

- *(docs)* Add advanced time controls example
- Release reqx version 0.1.27
## [0.1.26] - 2026-03-06

### 🚜 Refactor

- [**breaking**] Split response streaming internals and separate write-body errors
- Type retry decisions and group metrics snapshots

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.26
## [0.1.25] - 2026-03-06

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.25
## [0.1.24] - 2026-03-06

### 🐛 Bug Fixes

- Harden stream and upload edge cases
- Unify throttle and request prep

### 🚜 Refactor

- Simplify request status APIs and harden stream semantics
- Simplify request APIs and preserve blocking stream error semantics
- Streamline public API ergonomics
- [**breaking**] Simplify public API and make ResponseStream directly readable

### ⚙️ Miscellaneous Tasks

- Bump MSRV to 1.94
- Release reqx version 0.1.24
## [0.1.23] - 2026-03-04

### 🐛 Bug Fixes

- Finalize stream metrics and otel spans on body completion
- Correct stream in-flight and cancel metrics
- Correct blocking stream success/cancel metrics
- Enforce post-read total-timeout in blocking stream

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.23
## [0.1.22] - 2026-02-25

### 🐛 Bug Fixes

- Adopt async-safe tracing instrumentation across request loop

### 🧪 Testing

- Add async tracing abort regression coverage

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.22
## [0.1.21] - 2026-02-24

### 🐛 Bug Fixes

- Tighten throttle scope behavior and rustls backend-default roots
- Enforce retry-after cap and fail fast proxy auth config
- Align proxy auth validation across async and blocking

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.21
## [0.1.20] - 2026-02-14

### 🐛 Bug Fixes

- Harden retry/transport semantics and unify safe URI accessors
- Harden URI redaction, transport error classification, and rate limiter cleanup path
- Harden blocking proxy auth and unify terminal failure handling
- Harden adaptive concurrency, proxy validation, and retry-after capping

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.20
## [0.1.19] - 2026-02-13

### 🐛 Bug Fixes

- Harden redirect semantics and remove internal panic paths

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.19
## [0.1.18] - 2026-02-13

### 🐛 Bug Fixes

- Expose raw stream URI and add redacted URI accessor

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.18
## [0.1.17] - 2026-02-13

### 🚀 Features

- Harden transport resilience and async/blocking behavior contracts

### 🐛 Bug Fixes

- Enforce queue-wait deadlines and unify limiter cleanup
- Tighten timeout semantics, resilience classification, and feature-guard ergonomics

### 🚜 Refactor

- Unify async and blocking retry decision flow
- Unify status retry flow and enforce async stream body timeouts
- Align timeout semantics and add blocking in-flight limiters
- Unify timeout/retry semantics and restore strict feature guards

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.17
## [0.1.16] - 2026-02-12

### 🧪 Testing

- Deflake async-native retry budget resilience assertions

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.16
## [0.1.15] - 2026-02-12

### 🚀 Features

- Align stream concurrency lifetime, no_proxy port matching, and system+custom CA trust

### 🐛 Bug Fixes

- Harden policy validation and retry-budget semantics
- Harden rate limiting, async proxy routing, and no_proxy validation
- *(blocking)* Enforce no-redirect policy and add regression tests
- Align redirect body semantics and harden limiter cleanup
- Harden error redaction and add safe error accessors

### 🚜 Refactor

- Unify retry loops and enforce strict no_proxy validation

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.15
## [0.1.14] - 2026-02-12

### 🚀 Features

- Enforce TLS backend exclusivity and add ergonomic feature aliases

### 🐛 Bug Fixes

- Harden no_proxy IPv6 parsing and unify response body retry/decode flow

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.14
## [0.1.13] - 2026-02-11

### 🚀 Features

- Make stream Accept-Encoding opt-in by default

### 🐛 Bug Fixes

- Align stream HttpStatus headers with decoded error bodies
- Harden error contracts and redact debug output
- Harden async per-host concurrency and resilience paths
- Align per-authority concurrency and case-insensitive URI semantics
- Tighten feature-gated TLS paths and remove panic fallbacks

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.13
## [0.1.12] - 2026-02-11

### 🐛 Bug Fixes

- Align content-decoding with HTTP body semantics

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.12
## [0.1.11] - 2026-02-11

### 🐛 Bug Fixes

- Redact response bodies from error display messages

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.11
## [0.1.10] - 2026-02-11

### 🚀 Features

- Add response-first status policy and preserve non-2xx headers

### 🐛 Bug Fixes

- *(api)* Align retry semantics and decode error hooks

### 🚜 Refactor

- Align stream semantics and unify decode/retry paths
- Polish transport API contracts, naming, and resilience flows

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.10
## [0.1.9] - 2026-02-11

### 🚜 Refactor

- Standardize public API names to Client/Response

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.9
## [0.1.8] - 2026-02-10

### 🚜 Refactor

- Standardize public and internal naming conventions

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.8
## [0.1.7] - 2026-02-10

### 🐛 Bug Fixes

- Harden decoding limits and validate base URLs early

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.7
## [0.1.6] - 2026-02-10

### 🐛 Bug Fixes

- Gate examples and docs by feature set for blocking-only builds

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.6
## [0.1.5] - 2026-02-10

### 🚀 Features

- Unify TLS trust-store semantics for custom CAs

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.5
## [0.1.4] - 2026-02-10

### 🧪 Testing

- Stabilize async resilience served-count assertions

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.4
## [0.1.3] - 2026-02-10

### 🚀 Features

- Add redirects, interceptors, and connect timeout
- Add resilience controls for async and blocking clients
- Add built-in rate limiting with 429 retry-after backpressure
- Add zero-copy streaming I/O and granular retry controls
- Make metrics opt-in with zero-overhead default
- Add resumable multipart upload
- Harden uploads and observability
- Refine 429 throttle coordination

### 🐛 Bug Fixes

- Remove deprecated doc_auto_cfg for docs.rs nightly build

### 🚜 Refactor

- Modularize transport layers

### ⚙️ Miscellaneous Tasks

- *(examples)* Switch to a more reliable public echo service
- *(examples)* Switch to a more reliable public echo service
- Release reqx version 0.1.3
## [0.1.2] - 2026-02-09

### 🚀 Features

- [**breaking**] Split async/blocking transport and finalize release pipeline

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release reqx version 0.1.2
## [0.1.1] - 2026-02-09

### ⚙️ Miscellaneous Tasks

- Init commit
- Release reqx version 0.1.1
