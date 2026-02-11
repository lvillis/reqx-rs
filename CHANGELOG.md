## [0.1.10] - 2026-02-11

### 🚀 Features

- Add response-first status policy and preserve non-2xx headers

### 🐛 Bug Fixes

- *(api)* Align retry semantics and decode error hooks

### 🚜 Refactor

- Align stream semantics and unify decode/retry paths
- Polish transport API contracts, naming, and resilience flows
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
