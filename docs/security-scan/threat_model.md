# Overview

`sigv4-verify` is an authorization component for S3/MinIO-style object requests. It has two production runtime forms: a Go HTTP sidecar used by NGINX `auth_request`, and a native Rust NGINX access-phase module backed by a reusable Rust verification core. Both accept an original method, raw URI, and public host, reconstruct an AWS SigV4 canonical request, select a memory-resident credential, enforce per-credential host/method/path/expiry policy, and return allow only after constant-time HMAC comparison. The protected asset is the origin object namespace and any confidentiality, integrity, or cost boundary enforced by requiring a valid presigned URL.

Primary runtime code is in `cmd/sigv4-verify`, `internal/config`, `internal/server`, `internal/verifier`, `rust/sigv4-verifier`, `rust/module-config`, and `rust/nginx-module`. The e2e, fuzz, benchmark, example, documentation, presign helper, and corpus-generation paths support development or deployment but are not themselves request authorization surfaces. The NGINX module container build is a supply-chain and deployment surface because it downloads and links native NGINX sources and ships a dynamic module.

# Threat Model, Trust Boundaries, and Assumptions

- The public client is untrusted. It controls the HTTP method, public host, raw path, query order, percent encodings, duplicate query parameters, SigV4 scope fields, timestamps, expiry, access-key identifier, signature, and overall request size up to the surrounding server's limits.
- NGINX is a trusted policy-enforcement proxy for the Go sidecar. The sidecar trusts `X-Original-Method`, `X-Original-URI`, and `X-Original-Host` to accurately represent the client request. This trust is valid only when `/verify` is private and NGINX overwrites rather than forwards those headers. Exposing the sidecar directly lets a caller choose that metadata; signature verification still occurs, but any policy coupling to the actual outer request is lost.
- The origin server is outside the verifier's runtime trust path. Verification is intentionally offline and must not call S3, MinIO, or the origin or consume the client body. A successful authorization decision is expected to gate a separate NGINX serve/proxy action.
- Operators control YAML, environment variables, secret files, NGINX directives, listener address or Unix-socket path and mode, clock-skew and expiry limits, logging, and shadow/enforce mode. These are trusted administrative inputs, but parsing mistakes must fail configuration or fail closed rather than silently widening access.
- Credential secret values and derived signing keys are highly sensitive assets. Production services must keep them in process memory or protected files and out of responses, logs, metrics, panic payloads, and generated variables. The optional local presign helper's explicit secret flag is accepted operator-controlled tooling behavior; an environment fallback is available. Access-key hashes and stable reason strings are intentionally lower-sensitivity observability values.
- Object paths without query or signature material are accepted operational metadata in privileged denial logs. Both runtime forms provide an operator control for disabling denial logging; path visibility inside those logs is not treated as crossing the object-read authorization boundary.
- The Go sidecar's SIGHUP reloader and the NGINX configuration loader cross a privileged runtime boundary. Invalid replacement configuration must not partially install, erase the prior usable state, or briefly produce an allow-all verifier.
- The Rust NGINX module crosses an unsafe FFI boundary into NGINX request pools, headers, variables, and configuration structures. Pointer lifetime, allocation, panic containment, and ABI compatibility are security and availability assumptions. The shipped module must match the runtime NGINX ABI.
- The build and CI environment is developer-controlled but supply-chain-sensitive. GitHub Actions, pinned language toolchains, Cargo/Go dependency locks, downloaded NGINX source, base images, and action versions can affect the integrity of the shipped verifier.

Security invariants:

- Allow only a supported `GET` or `HEAD` request with exactly one required SigV4 query parameter, the supported algorithm/service/terminal, `host` as the only signed header, a valid timestamp and bounded unexpired lifetime, an enabled known credential, matching host/method/path policy, and a valid HMAC over the exact canonical request.
- Canonicalization and downstream routing must agree on the security-relevant path, host, method, and query semantics. Ambiguous separators, dot segments, encoded slashes or backslashes, malformed escapes, duplicate signed parameters, alternative spellings, and sorting/decoding discrepancies must be rejected or canonicalized identically to the signer and NGINX/origin.
- Policy is evaluated against the same raw/canonical representation that the signature authorizes. Empty or malformed allowlists must not unexpectedly mean allow-all, and prefix comparison must not create namespace-boundary confusion.
- Every unexpected internal state, parse error, panic, missing credential state, failed reload, and integration outage must deny or return an error that the caller treats as deny. Shadow mode is the sole intentional non-enforcing mode and must be an explicit operator choice.
- Untrusted input must have bounded CPU and memory cost. Request parsing, query collection/sorting, logging, metrics labels, key caches, and header handling must not provide practical denial-of-service amplification.
- Production secrets must not be disclosed through query logging, error strings, request IDs, metrics, configuration errors, or memory-unsafe FFI behavior. Explicit arguments to trusted local development tools are governed by operator shell and process-hygiene policy rather than the public runtime threat boundary.

# Attack Surface, Mitigations, and Attacker Stories

The main attack surface is canonical request reconstruction in `internal/verifier/canonical.go` and `rust/sigv4-verifier/src/lib.rs`. Realistic attackers will try duplicate or percent-encoded signed parameters, malformed dates and credential scopes, non-UTF-8 bytes in the native module, path normalization mismatches, encoded traversal or separators, host variants, signature exclusion tricks, integer/time overflow, and very large query strings. Existing controls reject whitespace/fragments, double slashes, dot segments, encoded `/` and `\\`, malformed escapes, duplicate required parameters, unsupported signed headers and services, out-of-range expiry, future-dated or expired URLs, and compare signatures in constant time. Differential tests and fuzz targets materially reduce divergence risk but do not replace review of both implementations and their callers.

The Go HTTP surface in `internal/server/server.go` exposes `/verify`, `/healthz`, `/readyz`, and `/metrics` on one listener. The verifier rejects a non-GET auth subrequest and converts panics to HTTP 500. Server header/time limits reduce request-exhaustion risk. Deployment must keep `/verify` and `/metrics` on a trusted network or Unix socket; proxy configuration must replace metadata headers and must deny on every non-204 result. Client-controlled `X-Request-ID`, `X-Real-IP`, and `X-Forwarded-For` reach responses or structured logs and therefore require log-injection, cardinality, spoofing, and size review even though they do not decide authorization.

Configuration in `internal/config`, `rust/module-config`, and the NGINX main-conf initializer accepts privileged secret and policy material. Existing controls require one secret source, validate supported methods and expiry bounds, reject duplicate access keys, reject ambiguous prefixes, retain the Go verifier's previous state after a failed reload, and require explicit allow-any flags in the Rust NGINX directive layer. The Go verifier intentionally treats omitted per-credential host/method/prefix lists as unrestricted or default policy; that is a documented operator footgun and must never be enabled accidentally by parsing away nonempty invalid values.

The native module runs before NGINX serves the object. It catches Rust panics, returns 500 for missing internal state, avoids logging raw queries or panic payloads, and uses request-pool-backed contexts. Security review must still cover every unsafe block and FFI callback for null pointers, lifetime errors, size truncation, mutable-static initialization races, and fail-open NGINX status handling. Shadow mode deliberately returns success on a denied verification result and must not be mistaken for enforcement.

The Docker build pins an NGINX tarball digest and aligns the build/runtime NGINX version, mitigating source substitution and ABI mismatch. Remaining supply-chain stories include compromised third-party GitHub Actions or registries, mutable image tags, malicious dependency updates, and an operator loading the module into a mismatched NGINX binary. These normally require developer or operator control and are less directly exploitable than public request-processing flaws.

Out of scope as standalone vulnerabilities are malicious administrators who can replace credentials, policy, the executable, NGINX configuration, or CI secrets; deliberate public exposure contrary to the integration contract without an accompanying code-level bypass; origin authorization rules not represented in this repository; and attacks requiring local process memory read access. These assumptions do not excuse accidental fail-open defaults, secret leakage, unsafe memory corruption, or documented configurations that turn an ordinary public request into a bypass.

# Severity Calibration (Critical, High, Medium, Low)

## Critical

- A remotely exploitable memory-safety flaw in the NGINX worker or verifier that provides code execution or disclosure of in-memory secret keys.
- A generic, unauthenticated signature-validation bypass that lets arbitrary public clients read any protected object across configured credentials, hosts, and prefixes.
- Direct extraction of all configured signing secrets through a public request or standard response/log surface.

## High

- A canonicalization, duplicate-parameter, host, method, expiry, or path-policy discrepancy that lets an untrusted client access a meaningful protected namespace without possessing a valid matching presigned URL.
- A fail-open reload, missing-state, or NGINX status-handling path that causes enforced deployments to allow requests during attacker-triggerable errors.
- A practical unsafe-FFI bug that corrupts NGINX worker memory or leaks credential material but has narrower preconditions than a critical issue.

## Medium

- A public-input denial of service that can reliably crash or saturate verifier or NGINX workers with modest traffic beyond ordinary rate-limiting expectations.
- Leakage of signature-bearing queries, credential secrets, stable credential identities beyond the intended hash, or other protected request metadata through default logs or metrics.
- A policy parsing or prefix-boundary error that widens access only within one already-authorized bucket/credential and requires a specially configured rule.
- An integration behavior that defeats enforcement under a plausible documented configuration but does not provide a universal bypass.

## Low

- Excessive logging, metric-cardinality growth, timing differences without a viable secret-recovery path, or verbose denial reasons that offer modest reconnaissance value.
- Build hardening or dependency-integrity weaknesses requiring a compromised developer/operator environment and lacking a direct shipped-runtime exploit path.
- Availability or information issues limited to health, readiness, local helpers, tests, examples, or opt-in development tooling with no credible production path.

Repository: target_sha256_92b0c781d6f3d8257dd8e510142825066ed5fbf9cb53ed24d40a67b2c89477d9
Version: a9ac6ddc5d5b256b3a47e6ca718802bee38a6839
