# Overview

`sigv4-verify` is a native Rust NGINX access-phase module backed by a reusable
safe Rust verification core. It reconstructs an AWS SigV4 canonical request
from the client method, raw URI, and public host; selects a memory-resident
credential; enforces host/method/path/expiry policy; and allows the request only
after constant-time HMAC comparison.

Runtime code is in `rust/sigv4-verifier`, `rust/module-config`, and
`rust/nginx-module`. The fuzz, benchmark, example, documentation, and signed
regression-corpus paths support development but are not independent
authorization surfaces. The NGINX module container is a supply-chain and
deployment surface because it downloads pinned NGINX source and ships a native
dynamic module.

# Trust boundaries and assumptions

- The public client is untrusted. It controls the HTTP method, public host, raw
  path, query order, encodings, duplicate parameters, SigV4 fields, timestamps,
  access-key identifier, signature, and request size within NGINX limits.
- NGINX is the policy-enforcement point. The module reads request state directly
  from NGINX and must run before static, proxy, or cache handling.
- The origin is outside the verification path. Verification must not call S3,
  MinIO, or the origin or read the request body.
- Operators control NGINX directives, secret files, clock-skew/expiry limits,
  logging, and shadow/enforce mode. Invalid or incomplete configuration must
  fail `nginx -t` or fail closed at request time.
- Credential secrets and derived signing keys must remain in protected files or
  process memory and never appear in logs, variables, errors, or panic payloads.
- The Rust module crosses an unsafe FFI boundary into NGINX request pools,
  headers, variables, and configuration structures. Pointer lifetimes,
  allocation, panic containment, and ABI compatibility are security and
  availability assumptions.
- The build environment is developer-controlled but supply-chain-sensitive.
  GitHub Actions, the pinned Rust toolchain, Cargo lockfile, NGINX source,
  container images, and action versions affect the shipped verifier.

# Security invariants

- Allow only supported `GET` or `HEAD` requests with exactly one of each
  required SigV4 parameter, the supported algorithm/service/terminal, `host` as
  the only signed header, a bounded unexpired lifetime, a known enabled
  credential, matching policy, and a valid HMAC over the canonical request.
- Canonicalization and downstream routing must agree on path, host, method, and
  query semantics. Ambiguous separators, dot segments, encoded slashes or
  backslashes, malformed escapes, duplicate signed parameters, and
  sorting/decoding discrepancies must be rejected.
- Every policy dimension must be explicitly configured. Parser failures must
  never convert a nonempty intended allowlist into unrestricted access.
- Unexpected internal state, parsing errors, panics, missing verifier state, and
  integration failures must deny or return an error treated as denial. Shadow
  mode is the sole intentional non-enforcing mode and must be explicit.
- Untrusted input must have bounded CPU and memory cost. Query sorting, logging,
  derived-key caching, and request parsing must not create practical
  amplification.
- Production secrets and signature-bearing raw queries must not be disclosed.

# Attack surface and mitigations

The main public-input surface is canonical request reconstruction in
`rust/sigv4-verifier/src/lib.rs`. Attackers may try duplicate or encoded signed
parameters, malformed dates and scopes, non-UTF-8 bytes, path-normalization
mismatches, traversal, encoded separators, host variants, signature-exclusion
tricks, integer overflow, and very large queries. Existing controls reject
whitespace/fragments, double slashes, dot segments, encoded `/` and `\\`,
malformed escapes, duplicate required parameters, unsupported headers and
services, invalid expiry, future-dated/expired URLs, and compare signatures in
constant time. Regression tests and fuzz targets reduce parser-regression risk.

Configuration in `rust/module-config` and the NGINX main-conf initializer
accepts privileged policy and secret material. Controls require exactly one
secret source, validate methods and expiry bounds, reject duplicate access keys
and ambiguous prefixes, and require explicit allow-any flags. Secret files are
read at configuration load, not per request.

The native module catches Rust panics, returns `500` for missing internal state,
does not log raw queries, and stores request context in NGINX request-pool
memory. Review must still cover every unsafe block and callback for null
pointers, lifetimes, size truncation, static initialization races, and
fail-open status handling. Shadow mode intentionally allows failed verification
and must never be mistaken for enforcement.

The Docker build pins the NGINX tarball digest and aligns build/runtime NGINX
versions. Remaining supply-chain risks include compromised actions or
registries, mutable base-image tags, malicious dependency updates, and loading
the module into an ABI-incompatible NGINX binary.

Out of scope as standalone vulnerabilities are malicious administrators able to
replace credentials, policy, module binaries, or NGINX configuration; origin
authorization rules not represented here; and attacks requiring local process
memory access. These assumptions do not excuse accidental fail-open defaults,
secret leakage, unsafe memory corruption, or misleading deployment guidance.

# Severity calibration

## Critical

- Remotely exploitable memory corruption yielding code execution or signing-key
  disclosure.
- A generic unauthenticated signature bypass across configured credentials,
  hosts, and prefixes.
- Public extraction of configured signing secrets.

## High

- A canonicalization, host, method, expiry, duplicate-parameter, or path-policy
  discrepancy granting meaningful unauthorized object access.
- An attacker-triggerable fail-open missing-state, reload, or NGINX status path.
- A narrower unsafe-FFI flaw that corrupts worker memory or leaks credentials.

## Medium

- Public-input denial of service that crashes or saturates workers with modest
  traffic beyond normal rate-limiting expectations.
- Leakage of signature-bearing queries, secret material, or stable credential
  identity beyond the intended truncated hash.
- A policy parser or prefix-boundary error that widens one configured namespace.
- A plausible documented integration configuration that defeats enforcement.

## Low

- Excessive logging, metric cardinality, or timing differences without a viable
  secret-recovery path.
- Supply-chain hardening gaps requiring a compromised developer/operator
  environment and lacking a direct shipped-runtime exploit path.
- Issues confined to tests, examples, benchmarks, or opt-in development tools.
