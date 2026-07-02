# Rust NGINX Module Requirements

This document defines requirements for a native Rust NGINX module that verifies
S3/MinIO SigV4 presigned URLs inside NGINX workers. The Go sidecar remains the
reference implementation and operational fallback.

The Rust module is a performance-oriented follow-up path. It should not weaken
the current fail-closed security model or reduce compatibility with MinIO/S3
presigned `GET` and `HEAD` URLs.

## Goals

- Verify supported SigV4 presigned URLs in the NGINX access phase without an
  `auth_request` subrequest, HTTP hop, TCP hop, or Unix socket hop.
- Preserve the current verifier behavior for the supported MVP envelope.
- Keep the SigV4 verifier core in safe Rust.
- Keep all `unsafe` code isolated to a small NGINX FFI boundary.
- Avoid GC/runtime embedding issues by using Rust instead of Go inside NGINX.
- Support NGINX reload semantics without per-request config or secret I/O.
- Provide a measurable latency and CPU reduction versus the Go sidecar over
  Unix socket.
- Retain the Go sidecar as a test oracle and fallback deployment option.

## Non-Goals

- No origin, MinIO, or S3 network calls during verification.
- No reads from request bodies.
- No support for header-based SigV4 authorization in the first module version.
- No support for signed streaming payloads in the first module version.
- No support for mutating requests, rewriting URLs, or proxying objects.
- No dependency on Lua, njs, OpenResty, or an embedded Go runtime.
- No attempt to support every NGINX build in one binary. Native modules must be
  built and packaged against compatible NGINX versions.

## Supported SigV4 Envelope

The module must initially match the Go sidecar MVP:

- Query-string presigned authentication only.
- Original methods `GET` and `HEAD` only.
- Algorithm `AWS4-HMAC-SHA256`.
- Credential scope service `s3`.
- Credential scope terminal value `aws4_request`.
- `X-Amz-SignedHeaders=host` only.
- Canonical payload hash `UNSIGNED-PAYLOAD`.
- Path-style S3/MinIO URLs where the bucket is in the path, for example
  `/my-bucket/public/report.pdf`.
- Maximum SigV4 expiry of seven days.
- Configurable smaller max expiry per credential.
- Configurable clock skew.

Anything outside this envelope must be denied.

## Request Flow

The module must run in NGINX's HTTP access phase.

```text
client request
  -> NGINX parses request
  -> ngx_http_sigv4_verify_module access handler
  -> Rust verifier core
  -> NGX_OK, NGX_HTTP_FORBIDDEN, or NGX_HTTP_INTERNAL_SERVER_ERROR
  -> normal cache/proxy/static handling continues only on NGX_OK
```

The module must use NGINX's original raw request URI, not a normalized URI.
The implementation must not verify against `$uri`-equivalent data.

## NGINX Integration Requirements

- The module must be loadable as a dynamic module unless a static-build target
  is explicitly selected for a packaged NGINX distribution.
- The module artifact should be named
  `ngx_http_sigv4_verify_module.so`.
- The access handler must return:
  - `NGX_OK` for allowed requests.
  - `NGX_HTTP_FORBIDDEN` for verification or policy denials.
  - `NGX_HTTP_INTERNAL_SERVER_ERROR` for module/config/runtime errors.
  - `NGX_DECLINED` only when verification is disabled for the location.
- The module must work before static file serving, `proxy_pass`, and
  `proxy_cache`.
- The module must not require `auth_request`.
- The module must not require an internal NGINX location.
- The module must not allocate or retain pointers to NGINX request memory beyond
  the active request.
- Rust panics must never unwind into NGINX C frames.
- The module must compile with panic behavior that is safe for FFI. Acceptable
  options are `panic = "abort"` or an FFI boundary that catches panics and
  returns `NGX_HTTP_INTERNAL_SERVER_ERROR`.

## Configuration Requirements

Configuration must be load-time only. Request handling must not read config
files, environment variables, or secret files.

Configuration must support:

- Enable/disable per `http`, `server`, and `location` context.
- Enforce mode and shadow mode.
- Allowed clock skew.
- Default max expiry.
- Supported methods.
- One or more credentials.
- Per-credential enabled flag.
- Per-credential max expiry.
- Per-credential allowed hosts.
- Per-credential allowed methods.
- Per-credential allowed path prefixes.
- Secret key loaded from file.
- Optional secret key literal for local development only.

Secret-file support is required. Environment-variable support is optional
because NGINX environment inheritance is explicit and easy to misconfigure.

Illustrative NGINX configuration:

```nginx
load_module modules/ngx_http_sigv4_verify_module.so;

http {
    sigv4_verify_clock_skew 5m;
    sigv4_verify_default_max_expires 15m;
    sigv4_verify_log_denies on;

    sigv4_verify_credential minio_public_reader {
        secret_key_file /run/secrets/minio-public-reader;
        enabled on;
        max_expires 10m;
        allowed_host assets.example.com;
        allowed_method GET;
        allowed_method HEAD;
        allowed_prefix /my-bucket/public/;
        allowed_prefix /my-bucket/reports/;
    }

    server {
        listen 443 ssl http2;
        server_name assets.example.com;

        location / {
            sigv4_verify on;
            proxy_pass http://minio_origin;
            proxy_cache s3_assets;
            proxy_cache_key "$scheme://$host$uri";
        }
    }
}
```

The final directive syntax may differ, but it must be documented and covered by
config parser tests.

## Config Validation Requirements

Invalid configuration must fail `nginx -t` and reload, not fail open at request
time.

The module must reject:

- Missing credentials when verification is enabled.
- Duplicate access keys.
- Credentials without a secret.
- Multiple secret sources for one credential.
- Empty secret files.
- Unsupported methods.
- Unsupported service values.
- Invalid durations.
- Negative clock skew.
- Max expiry values over seven days.
- Invalid or ambiguous allowed prefixes.
- Ambiguous host entries.

Policy-list semantics must be explicit. The preferred module behavior is:

- Empty allowed host list means any host only if explicitly configured with an
  `allow_any_host` flag.
- Empty allowed method list means inherited supported methods only if explicitly
  configured.
- Empty allowed prefix list means any path only if explicitly configured with an
  `allow_any_prefix` flag.

If compatibility mode keeps the Go sidecar's "omitted list means allow all"
behavior, the docs must call that out clearly, and tests must verify that a
mistyped or invalid list cannot silently become empty.

## Verification Requirements

The verifier must:

- Treat method comparison as case-sensitive after NGINX method normalization.
- Verify `GET` and `HEAD` signatures against the actual client method.
- Reject unsupported client methods before signature verification when possible.
- Read the canonical host from the public `Host` header used by the client.
- Preserve host casing rules by lowercasing for canonicalization.
- Preserve the exact raw path and raw query from the request URI.
- Reject request URIs containing fragments, spaces, tabs, CR, or LF.
- Reject malformed percent encoding.
- Reject encoded slash and encoded backslash in paths.
- Reject dot segments and percent-encoded dot segments.
- Reject double slashes in paths.
- Reject duplicate singleton SigV4 query parameters.
- Exclude `X-Amz-Signature` from canonical query construction.
- Include unknown query parameters and repeated non-singleton parameters in the
  canonical query.
- Sort canonical query parameters by encoded name and encoded value.
- Use constant-time signature comparison.
- Return structured reasons internally for logging and variables.

## Performance Requirements

The Rust module must be benchmarked against the Go sidecar over Unix socket and
TCP before it is considered production-ready.

Hot-path requirements:

- No origin I/O.
- No request body I/O.
- No per-request config file I/O.
- No per-request secret file I/O.
- No global lock on the common verification path.
- No heap allocation on the common successful request path unless benchmarking
  proves it is negligible.
- Cache derived signing keys per worker by access key, date, region, and
  service.
- Keep signing-key cache bounded.
- Avoid copying request URI, path, query, method, and host unless required to
  cross the unsafe boundary safely.

Acceptance targets should be set from measured baselines. Initial targets:

- Native module p50 verification latency lower than Go sidecar over Unix socket
  by at least 30 percent in the same NGINX e2e setup.
- Native module p99 verification latency lower than Go sidecar over Unix socket
  by at least 20 percent in the same NGINX e2e setup.
- No measurable throughput regression for cached object hits when verification
  is enabled.
- Stable memory usage under sustained load and reload churn.

## Memory Safety Requirements

The safe Rust verifier core must not expose unsafe APIs.

Unsafe code must be limited to:

- NGINX module registration.
- NGINX directive parsing glue.
- Reading NGINX request structures.
- Translating NGINX strings to Rust byte slices.
- Returning status codes and setting variables.

Unsafe blocks must be small and documented with the invariants they rely on.

The module must not:

- Hold NGINX request-pool pointers after the request returns.
- Store borrowed request data in global or worker-level state.
- Unwind panics through C.
- Use mutable global state without synchronization or per-worker isolation.
- Log secret keys, derived signing keys, signatures, or full credentials.

## Credential and Secret Handling

- Secret files must be read during config load or worker initialization, never
  during request verification.
- Secret values must be zeroized when config state is dropped where practical.
- Derived signing keys must be stored in bounded per-worker caches.
- Access keys may be logged only as a stable hash.
- Signature mismatch logs must not include the provided or expected signature.
- File permissions for secret files should be documented, but enforcement may be
  deployment-specific.

## Observability Requirements

The module cannot rely on the sidecar's HTTP `/metrics` endpoint. It must expose
NGINX-native observability surfaces.

Required variables:

- `$sigv4_verify_result`: `allow`, `deny`, `error`, `off`, or `shadow`.
- `$sigv4_verify_reason`: stable reason string.
- `$sigv4_verify_access_key_hash`: hash of the access key when known.
- `$sigv4_verify_latency_us`: verification latency in microseconds.

Required logging:

- Optional deny logging.
- Optional all-request logging for debugging.
- No secret material in logs.
- Stable reason strings matching the Go sidecar where possible.

Optional metrics:

- Shared-memory counters exposed through an NGINX status location.
- OpenTelemetry or Prometheus support via existing NGINX log/metrics pipelines.

## Shadow Mode Requirements

Shadow mode should verify requests and populate variables/logs but must not
deny requests.

Shadow mode is required for safe rollout. It enables:

- Comparing module decisions with the Go sidecar during canaries.
- Detecting compatibility gaps before enforcement.
- Measuring latency and CPU without changing request outcomes.

Enforce mode must deny failed verification with `403`.

## Build and Packaging Requirements

The build must produce:

- Rust verifier library.
- NGINX module artifact.
- Docker image containing compatible NGINX plus the module.
- Optional Debian/RPM packaging after the Docker path is stable.

The build must pin:

- Rust toolchain.
- NGINX source/package version.
- Target architecture.
- Cryptography dependencies.

The CI matrix should include:

- Linux `amd64`.
- Linux `arm64`.
- NGINX stable line selected for production.
- NGINX mainline line selected for forward compatibility, if supported.

Native NGINX modules are ABI-sensitive. The module must be built against an
NGINX version and configure option set compatible with the runtime NGINX
binary. Packaging must make that constraint explicit.

## Cryptography Requirements

The implementation must use reviewed cryptographic primitives for:

- HMAC-SHA256.
- SHA-256 hashing.
- Constant-time equality.

Pure Rust crypto is acceptable for the default module if it is benchmarked and
kept dependency-light. OpenSSL-backed crypto may be required for deployments
that need FIPS-mode alignment. The choice must be explicit in build docs.

The implementation must not hand-roll HMAC, SHA-256, or constant-time compare.

## Test Requirements

The Rust verifier core must have unit tests covering:

- Valid `GET` and `HEAD`.
- MinIO-generated presigned URLs.
- Response query parameters.
- Repeated query parameters.
- Empty query values.
- Encoded spaces and plus signs.
- Unicode path bytes.
- Missing required SigV4 query parameters.
- Duplicate singleton SigV4 query parameters.
- Unsupported algorithms.
- Unsupported signed headers.
- Invalid credential scope.
- Unknown access key.
- Disabled credential.
- Host policy denial.
- Method policy denial.
- Prefix policy denial.
- Expired URLs.
- Future-dated URLs.
- Invalid expiry.
- Signature mismatch.
- Malformed signatures.
- Traversal and ambiguous paths.

Differential tests are required:

- Generate a corpus with the Go sidecar verifier and MinIO SDK.
- Verify that Rust decisions match Go decisions for all supported cases.
- Include deny reasons where practical.

Fuzzing is required for:

- Raw URI splitting.
- Path validation.
- Percent decoding.
- Query parsing.
- Credential scope parsing.
- Canonical query construction.

NGINX e2e tests are required:

- Valid presigned `GET` through NGINX returns `200`.
- Valid presigned `HEAD` through NGINX returns `200` with no body.
- Valid auth with an origin miss returns origin `404`.
- Raw path and signed response query parameters are preserved.
- `GET` using a URL signed for `HEAD` returns `403`.
- Unsupported client method returns `403`.
- Missing SigV4 query returns `403`.
- Tampered signature returns `403`.
- Expired presign returns `403`.
- Host mismatch returns `403`.
- Prefix policy denial returns `403`.
- Module disabled allows normal NGINX behavior.
- Shadow mode logs/sets variables but allows the request.
- Invalid config fails `nginx -t`.
- Reload swaps credentials without worker crashes.

## Benchmark Requirements

Benchmarks must include:

- Rust core-only verifier benchmark.
- NGINX module e2e benchmark with static-file cache hits.
- NGINX module e2e benchmark with proxy/cache configuration.
- Go sidecar Unix socket baseline.
- Go sidecar TCP baseline.
- Mixed valid/invalid traffic.
- High-cardinality query strings.
- Long paths near configured header/URI limits.
- Reload churn while traffic is running.

Report:

- p50, p90, p99, and p999 latency.
- Requests per second per worker.
- CPU per request.
- Allocations per request for Rust core benchmarks.
- Worker RSS.
- Error/deny reason distribution.

## Compatibility Requirements

The module must be compatible with:

- MinIO path-style presigned URLs.
- S3 path-style presigned URLs within the supported envelope.
- NGINX serving static files.
- NGINX proxying to MinIO or another origin.
- NGINX proxy cache.
- HTTP/1.1 and HTTP/2 client connections as handled by NGINX.

The module must document:

- Supported NGINX versions.
- Supported Linux distributions or base images.
- Supported CPU architectures.
- Whether FIPS-compatible crypto builds are available.
- Exact semantic differences from the Go sidecar, if any.

## Rollout Requirements

Recommended rollout:

1. Build Rust core verifier and prove parity with the Go verifier.
2. Add NGINX module wrapper with shadow mode only.
3. Run NGINX e2e matrix against shadow mode and enforce mode.
4. Benchmark against Go sidecar Unix socket and TCP.
5. Deploy shadow mode in staging.
6. Deploy shadow mode in production on a small traffic slice.
7. Compare logs and deny reasons with the sidecar path.
8. Enable enforce mode on a canary.
9. Expand enforce mode gradually.
10. Keep the Go sidecar deployment path available for rollback.

Rollback must be possible by disabling the module or removing `load_module` and
returning to the Go sidecar `auth_request` config.

## Security Review Requirements

Before production use, review:

- Unsafe Rust boundary.
- Config parsing.
- Secret loading and zeroization.
- Canonicalization logic.
- Query parsing.
- Path ambiguity rejection.
- Constant-time signature comparison.
- Logging redaction.
- Reload behavior.
- Panic/abort behavior.
- Dependency supply chain.
- NGINX ABI/package compatibility.

The module should be fuzzed continuously in CI or scheduled jobs once the parser
is stable.

## Open Questions

- Should the module keep exact Go sidecar empty-policy semantics, or should it
  require explicit `allow_any_*` flags?
- Should configuration use NGINX directives only, a separate config file, or
  both?
- Should the first implementation use pure Rust crypto or OpenSSL-backed crypto?
- Should dynamic module packaging target nginx.org packages, distro packages,
  or only a bundled Docker image initially?
- How much observability is required beyond NGINX variables and logs?
- Does production require FIPS-compatible crypto?
- Which exact NGINX stable/mainline versions should be supported first?
- Should virtual-host-style bucket addressing be part of a future version?

## Acceptance Criteria

The Rust NGINX module is ready for production evaluation when:

- All supported Go sidecar verifier compatibility tests pass in Rust.
- NGINX e2e tests pass in enforce and shadow mode.
- Invalid config fails `nginx -t`.
- Fuzzers have run long enough to produce useful coverage without crashes.
- Benchmarks show a meaningful latency/CPU win over the Unix socket sidecar.
- Unsafe code has been reviewed and documented.
- Packaging pins NGINX and Rust versions.
- Rollback to the Go sidecar is documented and tested.
