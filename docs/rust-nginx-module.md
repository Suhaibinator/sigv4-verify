# Rust NGINX Module: `ngx_http_sigv4_verify_module`

Operator guide for the native NGINX module that verifies S3/MinIO SigV4
presigned `GET`/`HEAD` URLs in the NGINX access phase, without the Go sidecar's
`auth_request` hop.

The Go sidecar (see the [top-level README](../README.md)) remains the reference
implementation and the supported rollback path. This module is a
performance-oriented follow-up that keeps the same fail-closed security model.

> Status: production evaluation. The module is feature-complete against the
> supported SigV4 envelope, but it should be rolled out through shadow mode
> before enforce mode. See [Rollout](#rollout) and the
> [requirements' acceptance criteria](rust-nginx-module-requirements.md#acceptance-criteria).

## Contents

- [Overview and architecture](#overview-and-architecture)
- [Supported SigV4 envelope](#supported-sigv4-envelope)
- [Building the module](#building-the-module)
- [Directive reference](#directive-reference)
- [Variables and logging](#variables-and-logging)
- [Policy semantics vs. the Go sidecar](#policy-semantics-vs-the-go-sidecar)
- [Shadow-mode rollout](#shadow-mode-rollout)
- [Observability](#observability)
- [Security notes](#security-notes)
- [Supported versions, platforms, and ABI](#supported-versions-platforms-and-abi)
- [FIPS considerations](#fips-considerations)
- [Rollback to the Go sidecar](#rollback-to-the-go-sidecar)
- [Semantic differences from the Go sidecar](#semantic-differences-from-the-go-sidecar)

## Overview and architecture

The module registers an HTTP access-phase handler. For each request to a
location where verification is enabled, the handler:

1. Reads the client method, the raw (unparsed) request URI, and the `Host`
   header directly from the NGINX request structure.
2. Passes them to the safe Rust verifier core, which reconstructs the SigV4
   canonical request and checks the presigned signature against
   memory-resident credentials.
3. Returns one of:
   - `NGX_OK` — request allowed; normal static/`proxy_pass`/`proxy_cache`
     handling continues.
   - `NGX_HTTP_FORBIDDEN` (403) — verification or policy denial in enforce mode.
   - `NGX_HTTP_INTERNAL_SERVER_ERROR` (500) — internal/config/runtime error.
   - `NGX_DECLINED` — verification is disabled (`off`) for the location, so
     NGINX proceeds as if the module were not present.

There is no subrequest, no `auth_request`, no internal location, and no network,
socket, request-body, or per-request file I/O on the verification path. The
module runs before static file serving, `proxy_pass`, and `proxy_cache`.

The verifier uses the original raw request URI (`r->unparsed_uri`), not the
normalized `$uri`, so the exact signed path and query are preserved.

The codebase is split so that all `unsafe` is confined to a thin FFI layer:

| Crate | Path | Contents |
| --- | --- | --- |
| `sigv4-verifier` | `rust/sigv4-verifier` | Safe verifier core (canonicalization, crypto, policy). No `unsafe` public API. |
| `sigv4-module-config` | `rust/module-config` | Safe directive parsing/validation. No NGINX dependency. |
| `ngx-http-sigv4-verify` | `rust/nginx-module` | NGINX FFI glue: module registration, directive handlers, request reads, variables. |

## Supported SigV4 envelope

The module verifies the same narrow envelope as the Go sidecar MVP. Anything
outside it is denied.

- Query-string presigned authentication only (no header-based authorization).
- Original methods `GET` and `HEAD` only.
- Algorithm `AWS4-HMAC-SHA256`.
- Credential-scope service `s3`, terminal `aws4_request`.
- `X-Amz-SignedHeaders=host` only.
- Canonical payload hash `UNSIGNED-PAYLOAD`.
- Path-style URLs where the bucket is in the path (e.g.
  `/my-bucket/public/report.pdf`).
- Maximum expiry of seven days; a smaller cap is configurable per credential.
- Configurable clock skew.

## Building the module

The module is a dynamic module (`cdylib`). Two build modes are supported.

### Prerequisites

- Rust toolchain pinned by `rust-toolchain.toml` (currently `1.96.0`).
- A C toolchain and `make`.
- `libclang` (bindgen needs it to parse NGINX headers).
- PCRE2, zlib, and OpenSSL development headers.

On Debian/Ubuntu:

```sh
sudo apt-get install --no-install-recommends -y \
    build-essential clang libclang-dev libssl-dev libpcre2-dev zlib1g-dev
```

### Vendored NGINX source (self-contained)

Builds against a vendored, pinned NGINX source tree (NGINX 1.28.3). Use this for
CI and reproducible builds:

```sh
cargo build --release -p ngx-http-sigv4-verify --features vendored
```

Release builds set `panic = "abort"` (see the root `Cargo.toml`).

### Against an existing NGINX source tree

To build against the exact NGINX you run in production, point the build at a
`./configure`d NGINX source tree instead of the vendored copy (omit
`--features vendored`):

```sh
export NGINX_SOURCE_DIR=/path/to/nginx-1.28.x   # a ./configure'd source tree
cargo build --release -p ngx-http-sigv4-verify
```

The NGINX source must be configured with `--with-compat` and must match the
runtime NGINX version. See [ABI constraints](#supported-versions-platforms-and-abi).

### Artifact and deployment

The build produces `target/release/libngx_http_sigv4_verify_module.so` on Linux
(`.dylib` on macOS, for local development only). Deploy it under the NGINX
modules directory renamed to the conventional module name:

```sh
cp target/release/libngx_http_sigv4_verify_module.so \
   /etc/nginx/modules/ngx_http_sigv4_verify_module.so
```

Load it at the top of `nginx.conf`:

```nginx
load_module modules/ngx_http_sigv4_verify_module.so;
```

### Docker

A multi-stage Docker build under `build/nginx-module/Dockerfile` compiles the
module against a pinned, checksum-verified NGINX source (configured
`--with-compat`) and ships it inside the official `nginx:<version>` image, which
is also built `--with-compat`. Prefer the image for deployment because it pins
the NGINX version and build flags together with the module, removing the
ABI-matching burden described below.

```sh
docker build \
    -f build/nginx-module/Dockerfile \
    --build-arg NGINX_VERSION=1.28.0 \
    -t sigv4-verify-nginx-module:1.28.0 \
    .
```

`NGINX_VERSION` selects both the source the module is compiled against and the
runtime `nginx:<version>` base image; the two must be the same version (the
`build/nginx-module/Dockerfile` header documents the ABI constraint). The build
must run from the repository root so the Dockerfile can copy `Cargo.toml`,
`Cargo.lock`, `rust-toolchain.toml`, and `rust/`.

## Directive reference

All `http`-level directives may appear only inside the `http {}` block. The
`sigv4_verify` mode directive may appear in `http`, `server`, or `location` and
is inherited and overridden per the usual NGINX rules.

### `sigv4_verify on | off | shadow`

- Context: `http`, `server`, `location`
- Default: `off`

Selects the verification mode for a location:

- `on` — enforce. Failed verification returns `403`.
- `off` — disabled. The handler returns `NGX_DECLINED`; the request proceeds
  unverified. This is the effective default when the directive is absent
  everywhere.
- `shadow` — verify and record the outcome in variables and logs, but always
  allow the request (never returns `403`).

Inheritance: a value set at an outer level applies to inner levels unless the
inner level overrides it. An explicit `off` at a location overrides an inherited
`on`/`shadow`. Specifying the directive twice at the same level is a
configuration error.

### `sigv4_verify_clock_skew <duration>`

- Context: `http`
- Default: `15m`

Allowed skew when comparing `X-Amz-Date` against the current time. Durations use
NGINX-style units: a bare number is seconds; `s`, `m`, `h`, `d`, `w` are
seconds/minutes/hours/days/weeks; compound values like `1h30m` are supported.
Negative values are unrepresentable and therefore rejected.

### `sigv4_verify_default_max_expires <duration>`

- Context: `http`
- Default: `7d` (the SigV4 maximum)

Default cap on `X-Amz-Expires` for credentials that do not set their own
`max_expires=`. Must be between `1s` and `7d`; `0` or values over `7d` fail
`nginx -t`.

### `sigv4_verify_methods <method> [<method> ...]`

- Context: `http`
- Default: `GET HEAD`

Module-wide set of client methods eligible for verification. Only `GET` and
`HEAD` are accepted; any other value fails `nginx -t`.

### `sigv4_verify_log_denies on | off`

- Context: `http`
- Default: `on`

When `on`, every denied (or would-be-denied, in shadow mode) verification is
logged at `info` level.

### `sigv4_verify_log_all on | off`

- Context: `http`
- Default: `off`

When `on`, every verified request is logged (allow and deny), for debugging.
Off/declined locations are never logged.

### `sigv4_verify_credential <access-key> <arg>...`

- Context: `http`
- Repeatable (one per credential)

Defines one credential. The first argument is the SigV4 access key. Remaining
arguments are `key=value` pairs or bare flags. Unknown keys, empty values, and
conflicting arguments fail `nginx -t`, so a mistyped policy list can never
silently widen access.

Secret source (exactly one is required):

| Argument | Use |
| --- | --- |
| `secret_key_file=<path>` | Production. Secret is read from the file at config load time. |
| `secret_key=<value>` | Local development only. Inline secret literal. |

Other arguments:

| Argument | Default | Meaning |
| --- | --- | --- |
| `enabled=on\|off` | `on` | Disable a credential without removing it. A disabled credential denies with reason `unauthorized`. |
| `max_expires=<duration>` | inherits `sigv4_verify_default_max_expires` | Per-credential expiry cap. Must be `1s`–`7d`. |
| `allowed_host=<host>` | — | Repeatable. Public host accepted for this credential. |
| `allow_any_host` | — | Flag: accept any host. Mutually exclusive with `allowed_host=`. |
| `allowed_method=GET\|HEAD` | — | Repeatable. Method accepted for this credential. |
| `allow_default_methods` | — | Flag: accept the module-wide supported methods. Mutually exclusive with `allowed_method=`. |
| `allowed_prefix=<prefix>` | — | Repeatable. Path prefix (include the bucket segment) accepted for this credential. |
| `allow_any_prefix` | — | Flag: accept any path. Mutually exclusive with `allowed_prefix=`. |

Each of the three policy dimensions (host, method, prefix) **must** be specified
either as an explicit list or with its `allow_*` flag. Omitting both fails
`nginx -t`. This is the key difference from the Go sidecar; see
[Policy semantics](#policy-semantics-vs-the-go-sidecar).

Duplicate access keys across `sigv4_verify_credential` directives fail
`nginx -t`.

### Example configuration

```nginx
load_module modules/ngx_http_sigv4_verify_module.so;

http {
    sigv4_verify_clock_skew 5m;
    sigv4_verify_default_max_expires 15m;
    sigv4_verify_log_denies on;

    sigv4_verify_credential minio_public_reader
        secret_key_file=/run/secrets/minio-public-reader
        enabled=on
        max_expires=10m
        allowed_host=assets.example.com
        allowed_method=GET
        allowed_method=HEAD
        allowed_prefix=/my-bucket/public/
        allowed_prefix=/my-bucket/reports/;

    log_format sigv4 '$remote_addr "$request" $status '
                     'sigv4_result=$sigv4_verify_result '
                     'sigv4_reason=$sigv4_verify_reason '
                     'sigv4_key=$sigv4_verify_access_key_hash '
                     'sigv4_us=$sigv4_verify_latency_us';

    server {
        listen 443 ssl;
        http2 on;
        server_name assets.example.com;

        access_log /var/log/nginx/sigv4.log sigv4;

        location / {
            sigv4_verify on;
            proxy_pass http://minio_origin;
            proxy_cache s3_assets;
            proxy_cache_key "$scheme://$host$request_uri";
        }
    }
}
```

Use `proxy_cache_key "$scheme://$host$request_uri"` so the complete signed query
participates in cache identity. S3 query parameters can select a different object
version, response body, or response metadata for the same path. Refreshed presigned
URLs therefore create separate cache entries.

## Variables and logging

The module exposes four NGINX variables, usable in `log_format`, `map`, and
anywhere NGINX variables are allowed:

| Variable | Values |
| --- | --- |
| `$sigv4_verify_result` | `allow`, `deny`, `error`, `off`, or `shadow`. |
| `$sigv4_verify_reason` | Stable reason string (see below). |
| `$sigv4_verify_access_key_hash` | `sha256:<16 hex>` truncated hash of the access key, when known; otherwise not set. |
| `$sigv4_verify_latency_us` | Verification latency in microseconds. |

In shadow mode `$sigv4_verify_result` is always `shadow`, while
`$sigv4_verify_reason` reflects what the outcome *would* have been.

### Reason strings

These match the Go sidecar's stable reason strings so log pipelines can be
shared:

`ok`, `missing_metadata`, `invalid_uri`, `unsupported_method`,
`missing_query_param`, `unsupported_algorithm`, `invalid_credential_scope`,
`unknown_access_key`, `invalid_expiry`, `expired`, `future_dated`,
`unsupported_signed_header`, `signature_mismatch`, `unauthorized`.

`unauthorized` covers a disabled credential and host/method/prefix policy
denials (the module does not emit a distinct reason per policy dimension).

Two reasons are module-only, with no Go-sidecar equivalent:

- `internal_error` — a Rust panic was caught at the FFI boundary (returns 500).
- `not_configured` — verification was enabled but no compiled verifier exists
  (unreachable in a config that passed `nginx -t`; fails closed with 500).

### Log lines

When logging is enabled, each line is emitted at `info` level in the form:

```text
sigv4_verify: result=<r> reason=<reason> access_key_hash=<hash|-> method=<m> host=<h> path=<p>
```

The raw query string is **never** logged because it carries the signature.

## Policy semantics vs. the Go sidecar

This is the single most important behavioral difference to understand before
migrating.

The Rust **verifier core** treats an empty policy list the same way the Go
sidecar does: an empty allowed-host/method/prefix set means "allow any." The
difference is at the **configuration layer**: the Rust
`sigv4_verify_credential` directive refuses to *produce* an empty list unless
you explicitly opt in with `allow_any_host` / `allow_default_methods` /
`allow_any_prefix`. In the Go sidecar, simply omitting a list in YAML yields an
empty list, which means allow-all (fail-open by default).

Migration mapping:

| Go sidecar credential (YAML) | Rust module credential (directive) |
| --- | --- |
| `allowed_hosts: [assets.example.com]` | `allowed_host=assets.example.com` |
| `allowed_hosts` omitted (allows any host) | `allow_any_host` (must be explicit) |
| `allowed_methods: [GET, HEAD]` | `allowed_method=GET allowed_method=HEAD` |
| `allowed_methods` omitted (allows GET/HEAD) | `allow_default_methods` (must be explicit) |
| `allowed_prefixes: [/bucket/pub/]` | `allowed_prefix=/bucket/pub/` |
| `allowed_prefixes` omitted (allows any path) | `allow_any_prefix` (must be explicit) |
| `secret_key_file: /run/secrets/x` | `secret_key_file=/run/secrets/x` |
| `secret_key_env: SIGV4_SECRET_KEY` | no equivalent — use `secret_key_file=` (or `secret_key=` for dev) |
| `enabled: false` | `enabled=off` |
| `max_expires: 10m` | `max_expires=10m` |

Practical rule: when porting a Go credential that omitted a policy list, decide
deliberately whether you want the corresponding `allow_any_*` /
`allow_default_methods` flag. If you do not, the config will not load until you
add either the flag or an explicit list — by design.

## Shadow-mode rollout

Shadow mode verifies and records outcomes without changing request results, so
you can validate compatibility and measure latency before enforcing. This
mirrors the [requirements' rollout plan](rust-nginx-module-requirements.md#rollout-requirements):

1. Build the module against the production NGINX version (see [Building](#building-the-module)).
2. Deploy the module with `load_module` and `sigv4_verify shadow;` on the target
   locations, alongside the existing Go sidecar `auth_request` path.
3. Confirm `nginx -t` passes and reload.
4. Watch `$sigv4_verify_result` / `$sigv4_verify_reason` in access logs. In
   shadow mode every request is still allowed.
5. Compare the module's `reason` values against the Go sidecar's decisions for
   the same traffic. Investigate any request the module would deny that the
   sidecar allows (or vice versa).
6. Roll shadow mode out to a small production traffic slice, then wider.
7. Confirm latency/CPU using `$sigv4_verify_latency_us` and worker metrics.
8. Switch a canary location to `sigv4_verify on;` (enforce). Denials now return
   `403`.
9. Expand enforce mode gradually across locations and hosts.
10. Keep the Go sidecar deployment available for rollback throughout.

## Observability

The module has no HTTP `/metrics` endpoint (it lives inside NGINX workers).
Observability is through NGINX-native surfaces:

- The four variables above, exported into `access_log` via a custom
  `log_format` (see the example).
- Optional deny logging (`sigv4_verify_log_denies`, default on) and
  all-request logging (`sigv4_verify_log_all`, default off).
- Aggregate reason distribution, latency percentiles, and deny rates by feeding
  the log fields into your existing log/metrics pipeline (e.g. counting
  `sigv4_reason=` values, histogramming `sigv4_us=`).

Deny logs include the reason and the truncated access-key hash. They never
include secrets, derived signing keys, signatures, or the raw query string.

## Security notes

- **Fail closed.** Missing metadata, a non-UTF-8 method or host, an unknown
  access key, a disabled credential, a policy denial, or a signature mismatch
  all deny. A missing compiled verifier or a caught panic returns `500`, not a
  silent allow.
- **Secrets are load-time only.** Secret files are read during config load /
  reload in the master process, never during request handling. Store secrets
  outside the config and reference them with `secret_key_file=`. Recommended
  file permissions: `0400`, owned by the user the NGINX master runs as
  (typically `root`, since config is parsed before privilege drop).
- **Zeroization.** Secret material and derived seeds are wrapped in zeroizing
  containers and wiped when config state is dropped (including on reload).
- **Bounded signing-key cache.** Derived SigV4 signing keys are cached per
  credential (bounded to 32 entries, LRU), keyed by date/region/service. No
  unbounded per-request growth.
- **Constant-time comparison.** Signatures are compared with a constant-time
  equality check (`subtle`).
- **Panic safety.** Every FFI entry point wraps its body in `catch_unwind`, so a
  Rust panic can never unwind into NGINX C frames; it becomes a `500`. Release
  builds additionally compile with `panic = "abort"`.
- **No secrets in logs.** Access keys appear only as a truncated SHA-256 hash;
  signatures and the raw query are never logged.

## Supported versions, platforms, and ABI

- **NGINX:** stable 1.28.x line. The vendored build uses NGINX 1.28.3.
- **Platforms:** Linux `amd64` and `arm64`. (macOS `.dylib` builds work for
  local development but are not a deployment target.)
- **ABI constraint:** native NGINX modules are ABI-sensitive. The module **must**
  be built against the same NGINX version, with `--with-compat`, as the runtime
  NGINX binary. A mismatch can crash the worker at load or request time. The
  Docker image under `build/nginx-module/` pins the module and NGINX together to
  avoid this; if you build the module yourself, build it against your exact
  production NGINX source tree via `NGINX_SOURCE_DIR`.

## FIPS considerations

The crypto primitives (HMAC-SHA256, SHA-256) come from `ring`, with constant-time
comparison from `subtle`. These are reviewed, pure-Rust/BoringSSL-derived
primitives, but they are **not FIPS-validated**. Deployments that require
FIPS-mode alignment would need an OpenSSL-backed crypto variant of the verifier
core; that is future work and not available in this build.

## Rollback to the Go sidecar

Rollback does not require rebuilding anything:

1. Remove (or set to `off`) the `sigv4_verify` directives on the affected
   locations, and remove the `load_module` line for the module.
2. Restore the Go sidecar `auth_request` configuration (the
   [`examples/nginx.conf`](../examples/nginx.conf) pattern) pointing at the
   running sidecar.
3. Run `nginx -t` and reload.

Because the sidecar and the module verify the same envelope, presigned URLs that
were valid under one are valid under the other (subject to the policy-semantics
difference above), so no client-side change is needed.

## Semantic differences from the Go sidecar

Comparing `internal/config` + `internal/verifier` (Go) with `rust/module-config`
+ `rust/sigv4-verifier` (Rust), the verifier cores are behaviorally equivalent
for the supported envelope, including the same reason strings and the same
empty-list "allow-all" semantics in the verification core. The differences are:

1. **Policy-list configuration (most important).** The Rust directive parser
   requires an explicit list or an `allow_any_*` / `allow_default_methods` flag
   for each of host, method, and prefix. The Go sidecar treats an omitted list
   as allow-all. See [Policy semantics](#policy-semantics-vs-the-go-sidecar).
   Note the Go sidecar was hardened to reject inline (flow-style) YAML lists,
   which were previously dropped silently and could fail open; the Rust module
   avoids that class of footgun entirely by requiring explicit intent.
2. **Secret sources.** The Go sidecar supports `secret_key`, `secret_key_file`,
   and `secret_key_env` (environment). The Rust module supports
   `secret_key_file=` (production) and `secret_key=` (dev only); there is no
   environment-variable source, because NGINX environment inheritance is
   explicit and easy to misconfigure.
3. **Transport / integration.** The sidecar runs as a separate process reached
   over TCP or a Unix socket via `auth_request`; the module runs in-process in
   the NGINX access phase with no hop. It reads the raw request URI directly
   rather than an `X-Original-URI` header.
4. **Observability surface.** The sidecar exposes an HTTP `/metrics` endpoint;
   the module exposes NGINX variables and logs only, plus two module-only reason
   strings (`internal_error`, `not_configured`) for FFI-boundary panics and the
   fail-closed unconfigured path.

The set of accepted presigned URLs is otherwise the same, so a URL that verifies
against the sidecar verifies against the module when the credential policy is
configured equivalently.
