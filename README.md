# sigv4-verify

`sigv4-verify` is a lightweight Go sidecar for NGINX `auth_request`.
It verifies S3/MinIO SigV4 presigned `GET` and `HEAD` URLs before NGINX
serves or proxies the object request.

The verifier is designed to run offline: it does not call MinIO, S3, or the
origin server, and it does not read the client request body. It reconstructs
the SigV4 canonical request from headers supplied by NGINX, checks the
presigned query signature against memory-resident credentials, and fails
closed when a request is unsupported or invalid.

## Request Flow

1. A client requests a presigned object URL through the public NGINX host.
2. NGINX sends an internal `GET /verify` subrequest to this sidecar.
3. The sidecar verifies the original method, URI, host, scheme, credential
   scope, expiry, allowed host, allowed prefix, and HMAC signature.
4. NGINX allows the original request only when the subrequest returns `204`.

The `/verify` endpoint should be reachable only from NGINX or trusted local
infrastructure. Do not expose it directly to the public internet.

## Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/verify` | `GET` | Internal NGINX `auth_request` verifier. |
| `/healthz` | `GET` | Liveness probe. |
| `/readyz` | `GET` | Readiness probe. |
| `/metrics` | `GET` | Prometheus-style metrics. Expose only on trusted networks. |

`GET /verify` reads these NGINX-provided headers:

| Header | Required | Description |
| --- | --- | --- |
| `X-Original-Method` | Yes | Original client method. MVP accepts only `GET` and `HEAD`. |
| `X-Original-URI` | Yes | Original request URI, including path and query string. |
| `X-Original-Host` | Yes | Public host used by the client and included in the signed canonical `host` header. |
| `X-Original-Scheme` | No | Public scheme, usually `https`; useful when reconstructing the external URL. |

Responses:

| Status | Meaning |
| --- | --- |
| `204 No Content` | Signature and policy checks passed. NGINX should allow the original request. |
| `403 Forbidden` | Request is missing, unsupported, expired, outside policy, or has an invalid signature. |
| `500 Internal Server Error` | Service-side failure such as invalid runtime configuration. |

## Supported MVP

The initial verifier intentionally supports a narrow SigV4 subset:

- Presigned query authentication only.
- Original methods `GET` and `HEAD` only.
- Algorithm `AWS4-HMAC-SHA256`.
- Credential scope service `s3`.
- Credential scope terminal value `aws4_request`.
- `X-Amz-SignedHeaders=host` only.
- Canonical payload hash `UNSIGNED-PAYLOAD`.
- Path-style S3/MinIO URLs, where the bucket is part of the path, for example
  `/my-bucket/public/report.pdf`.

Anything outside this envelope should be denied with `403`.

## Offline Verification Model

Verification must stay independent of the origin:

- No MinIO, S3, or origin-server calls during verification.
- No reads from the original request body.
- Credentials loaded into memory from environment variables, secret files, or
  YAML config.
- Fail closed when config is missing, a credential is disabled, the request is
  outside an allowed host/prefix/method, or signature reconstruction is not
  possible.

The sidecar verifies that the signed public host matches the host seen by
NGINX. If a URL was presigned for `minio:9000` but the client requests
`https://assets.example.com/...`, verification should fail because the
canonical `host` value is different. Generate presigned URLs for the same
public host that clients will use.

## Configuration

The service should support configuration from a YAML file and environment
variables. `CONFIG_PATH` points to YAML config; environment variables are useful
for single-credential deployments and secret injection.

| Environment variable | Purpose |
| --- | --- |
| `NETWORK` / `SIGV4_NETWORK` | Listener network: `tcp` or `unix`. Defaults to `tcp`. |
| `ADDR` | Listen address, for example `:8080`. |
| `CONFIG_PATH` | Path to the YAML config file. |
| `SIGV4_SOCKET_MODE` | Unix socket permissions, for example `660`. Used only when `NETWORK=unix`. |
| `SIGV4_ACCESS_KEY` | Access key for a simple single-credential setup. |
| `SIGV4_SECRET_KEY` | Secret key value for the single credential. |
| `SIGV4_SECRET_KEY_FILE` | File containing the secret key when the value should not be in the environment. |
| `SIGV4_ALLOWED_HOSTS` | Comma-separated public hosts accepted for the credential, for example `assets.example.com,cdn.example.com`. |
| `SIGV4_ALLOWED_PREFIXES` | Comma-separated path prefixes accepted for the credential. For path-style URLs, include the bucket segment. |
| `SIGV4_MAX_EXPIRES` | Maximum `X-Amz-Expires` accepted for the credential, such as `15m` or `168h`. |
| `SIGV4_DEFAULT_MAX_EXPIRES` | Default max expiry used when a credential does not specify one. |
| `SIGV4_CLOCK_SKEW` | Allowed clock skew around `X-Amz-Date`, for example `5m`. |
| `SIGV4_LOG_ALL_REQUESTS` | Log every verification attempt when set to a truthy value. |

Example YAML configuration:

```yaml
server:
  network: "tcp"
  listen: ":8080"
  # For Unix sockets:
  # network: "unix"
  # listen: "/run/sigv4-verify/sigv4-verify.sock"
  # socket_mode: "660"

verification:
  allowed_clock_skew: 5m
  default_max_expires: 15m

credentials:
  - access_key: "minio-public-reader"
    secret_key_env: "SIGV4_SECRET_KEY"
    # Use secret_key_file instead of secret_key_env when mounting secrets.
    # secret_key_file: "/run/secrets/minio-public-reader"
    enabled: true
    max_expires: 10m
    allowed_hosts:
      - "assets.example.com"
    allowed_methods:
      - GET
      - HEAD
    allowed_prefixes:
      - "/my-bucket/public/"
      - "/my-bucket/reports/"
```

See [examples/config.yaml](examples/config.yaml)
for a complete example.

## Unix Socket Transport

When NGINX and the verifier run in the same container, pod, or host, the
sidecar can listen on a Unix domain socket instead of a TCP port. This still
uses HTTP, but avoids opening a TCP listener and lets filesystem permissions
define the local trust boundary.

Verifier config:

```yaml
server:
  network: "unix"
  listen: "/run/sigv4-verify/sigv4-verify.sock"
  socket_mode: "660"
```

Equivalent environment setup:

```sh
NETWORK=unix
ADDR=/run/sigv4-verify/sigv4-verify.sock
SIGV4_SOCKET_MODE=660
```

NGINX can connect through an upstream:

```nginx
upstream sigv4_verify {
    server unix:/run/sigv4-verify/sigv4-verify.sock;
    keepalive 128;
}

location = /_verify_sigv4 {
    internal;
    proxy_pass http://sigv4_verify/verify;
}
```

The verifier removes stale socket files on startup. If another process is
actively accepting connections on the configured socket path, startup fails.

## NGINX Integration

Use `auth_request` to call the verifier before proxying the original request.
The auth subrequest must not forward a request body, and it must pass the
original method, URI, host, and scheme to the sidecar.

Important details:

- Set `X-Original-URI` to `$request_uri` so the verifier receives the original
  query string containing the SigV4 parameters.
- Force the auth upstream method to `GET`; pass the client method separately in
  `X-Original-Method`.
- Set `X-Original-Host` to the public host used by the client.
- Keep the verifier upstream internal, with keepalive and short timeouts.
- If caching object responses, include the complete signed request URI in the
  cache key with `proxy_cache_key "$scheme://$host$request_uri";`. Signed S3
  query parameters can select a different object version, response body, or
  response metadata for the same path, so those requests must not share a cache
  entry. This also means refreshed presigned URLs create separate cache entries.
- Preserve signed public host alignment. Presign URLs for `assets.example.com`
  when clients request `assets.example.com`; do not presign for `minio:9000`
  and then serve the same URL through another public host.

See [examples/nginx.conf](examples/nginx.conf)
for a complete NGINX example.

## End-to-End POC

There is an opt-in Docker POC that exercises the full path: a sidecar
container, an ephemeral NGINX container using `auth_request`, real
MinIO-compatible presigned URLs generated in Go, and protected content served
only after verification. The POC runs both sidecar transports: Unix socket and
TCP.

Run it with Docker available:

```sh
go test -tags=e2e ./e2e -run 'TestNginx.*E2E' -count=1 -v
```

The test covers valid `GET`/`HEAD`, origin misses after valid auth, encoded
paths and response query parameters, method binding, missing/tampered/expired
SigV4 parameters, host mismatch, prefix policy denial, private auth endpoint
behavior, and fail-closed behavior when the sidecar is unavailable.

See [docs/poc-e2e.md](docs/poc-e2e.md)
for the full POC flow and manual presign helper usage.

## Rust NGINX Module

A native Rust NGINX module, `ngx_http_sigv4_verify_module`, verifies the same
presigned URLs directly in the NGINX access phase, removing the sidecar
transport hop (`auth_request`, HTTP/TCP/Unix socket) while keeping the verifier
core memory-safe. It uses the same stable reason strings as the sidecar and adds
NGINX variables (`$sigv4_verify_result`, `$sigv4_verify_reason`,
`$sigv4_verify_access_key_hash`, `$sigv4_verify_latency_us`) plus shadow and
enforce modes.

Status: production evaluation. Roll it out through shadow mode before enforcing,
and keep the Go sidecar as the rollback path. The main semantic difference is
that the module requires explicit per-credential policy lists (or explicit
`allow_any_*` flags), where the sidecar treats an omitted list as allow-all.

See [docs/rust-nginx-module.md](docs/rust-nginx-module.md) for the operator
guide (build, directives, variables, rollout, security, rollback) and
[docs/rust-nginx-module-requirements.md](docs/rust-nginx-module-requirements.md)
for requirements and acceptance criteria.

## Development

Use Go 1.26.4. The service implementation is intentionally dependency
light: the `cmd/sigv4-verify` binary imports only the Go standard library and
this repository's internal packages. The MinIO Go SDK is kept as a test-only
dependency for the sidecar so the verifier is checked against real MinIO
presigned `GET` and `HEAD` URL output in the default `go test ./...` suite.
The optional `cmd/presign-url` POC helper also uses the MinIO SDK.

Common checks:

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/sigv4-verify
go test ./internal/verifier -run '^$' -bench BenchmarkVerifierVerifyValid -benchmem
go test -tags=e2e ./e2e -run 'TestNginx.*E2E' -count=1 -v
```
