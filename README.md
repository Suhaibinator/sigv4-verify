# sigv4-verify

`sigv4-verify` is a native Rust NGINX module that verifies S3/MinIO SigV4
presigned `GET` and `HEAD` URLs directly in the NGINX access phase. Verification
is offline and in-process: there is no origin call, request-body read, or
authorization sidecar hop.

The module reconstructs the SigV4 canonical request from NGINX's raw request
URI and public host, enforces per-credential host/method/path/expiry policy, and
fails closed when a request or configuration is invalid. The verifier and
configuration logic live in safe Rust; `unsafe` code is limited to the NGINX
FFI boundary.

## Supported envelope

- Query-string presigned authentication only.
- Original methods `GET` and `HEAD` only.
- Algorithm `AWS4-HMAC-SHA256`.
- Credential scope service `s3` and terminal value `aws4_request`.
- `X-Amz-SignedHeaders=host` only.
- Canonical payload hash `UNSIGNED-PAYLOAD`.
- Path-style S3/MinIO URLs, with the bucket in the path.
- Per-credential host, method, path-prefix, and maximum-expiry policy.

Anything outside this envelope is denied with `403`. Internal module failures
return `500`; verification-disabled locations use normal NGINX handling.

## Quick start

Build the pinned NGINX image and Rust module:

```sh
docker build -f build/nginx-module/Dockerfile -t sigv4-verify-nginx:1.28.0 .
```

Create a secret file and an NGINX configuration based on
[`examples/nginx.conf`](examples/nginx.conf), then run:

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/examples/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/secret:/run/secrets/sigv4:ro" \
  sigv4-verify-nginx:1.28.0
```

Native NGINX modules are ABI-sensitive. Build the module against the same NGINX
version and compatible configure options as the runtime. The Docker image pins
those together; see the [image documentation](build/nginx-module/README.md) for
details and multi-architecture builds.

## Configuration

The module is configured entirely through NGINX directives:

```nginx
load_module /etc/nginx/modules/ngx_http_sigv4_verify_module.so;

events {}

http {
    sigv4_verify_clock_skew 5m;
    sigv4_verify_default_max_expires 15m;

    sigv4_verify_credential minio_public_reader
        secret_key_file=/run/secrets/sigv4
        enabled=on
        max_expires=10m
        allowed_host=assets.example.com
        allowed_method=GET
        allowed_method=HEAD
        allowed_prefix=/my-bucket/public/;

    server {
        listen 8080;
        server_name assets.example.com;

        location / {
            sigv4_verify on;
            proxy_pass http://minio_origin;
            proxy_cache_key "$scheme://$host$request_uri";
        }
    }
}
```

Every credential must explicitly configure each policy dimension with a list
or its corresponding `allow_any_*` / `allow_default_methods` flag. Invalid
configuration fails `nginx -t` rather than widening access.

The module also supports `shadow` mode and exposes
`$sigv4_verify_result`, `$sigv4_verify_reason`,
`$sigv4_verify_access_key_hash`, and `$sigv4_verify_latency_us` for NGINX
logging and metrics pipelines. See the full [operator guide](docs/rust-nginx-module.md).

## Development

The repository is a Rust workspace containing:

- `rust/sigv4-verifier`: safe, byte-oriented SigV4 verifier core.
- `rust/module-config`: safe NGINX directive parsing and validation.
- `rust/nginx-module`: dynamic-module FFI glue.

Run the standard checks:

```sh
cargo fmt --all -- --check
cargo clippy -p sigv4-verifier -p sigv4-module-config --locked --all-targets -- -D warnings
cargo test -p sigv4-verifier -p sigv4-module-config --locked
cargo build --release -p ngx-http-sigv4-verify --locked --features vendored
```

The verifier also includes Criterion benchmarks, a fixed signed regression
corpus, and `cargo-fuzz` targets. Performance methodology and historical
measurements are documented in [docs/benchmarks.md](docs/benchmarks.md).

## Security

- Keep secret keys in files readable only by the NGINX master and reference
  them with `secret_key_file=`.
- Preserve the complete signed query in cache identity with
  `proxy_cache_key "$scheme://$host$request_uri"`.
- Presign URLs for the same public host clients use.
- Roll out with `sigv4_verify shadow;`, observe decisions, then enable
  enforcement with `sigv4_verify on;`.
- Build and load the module only against an ABI-compatible NGINX release.

See [docs/security-scan/threat_model.md](docs/security-scan/threat_model.md) for
the repository threat model.
