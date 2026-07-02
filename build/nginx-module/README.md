# NGINX SigV4 verify module — Docker image

This directory packages the native Rust NGINX module
(`ngx_http_sigv4_verify_module`) into a runnable Docker image: the official
NGINX runtime plus the compiled module `.so`.

## ABI compatibility constraint (read this first)

Native NGINX modules are **ABI-sensitive**. A module `.so` is only loadable by
an `nginx` binary that was built from the **same source version** with a
**compatible configure option set**. Loading a mismatched module fails at
startup with an error such as:

```
nginx: [emerg] module "…ngx_http_sigv4_verify_module.so" version 1028003
instead of 1028000 in …
```

To keep this safe and explicit, the image:

- Builds the module against the exact pinned NGINX source
  (`ARG NGINX_VERSION`, default `1.28.0`) configured with **`--with-compat`**.
- Ships the module inside the official **`nginx:${NGINX_VERSION}`** image, which
  is itself built with `--with-compat`.

`NGINX_VERSION` **must** match the runtime image tag exactly. `--with-compat`
is what makes a module built out-of-tree loadable by the distributed nginx
binary; both sides must have it. If you bump `NGINX_VERSION`, update
`NGINX_SHA256` to match the new tarball (see "Pinning" below).

## What gets pinned

| Thing | Pin | Where |
| --- | --- | --- |
| NGINX version | `1.28.0` | `ARG NGINX_VERSION` + runtime `FROM nginx:${NGINX_VERSION}` |
| NGINX source checksum | `sha256:c6b5c6b0…ff76a` | `ARG NGINX_SHA256`, verified with `sha256sum -c` |
| Rust toolchain | `1.96.0` | `ARG RUST_IMAGE=rust:1.96.0-slim-bookworm` and `rust-toolchain.toml` |
| Crate versions | `Cargo.lock` | copied into the build stage; `cargo build` uses it |
| Base OS | Debian `bookworm` | both stages, so the module's glibc matches the runtime |
| Target architecture | build host arch | native build, no `--target`; works on `linux/amd64` and `linux/arm64` |

The crypto stack is pinned transitively through `Cargo.lock`: the
`sigv4-verifier` crate uses `ring` (HMAC-SHA256, SHA-256) and `subtle`
(constant-time compare). `ring` compiles a small amount of C/assembly, which is
why the build stage installs a C compiler.

## Build

From the repository root (the build context is the repo root because the
Dockerfile copies `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, and
`rust/`):

```sh
docker build -f build/nginx-module/Dockerfile -t sigv4-verify-nginx:1.28.0 .
```

Cross/multi-arch (module is arch-agnostic in the Dockerfile; buildx picks the
platform):

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -f build/nginx-module/Dockerfile -t sigv4-verify-nginx:1.28.0 .
```

The build downloads the NGINX source tarball and the Rust crate dependencies,
then compiles the module. Expect a few minutes on a cold cache.

## Run

The image inherits the official NGINX entrypoint, so it runs like stock nginx.
Provide your own `nginx.conf` that `load_module`s the module and a secret file:

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/secret:/run/secrets/sigv4:ro" \
  sigv4-verify-nginx:1.28.0
```

Minimal `nginx.conf`:

```nginx
load_module /etc/nginx/modules/ngx_http_sigv4_verify_module.so;

events {}

http {
    sigv4_verify_clock_skew 5m;
    sigv4_verify_default_max_expires 15m;
    sigv4_verify_methods GET HEAD;

    sigv4_verify_credential AKIA...
        secret_key_file=/run/secrets/sigv4
        allowed_host=assets.example.com
        allowed_method=GET allowed_method=HEAD
        allowed_prefix=/my-bucket/public/;

    server {
        listen 8080;
        server_name assets.example.com;
        location / {
            sigv4_verify on;          # or `shadow` / `off`
            proxy_pass http://minio_origin;
        }
    }
}
```

Validate a config without starting nginx:

```sh
docker run --rm -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
  sigv4-verify-nginx:1.28.0 nginx -t
```

Invalid module configuration fails `nginx -t` (fail-closed at config time),
so it never fails open at request time.

## Directives (quick reference)

- `sigv4_verify on|off|shadow;` — `http`/`server`/`location`.
- `sigv4_verify_clock_skew <dur>;` — `http`.
- `sigv4_verify_default_max_expires <dur>;` — `http`.
- `sigv4_verify_methods GET HEAD;` — `http`.
- `sigv4_verify_log_denies on|off;` (default `on`) — `http`.
- `sigv4_verify_log_all on|off;` (default `off`) — `http`.
- `sigv4_verify_credential <access-key> secret_key_file=… | secret_key=… [enabled=on|off] [max_expires=<dur>] allowed_host=…|allow_any_host allowed_method=…|allow_default_methods allowed_prefix=…|allow_any_prefix;` — `http`, repeatable.

Policy lists are mandatory or must be explicitly opted out with an
`allow_any_*` / `allow_default_methods` flag; a mistyped list cannot silently
become "allow everything".

Observability variables: `$sigv4_verify_result` (`allow|deny|error|off|shadow`),
`$sigv4_verify_reason`, `$sigv4_verify_access_key_hash`,
`$sigv4_verify_latency_us`.

## Tests

The e2e suite (`e2e/nginx_module_test.go`, build tag `e2e`) builds this image
and exercises the enforce/shadow/off matrix, `nginx -t` validation, and a
credential reload:

```sh
go test -tags e2e -run TestNginxModuleE2E -timeout 30m ./e2e/
```
