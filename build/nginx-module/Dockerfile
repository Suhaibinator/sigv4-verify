# syntax=docker/dockerfile:1

# Multi-stage build for the ngx_http_sigv4_verify NGINX dynamic module.
#
# ABI constraint (read build/nginx-module/README.md): a native NGINX module is
# only loadable by an nginx binary built from the SAME source version with a
# compatible configure option set. We build the module against nginx
# ${NGINX_VERSION} configured with --with-compat and ship it in the official
# nginx:${NGINX_VERSION} image, which is also built --with-compat. NGINX_VERSION
# must match the runtime image tag exactly.

ARG NGINX_VERSION=1.28.0
# Debian bookworm on both stages so the glibc the module links against matches
# the runtime image (nginx:1.28.0 is debian:bookworm-slim based).
ARG RUST_IMAGE=rust:1.96.0-slim-bookworm

# ---------------------------------------------------------------------------
# Stage 1: build the module .so
# ---------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS builder

ARG NGINX_VERSION
# sha256 of https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
ARG NGINX_SHA256=c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a

# Build dependencies:
#   make, gcc              - nginx ./configure + module compilation
#   clang, libclang-dev    - libclang for bindgen (ngx crate generates bindings)
#   libpcre2-dev           - nginx rewrite/regex (required by ./configure)
#   zlib1g-dev             - nginx gzip (required by ./configure)
#   libssl-dev             - present for parity; harmless for --with-compat
#   curl, ca-certificates  - fetch the pinned nginx source tarball
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        make \
        gcc \
        clang \
        libclang-dev \
        libpcre2-dev \
        zlib1g-dev \
        libssl-dev \
        curl \
        ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# Download, verify, extract, and ./configure the pinned nginx source. The
# module is linked against these headers; --with-compat produces a module that
# loads into any --with-compat nginx of the same version.
RUN set -eux; \
    curl -fsSL -o /tmp/nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"; \
    echo "${NGINX_SHA256}  /tmp/nginx.tar.gz" | sha256sum -c -; \
    mkdir -p /nginx; \
    tar -xzf /tmp/nginx.tar.gz -C /nginx --strip-components=1; \
    rm /tmp/nginx.tar.gz; \
    cd /nginx; \
    ./configure --with-compat

ENV NGINX_SOURCE_DIR=/nginx

WORKDIR /build

# Pin the Rust toolchain exactly as the repo requires (rust-toolchain.toml
# channel 1.96.0). Materialize it + its components in a cached layer before any
# sources change. The explicit version matches the toolchain file; keep them in
# sync.
COPY rust-toolchain.toml ./
RUN set -eux; \
    rustup default 1.96.0; \
    rustup component add rustfmt clippy

# Copy the workspace manifests and the Rust crates the module needs.
COPY Cargo.toml Cargo.lock ./
COPY rust ./rust

# Build only the module cdylib against the configured nginx source tree.
# No --target: this compiles for the build platform (works on amd64 and arm64).
RUN --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    set -eux; \
    cargo build --release -p ngx-http-sigv4-verify; \
    mkdir -p /out; \
    cp target/release/libngx_http_sigv4_verify_module.so \
       /out/ngx_http_sigv4_verify_module.so

# ---------------------------------------------------------------------------
# Stage 2: runtime = official nginx + the module
# ---------------------------------------------------------------------------
FROM nginx:${NGINX_VERSION}

# The runtime nginx is built --with-compat (official image), so this module
# built against the same version loads cleanly via `load_module`.
COPY --from=builder /out/ngx_http_sigv4_verify_module.so \
     /etc/nginx/modules/ngx_http_sigv4_verify_module.so

# Inherit the base image ENTRYPOINT/CMD so the container runs nginx normally.
