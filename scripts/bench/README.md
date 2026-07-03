# NGINX e2e benchmark harness

These scripts drive an HTTP load test against a running NGINX endpoint and
report latency percentiles and throughput. They are the e2e counterpart to the
core-only criterion benchmark in `rust/sigv4-verifier/benches/verify.rs`.

The harness only generates traffic and measures a running endpoint. It does not
stand up NGINX, the Rust module, or the Go sidecar for you — bring your own
endpoint (see `e2e/nginx_unix_socket_test.go` for how the sidecar/NGINX
containers are wired together, and reuse that topology for benchmarking).

## Files

- `gen-urls.sh` — produce a file of request lines (`METHOD /path?query`) from
  `./cmd/presign-url`, mixing valid and signature-tampered URLs.
- `multi-url.lua` — wrk script that replays a request-line file round-robin and
  prints p50/p90/p99/p99.9 latency.
- `bench.sh` — run wrk (primary) or oha (fallback) against a base URL and a
  request-line file.
- `e2e-linux.sh` — self-contained Linux reproducer: builds the module + Go
  sidecar images, stands up the baseline/module/sidecar stacks on a private
  docker network, and drives them in-network with `cmd/loadgen` (mixed corpus
  from `cmd/gen-barrage`), reporting RPS, latency percentiles, cgroup CPU/RSS,
  and sidecar GC cycles. Reproduces the "Results (Linux, NGINX e2e …)" tables in
  `docs/benchmarks.md`. Requires a cgroup-v2 host with Docker + Go.

## The benchmark matrix

The requirements doc calls for these cells. Stand each server config up
separately, point the harness at it, and compare:

| Target                                | How to stand it up |
| ------------------------------------- | ------------------ |
| Rust module, static-file cache hits   | NGINX + module, `root`/`try_files` serving a cached static origin |
| Rust module, proxy + `proxy_cache`    | NGINX + module, `proxy_pass` to an origin with `proxy_cache` warm |
| Go sidecar over unix socket           | NGINX `auth_request` → sidecar on a unix socket (baseline) |
| Go sidecar over TCP                   | NGINX `auth_request` → sidecar on TCP (baseline) |

Run each target against the same traffic profiles:

- **Mixed valid/invalid** — `gen-urls.sh --invalid-ratio 0.2` (default).
- **High-cardinality query strings** — see the note below; the valid-signature
  form of this is measured by the core criterion bench
  (`valid_get_high_cardinality_query`).
- **Long paths** — `gen-urls.sh --object "$(long key near the URI limit)"`.
- **Reload churn under load** — run `bench.sh` while issuing `nginx -s reload`
  (or the module's credential swap) on an interval in another shell.

Report per the requirements: p50/p90/p99/p999 latency, RPS per worker, CPU per
request, worker RSS, and the deny-reason distribution. wrk gives you the
percentiles and RPS directly; capture CPU/RSS with `pidstat`/`docker stats` on
the NGINX worker, and the deny-reason distribution from the module's NGINX log
variables (or the sidecar's `/metrics`).

### Acceptance targets

From the requirements doc, the native module must beat the Go sidecar over a
unix socket by **≥30% at p50** and **≥20% at p99** in the same NGINX e2e setup,
with no throughput regression on cached hits and stable memory under load.

## Usage

Generate a mixed corpus (20% tampered signatures by default):

```sh
scripts/bench/gen-urls.sh \
  -n 500 -o /tmp/urls.txt \
  --host assets.example.test \
  --access-key e2e-access-key --secret-key e2e-secret-key \
  --bucket my-bucket --object public/file.txt \
  --invalid-ratio 0.2
```

Run the load test (wrk primary):

```sh
scripts/bench/bench.sh \
  --base http://127.0.0.1:8080 \
  --urls /tmp/urls.txt \
  --host assets.example.test \
  --duration 30s --connections 64 --threads 4
```

## High-cardinality note

`cmd/presign-url` only signs the SigV4 parameters (plus optional
`response-content-*`), so it cannot emit *valid* URLs carrying 20 extra
high-cardinality query params: those params would have to be part of the signed
canonical query. The core criterion bench covers the valid high-cardinality
case directly. For the e2e path, use high-cardinality corpora to exercise the
deny path, or extend the generator to sign extra params if you need valid
high-cardinality e2e traffic.

## Installing a load generator

- wrk: <https://github.com/wg/wrk> (recommended; supports the lua replay and
  p99.9).
- oha: <https://github.com/hatoo/oha> (single-URL fallback only).
