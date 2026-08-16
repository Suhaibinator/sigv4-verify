# NGINX benchmark harness

These scripts drive an HTTP load test against a running NGINX endpoint and
report latency percentiles and throughput. They complement the core Criterion
benchmark in `rust/sigv4-verifier/benches/verify.rs`.

The harness measures an endpoint; it does not start NGINX or create presigned
URLs. Build the module image, configure NGINX from `examples/nginx.conf`, and
generate presigned URLs with the S3/MinIO client used by your deployment.

## Input format

Create a UTF-8 request file with one method and request URI per line:

```text
GET /my-bucket/public/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&...
HEAD /my-bucket/public/report.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&...
```

The request URI must contain the signed path and complete query string, but not
the scheme or host. Include a stable mix of valid, expired, tampered, unknown-key,
and policy-denied requests when measuring adversarial traffic. Never commit live
credentials or unexpired production URLs.

## Benchmark matrix

Measure each topology against the same corpus:

| Target | Configuration |
| --- | --- |
| Unverified baseline | NGINX serving the same origin with verification disabled. |
| Rust module, static files | Module in enforce mode before `root`/`try_files`. |
| Rust module, proxy cache | Module in enforce mode before a warm `proxy_cache`. |

Use traffic profiles that cover a hot valid URL, mixed valid/invalid requests,
high-cardinality query strings, long paths near configured URI limits, and
reload churn. Record p50/p90/p99/p99.9 latency, requests per second per worker,
CPU per request, worker RSS, and deny-reason distribution.

## Usage

Run the load test with `wrk`:

```sh
scripts/bench/bench.sh \
  --base http://127.0.0.1:8080 \
  --urls /tmp/urls.txt \
  --host assets.example.test \
  --duration 30s --connections 64 --threads 4
```

`multi-url.lua` replays the request file round-robin and reports
p50/p90/p99/p99.9 latency. If `wrk` is unavailable, `bench.sh` can use `oha` as
a single-request fallback.

## Load generators

- wrk: <https://github.com/wg/wrk> (recommended for mixed-corpus replay).
- oha: <https://github.com/hatoo/oha> (single-request fallback only).
