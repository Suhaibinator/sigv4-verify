# Benchmarks

This document covers how to run the benchmarks for the Rust SigV4 verifier core
and the NGINX module e2e path, the acceptance targets from
`docs/rust-nginx-module-requirements.md`, and the core-verifier results measured
so far.

## What is benchmarked

Two layers, matching the requirements doc:

1. **Core verifier (criterion).** Measures `Verifier::verify()` in isolation on
   pre-generated URIs, with no NGINX, no I/O, and no network. This isolates the
   Rust hot path and is where allocations-per-request are reported.
2. **NGINX module e2e (load harness).** Drives a running NGINX endpoint with a
   mixed valid/invalid corpus and reports wire latency percentiles and
   throughput. This is where the module is compared against the Go sidecar.

## Running the core benchmark

```sh
cargo bench -p sigv4-verifier
```

The harness is `rust/sigv4-verifier/benches/verify.rs` (criterion,
`harness = false`). It builds each input once, outside the timed loop, and warms
the per-worker signing-key cache before timing the valid path. Cases:

- `valid_get_warm_cache` — valid GET, signing-key cache hit.
- `valid_get_high_cardinality_query` — valid GET plus 20 extra high-cardinality
  query params.
- `valid_get_long_path` — valid GET with a ~2KB path.
- `deny_signature_mismatch` — tampered signature.
- `deny_missing_params` — a required SigV4 param removed.
- `deny_invalid_path_traversal` — `..` traversal in the path.
- `deny_expired` — expired presign (verified past its expiry).

A fixed `SystemTime` is used so results are stable across runs.

## Running the allocation report

```sh
cargo run -p sigv4-verifier --release --example alloc_report
```

`examples/alloc_report.rs` installs a counting global allocator (an `AtomicU64`
pair wrapping `System`, defined in the example — no new runtime dependencies)
and prints allocations and bytes per `verify()` call, averaged over 10k
iterations after warming the cache, for the valid, signature-mismatch, and
missing-params scenarios.

## Running the e2e harness

The load harness lives in `scripts/bench/` and measures a *running* endpoint; it
does not stand up NGINX or the sidecar for you. See `scripts/bench/README.md`
for the full matrix (Rust module static + proxy_cache, Go sidecar unix socket +
TCP, mixed traffic, high-cardinality, long paths, reload churn) and reuse the
container topology in `e2e/nginx_unix_socket_test.go`.

```sh
# 1. Generate a mixed valid/invalid corpus.
scripts/bench/gen-urls.sh -n 500 -o /tmp/urls.txt \
  --host assets.example.test --bucket my-bucket --object public/file.txt \
  --invalid-ratio 0.2

# 2. Load-test a running endpoint (wrk primary, oha fallback).
scripts/bench/bench.sh --base http://127.0.0.1:8080 --urls /tmp/urls.txt \
  --host assets.example.test --duration 30s --connections 64 --threads 4
```

## Acceptance targets

From `docs/rust-nginx-module-requirements.md` (Performance Requirements). These
apply to the **NGINX e2e** comparison, not the core-only bench:

- Native module p50 verification latency **≥30% lower** than the Go sidecar over
  a unix socket in the same NGINX e2e setup.
- Native module p99 verification latency **≥20% lower** than the Go sidecar over
  a unix socket in the same NGINX e2e setup.
- No measurable throughput regression for cached object hits with verification
  enabled.
- Stable memory usage under sustained load and reload churn.

Report p50/p90/p99/p999 latency, RPS per worker, CPU per request, allocations
per request (core bench), worker RSS, and the error/deny-reason distribution.

## Results (Apple Silicon, core-only)

Core-verifier-only. These are **not** the NGINX e2e numbers and are not directly
comparable to the Go sidecar — the acceptance targets above are defined against
the NGINX e2e path, which is measured on Linux (TBD). They characterize the Rust
hot path and its per-request allocations.

- Machine: Apple M4 Max (16 cores), macOS 26.5.2.
- Toolchain: rustc 1.96.0, `--release`/bench profile (`panic = "abort"`).
- criterion 0.5, 100 samples/case; the value shown is criterion's point
  estimate (median of the reported `[lo est hi]` interval).

### Latency per `verify()` call

| Case                                | Latency (point estimate) | Before alloc-reduction |
| ----------------------------------- | ------------------------ | ---------------------- |
| `valid_get_warm_cache`              | 1.20 µs                  | 2.82 µs                |
| `valid_get_high_cardinality_query`  | 2.89 µs                  | 7.12 µs                |
| `valid_get_long_path` (~2KB path)   | 6.04 µs                  | 10.70 µs               |
| `deny_signature_mismatch`           | 1.22 µs                  | 2.77 µs                |
| `deny_missing_params`               | 0.74 µs                  | 1.94 µs                |
| `deny_invalid_path_traversal`       | 0.13 µs                  | 0.24 µs                |
| `deny_expired`                      | 0.82 µs                  | 2.68 µs                |

The "before" column is the same benchmark prior to the borrow-based parser
rework (Cow query components, borrowed credential scope/date, pre-sized
canonical buffers) that cut allocations from ~47 to ~9 per call. Both columns
were measured on the same machine/toolchain; treat the ~2× improvement as
approximate since the runs were weeks apart.

### Allocations per `verify()` call

| Case                       | Allocations | Bytes  | Before rework    |
| -------------------------- | ----------- | ------ | ---------------- |
| `valid_get_warm_cache`     | 9           | 1060   | 47 / 1755 B      |
| `deny_signature_mismatch`  | 9           | 1074   | 47 / 1769 B      |
| `deny_missing_params`      | 7           | 560    | 39 / 1207 B      |

The parse layer now borrows from the raw URI instead of copying: query
components are `Cow<[u8]>` (owned only when a component actually needs
percent-recoding), the credential scope and `X-Amz-Date` are fully borrowed,
method/host normalization borrows when the input is already canonical, and the
canonical query string is built in one pre-sized buffer with an unstable sort
(no auxiliary allocation). What remains on the success path is essentially
irreducible without changing the public API: the owned result `path`, the
params vector, the slow-path re-encode of the credential value (it contains
`%2F`), the canonical-request and string-to-sign scratch buffers, and the
`String` clones in the returned `VerifyResult`.

### Notes

- Times were collected with other build jobs quiescent; a first noisy run under
  concurrent compilation showed ~15–25% wider confidence intervals, so treat
  these as order-of-magnitude, not sub-100ns-precise.

## Results (Docker on Apple Silicon, NGINX e2e, first pass)

Full NGINX-path comparison, re-measured 2026-07-02 with the module image
rebuilt from the alloc-reduced verifier (the original 2026-07-01 pass produced
the same stack-to-stack deltas within noise, as expected — the e2e numbers are
dominated by wire latency, not the µs-scale core path). Topology
mirrors the e2e tests: the module image (`build/nginx-module/Dockerfile`,
nginx 1.28.0 + module, enforce mode) versus the Go sidecar over a unix socket
behind `auth_request` (official `nginx:1.28.0`, `keepalive 16` upstream),
versus the same nginx serving the same file with no verification. One nginx
worker each, same static origin fixture, identical valid presigned GET
(warm signing-key cache), `hey -z 20s -c 50` after a 5s warmup, all responses
200.

| Stack                        | RPS   | p50    | p90    | p99     |
| ---------------------------- | ----- | ------ | ------ | ------- |
| Baseline (no verification)   | 7488  | 6.7 ms | 7.0 ms | 7.9 ms  |
| Rust module (in-process)     | 7275  | 6.8 ms | 7.2 ms | 8.1 ms  |
| Go sidecar (unix socket)     | 6533  | 7.6 ms | 8.3 ms | 9.5 ms  |

Verification overhead relative to the unverified baseline:

| Stack       | p50 overhead | p90 overhead | p99 overhead | Throughput cost |
| ----------- | ------------ | ------------ | ------------ | --------------- |
| Rust module | +0.1 ms      | +0.2 ms      | +0.2 ms      | −2.8%           |
| Go sidecar  | +0.9 ms      | +1.3 ms      | +1.6 ms      | −12.8%          |

Against the acceptance targets (verification latency vs the sidecar): the
module's added verification latency is ~85–90% lower than the sidecar's at
both p50 (+0.1 ms vs +0.9 ms) and p99 (+0.2 ms vs +1.6 ms) — comfortably past
the ≥30%/≥20% reduction targets in this setup.

Caveats: run under the Docker Desktop VM on macOS (its port forwarding
dominates the ~6.7 ms absolute baseline), single hot URL, 20 s windows.
Production sign-off still requires the same matrix on Linux `amd64`/`arm64`
bare Docker, plus the reload-churn scenario from `scripts/bench/`.

## Results (Docker on Apple Silicon, mixed adversarial barrage, in-network)

Re-measured 2026-07-02 with the alloc-reduced module image (originally run
2026-07-01 with the same topology and deltas within noise).
Sustained 60 s mixed-load runs with the load generator (wrk, alpine container,
`-t4 -c64`, `scripts/bench/multi-url.lua`) on the same Docker network as the
stacks, eliminating host port-forwarding. Corpus: 500 shuffled request lines —
55% valid GET (unique response-content-* params, warm signing-key cache), 10%
high-cardinality valid, 5% valid long path (~1 KB key, origin 404), 10%
tampered signature, 5% expired, 5% unknown access key, 5% prefix denial, 3%
missing SigV4 param, 2% POST. Expected reject ratio 35%; both verified stacks
returned exactly 35.0% non-2xx, confirming identical decisions under load.
Sidecar ran with `GODEBUG=gctrace=1`.

| Stack                      | RPS    | p50     | p90     | p99     | p99.9   | CPU (cores) | RSS      |
| -------------------------- | ------ | ------- | ------- | ------- | ------- | ----------- | -------- |
| Baseline (no verification) | 11,319 | 5.63 ms | 5.87 ms | 6.73 ms | 27.0 ms | 0.29        | ~3.7 MiB |
| Rust module (in-process)   | 15,607 | 4.10 ms | 4.51 ms | 5.25 ms | 9.6 ms  | 0.33        | 3.7 MiB  |
| Go sidecar (unix socket)   | 11,720 | 5.42 ms | 6.17 ms | 7.41 ms | 10.8 ms | 0.38 + 0.50 | 4.5 + 17 MiB |

(The unverified baseline returns 7.0% non-2xx on this corpus — the 5% long-path
404s and 2% POST 405s — since it serves everything else without verification.)

Module vs sidecar (identical request outcomes, so directly comparable):

- **Throughput +33%** (15,607 vs 11,720 RPS) at lower CPU.
- **CPU per request ~3.6× lower**: ~21 µs·core vs ~75 µs·core (sidecar total
  includes both the nginx worker and the verifier process).
- **Latency lower across the whole distribution**: p50 −24%, p90 −27%,
  p99 −29%.
- On this mix the module stack also posts higher RPS than the *unverified*
  baseline — but that is **not** an apples-to-apples "verification is free" claim
  and should not be read as one. The baseline serves all 500 corpus URLs from
  the filesystem, whereas the module short-circuits 35% of them to small 403s in
  the access phase without touching the origin, so it is simply doing less work
  per request on this reject-heavy corpus. The honest same-work comparison is
  the all-200 single-URL first pass above, where the module is ~2.8% *slower*
  than baseline (its true verification overhead). The useful takeaway here is a
  DoS-resilience property: under garbage/attack traffic the module gets
  *cheaper* rather than more expensive, because rejects never reach the origin.
  (The two result sections also use different network topologies — host
  port-forwarding in the first pass vs in-network load generation here — so
  their absolute RPS/latency numbers are not directly comparable across
  sections; only the within-section stack-to-stack deltas are.)

### Go GC behavior under the barrage

The sidecar verifier ran **2,568 GC cycles in the 60 s window** — one every
~23 ms, i.e. roughly every 270 requests — because its live heap is ~1 MB
against a 4 MB goal and per-request allocations churn straight through it.
Each cycle on a ~1 MB live heap is individually cheap (concurrent mark plus
sub-ms STW phases), so the effect is a steady background tax rather than
dramatic tail spikes; we did not isolate the GC's exact CPU share from the
verifier process's 0.50 cores, so no per-cycle CPU figure is claimed here. Note
also that 2,568 cycles is a function of the *default* `GOGC=100` on a tiny live
heap: raising `GOGC` or setting `GOMEMLIMIT` would cut the cycle count
substantially, so this is a default-tuning artifact, not an inherent floor. The
Rust module has no GC; its ~9 allocations/request are deterministic heap
operations, visible in its flatter distribution (p99 only 1.3× p50).

Same caveats as above: Docker Desktop VM on macOS, one nginx worker per
stack; re-run on Linux for production sign-off. Regenerate the corpus and
rerun with `scripts/bench/gen-urls.sh` + `scripts/bench/bench.sh`.
