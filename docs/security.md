# Security Review

**Not validated. Scan did not complete.** An automated repository-wide scan of
`sigv4-verify` at commit `a9ac6ddc5d5b256b3a47e6ca718802bee38a6839` (current `HEAD`)
produced 8 candidates, then stopped before executing any of them. Zero candidates were
reproduced by a test or harness; all 8 are static traces. Scope was repository-wide.
Treat this as a prioritized review backlog, not a vulnerability report.

## How to read this

Each row carries an **evidence strength**, and only three values are possible:

- **Demonstrated** — an executed test or harness actually reproduced the behavior.
- **Traced** — static reading with file:line evidence following source to sink; no execution.
- **Lead** — discovery-only, never validated; may not survive scrutiny.

Every candidate in this repo is **Traced**. Nothing here was run. Severities are the
scan's *suggested* values and were never finalized, because the step that owns final
severity never ran. These are candidates, not findings — do not cite this document as
proof they are real, or as proof they are not.

## Triage table

Ranked by what a maintainer should look at first — a blend of severity, blast radius,
and how cheaply the candidate can be confirmed or killed. Not ranked by candidate ID.

| # | Issue | Location | Severity | Evidence | Detail |
| --- | --- | --- | --- | --- | --- |
| 1 | The example NGINX config caches by path only, so two differently-signed requests for the same path can be served each other's cached response | `examples/nginx.conf:37,47,49,58` | medium | Traced | [FR006-CAND-1](security-candidates.md#fr006-cand-1--cache-identity-confusion) |
| 2 | A caller can make the sidecar do expensive sorting work before it checks any signature, by sending a query with many parameters | `internal/verifier/verifier.go:154`, `internal/verifier/canonical.go:163-168,224-235` | medium (pending measurement) | Traced | [FR004-CAND-1](security-candidates.md#fr004-cand-1--go-query-complexity) |
| 3 | **Same defect, instance 1 of 2 (Go sidecar):** a configured prefix without a trailing slash also allows sibling paths that merely start with the same letters (`/bucket/public` also permits `/bucket/publicity/...`) | `internal/config/config.go:500`, `internal/verifier/verifier.go:486-495` | medium | Traced | [FR003-CAND-1](security-candidates.md#fr003-cand-1--go-prefix-authorization) |
| 4 | **Same defect, instance 2 of 2 (Rust native module):** the same trailing-slash prefix gap in the independently deployed NGINX module | `rust/sigv4-verifier/src/lib.rs:471-479,1030-1035` | medium | Traced | [FR003-CAND-2](security-candidates.md#fr003-cand-2--rust-prefix-authorization) |
| 5 | A typo in a JSON config file is silently ignored, which can leave a credential's restriction list empty — and empty means allow-any | `internal/config/config.go:183-189,343-389`, `internal/verifier/verifier.go:470-495` | medium | Traced | [FR003-CAND-3](security-candidates.md#fr003-cand-3--json-policy-erasure) |
| 6 | **Same product decision, instance 1 of 2 (Rust native module):** denied requests write the requested object path into logs by default | `rust/nginx-module/src/lib.rs:69-71,635-647` | medium | Traced | [FR006-CAND-2](security-candidates.md#fr006-cand-2--native-denial-logs) |
| 7 | **Same product decision, instance 2 of 2 (Go sidecar):** denied requests write the requested object path into logs by default | `internal/config/config.go:216-218`, `internal/server/server.go:92-103` | medium | Traced | [PARENT-CAND-1](security-candidates.md#parent-cand-1--go-denial-logs) |
| 8 | The optional presign helper takes a signing secret as a command-line flag, where it lands in shell history and process lists | `cmd/presign-url/main.go:21,31,45-46` | low | Traced | [FR001-CAND-1](security-candidates.md#fr001-cand-1--cli-secret-argv) |

Rows 3 and 4 are one defect present in two independently deployed implementations, and
rows 6 and 7 likewise. They are listed separately because each ships and is configured
on its own, not because they are separate problems.

**The prefix candidates (3, 4) are not signature bypasses.** The SigV4 signature still
binds the full path. Exploiting them requires an attacker who *already holds a signing
capability* — a constrained credential or a presigning oracle — willing to sign the
adjacent path. They widen policy; they do not defeat the HMAC.

## Start here

1. **Fix `examples/nginx.conf` (row 1) now, regardless of validation.** It is a defect in
   documented example configuration, so it keeps propagating into real deployments for as
   long as it sits open; fixing it costs a config edit and removes that spread.
2. **Run the bounded benchmark for row 2.** Its own rubric contemplates suppression — if
   measured amplification under the default 8 KiB header limit is insufficient, the
   candidate is closed outright with measurements attached, removing it from the backlog
   for the cost of one benchmark.
3. **Decide the intended semantics of "path prefix" (rows 3 and 4) once.** If
   segment-boundary semantics are intended, both implementations need the fix plus a
   differential test; if lexical semantics are intended, document that and confirm the
   config layer rejects non-trailing-slash prefixes. Either answer settles both rows.
4. **Reject unknown fields in the JSON config branch (row 5)** to match the existing YAML
   strictness — a config-hardening task that settles the candidate by construction.
5. **Make one product decision about default denial-log verbosity (rows 6 and 7)** and
   apply it in both places; there is no per-implementation question to answer.

## Scope and limits

The scan completed discovery, coverage reconciliation, and deduplication, and authored
validation rubrics — then stopped before executing them. It never produced sealed final
artifacts (`findings.json`, `coverage.json`, `scan-manifest.json`, `report.md`) and never
wrote per-finding write-ups.

**What the unrun validation means.** Every candidate carries the disposition
`confirmed_static_candidate` with `validation_recommended: true`. That means a reviewer
read the code and believes the pattern really is present in the source. It does **not**
mean anyone demonstrated exploitability. The rubrics in
[`security-candidates.md`](security-candidates.md#validation-rubrics) are the work that
was planned and not done; all checkboxes are still empty.

| Field | Value |
| --- | --- |
| Target revision | `a9ac6ddc5d5b256b3a47e6ca718802bee38a6839` |
| Scope | Repository-wide |
| Worklist | 36 full-file rows (32 deterministic source-like + 4 add-backs for the Go manifest, CI workflow, production module image, and documented NGINX integration) |
| Receipts | 36 complete, each reconciled exactly once |
| Candidates | 8 raw → 8 deduped (none dropped or merged) |
| Seed research | Not applicable — no CVE/GHSA/advisory/issue/release seed in scan context |

**Verification that did run during the scan:** Go tests, race tests, and `go vet` passed;
Rust verifier, `module-config`, and differential tests passed; `govulncheck` found no
reachable Go vulnerability. RustSec advisory `RUSTSEC-2026-0204` is reachable only through
the Criterion dev-dependency and was suppressed from production findings.

**Surfaces examined and closed.** No generic signature/HMAC bypass, traversal via dot
segments or encoded separators, duplicate-singleton bypass, unsafe Rust FFI lifetime
violation, NGINX fail-open status path, public SSRF, command/query/template injection,
archive/upload sink, database/tenant/session boundary, unbounded key cache, or
production-reachable dependency advisory survived review. Per-file evidence and
suppression reasons are in
[`security-scan/repository_coverage_ledger.md`](security-scan/repository_coverage_ledger.md).

**Not carried over from the scan workspace:** the machine-readable ledgers
(`work_ledger.jsonl`, `raw_candidates.jsonl`, `rank_input.jsonl`,
`deduped_candidates.jsonl`, the eight per-candidate `candidate_ledger.jsonl` files) and
the nine `review_FR-*.json` per-file review artifacts. Their substance is summarized in
the documents indexed below. The workspace also contained a draft test,
`fr002_policy_validation_test.go`, which was not carried over.

## Artifact index

| File | Contents |
| --- | --- |
| [`security-candidates.md`](security-candidates.md) | Full per-candidate detail — reachability, impact path, counterevidence, severity drivers — plus the eight unrun validation rubrics |
| [`security-scan/threat_model.md`](security-scan/threat_model.md) | Trust boundaries, security invariants, attack surface, attacker stories, and the Critical/High/Medium/Low severity calibration used to rate the candidates |
| [`security-scan/finding_discovery_report.md`](security-scan/finding_discovery_report.md) | Scope, coverage counts, candidate summary table, and closed discovery surfaces |
| [`security-scan/repository_coverage_ledger.md`](security-scan/repository_coverage_ledger.md) | Per-boundary coverage rows with suppression reasons — the record of what was examined and cleared |
| [`security-scan/dedupe_report.md`](security-scan/dedupe_report.md) | Reconciliation of the 8 raw candidates, and why the Go/Rust instance pairs stayed separate |
