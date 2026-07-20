# Security Review

**The original scan did not complete validation.** An automated repository-wide scan of
`sigv4-verify` at commit `a9ac6ddc5d5b256b3a47e6ca718802bee38a6839`
produced eight static candidates, then stopped before executing any of them. Subsequent
maintainer review pruned three as non-findings, and commit `624f356` resolved three with
regression coverage. Two unvalidated candidates remain in the active review backlog.

## How to read this

Each row carries an **evidence strength**, and only three values are possible:

- **Demonstrated** — an executed test or harness actually reproduced the behavior.
- **Traced** — static reading with file:line evidence following source to sink; no execution.
- **Lead** — discovery-only, never validated; may not survive scrutiny.

The two active candidates remain **Traced**. Their severities are the scan's suggested
values and were never finalized because the step that owns final severity never ran.
Resolved candidates have executed regression evidence; pruned scan leads are not part of
the candidate set. Do not cite an active candidate as a confirmed vulnerability.

## Triage table

Ranked by what a maintainer should look at first — a blend of severity, blast radius,
and how cheaply the candidate can be confirmed or killed. Not ranked by candidate ID.

| # | Issue | Location | Severity | Evidence | Detail |
| --- | --- | --- | --- | --- | --- |
| 1 | The example NGINX config caches by path only, so two differently-signed requests for the same path can be served each other's cached response | `examples/nginx.conf:37,47,49,58` | medium | Traced | [FR006-CAND-1](security-candidates.md#fr006-cand-1--cache-identity-confusion) |
| 2 | A caller can make the sidecar do expensive sorting work before it checks any signature, by sending a query with many parameters | `internal/verifier/verifier.go:154`, `internal/verifier/canonical.go:163-168,224-235` | medium (pending measurement) | Traced | [FR004-CAND-1](security-candidates.md#fr004-cand-1--go-query-complexity) |

## Resolved since the scan

| Candidate | Resolution | Evidence |
| --- | --- | --- |
| [FR003-CAND-1](security-candidates.md#fr003-cand-1--go-prefix-authorization) | Go prefix authorization now requires an exact or `/`-delimited path boundary. | Commit `624f356`; signed exact/child controls and adjacent-sibling denial test. |
| [FR003-CAND-2](security-candidates.md#fr003-cand-2--rust-prefix-authorization) | Rust uses the same segment-boundary rule as Go. | Commit `624f356`; signed Rust regression and Go/Rust differential corpus. |
| [FR003-CAND-3](security-candidates.md#fr003-cand-3--json-policy-erasure) | JSON configuration rejects unknown fields before policy construction. | Commit `624f356`; misspelled-field rejection and valid-JSON control. |

Three additional scan leads were pruned by maintainer review. Denied-path logging in
privileged operational logs and explicit secret arguments to the optional local presign
helper are accepted product/tooling behavior and are not reportable security findings.

## Start here

1. **Fix `examples/nginx.conf` (row 1) now, regardless of validation.** It is a defect in
   documented example configuration, so it keeps propagating into real deployments for as
   long as it sits open; fixing it costs a config edit and removes that spread.
2. **Run the bounded benchmark for row 2.** Its own rubric contemplates suppression — if
   measured amplification under the default 8 KiB header limit is insufficient, the
   candidate is closed outright with measurements attached, removing it from the backlog
   for the cost of one benchmark.

## Scope and limits

The scan completed discovery, coverage reconciliation, and deduplication, and authored
validation rubrics — then stopped before executing them. It never produced sealed final
artifacts (`findings.json`, `coverage.json`, `scan-manifest.json`, `report.md`) and never
wrote per-finding write-ups.

**What the unrun validation means.** The two active candidates retain the scan-time
disposition `confirmed_static_candidate` with `validation_recommended: true`. That means
a reviewer traced the pattern in source; it does **not** mean exploitability was
demonstrated. Their remaining rubrics are in
[`security-candidates.md`](security-candidates.md#validation-rubrics).

| Field | Value |
| --- | --- |
| Target revision | `a9ac6ddc5d5b256b3a47e6ca718802bee38a6839` |
| Scope | Repository-wide |
| Worklist | 36 full-file rows (32 deterministic source-like + 4 add-backs for the Go manifest, CI workflow, production module image, and documented NGINX integration) |
| Receipts | 36 complete, each reconciled exactly once |
| Candidates | 8 original raw → 5 retained after maintainer pruning: 2 active, 3 resolved |
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
`deduped_candidates.jsonl`, the original eight per-candidate `candidate_ledger.jsonl` files) and
the nine `review_FR-*.json` per-file review artifacts. Their substance is summarized in
the documents indexed below. The workspace also contained a draft test,
`fr002_policy_validation_test.go`, which was not carried over.

## Artifact index

| File | Contents |
| --- | --- |
| [`security-candidates.md`](security-candidates.md) | Detail for the five retained candidates, including resolution evidence and the two remaining validation rubrics |
| [`security-scan/threat_model.md`](security-scan/threat_model.md) | Trust boundaries, security invariants, attack surface, attacker stories, and the Critical/High/Medium/Low severity calibration used to rate the candidates |
| [`security-scan/finding_discovery_report.md`](security-scan/finding_discovery_report.md) | Scope, coverage counts, candidate summary table, and closed discovery surfaces |
| [`security-scan/repository_coverage_ledger.md`](security-scan/repository_coverage_ledger.md) | Per-boundary coverage rows with suppression reasons — the record of what was examined and cleared |
| [`security-scan/dedupe_report.md`](security-scan/dedupe_report.md) | Reconciliation and current disposition of the five retained candidates |
