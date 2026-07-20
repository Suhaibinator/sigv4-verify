# Finding Discovery Report

## Scope and coverage

- Target: repository-wide scan of `sigv4-verify` at `a9ac6ddc5d5b256b3a47e6ca718802bee38a6839`.
- Worklist: 36 full-file rows; 32 deterministic source-like rows plus four add-backs for the Go manifest, CI workflow, production module image, and documented NGINX integration.
- Receipts: 36 complete, reconciled exactly once in `work_ledger.jsonl`.
- Candidate coverage: eight raw and eight deduped candidates; all eight have discovery, candidate-local validation, and candidate-local attack-path receipts.
- Seed research: not applicable because the prompt and scan context contain no CVE, GHSA, advisory, issue, release, package-version, or vulnerability-family seed.
- Verification: Go tests, race tests and vet passed; Rust verifier/module-config tests and differential tests passed. `govulncheck` found no reachable Go vulnerability. RustSec advisory RUSTSEC-2026-0204 is present only through the Criterion dev-dependency and is suppressed from production findings.

## Candidates continuing to validation

| Candidate | Plausible issue | Principal evidence | Discovery severity hint |
| --- | --- | --- | --- |
| FR001-CAND-1 | Presign helper accepts a signing secret in argv | `cmd/presign-url/main.go:21,31,45-46` and documented literal use | low |
| FR003-CAND-1 | Go lexical path-prefix check accepts adjacent namespace names | `internal/config/config.go:500`, `internal/verifier/verifier.go:486-495` | medium |
| FR003-CAND-2 | Rust lexical path-prefix check accepts adjacent namespace names | `rust/sigv4-verifier/src/lib.rs:471-479,1030-1035` | medium |
| FR003-CAND-3 | Unknown JSON policy fields are ignored and zero-value lists mean allow-any | `internal/config/config.go:183-189,343-389`, `internal/verifier/verifier.go:470-495` | medium |
| FR004-CAND-1 | Go query canonicalizer uses pre-authentication quadratic insertion sort | `internal/verifier/verifier.go:154`, `internal/verifier/canonical.go:163-168,224-235` | medium pending measurement |
| FR006-CAND-1 | Documented path-only cache key conflates signed representation-selecting queries | `examples/nginx.conf:37,47,49,58` | medium |
| FR006-CAND-2 | Native module logs denied object paths by default | `rust/nginx-module/src/lib.rs:69-71,635-647` | medium |
| PARENT-CAND-1 | Go sidecar logs denied object paths by default | `internal/config/config.go:216-218`, `internal/server/server.go:92-103` | medium |

Discovery severity hints are not final. Validation and attack-path analysis own suppression, reportability, and final severity.

## Closed discovery surfaces

No generic signature/HMAC bypass, traversal via dot segments or encoded separators, duplicate singleton bypass, unsafe Rust FFI lifetime violation, NGINX fail-open status path, public SSRF, command/query/template injection, archive/upload sink, database/tenant/session boundary, unbounded key cache, or production-reachable dependency advisory survived the frontier and full-file reviews. Exact per-file evidence and suppressions remain in the nine review artifacts and repository coverage ledger.
