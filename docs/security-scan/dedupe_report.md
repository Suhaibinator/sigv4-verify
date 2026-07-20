# Candidate Reconciliation

Eight raw candidates were reconciled. No candidate was dropped or merged into another id. The Go and Rust prefix-policy issues remain distinct because they are independently deployed authorization implementations. The Go and Rust default denial-log issues likewise remain separate runtime instances. Supporting evidence emitted by later file reviews was attached to the original ids instead of creating duplicates.

| Dedupe id | Raw id | Instance | Disposition |
| --- | --- | --- | --- |
| FR001-CAND-1 | FR001-CAND-1 | `secret-exposure:cmd/presign-url/main.go:21` | preserved |
| FR003-CAND-1 | FR003-CAND-1 | Go sidecar prefix authorization | preserved independently |
| FR003-CAND-2 | FR003-CAND-2 | Native Rust prefix authorization | preserved independently |
| FR003-CAND-3 | FR003-CAND-3 | JSON policy-field parsing | preserved |
| FR004-CAND-1 | FR004-CAND-1 | Go canonical-query complexity | preserved |
| FR006-CAND-1 | FR006-CAND-1 | Documented NGINX cache identity | preserved |
| FR006-CAND-2 | FR006-CAND-2 | Native Rust denial logging | preserved independently |
| PARENT-CAND-1 | PARENT-CAND-1 | Go sidecar denial logging | preserved independently |

Each deduped row records its raw id and candidate-ledger path in `deduped_candidates.jsonl`. Every ledger contains discovery, candidate-local validation, and candidate-local attack-path receipts.
