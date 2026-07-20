# Candidate Reconciliation

Eight raw scan leads were reconciled. Maintainer review retained five candidates and
pruned three as non-findings. The Go and Rust prefix-policy candidates remain distinct
because they are independently deployed authorization implementations. Supporting
evidence emitted by later file reviews was attached to the original ids instead of
creating duplicates.

| Dedupe id | Raw id | Instance | Disposition |
| --- | --- | --- | --- |
| FR003-CAND-1 | FR003-CAND-1 | Go sidecar prefix authorization | resolved in `624f356` |
| FR003-CAND-2 | FR003-CAND-2 | Native Rust prefix authorization | resolved in `624f356` |
| FR003-CAND-3 | FR003-CAND-3 | JSON policy-field parsing | resolved in `624f356` |
| FR004-CAND-1 | FR004-CAND-1 | Go canonical-query complexity | retained; validation pending |
| FR006-CAND-1 | FR006-CAND-1 | Documented NGINX cache identity | retained; validation pending |

The original scan workspace retains the raw and candidate-local receipts. This curated
report intentionally excludes the three maintainer-pruned leads from the candidate set.
