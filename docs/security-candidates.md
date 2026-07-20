# Candidate Detail

Per-candidate detail for the eight candidates listed in
[`security.md`](security.md). Every candidate on this page is **Traced** — static
reading with file:line evidence, no execution. None were validated. Read the
counterevidence in each section before acting on it.

Sections are ordered by candidate ID. The triage table in
[`security.md`](security.md) is ordered by what to look at first.

---

## FR003-CAND-1 — Go prefix authorization

*Go sidecar path-prefix authorization permits adjacent namespace names.*
Root control `internal/config/config.go:500`; authorization control
`internal/verifier/verifier.go:486`; broken control `internal/verifier/verifier.go:491`.

**Reachability.** Production reachable in the Go sidecar deployment through the public
NGINX request path; requires the non-trailing-slash policy configuration and a valid
signature for the adjacent path.

**Impact path.**
1. Operator deploys the Go sidecar with `allowed_prefixes` containing `/my-bucket/public` without a trailing slash.
2. Attacker obtains a valid SigV4 signature for `/my-bucket/publicity/secret` using the same constrained credential or an upstream presigning endpoint.
3. Method, host, expiry, and HMAC controls pass because the request is otherwise valid.
4. Lexical prefix comparison passes despite crossing the intended namespace boundary.
5. NGINX `auth_request` receives the allow result and exposes the adjacent protected object.

**Counterevidence.** All repository examples use directory-like prefixes ending in `/`,
which avoid this adjacent-name case. The SigV4 signature still binds the full path — an
attacker cannot mutate an existing URL without the signing key, and instead needs a
constrained key or a presigning capability willing to sign the adjacent path. The
documented term "path prefix" can be read as intentional lexical-prefix semantics,
though the threat model explicitly requires avoiding namespace-boundary confusion.

**Severity drivers.** Increases: authorization policy widening at the protected object
namespace boundary; the threat model explicitly treats prefix-boundary confusion as
medium-class. Reduces: requires a specially shaped configuration without the trailing
slash shown in examples; does not bypass HMAC; impact is limited to sibling names
sharing the configured lexical prefix.

## FR003-CAND-2 — Rust prefix authorization

*Native NGINX verifier path-prefix authorization permits adjacent namespace names.*
Root control `rust/sigv4-verifier/src/lib.rs:471`; configuration validation `:477`;
authorization control `:1030`; broken control `:1035`.

**Reachability.** Production reachable through a public NGINX location with
`sigv4_verify on`; requires a non-trailing-slash prefix and a valid signature for a
sibling path sharing the lexical prefix.

**Impact path.**
1. Operator configures `allowed_prefix=/my-bucket/public` without a trailing slash in an enforcing native-module deployment.
2. Attacker obtains a valid SigV4 signature for `/my-bucket/publicity/secret` using the constrained credential or an upstream presigning endpoint.
3. Signature, host, method, and expiry checks pass for that exact request.
4. Byte-prefix authorization accepts the path despite crossing the intended namespace boundary.
5. The NGINX access handler allows the adjacent protected object request.

**Counterevidence.** The Rust directive layer requires explicit `allowed_prefix` entries
or `allow_any_prefix`, avoiding accidental omission. Repository examples use
directory-like prefixes ending in `/`. The signature binds the full target path, so an
attacker needs a constrained signing capability or presigning oracle for that target
rather than mutating an existing URL.

**Severity drivers.** Increases: this is an independently deployed authorization
instance in the NGINX worker; the threat model calls prefix-boundary confusion
medium-class. Reduces: requires configuration contrary to repository examples; does not
bypass HMAC; limited to sibling names with the same lexical prefix.

## FR003-CAND-3 — JSON policy erasure

*Misspelled JSON policy fields silently widen sidecar credentials to allow-any.*
Entrypoint `cmd/sigv4-verify/main.go:24`; format dispatch
`internal/config/config.go:183`; broken parse control `:186`; policy build `:374`;
authorization sink `internal/verifier/verifier.go:486`.

**Reachability.** Production startup and reload reachable for the explicit `.json`
parser branch. Exploitation of the broadened state occurs through the normal public
request path but depends on an operator typo and a valid signature under the affected
credential.

**Impact path.**
1. Operator deploys or reloads a `.json` configuration with a typo such as `allowed_prefix`.
2. `json.Unmarshal` silently ignores the unknown property and `Config.Load` succeeds.
3. The verifier atomically installs a credential with an empty allowed-prefix list.
4. A client obtains or creates a valid SigV4 URL under that credential for a path outside the intended namespace.
5. NGINX `auth_request` accepts the sidecar's allow result and exposes the unintended object.

**Counterevidence.** `README.md` documents `CONFIG_PATH` as YAML rather than advertising
JSON, reducing expected use of this accepted runtime branch. The configuration source is
operator-controlled, not public request input. A correctly spelled JSON policy field is
enforced, and a valid SigV4 signature is still required after widening. Empty policy
lists intentionally mean allow-any in the Go sidecar, so the defect is the failure to
distinguish omission from an ignored unknown field — not the empty-list semantic itself.

**Severity drivers.** Increases: a parsing mistake silently widens an authorization
policy and persists across requests; the threat model requires malformed administrative
allowlists to fail configuration or fail closed; the same root cause can erase host,
method, or prefix restrictions. Reduces: JSON is accepted in code but README documents
YAML; requires operator error in trusted configuration; does not defeat HMAC validation
by itself.

## FR004-CAND-1 — Go query complexity

*Quadratic canonical-query sorting permits pre-authentication CPU amplification.*
Entrypoint `internal/verifier/verifier.go:154`; root control
`internal/verifier/canonical.go:163`; sink `:224`.

**Reachability.** Production-reachable through the normal Go sidecar authorization path,
subject to configured NGINX and Go header-size limits.

**Impact path.**
1. Client sends a high-cardinality, adversarially ordered query to the protected NGINX location.
2. NGINX copies the raw URI into `X-Original-URI` for the internal auth subrequest.
3. The sidecar collects all parameters and executes quadratic insertion-sort work.
4. Only after sorting does it reject missing/invalid SigV4 fields — so no secret or valid signature is required.
5. Concurrent requests consume authorization CPU and delay legitimate object requests.

**Counterevidence.** `cmd/sigv4-verify/main.go` configures `http.Server.MaxHeaderBytes`
and `internal/config` defaults it to 8 KiB. NGINX deployments also commonly bound
request-line and header size. The practical request rate needed for saturation has not
been measured.

**Severity drivers.** Suggested medium at *medium confidence*. Increases:
pre-authentication sink; quadratic attacker-selected work; shared authorization
availability impact. Reduces: default 8 KiB sidecar header limit; no measured saturation
benchmark; deployment request limits may further constrain cardinality.

This is the one candidate whose rubric explicitly contemplates suppression: if a bounded
benchmark shows insufficient amplification, it should be closed with the measurements
attached rather than reported.

## FR006-CAND-1 — Cache identity confusion

*Path-only cache key conflates distinct signed S3 response representations.*
Raw-URI source `examples/nginx.conf:37`; authorization control `:47`; origin sink `:49`;
broken cache control `:58`.

**Reachability.** Documented production example plus an S3-compatible origin that honors
signed representation-selection parameters and returns a cacheable response.

**Impact path.**
1. One valid signed query selects and populates representation A for a path.
2. A different valid signed query for the same scheme, host, and path selects representation B.
3. The shared cache key resolves the second request to representation A.
4. Content, version, partial bytes, or response metadata crosses the intended query boundary.

**Counterevidence.** Each lookup remains gated by `auth_request`. Origins that ignore all
non-auth query parameters have no differing representations. Normal NGINX cacheability
rules and origin headers can prevent population.

**Severity drivers.** Increases: the repository explicitly preserves signed response
query parameters; the documented configuration enables and recommends the conflicting
cache key. Reduces: a valid URL for the colliding path is still required; origin and
cache behavior determine concrete representation and retention.

Note this is a defect in *documented example configuration* (`examples/nginx.conf`),
not in verifier code — which makes it cheap to fix and easy to have already copied into
real deployments.

## FR006-CAND-2 — Native denial logs

*Native module logs object paths on verification denials by default.*
Default control `rust/nginx-module/src/lib.rs:69`; request source `:623`; logging
control `:635`; log sink `:641`.

**Reachability.** Default production behavior for native-module requests that pass URI
splitting and fail a later check.

**Impact path.**
1. NGINX passes the public raw URI into the native access handler.
2. The verifier parses and retains the path before a later denial.
3. Default `log_denies` selects the denied outcome.
4. The complete object path is exported to operational logs.

**Counterevidence.** Early malformed metadata/URI denials can have an empty path. The raw
query and signature are deliberately omitted. Operators can set
`sigv4_verify_log_denies off`, and NGINX logs are normally privileged.

**Severity drivers.** Increases: the threat model explicitly classifies signed
object-path leakage through default logs as medium; expired real URLs and
policy/signature denials retain the parsed path. Reduces: requires access to operational
logs; an explicit directive disables the sink; signature-bearing query data is not
logged.

## PARENT-CAND-1 — Go denial logs

*Go sidecar logs object paths on verification denials by default.*
Default control `internal/config/config.go:217`; logging control
`internal/server/server.go:92`; log sink `:97`.

**Reachability.** Production reachable in the Go sidecar's default logging configuration
for parsed denied requests.

**Impact path.**
1. Client submits an expired, unauthorized, or signature-mismatched URL containing a sensitive object path.
2. Verifier returns a denial while preserving `rawPath`.
3. Default `log_denies` causes the path to be logged.
4. A log reader or aggregator learns object names and namespace structure outside object-read authorization.

**Counterevidence.** Malformed requests rejected before URI parsing can have an empty
path. Logs are normally privileged operational data. Operators can set
`log_denies false`. The raw query and signature are omitted.

**Severity drivers.** Increases: the threat model treats default signed-object-path
leakage as medium; public denied requests reach the sink. Reduces: requires access to
operational logs; no signature-bearing query is logged; an opt-out exists.

## FR001-CAND-1 — CLI secret argv

*Presign helper exposes signing secrets through command-line arguments.*
Entrypoint `cmd/presign-url/main.go:21`; sink `:31`.

**Reachability.** Privileged/local tooling only. There is no public HTTP path to this
helper and no direct production-runtime reachability.

**Impact path.**
1. Victim invokes the POC helper with `-secret-key <real secret>`.
2. The literal is retained in argv and may persist in shell or CI command records.
3. An attacker with same-host process visibility, or access to those records, recovers the key.
4. The attacker generates valid SigV4 presigned URLs within the credential's host/method/path/expiry policy.

**Counterevidence.** The helper is documented as an optional POC/development command, not
a production request handler. Environment-variable fallbacks exist, so users can avoid
the vulnerable input form. The command is short-lived, narrowing process-list
observation — although shell history and CI command tracing can persist the argument.

**Severity drivers.** Increases: the exposed value is a signing secret capable of
authorizing protected object requests within policy; repository documentation
demonstrates the unsafe argument form. Reduces: requires victim use of an optional POC
helper and the explicit flag; requires local process/history/CI-log visibility;
environment fallback is available; no generic signature bypass or cross-credential
exposure follows automatically.

---

# Validation Rubrics

These are the checks the scan planned in order to promote each candidate to a finding,
adjust its severity, or suppress it. **None were executed** — every checkbox below is
still empty, and that is the actual state of the work, not a formatting artifact. A
candidate whose rubric fails should be closed, not reported.

## FR003-CAND-1 — Go prefix authorization

- [ ] A non-trailing-slash prefix is accepted by production configuration/compilation.
- [ ] A sibling path that shares only the lexical prefix passes the exact authorization control.
- [ ] A realistic signed request for that sibling path reaches the Go verifier and is allowed.
- [ ] Segment-safe nearby controls do not establish the missing boundary.
- [ ] Preconditions and protected-object impact are supported by repository deployment evidence.

## FR003-CAND-2 — Rust prefix authorization

- [ ] The native directive/core accepts a non-trailing-slash prefix.
- [ ] The byte-prefix control admits an adjacent sibling name.
- [ ] A correctly signed sibling request is allowed by the Rust verifier through a focused harness.
- [ ] Module wrapper/config checks do not add a later segment-boundary control.
- [ ] This independently deployed instance remains separate from the Go sidecar.

## FR003-CAND-3 — JSON policy erasure

- [ ] The supported `.json` branch accepts an unknown or misspelled restriction field.
- [ ] Required credential fields still load successfully while the intended restriction remains empty.
- [ ] Empty compiled policy has documented/runtime allow-any semantics.
- [ ] A signed request outside the intended policy receives an allow decision.
- [ ] YAML strictness, startup/reload behavior, and trusted-operator preconditions are accurately scoped.

## FR004-CAND-1 — Go query complexity

- [ ] Public unauthenticated input reaches sorting before credential/signature rejection.
- [ ] Worst-case parameter ordering exercises quadratic inner-loop behavior.
- [ ] A bounded benchmark measures cost at default and larger supported request limits against a safe/ordered control.
- [ ] HTTP/NGINX limits and required request rate are quantified as counterevidence.
- [ ] Observed amplification is sufficient for a practical availability finding; otherwise suppress with measurements.

## FR006-CAND-1 — Cache identity confusion

- [ ] The verifier signs and authorizes the complete raw query.
- [ ] The documented origin request forwards representation-selecting query parameters.
- [ ] The documented cache key omits those differentiating parameters.
- [ ] S3-compatible semantics provide at least one concrete distinct representation for the same path.
- [ ] Valid-URL, cacheability, and deployment preconditions are explicit and do not defeat the cross-representation impact.

## FR006-CAND-2 — Native denial logs

- [ ] Denial logging is enabled by default.
- [ ] A public denied request can retain a nonempty object path.
- [ ] The native module emits that path to the NGINX error log.
- [ ] Query/signature omission and operator opt-out are recorded as limiting controls.
- [ ] Threat-model policy supports reportability across the object/log access boundary.

## PARENT-CAND-1 — Go denial logs

- [ ] Denial logging is enabled by default.
- [ ] A public denied request can retain a nonempty object path.
- [ ] The Go sidecar emits that path to its structured log.
- [ ] Query/signature omission and operator opt-out are recorded as limiting controls.
- [ ] This independently deployed instance remains separate from the native module.

## FR001-CAND-1 — CLI secret argv

- [ ] The documented CLI accepts a real signing secret in process argv and prioritizes it.
- [ ] Process metadata, shell history, or CI tracing is a realistic exposure sink for the documented use.
- [ ] Environment fallback does not remove the unsafe explicit form.
- [ ] Local-only/optional-tool and observer-permission preconditions are explicit.
- [ ] The recovered secret's authorization impact and final low-severity/reportability bar are justified.
