# sigv4-verifier

Safe Rust verifier core for the native NGINX module path described in
`docs/rust-nginx-module-requirements.md`.

This crate intentionally does not bind to NGINX. It owns the supported SigV4
MVP semantics and keeps the API byte-oriented for raw request URIs so the future
NGINX FFI boundary can pass `$request_uri`-equivalent bytes without URL parser
normalization.

The current policy-list behavior matches the Go sidecar for compatibility:
omitted allowed hosts, methods, or prefixes allow all values in that dimension.
A stricter NGINX directive layer can add explicit `allow_any_*` flags before
production rollout.

