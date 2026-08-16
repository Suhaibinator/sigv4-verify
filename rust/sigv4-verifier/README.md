# sigv4-verifier

Safe Rust verifier core for the native NGINX module documented in
`docs/rust-nginx-module.md`.

This crate intentionally does not bind to NGINX. It owns the supported SigV4
SigV4 semantics and keeps the API byte-oriented so the NGINX FFI boundary can
pass the raw request URI without URL-parser normalization.

Empty policy lists in the core mean unrestricted values for that dimension.
The NGINX directive layer prevents accidental empty lists by requiring explicit
`allow_any_*` or `allow_default_methods` flags.
