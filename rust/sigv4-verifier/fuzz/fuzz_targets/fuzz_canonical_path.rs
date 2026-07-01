#![no_main]

use libfuzzer_sys::fuzz_target;
use sigv4_verifier::internals;

/// True when `byte` may appear literally in an S3 canonical URI.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// The canonical URI may only contain slashes, unreserved bytes, and
/// uppercase percent escapes.
fn is_canonical_form(path: &[u8]) -> bool {
    let mut i = 0;
    while i < path.len() {
        match path[i] {
            b'/' => i += 1,
            b'%' => {
                if i + 2 >= path.len()
                    || !path[i + 1].is_ascii_hexdigit()
                    || !path[i + 2].is_ascii_hexdigit()
                    || path[i + 1].is_ascii_lowercase()
                    || path[i + 2].is_ascii_lowercase()
                {
                    return false;
                }
                i += 3;
            }
            byte if is_unreserved(byte) => i += 1,
            _ => return false,
        }
    }
    true
}

fuzz_target!(|data: &[u8]| {
    // Only paths that pass validation are ever canonicalized by the verifier.
    if internals::validate_raw_path(data) {
        let canonical = internals::canonical_uri_from_valid_path(data);
        // The canonical form is a signing artifact, not a request path: it is
        // never re-validated by the verifier (raw bytes like `\` are escaped
        // to %5C, which request-path validation would reject by design). Its
        // invariants are the S3 canonical URI grammar and idempotence.
        assert!(
            is_canonical_form(&canonical),
            "canonical path must only contain slashes, unreserved bytes, and uppercase escapes"
        );
        let recanonical = internals::canonical_uri_from_valid_path(&canonical);
        assert_eq!(
            canonical, recanonical,
            "canonical path construction must be idempotent"
        );
    }
});
