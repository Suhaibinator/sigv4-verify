#![no_main]

use libfuzzer_sys::fuzz_target;
use sigv4_verifier::internals;

fuzz_target!(|data: &[u8]| {
    if let Some(canonical) = internals::canonical_query(data) {
        // Re-canonicalizing the canonical output must succeed and be a fixed
        // point (idempotent).
        let recanonical =
            internals::canonical_query(&canonical).expect("canonical query must re-canonicalize");
        assert_eq!(
            canonical, recanonical,
            "canonical query construction must be idempotent"
        );
    }
});
