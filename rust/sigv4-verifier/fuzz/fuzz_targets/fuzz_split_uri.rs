#![no_main]

use libfuzzer_sys::fuzz_target;
use sigv4_verifier::internals;

fuzz_target!(|data: &[u8]| {
    if let Some((path, _query)) = internals::split_original_uri(data) {
        // A successful split must yield an absolute path.
        assert_eq!(path.first().copied(), Some(b'/'), "path must start with '/'");
        // The returned path must itself pass raw-path validation.
        assert!(
            internals::validate_raw_path(&path),
            "split path must re-validate"
        );
    }
});
