#![no_main]

use libfuzzer_sys::fuzz_target;
use sigv4_verifier::internals;

fuzz_target!(|data: &str| {
    // Credential scope parsing must never panic on arbitrary text.
    let _ = internals::parse_credential_scope(data);
});
