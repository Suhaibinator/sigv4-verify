#![no_main]

use libfuzzer_sys::fuzz_target;
use sigv4_verifier::internals;

fuzz_target!(|data: &[u8]| {
    // Percent decoding must never panic on arbitrary input.
    let _ = internals::percent_decode(data);
});
