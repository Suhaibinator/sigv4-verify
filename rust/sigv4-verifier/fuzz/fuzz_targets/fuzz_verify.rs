#![no_main]

use std::sync::OnceLock;
use std::time::{Duration, UNIX_EPOCH};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sigv4_verifier::{Credential, Settings, Verifier};

#[derive(Arbitrary, Debug)]
struct Input {
    method: String,
    uri: Vec<u8>,
    host: String,
    now_secs: u64,
}

fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let settings = Settings {
            allowed_clock_skew: Duration::from_secs(60),
            default_max_expires: Duration::from_secs(60 * 60),
            supported_methods: vec!["GET".to_string(), "HEAD".to_string()],
            supported_service: "s3".to_string(),
        };
        let credential = Credential {
            access_key: "AKIATEST".to_string(),
            secret_key: "test-secret".to_string(),
            enabled: true,
            max_expires: Duration::from_secs(60 * 60),
            allowed_hosts: vec!["minio.example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "HEAD".to_string()],
            allowed_prefixes: vec![b"/bucket/".to_vec()],
        };
        Verifier::new(settings, vec![credential]).expect("fuzz verifier config is valid")
    })
}

fuzz_target!(|input: Input| {
    // SystemTime addition panics on platform-dependent overflow; the module
    // only ever passes SystemTime::now(), so clamp instead of crashing the
    // harness while still covering far-future timestamps.
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(input.now_secs))
        .unwrap_or_else(|| UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) * 2));
    let result = verifier().verify(&input.method, &input.uri, &input.host, now);

    // Cheap sanity invariant: a request can only be allowed if it carried a
    // signature parameter at all.
    if result.allowed {
        let has_signature = input
            .uri
            .windows(b"X-Amz-Signature".len())
            .any(|w| w == b"X-Amz-Signature");
        assert!(
            has_signature,
            "verify allowed a URI with no X-Amz-Signature: {:?}",
            input
        );
    }
});
