use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sigv4_verifier::{Credential, Settings, Verifier};
use std::hint::black_box;

// Brings in the presigner plus `std::time::{Duration, SystemTime, ...}`.
include!("support/presign.rs");

/// A pre-generated verification input. URIs are built once, outside the hot
/// loop, so the benchmark measures `verify()` and not presign/encoding work.
struct Scenario {
    name: &'static str,
    method: &'static str,
    uri: Vec<u8>,
    now: SystemTime,
}

fn bench_verifier() -> Verifier {
    let settings = Settings {
        allowed_clock_skew: Duration::from_secs(60),
        default_max_expires: Duration::from_secs(60 * 60),
        supported_methods: vec!["GET".to_string(), "HEAD".to_string()],
        supported_service: BENCH_SERVICE.to_string(),
    };
    let credential = Credential {
        access_key: BENCH_ACCESS_KEY.to_string(),
        secret_key: BENCH_SECRET_KEY.to_string(),
        enabled: true,
        max_expires: Duration::from_secs(60 * 60),
        allowed_hosts: vec![BENCH_HOST.to_string()],
        allowed_methods: vec!["GET".to_string(), "HEAD".to_string()],
        allowed_prefixes: vec![b"/bucket/".to_vec()],
    };
    Verifier::new(settings, vec![credential]).expect("bench verifier config is valid")
}

/// Builds a ~2KB valid path made of unreserved segments under `/bucket/`.
fn long_path() -> String {
    let mut path = String::from("/bucket");
    while path.len() < 2000 {
        path.push_str("/abcdefghijklmnop");
    }
    path.push_str("/report.pdf");
    path
}

/// 20 distinct, high-cardinality (unknown) query params added to a valid URL.
fn high_cardinality_extra() -> Vec<RawQueryParam> {
    (0..20)
        .map(|i| {
            qp(
                &format!("x-req-{i:02}"),
                format!("v-{i:02}-6f1c9ab4d27e0835a9c1f4e2b7d60c93"),
            )
        })
        .collect()
}

fn scenarios() -> Vec<Scenario> {
    let now = bench_now();

    let valid = presigned_uri(PresignInput::default());

    let high_cardinality = presigned_uri(PresignInput {
        extra: high_cardinality_extra(),
        ..PresignInput::default()
    });

    let long = long_path();
    let long_path_uri = presigned_uri(PresignInput {
        path: &long,
        ..PresignInput::default()
    });

    let signature_mismatch =
        replace_query_param(&valid, "X-Amz-Signature", &tampered_signature(&valid));

    let missing_params = remove_query_param(&valid, "X-Amz-Date");

    let traversal = replace_uri_path(&valid, "/bucket/../secret.pdf");

    // Signed with a 60s expiry, verified 61s later so it reads as expired.
    let expired = presigned_uri(PresignInput {
        expires: Duration::from_secs(60),
        ..PresignInput::default()
    });

    vec![
        Scenario {
            name: "valid_get_warm_cache",
            method: "GET",
            uri: valid.into_bytes(),
            now,
        },
        Scenario {
            name: "valid_get_high_cardinality_query",
            method: "GET",
            uri: high_cardinality.into_bytes(),
            now,
        },
        Scenario {
            name: "valid_get_long_path",
            method: "GET",
            uri: long_path_uri.into_bytes(),
            now,
        },
        Scenario {
            name: "deny_signature_mismatch",
            method: "GET",
            uri: signature_mismatch.into_bytes(),
            now,
        },
        Scenario {
            name: "deny_missing_params",
            method: "GET",
            uri: missing_params.into_bytes(),
            now,
        },
        Scenario {
            name: "deny_invalid_path_traversal",
            method: "GET",
            uri: traversal.into_bytes(),
            now,
        },
        Scenario {
            name: "deny_expired",
            method: "GET",
            uri: expired.into_bytes(),
            now: now + Duration::from_secs(61),
        },
    ]
}

fn bench_verify(c: &mut Criterion) {
    let verifier = bench_verifier();
    let scenarios = scenarios();

    // Warm the per-worker signing-key cache so the valid path reflects a cache
    // hit rather than the one-time key derivation.
    verifier.verify("GET", &scenarios[0].uri, BENCH_HOST, scenarios[0].now);

    let mut group = c.benchmark_group("verify");
    for scenario in &scenarios {
        group.bench_with_input(
            BenchmarkId::from_parameter(scenario.name),
            scenario,
            |b, scenario| {
                b.iter(|| {
                    verifier.verify(
                        black_box(scenario.method),
                        black_box(scenario.uri.as_slice()),
                        black_box(BENCH_HOST),
                        black_box(scenario.now),
                    )
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
