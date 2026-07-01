//! Reports heap allocations and bytes per `verify()` call for a few
//! representative scenarios, using a counting global allocator that wraps the
//! system allocator. No new runtime dependencies: the allocator lives here in
//! the example and never ships with the library.
//!
//! Run with: `cargo run -p sigv4-verifier --release --example alloc_report`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use sigv4_verifier::{Credential, Settings, Verifier};

// Brings in the presigner plus `std::time::{Duration, SystemTime, ...}`.
include!("../benches/support/presign.rs");

struct CountingAllocator;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() && new_size > layout.size() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add((new_size - layout.size()) as u64, Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

struct Snapshot {
    count: u64,
    bytes: u64,
}

fn snapshot() -> Snapshot {
    Snapshot {
        count: ALLOC_COUNT.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    }
}

fn build_verifier() -> Verifier {
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
    Verifier::new(settings, vec![credential]).expect("verifier config is valid")
}

/// Measures allocations attributable to `iters` verify() calls, averaged.
fn measure(verifier: &Verifier, uri: &[u8], now: SystemTime, iters: u64) -> (f64, f64) {
    let before = snapshot();
    for _ in 0..iters {
        let result = verifier.verify("GET", uri, BENCH_HOST, now);
        std::hint::black_box(&result);
    }
    let after = snapshot();
    let count = (after.count - before.count) as f64 / iters as f64;
    let bytes = (after.bytes - before.bytes) as f64 / iters as f64;
    (count, bytes)
}

fn main() {
    let verifier = build_verifier();
    let now = bench_now();

    let valid = presigned_uri(PresignInput::default()).into_bytes();
    let signature_mismatch = {
        let uri = presigned_uri(PresignInput::default());
        replace_query_param(&uri, "X-Amz-Signature", &tampered_signature(&uri)).into_bytes()
    };
    let missing_params =
        remove_query_param(&presigned_uri(PresignInput::default()), "X-Amz-Date").into_bytes();

    // Warm the signing-key cache and any other one-time state before measuring.
    verifier.verify("GET", &valid, BENCH_HOST, now);

    const ITERS: u64 = 10_000;
    let cases: [(&str, &[u8]); 3] = [
        ("valid_get_warm_cache", &valid),
        ("deny_signature_mismatch", &signature_mismatch),
        ("deny_missing_params", &missing_params),
    ];

    println!("verify() allocations per call (averaged over {ITERS} iterations)");
    println!(
        "{:<28} {:>12} {:>14}",
        "scenario", "allocs/call", "bytes/call"
    );
    for (name, uri) in cases {
        let (count, bytes) = measure(&verifier, uri, now, ITERS);
        println!("{name:<28} {count:>12.2} {bytes:>14.1}");
    }
}
