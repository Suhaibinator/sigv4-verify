// Shared presigner used by the criterion benchmark and the allocation report.
//
// This is a self-contained SigV4 presigner adapted from
// `tests/verifier.rs`. It is included via `include!` rather than a normal
// module so both `benches/verify.rs` and `examples/alloc_report.rs` can reuse
// it without publishing a test-only helper from the library crate.

use ring::{digest, hmac};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const BENCH_ACCESS_KEY: &str = "AKIABENCH";
pub const BENCH_SECRET_KEY: &str = "bench-secret";
pub const BENCH_REGION: &str = "us-east-1";
pub const BENCH_SERVICE: &str = "s3";
pub const BENCH_HOST: &str = "assets.example.com";

// Fixed signing instant so benchmark inputs (and therefore results) are stable.
pub const BENCH_DATE: &str = "20260102";
pub const BENCH_TIMESTAMP: &str = "20260102T030405Z";

#[allow(dead_code)]
pub fn bench_now() -> SystemTime {
    system_time(2026, 1, 2, 3, 4, 5)
}

#[derive(Clone)]
pub struct RawQueryParam {
    pub name: String,
    pub value: String,
}

#[derive(Clone)]
pub struct PresignInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub host: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub expires: Duration,
    pub extra: Vec<RawQueryParam>,
}

impl Default for PresignInput<'_> {
    fn default() -> Self {
        Self {
            method: "GET",
            path: "/bucket/file.jpg",
            host: BENCH_HOST,
            access_key: BENCH_ACCESS_KEY,
            secret_key: BENCH_SECRET_KEY,
            region: BENCH_REGION,
            expires: Duration::from_secs(5 * 60),
            extra: Vec::new(),
        }
    }
}

pub fn presigned_uri(input: PresignInput<'_>) -> String {
    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        BENCH_DATE, input.region, BENCH_SERVICE
    );
    let mut params = vec![
        qp("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        qp(
            "X-Amz-Credential",
            uri_encode_str(&format!("{}/{}", input.access_key, credential_scope)),
        ),
        qp("X-Amz-Date", BENCH_TIMESTAMP),
        qp("X-Amz-Expires", input.expires.as_secs().to_string()),
        qp("X-Amz-SignedHeaders", "host"),
    ];
    params.extend(input.extra);

    let raw_query = join_raw_query(&params);
    let canonical_path = canonical_path(input.path.as_bytes());
    let canonical_query = canonical_query(raw_query.as_bytes());
    let mut canonical_request = Vec::new();
    canonical_request.extend_from_slice(input.method.as_bytes());
    canonical_request.push(b'\n');
    canonical_request.extend_from_slice(&canonical_path);
    canonical_request.push(b'\n');
    canonical_request.extend_from_slice(&canonical_query);
    canonical_request.extend_from_slice(b"\nhost:");
    canonical_request.extend_from_slice(input.host.trim().to_ascii_lowercase().as_bytes());
    canonical_request.extend_from_slice(b"\n\nhost\nUNSIGNED-PAYLOAD");
    let canonical_hash = sha256(&canonical_request);

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        BENCH_TIMESTAMP,
        credential_scope,
        hex_lower(&canonical_hash),
    );
    let signature = signature(
        input.secret_key,
        BENCH_DATE,
        input.region,
        BENCH_SERVICE,
        string_to_sign.as_bytes(),
    );

    format!(
        "{}?{}&X-Amz-Signature={}",
        input.path,
        raw_query,
        hex_lower(&signature)
    )
}

#[allow(dead_code)]
pub fn remove_query_param(raw_uri: &str, key: &str) -> String {
    let Some((path, query)) = raw_uri.split_once('?') else {
        return raw_uri.to_string();
    };
    let parts: Vec<_> = query
        .split('&')
        .filter(|part| part.split_once('=').map(|(name, _)| name) != Some(key))
        .collect();
    format!("{path}?{}", parts.join("&"))
}

#[allow(dead_code)]
pub fn replace_query_param(raw_uri: &str, key: &str, raw_value: &str) -> String {
    let Some((path, query)) = raw_uri.split_once('?') else {
        return raw_uri.to_string();
    };
    let parts: Vec<_> = query
        .split('&')
        .map(|part| {
            let Some((name, _)) = part.split_once('=') else {
                return part.to_string();
            };
            if name == key {
                format!("{key}={raw_value}")
            } else {
                part.to_string()
            }
        })
        .collect();
    format!("{path}?{}", parts.join("&"))
}

#[allow(dead_code)]
pub fn replace_uri_path(raw_uri: &str, path: &str) -> String {
    let Some((_, query)) = raw_uri.split_once('?') else {
        return path.to_string();
    };
    format!("{path}?{query}")
}

#[allow(dead_code)]
pub fn tampered_signature(raw_uri: &str) -> String {
    let Some((_, query)) = raw_uri.split_once('?') else {
        return "0".repeat(64);
    };
    for part in query.split('&') {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name == "X-Amz-Signature" && !value.is_empty() {
            let replacement = if value.as_bytes()[0] == b'0' { '1' } else { '0' };
            return format!("{replacement}{}", &value[1..]);
        }
    }
    "0".repeat(64)
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct EncodedQueryParam {
    name: Vec<u8>,
    value: Vec<u8>,
}

fn canonical_query(raw_query: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    for part in raw_query.split(|b| *b == b'&') {
        let eq = part.iter().position(|b| *b == b'=').unwrap_or(part.len());
        let name = percent_decode(&part[..eq]);
        let value = if eq < part.len() {
            percent_decode(&part[eq + 1..])
        } else {
            Vec::new()
        };
        if name == b"X-Amz-Signature" {
            continue;
        }
        params.push(EncodedQueryParam {
            name: uri_encode(&name),
            value: uri_encode(&value),
        });
    }
    params.sort();

    let mut out = Vec::new();
    for (idx, param) in params.iter().enumerate() {
        if idx > 0 {
            out.push(b'&');
        }
        out.extend_from_slice(&param.name);
        out.push(b'=');
        out.extend_from_slice(&param.value);
    }
    out
}

fn canonical_path(raw_path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw_path.len());
    let mut i = 0;
    while i < raw_path.len() {
        let c = raw_path[i];
        if c == b'/' {
            out.push(b'/');
            i += 1;
        } else if c == b'%'
            && i + 2 < raw_path.len()
            && is_hex(raw_path[i + 1])
            && is_hex(raw_path[i + 2])
        {
            out.push(b'%');
            out.push(upper_hex(raw_path[i + 1]));
            out.push(upper_hex(raw_path[i + 2]));
            i += 3;
        } else if is_unreserved(c) {
            out.push(c);
            i += 1;
        } else {
            write_escaped_byte(&mut out, c);
            i += 1;
        }
    }
    out
}

fn uri_encode_str(value: &str) -> String {
    String::from_utf8(uri_encode(value.as_bytes())).expect("uri encoding is ascii")
}

fn uri_encode(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for c in value {
        if is_unreserved(*c) {
            out.push(*c);
        } else {
            write_escaped_byte(&mut out, *c);
        }
    }
    out
}

fn percent_decode(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        let c = value[i];
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        out.push(from_hex(value[i + 1]) << 4 | from_hex(value[i + 2]));
        i += 3;
    }
    out
}

fn join_raw_query(params: &[RawQueryParam]) -> String {
    params
        .iter()
        .map(|param| format!("{}={}", param.name, param.value))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn qp(name: &str, value: impl Into<String>) -> RawQueryParam {
    RawQueryParam {
        name: name.to_string(),
        value: value.into(),
    }
}

fn signature(
    secret_key: &str,
    date: &str,
    region: &str,
    service: &str,
    string_to_sign: &[u8],
) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    hmac_sha256(&k_signing, string_to_sign)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, data);
    let mut out = [0; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut out = [0; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

fn system_time(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> SystemTime {
    let seconds = days_from_civil(year, month, day) * 86_400
        + hour as i64 * 3_600
        + minute as i64 * 60
        + second as i64;
    UNIX_EPOCH + Duration::from_secs(seconds as u64)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month as i32;
    let day = day as i32;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe as i64 - 719_468
}

fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn from_hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

fn upper_hex(c: u8) -> u8 {
    if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
    } else {
        c
    }
}

fn write_escaped_byte(out: &mut Vec<u8>, c: u8) {
    out.push(b'%');
    out.push(HEX_UPPER[(c >> 4) as usize]);
    out.push(HEX_UPPER[(c & 0x0f) as usize]);
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
