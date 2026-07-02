use ring::{digest, hmac};
use sigv4_verifier::{
    Credential, MAX_SIGV4_EXPIRES, REASON_EXPIRED, REASON_FUTURE_DATED,
    REASON_INVALID_CREDENTIAL_SCOPE, REASON_INVALID_EXPIRY, REASON_INVALID_URI,
    REASON_MISSING_QUERY_PARAM, REASON_OK, REASON_SIGNATURE_MISMATCH, REASON_UNAUTHORIZED,
    REASON_UNKNOWN_ACCESS_KEY, REASON_UNSUPPORTED_ALGORITHM, REASON_UNSUPPORTED_METHOD,
    REASON_UNSUPPORTED_SIGNED_HEADER, Settings, Verifier, VerifyResult, hash_access_key,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TEST_ACCESS_KEY: &str = "AKIATEST";
const TEST_SECRET_KEY: &str = "test-secret";
const TEST_REGION: &str = "us-east-1";
const TEST_SERVICE: &str = "s3";
const TEST_HOST: &str = "minio.example.com";

#[test]
fn allows_valid_presigned_get_and_head() {
    let verifier = new_test_verifier(vec![]);

    for method in ["GET", "HEAD"] {
        let raw_uri = presigned_uri(PresignInput {
            method,
            path: "/bucket/file.jpg",
            host: TEST_HOST,
            ..PresignInput::default()
        });

        let result = verifier.verify(method, raw_uri.as_bytes(), TEST_HOST, test_now());
        require_allowed(result, b"/bucket/file.jpg");
    }
}

#[test]
fn rejects_missing_and_duplicate_singleton_query_params() {
    let verifier = new_test_verifier(vec![]);
    let raw_uri = presigned_uri(PresignInput::default());

    for key in [
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-SignedHeaders",
        "X-Amz-Signature",
    ] {
        let result = verifier.verify(
            "GET",
            remove_query_param(&raw_uri, key).as_bytes(),
            TEST_HOST,
            test_now(),
        );
        require_denied(result, REASON_MISSING_QUERY_PARAM);
    }

    let duplicate_expires = format!("{raw_uri}&X-Amz-Expires=60");
    let result = verifier.verify("GET", duplicate_expires.as_bytes(), TEST_HOST, test_now());
    require_denied(result, REASON_MISSING_QUERY_PARAM);
}

#[test]
fn rejects_unsupported_method_algorithm_and_signed_headers() {
    let verifier = new_test_verifier(vec![]);
    let raw_uri = presigned_uri(PresignInput::default());

    let result = verifier.verify("POST", raw_uri.as_bytes(), TEST_HOST, test_now());
    require_denied(result, REASON_UNSUPPORTED_METHOD);

    let result = verifier.verify(
        "GET",
        replace_query_param(&raw_uri, "X-Amz-Algorithm", "AWS4-HMAC-SHA1").as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_UNSUPPORTED_ALGORITHM);

    let result = verifier.verify(
        "GET",
        replace_query_param(
            &raw_uri,
            "X-Amz-SignedHeaders",
            &uri_encode_str("host;x-amz-content-sha256"),
        )
        .as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_UNSUPPORTED_SIGNED_HEADER);
}

#[test]
fn rejects_invalid_credential_scope() {
    let verifier = new_test_verifier(vec![]);
    let raw_uri = presigned_uri(PresignInput::default());

    for credential in [
        // Too few scope parts.
        uri_encode_str(&format!("{TEST_ACCESS_KEY}/20260102/{TEST_REGION}/s3")),
        // Too many scope parts.
        uri_encode_str(&format!(
            "{TEST_ACCESS_KEY}/20260102/{TEST_REGION}/s3/aws4_request/extra"
        )),
        // Non-digit date.
        uri_encode_str(&format!(
            "{TEST_ACCESS_KEY}/2026010X/{TEST_REGION}/s3/aws4_request"
        )),
        // Unsupported service.
        uri_encode_str(&format!(
            "{TEST_ACCESS_KEY}/20260102/{TEST_REGION}/ec2/aws4_request"
        )),
        // Wrong terminal value.
        uri_encode_str(&format!(
            "{TEST_ACCESS_KEY}/20260102/{TEST_REGION}/s3/aws4_request_v2"
        )),
        // Empty region.
        uri_encode_str(&format!("{TEST_ACCESS_KEY}/20260102//s3/aws4_request")),
    ] {
        let result = verifier.verify(
            "GET",
            replace_query_param(&raw_uri, "X-Amz-Credential", &credential).as_bytes(),
            TEST_HOST,
            test_now(),
        );
        require_denied(result, REASON_INVALID_CREDENTIAL_SCOPE);
    }

    // X-Amz-Date day must match the credential scope date.
    let result = verifier.verify(
        "GET",
        replace_query_param(&raw_uri, "X-Amz-Date", "20260103T030405Z").as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_INVALID_CREDENTIAL_SCOPE);
}

#[test]
fn rejects_invalid_expiry_values() {
    let verifier = new_test_verifier(vec![]);
    let raw_uri = presigned_uri(PresignInput::default());

    for expires in ["0", "-60", "abc", "60.5", ""] {
        let result = verifier.verify(
            "GET",
            replace_query_param(&raw_uri, "X-Amz-Expires", expires).as_bytes(),
            TEST_HOST,
            test_now(),
        );
        require_denied(result, REASON_INVALID_EXPIRY);
    }
}

#[test]
fn rejects_credential_and_policy_denials() {
    let raw_uri = presigned_uri(PresignInput {
        access_key: "UNKNOWN",
        secret_key: "unknown-secret",
        ..PresignInput::default()
    });
    let result = new_test_verifier(vec![]).verify("GET", raw_uri.as_bytes(), TEST_HOST, test_now());
    require_denied(result, REASON_UNKNOWN_ACCESS_KEY);

    let mut disabled = test_credential();
    disabled.enabled = false;
    let raw_uri = presigned_uri(PresignInput::default());
    let result =
        new_test_verifier(vec![disabled]).verify("GET", raw_uri.as_bytes(), TEST_HOST, test_now());
    require_denied(result, REASON_UNAUTHORIZED);

    let mut host_limited = test_credential();
    host_limited.allowed_hosts = vec![TEST_HOST.to_string()];
    let raw_uri = presigned_uri(PresignInput {
        host: "blocked.example.com",
        ..PresignInput::default()
    });
    let result = new_test_verifier(vec![host_limited]).verify(
        "GET",
        raw_uri.as_bytes(),
        "blocked.example.com",
        test_now(),
    );
    require_denied(result, REASON_UNAUTHORIZED);

    let mut method_limited = test_credential();
    method_limited.allowed_methods = vec!["GET".to_string()];
    let raw_uri = presigned_uri(PresignInput {
        method: "HEAD",
        ..PresignInput::default()
    });
    let result = new_test_verifier(vec![method_limited]).verify(
        "HEAD",
        raw_uri.as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_UNAUTHORIZED);

    let mut prefix_limited = test_credential();
    prefix_limited.allowed_prefixes = vec![b"/allowed/".to_vec()];
    let raw_uri = presigned_uri(PresignInput::default());
    let result = new_test_verifier(vec![prefix_limited]).verify(
        "GET",
        raw_uri.as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_UNAUTHORIZED);
}

#[test]
fn rejects_expired_future_dated_and_over_max_expiry() {
    let verifier = new_test_verifier(vec![]);

    let expired_uri = presigned_uri(PresignInput {
        expires: Duration::from_secs(60),
        ..PresignInput::default()
    });
    let result = verifier.verify(
        "GET",
        expired_uri.as_bytes(),
        TEST_HOST,
        test_now() + Duration::from_secs(61),
    );
    require_denied(result, REASON_EXPIRED);

    let future_uri = presigned_uri(PresignInput {
        sign_time: AmzTime {
            date: "20260102",
            timestamp: "20260102T030605Z",
            system_time: system_time(2026, 1, 2, 3, 6, 5),
        },
        ..PresignInput::default()
    });
    let result = verifier.verify("GET", future_uri.as_bytes(), TEST_HOST, test_now());
    require_denied(result, REASON_FUTURE_DATED);

    let mut short_lived = test_credential();
    short_lived.max_expires = Duration::from_secs(60);
    let over_credential_max = presigned_uri(PresignInput {
        expires: Duration::from_secs(120),
        ..PresignInput::default()
    });
    let result = new_test_verifier(vec![short_lived]).verify(
        "GET",
        over_credential_max.as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_INVALID_EXPIRY);

    let over_sigv4_max = presigned_uri(PresignInput {
        expires: MAX_SIGV4_EXPIRES + Duration::from_secs(1),
        ..PresignInput::default()
    });
    let result = verifier.verify("GET", over_sigv4_max.as_bytes(), TEST_HOST, test_now());
    require_denied(result, REASON_INVALID_EXPIRY);
}

#[test]
fn rejects_signature_mismatch_and_malformed_signature() {
    let verifier = new_test_verifier(vec![]);
    let raw_uri = presigned_uri(PresignInput::default());

    let result = verifier.verify(
        "GET",
        replace_query_param(&raw_uri, "X-Amz-Signature", &tampered_signature(&raw_uri)).as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_SIGNATURE_MISMATCH);

    let result = verifier.verify(
        "GET",
        replace_query_param(&raw_uri, "X-Amz-Signature", &"z".repeat(64)).as_bytes(),
        TEST_HOST,
        test_now(),
    );
    require_denied(result, REASON_SIGNATURE_MISMATCH);
}

#[test]
fn allows_canonical_path_cases() {
    let verifier = new_test_verifier(vec![]);

    for path in [
        "/bucket/file.jpg",
        "/bucket/path/to/file.jpg",
        "/bucket/a%20b.jpg",
        "/bucket/a+b.jpg",
        "/bucket/a%2Bb.jpg",
        "/bucket/%E2%9C%93.jpg",
        "/bucket/a%252Fb.jpg",
    ] {
        let raw_uri = presigned_uri(PresignInput {
            path,
            ..PresignInput::default()
        });
        let result = verifier.verify("GET", raw_uri.as_bytes(), TEST_HOST, test_now());
        require_allowed(result, path.as_bytes());
    }
}

#[test]
fn allows_canonical_query_cases() {
    let verifier = new_test_verifier(vec![]);

    let tests = [
        (
            "repeated params",
            vec![qp("partNumber", "2"), qp("partNumber", "1")],
        ),
        ("empty value", vec![qp("empty", "")]),
        ("space as percent 20", vec![qp("note", "a%20b")]),
        ("plus as percent 2B", vec![qp("note", "a%2Bb")]),
        (
            "response content disposition",
            vec![qp(
                "response-content-disposition",
                uri_encode_str("attachment; filename=\"a b.jpg\""),
            )],
        ),
    ];

    for (name, extra) in tests {
        let raw_uri = presigned_uri(PresignInput {
            extra,
            ..PresignInput::default()
        });
        let result = verifier.verify("GET", raw_uri.as_bytes(), TEST_HOST, test_now());
        assert!(result.allowed, "{name}: denied with {}", result.reason);
    }
}

#[test]
fn rejects_traversal_and_ambiguous_paths() {
    let verifier = new_test_verifier(vec![]);
    let raw_uri = presigned_uri(PresignInput::default());

    for path in [
        "/bucket/../secret",
        "/bucket/%2e%2e/secret",
        "/bucket/a//b",
        "/bucket/%2Fsecret",
        "/bucket/%5Csecret",
        "/bucket/%zz",
        "/bucket/file name",
    ] {
        let result = verifier.verify(
            "GET",
            replace_uri_path(&raw_uri, path).as_bytes(),
            TEST_HOST,
            test_now(),
        );
        require_denied(result, REASON_INVALID_URI);
    }
}

#[test]
fn binds_signature_to_client_method_and_host() {
    let verifier = new_test_verifier(vec![]);

    let head_uri = presigned_uri(PresignInput {
        method: "HEAD",
        ..PresignInput::default()
    });
    let result = verifier.verify("GET", head_uri.as_bytes(), TEST_HOST, test_now());
    require_denied(result, REASON_SIGNATURE_MISMATCH);

    let raw_uri = presigned_uri(PresignInput::default());
    let result = verifier.verify("GET", raw_uri.as_bytes(), "other.example.com", test_now());
    require_denied(result, REASON_UNAUTHORIZED);
}

#[test]
fn validates_configuration_before_serving_requests() {
    let settings = test_settings();

    let duplicate = vec![test_credential(), test_credential()];
    assert!(Verifier::new(settings.clone(), duplicate).is_err());

    let mut no_secret = test_credential();
    no_secret.secret_key.clear();
    assert!(Verifier::new(settings.clone(), vec![no_secret]).is_err());

    let mut invalid_method = test_credential();
    invalid_method.allowed_methods = vec!["POST".to_string()];
    assert!(Verifier::new(settings.clone(), vec![invalid_method]).is_err());

    let mut invalid_host = test_credential();
    invalid_host.allowed_hosts = vec!["assets.example.com/path".to_string()];
    assert!(Verifier::new(settings.clone(), vec![invalid_host]).is_err());

    let mut invalid_prefix = test_credential();
    invalid_prefix.allowed_prefixes = vec![b"/bucket/../secret".to_vec()];
    assert!(Verifier::new(settings.clone(), vec![invalid_prefix]).is_err());

    let mut invalid_service = settings;
    invalid_service.supported_service = "ec2".to_string();
    assert!(Verifier::new(invalid_service, vec![test_credential()]).is_err());
}

#[derive(Clone)]
struct AmzTime {
    date: &'static str,
    timestamp: &'static str,
    system_time: SystemTime,
}

#[derive(Clone)]
struct RawQueryParam {
    name: String,
    value: String,
}

#[derive(Clone)]
struct PresignInput<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
    sign_time: AmzTime,
    expires: Duration,
    extra: Vec<RawQueryParam>,
}

impl Default for PresignInput<'_> {
    fn default() -> Self {
        Self {
            method: "GET",
            path: "/bucket/file.jpg",
            host: TEST_HOST,
            access_key: TEST_ACCESS_KEY,
            secret_key: TEST_SECRET_KEY,
            region: TEST_REGION,
            sign_time: test_amz_time(),
            expires: Duration::from_secs(5 * 60),
            extra: Vec::new(),
        }
    }
}

fn new_test_verifier(credentials: Vec<Credential>) -> Verifier {
    let credentials = if credentials.is_empty() {
        vec![test_credential()]
    } else {
        credentials
    };
    Verifier::new(test_settings(), credentials).expect("test verifier config is valid")
}

fn test_settings() -> Settings {
    Settings {
        allowed_clock_skew: Duration::from_secs(60),
        default_max_expires: Duration::from_secs(60 * 60),
        supported_methods: vec!["GET".to_string(), "HEAD".to_string()],
        supported_service: TEST_SERVICE.to_string(),
    }
}

fn test_credential() -> Credential {
    Credential {
        access_key: TEST_ACCESS_KEY.to_string(),
        secret_key: TEST_SECRET_KEY.to_string(),
        enabled: true,
        max_expires: Duration::from_secs(60 * 60),
        allowed_hosts: vec![TEST_HOST.to_string()],
        allowed_methods: vec!["GET".to_string(), "HEAD".to_string()],
        allowed_prefixes: vec![b"/bucket/".to_vec()],
    }
}

fn presigned_uri(input: PresignInput<'_>) -> String {
    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        input.sign_time.date, input.region, TEST_SERVICE
    );
    let mut params = vec![
        qp("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        qp(
            "X-Amz-Credential",
            uri_encode_str(&format!("{}/{}", input.access_key, credential_scope)),
        ),
        qp("X-Amz-Date", input.sign_time.timestamp),
        qp("X-Amz-Expires", input.expires.as_secs().to_string()),
        qp("X-Amz-SignedHeaders", "host"),
    ];
    params.extend(input.extra);

    let raw_query = join_raw_query(&params);
    let canonical_path = test_canonical_path(input.path.as_bytes());
    let canonical_query = test_canonical_query(raw_query.as_bytes());
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
        input.sign_time.timestamp,
        credential_scope,
        hex_lower(&canonical_hash),
    );
    let signature = test_signature(
        input.secret_key,
        input.sign_time.date,
        input.region,
        TEST_SERVICE,
        string_to_sign.as_bytes(),
    );

    format!(
        "{}?{}&X-Amz-Signature={}",
        input.path,
        raw_query,
        hex_lower(&signature)
    )
}

fn require_allowed(result: VerifyResult, path: &[u8]) {
    assert!(result.allowed, "denied with {}", result.reason);
    assert_eq!(result.reason, REASON_OK);
    assert_eq!(result.path, path);
    assert_eq!(result.access_key.as_deref(), Some(TEST_ACCESS_KEY));
    assert_eq!(result.access_key_hash, hash_access_key(TEST_ACCESS_KEY));
}

fn require_denied(result: VerifyResult, reason: &'static str) {
    assert!(!result.allowed, "allowed request, want deny {reason}");
    assert_eq!(result.reason, reason);
}

fn test_now() -> SystemTime {
    test_amz_time().system_time
}

fn test_amz_time() -> AmzTime {
    AmzTime {
        date: "20260102",
        timestamp: "20260102T030405Z",
        system_time: system_time(2026, 1, 2, 3, 4, 5),
    }
}

fn remove_query_param(raw_uri: &str, key: &str) -> String {
    let Some((path, query)) = raw_uri.split_once('?') else {
        return raw_uri.to_string();
    };
    let parts: Vec<_> = query
        .split('&')
        .filter(|part| part.split_once('=').map(|(name, _)| name) != Some(key))
        .collect();
    format!("{path}?{}", parts.join("&"))
}

fn replace_query_param(raw_uri: &str, key: &str, raw_value: &str) -> String {
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

fn replace_uri_path(raw_uri: &str, path: &str) -> String {
    let Some((_, query)) = raw_uri.split_once('?') else {
        return path.to_string();
    };
    format!("{path}?{query}")
}

fn tampered_signature(raw_uri: &str) -> String {
    let Some((_, query)) = raw_uri.split_once('?') else {
        return "0".repeat(64);
    };
    for part in query.split('&') {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name == "X-Amz-Signature" && !value.is_empty() {
            let replacement = if value.as_bytes()[0] == b'0' {
                '1'
            } else {
                '0'
            };
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

fn test_canonical_query(raw_query: &[u8]) -> Vec<u8> {
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

fn test_canonical_path(raw_path: &[u8]) -> Vec<u8> {
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

fn qp(name: &str, value: impl Into<String>) -> RawQueryParam {
    RawQueryParam {
        name: name.to_string(),
        value: value.into(),
    }
}

fn test_signature(
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
