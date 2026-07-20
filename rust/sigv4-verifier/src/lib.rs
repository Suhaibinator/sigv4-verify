use ring::{digest, hmac};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const REASON_OK: &str = "ok";
pub const REASON_MISSING_METADATA: &str = "missing_metadata";
pub const REASON_INVALID_URI: &str = "invalid_uri";
pub const REASON_UNSUPPORTED_METHOD: &str = "unsupported_method";
pub const REASON_MISSING_QUERY_PARAM: &str = "missing_query_param";
pub const REASON_UNSUPPORTED_ALGORITHM: &str = "unsupported_algorithm";
pub const REASON_INVALID_CREDENTIAL_SCOPE: &str = "invalid_credential_scope";
pub const REASON_UNKNOWN_ACCESS_KEY: &str = "unknown_access_key";
pub const REASON_INVALID_EXPIRY: &str = "invalid_expiry";
pub const REASON_EXPIRED: &str = "expired";
pub const REASON_FUTURE_DATED: &str = "future_dated";
pub const REASON_UNSUPPORTED_SIGNED_HEADER: &str = "unsupported_signed_header";
pub const REASON_SIGNATURE_MISMATCH: &str = "signature_mismatch";
pub const REASON_UNAUTHORIZED: &str = "unauthorized";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const TERMINAL: &str = "aws4_request";
const PAYLOAD_HASH: &str = "UNSIGNED-PAYLOAD";
const MAX_SIGV4_EXPIRES_SECS: u64 = 7 * 24 * 60 * 60;
const SIGNING_CACHE_CAPACITY: usize = 32;

pub const MAX_SIGV4_EXPIRES: Duration = Duration::from_secs(MAX_SIGV4_EXPIRES_SECS);

#[derive(Clone, Debug)]
pub struct Settings {
    pub allowed_clock_skew: Duration,
    pub default_max_expires: Duration,
    pub supported_methods: Vec<String>,
    pub supported_service: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allowed_clock_skew: Duration::from_secs(15 * 60),
            default_max_expires: MAX_SIGV4_EXPIRES,
            supported_methods: vec!["GET".to_string(), "HEAD".to_string()],
            supported_service: "s3".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Credential {
    pub access_key: String,
    pub secret_key: String,
    pub enabled: bool,
    pub max_expires: Duration,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_prefixes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyResult {
    pub allowed: bool,
    pub reason: &'static str,
    pub path: Vec<u8>,
    pub access_key: Option<String>,
    pub access_key_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone)]
pub struct Verifier {
    state: Arc<State>,
}

struct State {
    settings: Settings,
    credentials: HashMap<String, Arc<CompiledCredential>>,
    supported_methods: HashSet<String>,
}

struct CompiledCredential {
    access_key: String,
    access_key_hash: String,
    secret_seed: Zeroizing<Vec<u8>>,
    enabled: bool,
    max_expires: Duration,
    allowed_hosts: HashSet<String>,
    allowed_methods: HashSet<String>,
    allowed_prefixes: Vec<Vec<u8>>,
    signing_cache: RwLock<VecDeque<SigningKeyCacheEntry>>,
}

#[derive(Clone)]
struct SigningKeyCacheEntry {
    date: String,
    region: String,
    service: String,
    key: [u8; digest::SHA256_OUTPUT_LEN],
}

struct CredentialScope<'a> {
    access_key: &'a str,
    date: &'a str,
    region: &'a str,
    service: &'a str,
    terminal: &'a str,
    scope: &'a str,
}

struct ParsedAmzDate<'a> {
    date: &'a str,
    epoch_seconds: i64,
}

struct SigV4Query<'a> {
    algorithm: Cow<'a, str>,
    algorithm_count: usize,
    credential: Cow<'a, str>,
    credential_count: usize,
    date: Cow<'a, str>,
    date_count: usize,
    expires: Cow<'a, str>,
    expires_count: usize,
    signed_headers: Cow<'a, str>,
    signed_headers_count: usize,
    signature: Cow<'a, str>,
    signature_count: usize,
}

impl Default for SigV4Query<'_> {
    fn default() -> Self {
        Self {
            algorithm: Cow::Borrowed(""),
            algorithm_count: 0,
            credential: Cow::Borrowed(""),
            credential_count: 0,
            date: Cow::Borrowed(""),
            date_count: 0,
            expires: Cow::Borrowed(""),
            expires_count: 0,
            signed_headers: Cow::Borrowed(""),
            signed_headers_count: 0,
            signature: Cow::Borrowed(""),
            signature_count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UriError;

impl Verifier {
    pub fn new(settings: Settings, credentials: Vec<Credential>) -> Result<Self, ConfigError> {
        Ok(Self {
            state: Arc::new(compile_state(settings, credentials)?),
        })
    }

    pub fn reload(
        &mut self,
        settings: Settings,
        credentials: Vec<Credential>,
    ) -> Result<(), ConfigError> {
        self.state = Arc::new(compile_state(settings, credentials)?);
        Ok(())
    }

    pub fn ready(&self) -> bool {
        !self.state.credentials.is_empty()
    }

    pub fn credential_count(&self) -> usize {
        self.state.credentials.len()
    }

    pub fn verify(
        &self,
        method: &str,
        raw_uri: &[u8],
        host: &str,
        now: SystemTime,
    ) -> VerifyResult {
        let method = ascii_upper_cow(method.trim());
        let host = ascii_lower_cow(host.trim());
        if method.is_empty() || raw_uri.is_empty() || host.is_empty() {
            return deny(REASON_MISSING_METADATA, Vec::new(), "");
        }
        if !self.state.supported_methods.contains(method.as_ref()) {
            let path = split_original_uri(raw_uri)
                .map(|(path, _)| path.to_vec())
                .unwrap_or_default();
            return deny(REASON_UNSUPPORTED_METHOD, path, "");
        }

        let (raw_path, raw_query) = match split_original_uri(raw_uri) {
            Ok(parts) => parts,
            Err(_) => return deny(REASON_INVALID_URI, Vec::new(), ""),
        };
        let path = raw_path.to_vec();
        let (canonical_query_string, query) = match canonical_query(raw_query) {
            Ok(parts) => parts,
            Err(_) => return deny(REASON_INVALID_URI, path, ""),
        };

        let Some(alg) = single_known_query_value(&query.algorithm, query.algorithm_count) else {
            return deny(REASON_MISSING_QUERY_PARAM, path, "");
        };
        if alg != ALGORITHM {
            return deny(REASON_UNSUPPORTED_ALGORITHM, path, "");
        }

        let Some(credential_value) =
            single_known_query_value(&query.credential, query.credential_count)
        else {
            return deny(REASON_MISSING_QUERY_PARAM, path, "");
        };
        let scope = match parse_credential_scope(credential_value) {
            Ok(scope) => scope,
            Err(_) => return deny(REASON_INVALID_CREDENTIAL_SCOPE, path, ""),
        };
        if scope.service != self.state.settings.supported_service || scope.terminal != TERMINAL {
            return deny(
                REASON_INVALID_CREDENTIAL_SCOPE,
                path,
                &hash_access_key(scope.access_key),
            );
        }

        let Some(signed_headers) =
            single_known_query_value(&query.signed_headers, query.signed_headers_count)
        else {
            return deny(
                REASON_MISSING_QUERY_PARAM,
                path,
                &hash_access_key(scope.access_key),
            );
        };
        if signed_headers != "host" {
            return deny(
                REASON_UNSUPPORTED_SIGNED_HEADER,
                path,
                &hash_access_key(scope.access_key),
            );
        }

        let Some(amz_date) = single_known_query_value(&query.date, query.date_count) else {
            return deny(
                REASON_MISSING_QUERY_PARAM,
                path,
                &hash_access_key(scope.access_key),
            );
        };
        let parsed_date = match parse_amz_date(amz_date) {
            Some(parsed) if parsed.date == scope.date => parsed,
            _ => {
                return deny(
                    REASON_INVALID_CREDENTIAL_SCOPE,
                    path,
                    &hash_access_key(scope.access_key),
                );
            }
        };

        let Some(expires_value) = single_known_query_value(&query.expires, query.expires_count)
        else {
            return deny(
                REASON_MISSING_QUERY_PARAM,
                path,
                &hash_access_key(scope.access_key),
            );
        };
        let Ok(expires_seconds) = expires_value.parse::<u64>() else {
            return deny(
                REASON_INVALID_EXPIRY,
                path,
                &hash_access_key(scope.access_key),
            );
        };
        if expires_seconds == 0 || expires_seconds > MAX_SIGV4_EXPIRES_SECS {
            return deny(
                REASON_INVALID_EXPIRY,
                path,
                &hash_access_key(scope.access_key),
            );
        }

        if single_known_query_value(&query.signature, query.signature_count).is_none() {
            return deny(
                REASON_MISSING_QUERY_PARAM,
                path,
                &hash_access_key(scope.access_key),
            );
        }

        let Some(cred) = self.state.credentials.get(scope.access_key) else {
            return deny(
                REASON_UNKNOWN_ACCESS_KEY,
                path,
                &hash_access_key(scope.access_key),
            );
        };
        let access_key_hash = cred.access_key_hash.clone();
        if !cred.enabled {
            return deny(REASON_UNAUTHORIZED, path, &access_key_hash);
        }
        if !cred.method_allowed(&method)
            || !cred.host_allowed(&host)
            || !cred.path_allowed(raw_path)
        {
            return deny(REASON_UNAUTHORIZED, path, &access_key_hash);
        }
        if Duration::from_secs(expires_seconds) > cred.max_expires {
            return deny(REASON_INVALID_EXPIRY, path, &access_key_hash);
        }

        let now_seconds = system_time_epoch_seconds(now);
        let skew = saturating_duration_i64(self.state.settings.allowed_clock_skew);
        if parsed_date.epoch_seconds > now_seconds.saturating_add(skew) {
            return deny(REASON_FUTURE_DATED, path, &access_key_hash);
        }
        if now_seconds
            > parsed_date
                .epoch_seconds
                .saturating_add(expires_seconds.min(i64::MAX as u64) as i64)
        {
            return deny(REASON_EXPIRED, path, &access_key_hash);
        }

        let canonical_path = canonical_uri_from_valid_path(raw_path);
        let canonical_hash =
            hash_canonical_request(&method, &canonical_path, &canonical_query_string, &host);
        let expected = sign(
            cred,
            scope.date,
            scope.region,
            scope.service,
            amz_date,
            scope.scope,
            canonical_hash,
        );

        let signature_hex = single_known_query_value(&query.signature, query.signature_count)
            .expect("signature was checked above");
        let signature = match decode_signature(signature_hex) {
            Some(signature) => signature,
            None => return deny(REASON_SIGNATURE_MISMATCH, path, &access_key_hash),
        };
        if signature.ct_eq(&expected).unwrap_u8() != 1 {
            return deny(REASON_SIGNATURE_MISMATCH, path, &access_key_hash);
        }

        VerifyResult {
            allowed: true,
            reason: REASON_OK,
            path,
            access_key: Some(cred.access_key.clone()),
            access_key_hash,
        }
    }
}

fn compile_state(
    mut settings: Settings,
    credentials: Vec<Credential>,
) -> Result<State, ConfigError> {
    if settings.default_max_expires.is_zero() || settings.default_max_expires > MAX_SIGV4_EXPIRES {
        settings.default_max_expires = MAX_SIGV4_EXPIRES;
    }
    settings.supported_service = settings.supported_service.trim().to_string();
    if settings.supported_service.is_empty() {
        settings.supported_service = "s3".to_string();
    }
    if settings.supported_service != "s3" {
        return Err(ConfigError::new(format!(
            "unsupported service {:?}",
            settings.supported_service
        )));
    }
    if settings.supported_methods.is_empty() {
        settings.supported_methods = vec!["GET".to_string(), "HEAD".to_string()];
    }

    let mut supported_methods = HashSet::with_capacity(settings.supported_methods.len());
    for method in &settings.supported_methods {
        let method = normalize_method(method)?;
        supported_methods.insert(method);
    }

    let mut compiled_credentials = HashMap::with_capacity(credentials.len());
    for credential in credentials {
        let compiled = compile_credential(credential, settings.default_max_expires)?;
        if compiled_credentials
            .insert(compiled.access_key.clone(), Arc::new(compiled))
            .is_some()
        {
            return Err(ConfigError::new("duplicate access key"));
        }
    }

    Ok(State {
        settings,
        credentials: compiled_credentials,
        supported_methods,
    })
}

fn compile_credential(
    credential: Credential,
    default_max_expires: Duration,
) -> Result<CompiledCredential, ConfigError> {
    let access_key = credential.access_key.trim().to_string();
    if access_key.is_empty() {
        return Err(ConfigError::new("access key is required"));
    }
    if credential.secret_key.is_empty() {
        return Err(ConfigError::new(format!(
            "secret key for {:?} is required",
            access_key
        )));
    }

    let max_expires = if credential.max_expires.is_zero() {
        default_max_expires
    } else {
        credential.max_expires
    };
    if max_expires.is_zero() || max_expires > MAX_SIGV4_EXPIRES {
        return Err(ConfigError::new(format!(
            "invalid max expires for {:?}",
            access_key
        )));
    }

    let mut allowed_hosts = HashSet::with_capacity(credential.allowed_hosts.len());
    for host in credential.allowed_hosts {
        let host = normalize_host(&host)?;
        if !host.is_empty() {
            allowed_hosts.insert(host);
        }
    }

    let mut allowed_methods = HashSet::with_capacity(credential.allowed_methods.len());
    for method in credential.allowed_methods {
        let method = normalize_method(&method)?;
        allowed_methods.insert(method);
    }

    let mut allowed_prefixes = Vec::with_capacity(credential.allowed_prefixes.len());
    let mut seen_prefixes = HashSet::with_capacity(credential.allowed_prefixes.len());
    for prefix in credential.allowed_prefixes {
        if prefix.is_empty() {
            continue;
        }
        validate_raw_path(&prefix).map_err(|_| ConfigError::new("invalid allowed prefix"))?;
        if seen_prefixes.insert(prefix.clone()) {
            allowed_prefixes.push(prefix);
        }
    }

    let mut secret_key = credential.secret_key;
    let mut secret_seed = Vec::with_capacity("AWS4".len() + secret_key.len());
    secret_seed.extend_from_slice(b"AWS4");
    secret_seed.extend_from_slice(secret_key.as_bytes());
    secret_key.zeroize();

    Ok(CompiledCredential {
        access_key: access_key.clone(),
        access_key_hash: hash_access_key(&access_key),
        secret_seed: Zeroizing::new(secret_seed),
        enabled: credential.enabled,
        max_expires,
        allowed_hosts,
        allowed_methods,
        allowed_prefixes,
        signing_cache: RwLock::new(VecDeque::with_capacity(SIGNING_CACHE_CAPACITY)),
    })
}

fn ascii_upper_cow(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|b| b.is_ascii_lowercase()) {
        Cow::Owned(value.to_ascii_uppercase())
    } else {
        Cow::Borrowed(value)
    }
}

fn ascii_lower_cow(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

fn normalize_method(method: &str) -> Result<String, ConfigError> {
    let method = method.trim().to_ascii_uppercase();
    match method.as_str() {
        "GET" | "HEAD" => Ok(method),
        _ => Err(ConfigError::new(format!("unsupported method {:?}", method))),
    }
}

fn normalize_host(host: &str) -> Result<String, ConfigError> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Ok(host);
    }
    if host
        .bytes()
        .any(|b| matches!(b, b'/' | b'\\' | b'?' | b'#' | b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Err(ConfigError::new(format!("ambiguous host {:?}", host)));
    }
    Ok(host)
}

fn parse_credential_scope(value: &str) -> Result<CredentialScope<'_>, UriError> {
    let mut parts = value.split('/');
    let ((Some(access_key), Some(date), Some(region), Some(service), Some(terminal)), None) = (
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        parts.next(),
    ) else {
        return Err(UriError);
    };
    if access_key.is_empty()
        || region.is_empty()
        || service.is_empty()
        || terminal.is_empty()
        || date.len() != 8
        || !date.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(UriError);
    }

    Ok(CredentialScope {
        access_key,
        date,
        region,
        service,
        terminal,
        // Everything after the first '/'; identical to re-joining the four
        // trailing components since they were split on '/'.
        scope: &value[access_key.len() + 1..],
    })
}

fn split_original_uri(raw_uri: &[u8]) -> Result<(&[u8], &[u8]), UriError> {
    if raw_uri.first().copied() != Some(b'/') {
        return Err(UriError);
    }
    if raw_uri
        .iter()
        .any(|b| matches!(*b, b'\r' | b'\n' | b'\t' | b' ' | b'#'))
    {
        return Err(UriError);
    }
    let (path, query) = match raw_uri.iter().position(|b| *b == b'?') {
        Some(idx) => (&raw_uri[..idx], &raw_uri[idx + 1..]),
        None => (raw_uri, &[][..]),
    };
    validate_raw_path(path)?;
    Ok((path, query))
}

fn validate_raw_path(path: &[u8]) -> Result<(), UriError> {
    if path.first().copied() != Some(b'/') {
        return Err(UriError);
    }
    if path.windows(2).any(|w| w == b"//") {
        return Err(UriError);
    }

    let mut i = 0;
    while i < path.len() {
        let b = path[i];
        if b <= 0x20 || b == 0x7f {
            return Err(UriError);
        }
        if b != b'%' {
            i += 1;
            continue;
        }
        if i + 2 >= path.len() || !is_hex(path[i + 1]) || !is_hex(path[i + 2]) {
            return Err(UriError);
        }
        let hi = upper_hex(path[i + 1]);
        let lo = upper_hex(path[i + 2]);
        if (hi == b'2' && lo == b'F') || (hi == b'5' && lo == b'C') {
            return Err(UriError);
        }
        i += 3;
    }

    let mut start = 1;
    while start <= path.len() {
        let end = path[start..]
            .iter()
            .position(|b| *b == b'/')
            .map(|rel| start + rel)
            .unwrap_or(path.len());
        let segment = &path[start..end];
        if !segment.is_empty() {
            if !segment.contains(&b'%') {
                if segment == b"." || segment == b".." {
                    return Err(UriError);
                }
            } else {
                let decoded = percent_decode(segment)?;
                if decoded == b"." || decoded == b".." {
                    return Err(UriError);
                }
            }
        }
        start = end + 1;
    }
    Ok(())
}

fn canonical_uri_from_valid_path(raw_path: &[u8]) -> Cow<'_, [u8]> {
    if is_canonical_path(raw_path) {
        return Cow::Borrowed(raw_path);
    }
    let mut out = Vec::with_capacity(raw_path.len() + 8);
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
    Cow::Owned(out)
}

fn is_canonical_path(raw_path: &[u8]) -> bool {
    let mut i = 0;
    while i < raw_path.len() {
        let c = raw_path[i];
        if c == b'/' || is_unreserved(c) {
            i += 1;
            continue;
        }
        if c == b'%' && i + 2 < raw_path.len() && is_hex(raw_path[i + 1]) && is_hex(raw_path[i + 2])
        {
            if raw_path[i + 1] != upper_hex(raw_path[i + 1])
                || raw_path[i + 2] != upper_hex(raw_path[i + 2])
            {
                return false;
            }
            i += 3;
            continue;
        }
        return false;
    }
    true
}

fn canonical_query(raw_query: &[u8]) -> Result<(Vec<u8>, SigV4Query<'_>), UriError> {
    let mut values: SigV4Query<'_> = SigV4Query::default();
    if raw_query.is_empty() {
        return Ok((Vec::new(), values));
    }
    if raw_query.last().copied() == Some(b'&') {
        return Err(UriError);
    }

    let mut params = Vec::with_capacity(raw_query.iter().filter(|b| **b == b'&').count() + 1);
    let mut start = 0;
    while start < raw_query.len() {
        let end = raw_query[start..]
            .iter()
            .position(|b| *b == b'&')
            .map(|rel| start + rel)
            .unwrap_or(raw_query.len());
        if end == start {
            return Err(UriError);
        }
        let part = &raw_query[start..end];
        let eq = part.iter().position(|b| *b == b'=').unwrap_or(part.len());
        let name_raw = &part[..eq];
        let value_raw = if eq < part.len() {
            &part[eq + 1..]
        } else {
            &[][..]
        };

        let (encoded_name, decoded_name) = canonicalize_query_component(name_raw, true)?;
        let decoded_name = decoded_name.expect("query names are decoded");
        if decoded_name.is_empty() {
            return Err(UriError);
        }

        if decoded_name.as_ref() == b"X-Amz-Signature" {
            let (_, decoded_value) = canonicalize_query_component(value_raw, true)?;
            values.set(
                &decoded_name,
                decoded_value.expect("signature value is decoded"),
            )?;
            start = end + 1;
            continue;
        }

        let known_name = is_known_query_name(&decoded_name);
        let (encoded_value, decoded_value) = canonicalize_query_component(value_raw, known_name)?;
        if known_name {
            values.set(
                &decoded_name,
                decoded_value.expect("known query value is decoded"),
            )?;
        }
        params.push(CanonicalQueryParam {
            name: encoded_name,
            value: encoded_value,
        });
        start = end + 1;
    }

    // Ties are byte-identical under this comparator (name and value both
    // compare equal), so an unstable sort is observationally identical to a
    // stable one and avoids the stable sort's auxiliary allocation.
    params.sort_unstable_by(|a, b| match a.name.cmp(&b.name) {
        std::cmp::Ordering::Equal => a.value.cmp(&b.value),
        ordering => ordering,
    });

    let capacity = params
        .iter()
        .map(|param| param.name.len() + param.value.len() + 2)
        .sum();
    let mut out = Vec::with_capacity(capacity);
    for (idx, param) in params.iter().enumerate() {
        if idx > 0 {
            out.push(b'&');
        }
        out.extend_from_slice(&param.name);
        out.push(b'=');
        out.extend_from_slice(&param.value);
    }
    Ok((out, values))
}

struct CanonicalQueryParam<'a> {
    name: Cow<'a, [u8]>,
    value: Cow<'a, [u8]>,
}

impl<'a> SigV4Query<'a> {
    fn set(&mut self, name: &[u8], value: Cow<'a, [u8]>) -> Result<(), UriError> {
        let value: Cow<'a, str> = match value {
            Cow::Borrowed(bytes) => {
                Cow::Borrowed(std::str::from_utf8(bytes).map_err(|_| UriError)?)
            }
            Cow::Owned(bytes) => Cow::Owned(String::from_utf8(bytes).map_err(|_| UriError)?),
        };
        match name {
            b"X-Amz-Algorithm" => {
                self.algorithm = value;
                self.algorithm_count += 1;
            }
            b"X-Amz-Credential" => {
                self.credential = value;
                self.credential_count += 1;
            }
            b"X-Amz-Date" => {
                self.date = value;
                self.date_count += 1;
            }
            b"X-Amz-Expires" => {
                self.expires = value;
                self.expires_count += 1;
            }
            b"X-Amz-SignedHeaders" => {
                self.signed_headers = value;
                self.signed_headers_count += 1;
            }
            b"X-Amz-Signature" => {
                self.signature = value;
                self.signature_count += 1;
            }
            _ => {}
        }
        Ok(())
    }
}

fn is_known_query_name(name: &[u8]) -> bool {
    matches!(
        name,
        b"X-Amz-Algorithm"
            | b"X-Amz-Credential"
            | b"X-Amz-Date"
            | b"X-Amz-Expires"
            | b"X-Amz-SignedHeaders"
            | b"X-Amz-Signature"
    )
}

fn single_known_query_value(value: &str, count: usize) -> Option<&str> {
    if count == 1 { Some(value) } else { None }
}

/// A canonically re-encoded query component and, when requested, its
/// percent-decoded form. Both borrow the input when it is already canonical.
type QueryComponent<'a> = (Cow<'a, [u8]>, Option<Cow<'a, [u8]>>);

fn canonicalize_query_component(
    raw: &[u8],
    want_decoded: bool,
) -> Result<QueryComponent<'_>, UriError> {
    let slow = query_component_needs_slow_path(raw)?;
    if !slow {
        return Ok((
            Cow::Borrowed(raw),
            want_decoded.then_some(Cow::Borrowed(raw)),
        ));
    }

    let mut encoded: Vec<u8> = Vec::with_capacity(raw.len() + 8);
    let mut decoded: Option<Vec<u8>> = want_decoded.then(|| Vec::with_capacity(raw.len()));
    let mut i = 0;
    while i < raw.len() {
        let c: u8 = raw[i];
        let b: u8 = if c == b'%' {
            if i + 2 >= raw.len() || !is_hex(raw[i + 1]) || !is_hex(raw[i + 2]) {
                return Err(UriError);
            }
            let b = from_hex(raw[i + 1]) << 4 | from_hex(raw[i + 2]);
            i += 3;
            b
        } else {
            i += 1;
            c
        };

        if let Some(decoded) = decoded.as_mut() {
            decoded.push(b);
        }
        if is_unreserved(b) {
            encoded.push(b);
        } else {
            write_escaped_byte(&mut encoded, b);
        }
    }
    Ok((Cow::Owned(encoded), decoded.map(Cow::Owned)))
}

fn query_component_needs_slow_path(raw: &[u8]) -> Result<bool, UriError> {
    let mut slow = false;
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'%' {
            if i + 2 >= raw.len() || !is_hex(raw[i + 1]) || !is_hex(raw[i + 2]) {
                return Err(UriError);
            }
            slow = true;
            i += 3;
            continue;
        }
        if !is_unreserved(c) {
            slow = true;
        }
        i += 1;
    }
    Ok(slow)
}

fn percent_decode(value: &[u8]) -> Result<Vec<u8>, UriError> {
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        let c = value[i];
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        if i + 2 >= value.len() || !is_hex(value[i + 1]) || !is_hex(value[i + 2]) {
            return Err(UriError);
        }
        out.push(from_hex(value[i + 1]) << 4 | from_hex(value[i + 2]));
        i += 3;
    }
    Ok(out)
}

fn hash_canonical_request(
    method: &str,
    canonical_path: &[u8],
    canonical_query_string: &[u8],
    canonical_host: &str,
) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let mut canonical = Vec::with_capacity(
        method.len()
            + canonical_path.len()
            + canonical_query_string.len()
            + canonical_host.len()
            + 64,
    );
    canonical.extend_from_slice(method.as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(canonical_path);
    canonical.push(b'\n');
    canonical.extend_from_slice(canonical_query_string);
    canonical.extend_from_slice(b"\nhost:");
    canonical.extend_from_slice(canonical_host.as_bytes());
    canonical.extend_from_slice(b"\n\nhost\n");
    canonical.extend_from_slice(PAYLOAD_HASH.as_bytes());
    sha256(&canonical)
}

fn sign(
    cred: &CompiledCredential,
    date: &str,
    region: &str,
    service: &str,
    amz_date: &str,
    credential_scope: &str,
    canonical_hash: [u8; digest::SHA256_OUTPUT_LEN],
) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let signing_key = cred.signing_key(date, region, service);
    let mut string_to_sign =
        Vec::with_capacity(ALGORITHM.len() + amz_date.len() + credential_scope.len() + 98);
    string_to_sign.extend_from_slice(ALGORITHM.as_bytes());
    string_to_sign.push(b'\n');
    string_to_sign.extend_from_slice(amz_date.as_bytes());
    string_to_sign.push(b'\n');
    string_to_sign.extend_from_slice(credential_scope.as_bytes());
    string_to_sign.push(b'\n');
    append_hex_lower(&mut string_to_sign, &canonical_hash);
    hmac_sha256(&signing_key, &string_to_sign)
}

impl CompiledCredential {
    fn signing_key(
        &self,
        date: &str,
        region: &str,
        service: &str,
    ) -> [u8; digest::SHA256_OUTPUT_LEN] {
        if let Ok(cache) = self.signing_cache.read()
            && let Some(cached) = cache.iter().find(|entry| {
                entry.date == date && entry.region == region && entry.service == service
            })
        {
            return cached.key;
        }

        let mut cache = self
            .signing_cache
            .write()
            .expect("signing key cache lock poisoned");
        if let Some(position) = cache.iter().position(|entry| {
            entry.date == date && entry.region == region && entry.service == service
        }) {
            let cached = cache.remove(position).expect("cache position is valid");
            let key = cached.key;
            cache.push_front(cached);
            return key;
        }

        let k_date = hmac_sha256(&self.secret_seed, date.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        let key = hmac_sha256(&k_service, TERMINAL.as_bytes());
        cache.push_front(SigningKeyCacheEntry {
            date: date.to_string(),
            region: region.to_string(),
            service: service.to_string(),
            key,
        });
        while cache.len() > SIGNING_CACHE_CAPACITY {
            cache.pop_back();
        }
        key
    }

    fn method_allowed(&self, method: &str) -> bool {
        self.allowed_methods.is_empty() || self.allowed_methods.contains(method)
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.allowed_hosts.is_empty() || self.allowed_hosts.contains(host)
    }

    fn path_allowed(&self, path: &[u8]) -> bool {
        self.allowed_prefixes.is_empty()
            || self
                .allowed_prefixes
                .iter()
                .any(|prefix| path_matches_prefix(path, prefix))
    }
}

fn path_matches_prefix(path: &[u8], prefix: &[u8]) -> bool {
    path.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.is_empty() || prefix.ends_with(b"/") || suffix.starts_with(b"/")
    })
}

fn sha256(data: &[u8]) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let digest = digest::digest(&digest::SHA256, data);
    let mut out = [0; digest::SHA256_OUTPUT_LEN];
    out.copy_from_slice(digest.as_ref());
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut out = [0; digest::SHA256_OUTPUT_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

fn decode_signature(value: &str) -> Option<[u8; digest::SHA256_OUTPUT_LEN]> {
    let bytes = value.as_bytes();
    if bytes.len() != digest::SHA256_OUTPUT_LEN * 2 {
        return None;
    }
    let mut out = [0; digest::SHA256_OUTPUT_LEN];
    for idx in 0..digest::SHA256_OUTPUT_LEN {
        let hi = bytes[idx * 2];
        let lo = bytes[idx * 2 + 1];
        if !is_hex(hi) || !is_hex(lo) {
            return None;
        }
        out[idx] = from_hex(hi) << 4 | from_hex(lo);
    }
    Some(out)
}

fn deny(reason: &'static str, path: Vec<u8>, access_key_hash: &str) -> VerifyResult {
    VerifyResult {
        allowed: false,
        reason,
        path,
        access_key: None,
        access_key_hash: access_key_hash.to_string(),
    }
}

pub fn hash_access_key(access_key: &str) -> String {
    if access_key.is_empty() {
        return String::new();
    }
    let sum = sha256(access_key.as_bytes());
    let mut out = String::with_capacity("sha256:".len() + 16);
    out.push_str("sha256:");
    for b in &sum[..8] {
        out.push(hex_lower(b >> 4) as char);
        out.push(hex_lower(b & 0x0f) as char);
    }
    out
}

fn parse_amz_date(value: &str) -> Option<ParsedAmzDate<'_>> {
    let b = value.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let year = parse_digits_i32(&b[0..4])?;
    let month = parse_digits_u32(&b[4..6])?;
    let day = parse_digits_u32(&b[6..8])?;
    let hour = parse_digits_u32(&b[9..11])?;
    let minute = parse_digits_u32(&b[11..13])?;
    let second = parse_digits_u32(&b[13..15])?;

    if month == 0
        || month > 12
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let epoch_seconds = days
        .saturating_mul(86_400)
        .saturating_add((hour as i64) * 3_600)
        .saturating_add((minute as i64) * 60)
        .saturating_add(second as i64);
    Some(ParsedAmzDate {
        date: &value[..8],
        epoch_seconds,
    })
}

fn parse_digits_i32(bytes: &[u8]) -> Option<i32> {
    let mut out = 0i32;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.saturating_mul(10).saturating_add((b - b'0') as i32);
    }
    Some(out)
}

fn parse_digits_u32(bytes: &[u8]) -> Option<u32> {
    let mut out = 0u32;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    Some(out)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
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

fn system_time_epoch_seconds(value: SystemTime) -> i64 {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().min(i64::MAX as u64) as i64,
        Err(err) => -(err.duration().as_secs().min(i64::MAX as u64) as i64),
    }
}

fn saturating_duration_i64(value: Duration) -> i64 {
    value.as_secs().min(i64::MAX as u64) as i64
}

fn write_escaped_byte(out: &mut Vec<u8>, c: u8) {
    out.push(b'%');
    out.push(hex_upper(c >> 4));
    out.push(hex_upper(c & 0x0f));
}

fn append_hex_lower(out: &mut Vec<u8>, bytes: &[u8]) {
    for b in bytes {
        out.push(hex_lower(b >> 4));
        out.push(hex_lower(b & 0x0f));
    }
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

fn hex_upper(n: u8) -> u8 {
    b"0123456789ABCDEF"[n as usize]
}

fn hex_lower(n: u8) -> u8 {
    b"0123456789abcdef"[n as usize]
}

/// Thin wrappers over the private parser internals, exposed only for fuzzing.
///
/// This module is gated behind the `internals` feature and hidden from docs so
/// the public API surface is unchanged for normal builds. The wrappers copy
/// borrowed output into owned values and collapse the private error/result
/// types, but do not alter any parsing behavior.
#[cfg(feature = "internals")]
#[doc(hidden)]
pub mod internals {
    /// Split a raw request URI into its raw path and raw query components.
    pub fn split_original_uri(raw_uri: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        super::split_original_uri(raw_uri)
            .map(|(path, query)| (path.to_vec(), query.to_vec()))
            .ok()
    }

    /// Report whether a raw path is well-formed and unambiguous.
    pub fn validate_raw_path(path: &[u8]) -> bool {
        super::validate_raw_path(path).is_ok()
    }

    /// Percent-decode a byte slice, rejecting malformed escapes.
    pub fn percent_decode(value: &[u8]) -> Option<Vec<u8>> {
        super::percent_decode(value).ok()
    }

    /// Build the canonical query string from a raw query, discarding the parsed
    /// SigV4 parameter view.
    pub fn canonical_query(raw_query: &[u8]) -> Option<Vec<u8>> {
        super::canonical_query(raw_query)
            .map(|(canonical, _)| canonical)
            .ok()
    }

    /// Report whether a credential scope parses successfully.
    pub fn parse_credential_scope(value: &str) -> bool {
        super::parse_credential_scope(value).is_ok()
    }

    /// Re-encode a validated raw path into its canonical form.
    pub fn canonical_uri_from_valid_path(raw_path: &[u8]) -> Vec<u8> {
        super::canonical_uri_from_valid_path(raw_path).into_owned()
    }

    /// Parse an `X-Amz-Date` value, returning the epoch seconds on success.
    pub fn parse_amz_date(value: &str) -> Option<i64> {
        super::parse_amz_date(value).map(|parsed| parsed.epoch_seconds)
    }
}
