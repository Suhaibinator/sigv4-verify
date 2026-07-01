//! Directive parsing and validation for the sigv4-verify NGINX module.
//!
//! This crate is deliberately free of any NGINX dependency so the config
//! parser can be unit-tested on every platform. The NGINX glue crate only
//! tokenizes directive arguments and hands them here.
//!
//! Policy-list semantics are explicit: a credential must either list
//! allowed hosts/prefixes or opt out with `allow_any_host`/`allow_any_prefix`,
//! and must either list allowed methods or opt in to the module-wide
//! supported methods with `allow_default_methods`. This is stricter than the
//! Go sidecar, where an omitted list means "allow all".

use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use sigv4_verifier::{Credential, MAX_SIGV4_EXPIRES};
use zeroize::{Zeroize, Zeroizing};

/// Error produced while parsing or validating module configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectiveError {
    message: String,
}

impl DirectiveError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DirectiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DirectiveError {}

/// Per-location verification mode selected by `sigv4_verify`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Mode {
    /// Directive not present at this level; inherit from the outer level.
    #[default]
    Unset,
    /// Verification disabled: the access handler declines.
    Off,
    /// Enforce mode: failed verification is denied with 403.
    On,
    /// Shadow mode: verification runs and is observable, but never denies.
    Shadow,
}

impl Mode {
    /// Parses the `sigv4_verify` argument.
    pub fn parse(value: &str) -> Result<Self, DirectiveError> {
        match value {
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            "shadow" => Ok(Self::Shadow),
            other => Err(DirectiveError::new(format!(
                "invalid value {other:?}, expected \"on\", \"off\", or \"shadow\""
            ))),
        }
    }

    /// Merges a location-level value with the inherited outer value.
    pub fn merge(self, outer: Self) -> Self {
        match self {
            Self::Unset => match outer {
                Self::Unset => Self::Off,
                other => other,
            },
            other => other,
        }
    }

    /// True when requests must be verified (enforce or shadow).
    pub fn verifies(self) -> bool {
        matches!(self, Self::On | Self::Shadow)
    }
}

/// Parses `on`/`off` boolean directive arguments.
pub fn parse_on_off(value: &str) -> Result<bool, DirectiveError> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(DirectiveError::new(format!(
            "invalid value {other:?}, expected \"on\" or \"off\""
        ))),
    }
}

/// Parses an NGINX-style non-negative duration such as `30`, `90s`, `15m`,
/// `12h`, `7d`, `1w`, or a compound like `1h30m`.
///
/// A bare number means seconds. Negative values are unrepresentable by
/// construction, which satisfies the "reject negative clock skew" rule.
pub fn parse_duration(value: &str) -> Result<Duration, DirectiveError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(DirectiveError::new("empty duration"));
    }
    let err = || DirectiveError::new(format!("invalid duration {value:?}"));

    let mut total: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            return Err(err());
        }
        let mut number: u64 = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            number = number
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(bytes[i] - b'0')))
                .ok_or_else(err)?;
            i += 1;
        }
        let unit_seconds = if i < bytes.len() {
            let unit = bytes[i];
            i += 1;
            match unit {
                b's' => 1,
                b'm' => 60,
                b'h' => 60 * 60,
                b'd' => 24 * 60 * 60,
                b'w' => 7 * 24 * 60 * 60,
                _ => return Err(err()),
            }
        } else {
            1
        };
        total = number
            .checked_mul(unit_seconds)
            .and_then(|n| total.checked_add(n))
            .ok_or_else(err)?;
    }
    Ok(Duration::from_secs(total))
}

/// Where a credential secret comes from. Exactly one source is required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretSource {
    /// Secret loaded from a file at config load time.
    File(PathBuf),
    /// Inline secret literal; local development only.
    Literal(Zeroizing<String>),
}

/// One parsed `sigv4_verify_credential` directive, before secret loading and
/// policy validation.
#[derive(Clone, Debug, Default)]
pub struct CredentialDirective {
    /// SigV4 access key identifier.
    pub access_key: String,
    /// Secret source; `None` until a `secret_key_file=`/`secret_key=` argument is seen.
    pub secret: Option<SecretSource>,
    /// Per-credential enable flag; defaults to enabled.
    pub enabled: Option<bool>,
    /// Per-credential expiry cap; defaults to the module-wide default.
    pub max_expires: Option<Duration>,
    /// Explicit allowed host list.
    pub allowed_hosts: Vec<String>,
    /// Explicit opt-out of host restrictions.
    pub allow_any_host: bool,
    /// Explicit allowed method list.
    pub allowed_methods: Vec<String>,
    /// Explicit opt-in to the module-wide supported methods.
    pub allow_default_methods: bool,
    /// Explicit allowed path prefix list.
    pub allowed_prefixes: Vec<String>,
    /// Explicit opt-out of prefix restrictions.
    pub allow_any_prefix: bool,
}

impl CredentialDirective {
    /// Parses the arguments of one `sigv4_verify_credential` directive.
    ///
    /// `args[0]` is the access key; the rest are `key=value` pairs or bare
    /// flags. Unknown keys, empty values, and conflicting arguments are
    /// rejected so a mistyped policy list can never silently allow more than
    /// intended.
    pub fn parse(args: &[&str]) -> Result<Self, DirectiveError> {
        let Some((&access_key, rest)) = args.split_first() else {
            return Err(DirectiveError::new("missing access key"));
        };
        let access_key = access_key.trim();
        if access_key.is_empty() {
            return Err(DirectiveError::new("access key must not be empty"));
        }
        if access_key.contains('=') {
            return Err(DirectiveError::new(
                "the first argument must be the access key",
            ));
        }

        let mut directive = Self {
            access_key: access_key.to_string(),
            ..Self::default()
        };

        for &arg in rest {
            match arg {
                "allow_any_host" => {
                    directive.allow_any_host = true;
                    continue;
                }
                "allow_any_prefix" => {
                    directive.allow_any_prefix = true;
                    continue;
                }
                "allow_default_methods" => {
                    directive.allow_default_methods = true;
                    continue;
                }
                _ => {}
            }

            let Some((key, value)) = arg.split_once('=') else {
                return Err(DirectiveError::new(format!(
                    "unknown flag {arg:?}; expected key=value or one of \
                     allow_any_host, allow_any_prefix, allow_default_methods"
                )));
            };
            if value.is_empty() {
                return Err(DirectiveError::new(format!("{key:?} has an empty value")));
            }

            match key {
                "secret_key_file" => {
                    directive.set_secret(SecretSource::File(PathBuf::from(value)))?;
                }
                "secret_key" => {
                    directive
                        .set_secret(SecretSource::Literal(Zeroizing::new(value.to_string())))?;
                }
                "enabled" => {
                    if directive.enabled.is_some() {
                        return Err(DirectiveError::new("duplicate \"enabled\" argument"));
                    }
                    directive.enabled = Some(parse_on_off(value)?);
                }
                "max_expires" => {
                    if directive.max_expires.is_some() {
                        return Err(DirectiveError::new("duplicate \"max_expires\" argument"));
                    }
                    directive.max_expires = Some(parse_duration(value)?);
                }
                "allowed_host" => directive.allowed_hosts.push(value.to_string()),
                "allowed_method" => directive.allowed_methods.push(value.to_string()),
                "allowed_prefix" => directive.allowed_prefixes.push(value.to_string()),
                other => {
                    return Err(DirectiveError::new(format!("unknown argument {other:?}")));
                }
            }
        }

        directive.validate()?;
        Ok(directive)
    }

    fn set_secret(&mut self, source: SecretSource) -> Result<(), DirectiveError> {
        if self.secret.is_some() {
            return Err(DirectiveError::new(format!(
                "credential {:?} has multiple secret sources",
                self.access_key
            )));
        }
        self.secret = Some(source);
        Ok(())
    }

    fn validate(&self) -> Result<(), DirectiveError> {
        let key = &self.access_key;
        if self.secret.is_none() {
            return Err(DirectiveError::new(format!(
                "credential {key:?} needs secret_key_file= (or secret_key= for local development)"
            )));
        }
        if self.allow_any_host && !self.allowed_hosts.is_empty() {
            return Err(DirectiveError::new(format!(
                "credential {key:?} sets both allow_any_host and allowed_host="
            )));
        }
        if !self.allow_any_host && self.allowed_hosts.is_empty() {
            return Err(DirectiveError::new(format!(
                "credential {key:?} needs allowed_host= entries or the explicit allow_any_host flag"
            )));
        }
        if self.allow_any_prefix && !self.allowed_prefixes.is_empty() {
            return Err(DirectiveError::new(format!(
                "credential {key:?} sets both allow_any_prefix and allowed_prefix="
            )));
        }
        if !self.allow_any_prefix && self.allowed_prefixes.is_empty() {
            return Err(DirectiveError::new(format!(
                "credential {key:?} needs allowed_prefix= entries or the explicit allow_any_prefix flag"
            )));
        }
        if self.allow_default_methods && !self.allowed_methods.is_empty() {
            return Err(DirectiveError::new(format!(
                "credential {key:?} sets both allow_default_methods and allowed_method="
            )));
        }
        if !self.allow_default_methods && self.allowed_methods.is_empty() {
            return Err(DirectiveError::new(format!(
                "credential {key:?} needs allowed_method= entries or the explicit \
                 allow_default_methods flag"
            )));
        }
        if let Some(max_expires) = self.max_expires
            && (max_expires.is_zero() || max_expires > MAX_SIGV4_EXPIRES)
        {
            return Err(DirectiveError::new(format!(
                "credential {key:?} max_expires must be between 1s and 7d"
            )));
        }
        Ok(())
    }

    /// Loads the secret and produces the verifier-core credential.
    ///
    /// Secret files are read here, at config load time; request handling
    /// never touches the filesystem. A missing, unreadable, or empty secret
    /// file fails config load.
    pub fn resolve(&self) -> Result<Credential, DirectiveError> {
        let secret_key = self.load_secret()?;
        Ok(Credential {
            access_key: self.access_key.clone(),
            secret_key,
            enabled: self.enabled.unwrap_or(true),
            max_expires: self.max_expires.unwrap_or(Duration::ZERO),
            allowed_hosts: self.allowed_hosts.clone(),
            allowed_methods: self.allowed_methods.clone(),
            allowed_prefixes: self
                .allowed_prefixes
                .iter()
                .map(|prefix| prefix.clone().into_bytes())
                .collect(),
        })
    }

    fn load_secret(&self) -> Result<String, DirectiveError> {
        let source = self.secret.as_ref().expect("validated in parse");
        let mut secret = match source {
            SecretSource::Literal(secret) => secret.as_str().to_string(),
            SecretSource::File(path) => {
                let mut raw = Zeroizing::new(fs::read(path).map_err(|err| {
                    DirectiveError::new(format!(
                        "credential {:?}: cannot read secret file {}: {err}",
                        self.access_key,
                        path.display()
                    ))
                })?);
                // Secret files conventionally end with one trailing newline.
                while raw.last() == Some(&b'\n') || raw.last() == Some(&b'\r') {
                    raw.pop();
                }
                String::from_utf8(raw.to_vec()).map_err(|_| {
                    DirectiveError::new(format!(
                        "credential {:?}: secret file {} is not valid UTF-8",
                        self.access_key,
                        path.display()
                    ))
                })?
            }
        };
        if secret.is_empty() {
            secret.zeroize();
            return Err(DirectiveError::new(format!(
                "credential {:?} has an empty secret",
                self.access_key
            )));
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse(args: &[&str]) -> Result<CredentialDirective, DirectiveError> {
        CredentialDirective::parse(args)
    }

    const BASE: [&str; 5] = [
        "AKIATEST",
        "secret_key=local-dev",
        "allowed_host=assets.example.com",
        "allowed_method=GET",
        "allowed_prefix=/bucket/",
    ];

    #[test]
    fn parses_full_credential_directive() {
        let directive = parse(&[
            "AKIATEST",
            "secret_key=local-dev",
            "enabled=on",
            "max_expires=10m",
            "allowed_host=assets.example.com",
            "allowed_host=cdn.example.com",
            "allowed_method=GET",
            "allowed_method=HEAD",
            "allowed_prefix=/my-bucket/public/",
            "allowed_prefix=/my-bucket/reports/",
        ])
        .expect("directive parses");

        assert_eq!(directive.access_key, "AKIATEST");
        assert_eq!(directive.enabled, Some(true));
        assert_eq!(directive.max_expires, Some(Duration::from_secs(600)));
        assert_eq!(directive.allowed_hosts.len(), 2);
        assert_eq!(directive.allowed_methods, ["GET", "HEAD"]);
        assert_eq!(directive.allowed_prefixes.len(), 2);

        let credential = directive.resolve().expect("resolves");
        assert_eq!(credential.access_key, "AKIATEST");
        assert_eq!(credential.secret_key, "local-dev");
        assert!(credential.enabled);
    }

    #[test]
    fn parses_explicit_allow_any_flags() {
        let directive = parse(&[
            "AKIATEST",
            "secret_key=local-dev",
            "allow_any_host",
            "allow_default_methods",
            "allow_any_prefix",
        ])
        .expect("directive parses");
        let credential = directive.resolve().expect("resolves");
        assert!(credential.allowed_hosts.is_empty());
        assert!(credential.allowed_methods.is_empty());
        assert!(credential.allowed_prefixes.is_empty());
    }

    #[test]
    fn rejects_omitted_policy_lists_without_explicit_flags() {
        // Omitting a list without the matching allow_* flag must fail, so a
        // mistyped list can never silently become "allow everything".
        let mut without_host: Vec<&str> = BASE.to_vec();
        without_host.remove(2);
        assert!(parse(&without_host).is_err());

        let mut without_method: Vec<&str> = BASE.to_vec();
        without_method.remove(3);
        assert!(parse(&without_method).is_err());

        let mut without_prefix: Vec<&str> = BASE.to_vec();
        without_prefix.remove(4);
        assert!(parse(&without_prefix).is_err());
    }

    #[test]
    fn rejects_conflicting_policy_arguments() {
        let mut conflicting_host: Vec<&str> = BASE.to_vec();
        conflicting_host.push("allow_any_host");
        assert!(parse(&conflicting_host).is_err());

        let mut conflicting_method: Vec<&str> = BASE.to_vec();
        conflicting_method.push("allow_default_methods");
        assert!(parse(&conflicting_method).is_err());

        let mut conflicting_prefix: Vec<&str> = BASE.to_vec();
        conflicting_prefix.push("allow_any_prefix");
        assert!(parse(&conflicting_prefix).is_err());
    }

    #[test]
    fn rejects_malformed_arguments() {
        for args in [
            vec![],
            vec![""],
            vec!["secret_key=x"],
            vec!["AKIATEST"],
            vec!["AKIATEST", "bogus"],
            vec!["AKIATEST", "bogus=1"],
            vec!["AKIATEST", "allowed_host="],
            vec!["AKIATEST", "secret_key=a", "secret_key=b"],
            vec!["AKIATEST", "secret_key=a", "secret_key_file=/x"],
            vec!["AKIATEST", "secret_key=a", "enabled=maybe"],
            vec!["AKIATEST", "secret_key=a", "enabled=on", "enabled=on"],
            vec!["AKIATEST", "secret_key=a", "max_expires=abc"],
            vec!["AKIATEST", "secret_key=a", "max_expires=8d"],
            vec!["AKIATEST", "secret_key=a", "max_expires=0"],
        ] {
            assert!(parse(&args).is_err(), "expected error for {args:?}");
        }
    }

    #[test]
    fn loads_secret_from_file_and_trims_trailing_newline() {
        let dir = std::env::temp_dir().join(format!("sigv4-conf-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("secret");
        let mut file = std::fs::File::create(&path).expect("create secret file");
        file.write_all(b"file-secret\n").expect("write secret");
        drop(file);

        let arg = format!("secret_key_file={}", path.display());
        let directive = parse(&[
            "AKIATEST",
            &arg,
            "allow_any_host",
            "allow_default_methods",
            "allow_any_prefix",
        ])
        .expect("directive parses");
        let credential = directive.resolve().expect("resolves");
        assert_eq!(credential.secret_key, "file-secret");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_missing_and_empty_secret_files() {
        let dir = std::env::temp_dir().join(format!("sigv4-conf-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let empty = dir.join("empty");
        std::fs::write(&empty, b"\n").expect("write empty secret");

        for path in [
            empty.display().to_string(),
            format!("{}/absent", dir.display()),
        ] {
            let arg = format!("secret_key_file={path}");
            let directive = parse(&[
                "AKIATEST",
                &arg,
                "allow_any_host",
                "allow_default_methods",
                "allow_any_prefix",
            ])
            .expect("directive parses");
            assert!(directive.resolve().is_err(), "expected error for {path:?}");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_durations() {
        for (input, want) in [
            ("30", 30),
            ("90s", 90),
            ("15m", 15 * 60),
            ("12h", 12 * 60 * 60),
            ("7d", 7 * 24 * 60 * 60),
            ("1w", 7 * 24 * 60 * 60),
            ("1h30m", 90 * 60),
            ("0", 0),
        ] {
            assert_eq!(
                parse_duration(input),
                Ok(Duration::from_secs(want)),
                "input {input:?}"
            );
        }
        for input in [
            "",
            "-5m",
            "5x",
            "m",
            "1.5h",
            " 5m",
            "5m ",
            "99999999999999999999d",
        ] {
            assert!(
                parse_duration(input).is_err(),
                "expected error for {input:?}"
            );
        }
    }

    #[test]
    fn parses_mode_and_merges() {
        assert_eq!(Mode::parse("on"), Ok(Mode::On));
        assert_eq!(Mode::parse("off"), Ok(Mode::Off));
        assert_eq!(Mode::parse("shadow"), Ok(Mode::Shadow));
        assert!(Mode::parse("enabled").is_err());

        assert_eq!(Mode::Unset.merge(Mode::On), Mode::On);
        assert_eq!(Mode::Unset.merge(Mode::Unset), Mode::Off);
        assert_eq!(Mode::Off.merge(Mode::On), Mode::Off);
        assert_eq!(Mode::Shadow.merge(Mode::On), Mode::Shadow);
        assert!(Mode::On.verifies());
        assert!(Mode::Shadow.verifies());
        assert!(!Mode::Off.verifies());
    }
}
