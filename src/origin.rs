//! Which browser origins this gateway admits, read and checked at boot
//! (yaadgaar #294, ruled by Max).
//!
//! THIS IS NOT CORS. No CORS header is ever sent. The list feeds one check,
//! `http::gate::origin_ok`, which refuses a request whose `Origin` header is
//! present and not on the list. It is the MCP spec's DNS-rebinding defence:
//! a web page in a browser must not drive this server.
//!
//! # What is refused at boot, and why a refusal and not a fix-up
//!
//! The request side compares EXACTLY. A browser serializes an origin as a
//! lowercase scheme, a lowercase host and a port only when it is not the
//! scheme's default, with no path and no trailing slash. So an entry in any
//! other shape can never match, and an entry that silently never matches is
//! an operator's mistake nobody sees. Each one is a boot refusal that names
//! the entry:
//!
//! - a wildcard (`*` anywhere). The ruling refuses it outright: a list that
//!   admits every origin is no list;
//! - `http://`, unless the development switch [`ALLOW_HTTP_ORIGINS`] is `"1"`.
//!   A cleartext origin is one a network attacker can serve;
//! - any other scheme, a bare hostname and the opaque origin `null`;
//! - a path, a trailing slash, a query, a fragment or a userinfo part;
//! - an uppercase letter;
//! - a port that is empty, not a number, out of range, or the scheme's own
//!   default (443 for https, 80 for http).
//!
//! An EMPTY list is legal and is the closed posture: no browser origin at all.

/// The environment variable that holds the allowlist (chart: `cors.allowedOrigins`).
pub const ALLOWED_ORIGINS: &str = "YADGAR_ALLOWED_ORIGINS";

/// The development switch that admits `http://` entries (chart:
/// `cors.allowHttpOrigins`).
pub const ALLOW_HTTP_ORIGINS: &str = "YADGAR_ALLOWED_ORIGINS_ALLOW_HTTP";

/// Whether this deployment admits a cleartext (`http://`) origin.
///
/// **NO `Default`, AND NO COMPILED-IN DEFAULT IS READ (ADR-0569).** The chart
/// renders the variable unconditionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpOrigins {
    /// `"0"`: only `https://` origins. The shipped value.
    Refused,
    /// `"1"`: development only. `http://` origins are admitted as well.
    Admitted,
}

impl HttpOrigins {
    /// Resolve the switch from this process's environment.
    ///
    /// # Errors
    ///
    /// See [`Self::from_lookup`].
    pub fn from_env() -> Result<Self, OriginError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Resolve the switch from an injected lookup (a test seam).
    ///
    /// # Errors
    ///
    /// An absent value, and any value that is not exactly `"1"` or `"0"`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, OriginError> {
        match lookup(ALLOW_HTTP_ORIGINS).as_deref() {
            None => Err(OriginError::SwitchAbsent),
            Some("0") => Ok(Self::Refused),
            Some("1") => Ok(Self::Admitted),
            Some(other) => Err(OriginError::SwitchUnknown(other.to_string())),
        }
    }
}

/// An allowlist, or its switch, that this gateway refuses to boot with.
#[derive(Debug, thiserror::Error)]
pub enum OriginError {
    #[error(
        "{ALLOW_HTTP_ORIGINS} is not set. It chooses whether {ALLOWED_ORIGINS} may name an \
         http:// origin, and there is no compiled-in default (ADR-0569). Set it to \"0\" \
         (chart: cors.allowHttpOrigins: false, the shipped value) or, in development only, \
         to \"1\"."
    )]
    SwitchAbsent,

    #[error(
        "{ALLOW_HTTP_ORIGINS} is {0:?}, and only \"1\" or \"0\" are accepted (chart: \
         cors.allowHttpOrigins). A value outside the two is refused rather than read as either."
    )]
    SwitchUnknown(String),

    #[error(
        "{ALLOWED_ORIGINS} entry {0:?} is a wildcard, and a wildcard is refused (chart: \
         cors.allowedOrigins). List each browser origin in full."
    )]
    Wildcard(String),

    #[error(
        "{ALLOWED_ORIGINS} entry {0:?} is an http:// origin, and cleartext origins are refused \
         unless {ALLOW_HTTP_ORIGINS}=1 (chart: cors.allowHttpOrigins: true, development only). \
         Use the https:// origin (chart: cors.allowedOrigins)."
    )]
    Cleartext(String),

    #[error(
        "{ALLOWED_ORIGINS} entry {0:?} is not a browser origin: {1}. A browser sends a \
         lowercase scheme://host[:port] with no path, no trailing slash and no default port, \
         and the match is exact, so this entry could never match (chart: cors.allowedOrigins)."
    )]
    NotAnOrigin(String, &'static str),
}

/// Parse `YADGAR_ALLOWED_ORIGINS`: comma-separated, blank entries dropped,
/// every other entry checked as the module comment lists.
///
/// # Errors
///
/// The FIRST entry that is refused, as an [`OriginError`] naming it.
pub fn parse_allowlist(raw: &str, http: HttpOrigins) -> Result<Vec<String>, OriginError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| check(entry, http).map(|()| entry.to_string()))
        .collect()
}

/// One entry, in the order a reader expects the refusal: wildcard first,
/// because it is the one the ruling names.
fn check(entry: &str, http: HttpOrigins) -> Result<(), OriginError> {
    let refuse = |why| Err(OriginError::NotAnOrigin(entry.to_string(), why));
    if entry.contains('*') {
        return Err(OriginError::Wildcard(entry.to_string()));
    }
    let (authority, default_port) = if let Some(rest) = entry.strip_prefix("https://") {
        (rest, "443")
    } else if let Some(rest) = entry.strip_prefix("http://") {
        if http != HttpOrigins::Admitted {
            return Err(OriginError::Cleartext(entry.to_string()));
        }
        (rest, "80")
    } else {
        return refuse("the scheme is not https:// (or http:// with the development switch)");
    };
    if authority.chars().any(|c| c.is_ascii_uppercase()) {
        return refuse("it carries an uppercase letter");
    }
    if !authority.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | ':' | '[' | ']')
    }) {
        return refuse(
            "it carries a path, a query, a fragment, a userinfo part or a character no host has",
        );
    }
    // A bracketed IPv6 host carries its own colons; the port follows the `]`.
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((v6, after)) = inner.split_once(']') else {
            return refuse("an IPv6 host has no closing ]");
        };
        let port = match after.strip_prefix(':') {
            Some(port) => Some(port),
            None if after.is_empty() => None,
            None => return refuse("something other than a port follows the IPv6 host"),
        };
        (v6, port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return refuse("it has no host");
    }
    if host.contains(['[', ']']) {
        return refuse("a bracket appears outside an IPv6 host");
    }
    if let Some(port) = port {
        // Digits only and no leading zero: the form a browser serializes.
        let digits =
            !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !port.starts_with('0');
        if !digits || port.parse::<u16>().is_err() {
            return refuse("the port is not a number from 1 to 65535");
        }
        if port == default_port {
            return refuse("the port is the scheme's default, which a browser never sends");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
