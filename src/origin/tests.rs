//! The boot-time half of the Origin allowlist (yaadgaar #294). Each test names
//! the mutant it exists to kill; the PR body carries the table.

use super::*;

fn https_only(raw: &str) -> Result<Vec<String>, OriginError> {
    parse_allowlist(raw, HttpOrigins::Refused)
}

fn with_http(raw: &str) -> Result<Vec<String>, OriginError> {
    parse_allowlist(raw, HttpOrigins::Admitted)
}

fn refused(result: Result<Vec<String>, OriginError>) -> String {
    match result {
        Ok(list) => panic!("expected a boot refusal, got the allowlist {list:?}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn an_empty_allowlist_is_the_closed_posture_and_parses() {
    assert!(https_only("").expect("empty is a real answer").is_empty());
    assert!(https_only(" , ").expect("blank entries drop").is_empty());
}

#[test]
fn an_exact_https_origin_is_kept_verbatim() {
    assert_eq!(
        https_only("https://gateway.example.com").expect("a serialized origin"),
        vec!["https://gateway.example.com".to_string()]
    );
    assert_eq!(
        https_only(" https://a.example , https://b.example:18443 ").expect("two origins"),
        vec![
            "https://a.example".to_string(),
            "https://b.example:18443".to_string()
        ]
    );
    assert_eq!(
        https_only("https://[::1]:8443").expect("a bracketed IPv6 host"),
        vec!["https://[::1]:8443".to_string()]
    );
}

#[test]
fn a_wildcard_is_refused_even_with_the_development_switch_on() {
    // MUTANT: the wildcard check deleted. `*` would then fail the scheme check
    // with a message that does not say why; `https://*.example` would PASS.
    for raw in [
        "*",
        "https://*.example.com",
        "https://gateway.example.com,*",
    ] {
        let message = refused(with_http(raw));
        assert!(message.contains("wildcard"), "{raw}: {message}");
    }
}

#[test]
fn cleartext_is_refused_unless_the_development_switch_is_on() {
    // MUTANT: the switch ignored (http always admitted), or always refused.
    let message = refused(https_only("http://localhost:3000"));
    assert!(message.contains(ALLOW_HTTP_ORIGINS), "{message}");
    assert!(message.contains("cors.allowHttpOrigins"), "{message}");
    assert_eq!(
        with_http("http://localhost:3000").expect("development switch on"),
        vec!["http://localhost:3000".to_string()]
    );
    // The switch admits http and nothing else.
    assert_eq!(
        with_http("https://gateway.example.com").expect("https stays admitted"),
        vec!["https://gateway.example.com".to_string()]
    );
}

#[test]
fn a_scheme_that_is_not_https_or_http_is_refused() {
    for raw in [
        "ftp://gateway.example.com",
        "ws://gateway.example.com",
        "gateway.example.com",
        "null",
        "file://",
    ] {
        refused(with_http(raw));
    }
}

#[test]
fn a_trailing_slash_or_a_path_is_refused_not_trimmed() {
    // MUTANT: `trim_end_matches('/')`. A browser never sends the slash, so a
    // silently trimmed entry would hide that the operator wrote a URL, and a
    // kept one would never match.
    for raw in [
        "https://gateway.example.com/",
        "https://gateway.example.com/ui",
        "https://gateway.example.com?x=1",
        "https://gateway.example.com#top",
        "https://user@gateway.example.com",
    ] {
        refused(https_only(raw));
    }
}

#[test]
fn an_uppercase_origin_is_refused_not_lowered() {
    // MUTANT: `to_ascii_lowercase()` on the entry, or an uppercase-tolerant
    // charset. A browser serializes scheme and host in lowercase, so an
    // uppercase entry can never match; it is a typo to report at boot.
    for raw in ["HTTPS://gateway.example.com", "https://Gateway.example.com"] {
        refused(https_only(raw));
    }
}

#[test]
fn a_default_port_is_refused_and_a_bad_port_is_refused() {
    // MUTANT: the default-port check deleted. A browser omits :443 on https
    // (and :80 on http), so `https://h:443` would never match `https://h`.
    refused(https_only("https://gateway.example.com:443"));
    refused(with_http("http://localhost:80"));
    for raw in [
        "https://gateway.example.com:",
        "https://gateway.example.com:0",
        "https://gateway.example.com:65536",
        "https://gateway.example.com:84x3",
        "https://",
        "https://:8443",
        "https://gateway.example.com:08443",
        "https://gate]way.example.com",
        "https://[::1",
        "https://[::1]x",
    ] {
        refused(https_only(raw));
    }
    // The non-default ports stay legal.
    https_only("https://gateway.example.com:80").expect("80 is not https's default");
    with_http("http://localhost:443").expect("443 is not http's default");
}

#[test]
fn a_refusal_names_the_entry_and_the_chart_key() {
    let message = refused(https_only("https://gateway.example.com/"));
    assert!(
        message.contains("\"https://gateway.example.com/\""),
        "{message}"
    );
    assert!(message.contains("cors.allowedOrigins"), "{message}");
}

#[test]
fn the_development_switch_takes_exactly_one_or_zero() {
    let lookup = |value: Option<&'static str>| {
        move |key: &str| {
            assert_eq!(key, ALLOW_HTTP_ORIGINS);
            value.map(str::to_string)
        }
    };
    assert_eq!(
        HttpOrigins::from_lookup(lookup(Some("0"))).expect("0"),
        HttpOrigins::Refused
    );
    assert_eq!(
        HttpOrigins::from_lookup(lookup(Some("1"))).expect("1"),
        HttpOrigins::Admitted
    );
    // MUTANT: absent read as off (a compiled-in default, ADR-0569).
    let absent = HttpOrigins::from_lookup(lookup(None)).expect_err("absent refuses");
    assert!(absent.to_string().contains(ALLOW_HTTP_ORIGINS), "{absent}");
    // MUTANT: a permissive parse that reads `true` as on.
    for word in ["true", "false", "", "yes", " 1"] {
        HttpOrigins::from_lookup(lookup(Some(word))).expect_err("only 1 or 0");
    }
}
