//! Tests for [`super`].
//!
//! **The assertion that matters is that a FORGED entry is not believed**, not
//! that some address came out. "An address was recorded" passes identically
//! against the naive implementation that takes the leftmost `X-Forwarded-For`
//! entry — the check-that-cannot-fail shape this project keeps finding. So every
//! test below that supplies a chain supplies a forged leftmost entry and names
//! the value that must NOT be chosen.
//!
//! The addresses are RFC 5737 documentation ranges, chosen so that no value here
//! could have come from the implementation: `192.0.2.0/24`, `198.51.100.0/24` and
//! `203.0.113.0/24` appear nowhere in `source.rs`.

use super::*;

/// The socket's own remote address in every test that has one. Distinct from
/// every documentation range below, so "the peer leaked into the answer" is
/// visible rather than coincidental.
const PEER: &str = "10.244.3.11";

fn peer() -> Option<IpAddr> {
    Some(PEER.parse().expect("the peer address parses"))
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("the address parses")
}

/// One `X-Forwarded-For` header line.
fn xff(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(X_FORWARDED_FOR, value.parse().expect("a valid header"));
    headers
}

// ---- The refusing default ------------------------------------------------

#[test]
fn undeclared_records_no_address_even_though_a_header_arrived() {
    let source = Source::resolve(
        TrustBoundary::Undeclared,
        peer(),
        &xff("203.0.113.7, 198.51.100.4"),
    );
    // THE POINT OF THE TASK: unconfigured means unknown, so the audit record
    // carries nothing rather than the header's value.
    assert_eq!(source.attributed(), None);
    // And it is still keyable, on the hop this process actually saw.
    assert_eq!(source.key(), Some(ip(PEER)));
}

#[test]
fn undeclared_with_no_header_at_all_still_records_no_address() {
    let source = Source::resolve(TrustBoundary::Undeclared, peer(), &HeaderMap::new());
    assert_eq!(source.attributed(), None);
}

#[test]
fn no_peer_and_no_boundary_is_unknown_and_keys_nothing() {
    let source = Source::resolve(TrustBoundary::Undeclared, None, &xff("203.0.113.7"));
    assert_eq!(source, Source::Unknown);
    assert_eq!(source.attributed(), None);
    assert_eq!(source.key(), None);
}

// ---- Counting from the right ---------------------------------------------

#[test]
fn one_hop_takes_the_rightmost_entry_and_not_the_forged_leftmost_one() {
    // Three entries. The caller wrote the first two; the single trusted proxy
    // appended the third.
    let source = Source::resolve(
        TrustBoundary::Hops(1),
        peer(),
        &xff("192.0.2.9, 198.51.100.4, 203.0.113.7"),
    );
    assert_eq!(source.attributed(), Some(ip("203.0.113.7")));
    // NAMED EXPLICITLY, because this is the value the naive implementation
    // returns and the one an attacker chooses.
    assert_ne!(source.attributed(), Some(ip("192.0.2.9")));
}

#[test]
fn two_hops_takes_the_second_entry_from_the_right() {
    let source = Source::resolve(
        TrustBoundary::Hops(2),
        peer(),
        &xff("192.0.2.9, 198.51.100.4, 203.0.113.7"),
    );
    // The off-by-one that matters: not the rightmost, not the leftmost, not the
    // second from the LEFT (which is the same entry only for a 3-list, so the
    // four-entry case below separates them).
    assert_eq!(source.attributed(), Some(ip("198.51.100.4")));
}

#[test]
fn two_hops_counts_from_the_right_rather_than_the_left() {
    // FOUR entries, so "second from the right" and "second from the left" are
    // different values. A three-entry list cannot tell those two implementations
    // apart, which is why this case exists separately.
    let source = Source::resolve(
        TrustBoundary::Hops(2),
        peer(),
        &xff("192.0.2.9, 192.0.2.44, 198.51.100.4, 203.0.113.7"),
    );
    assert_eq!(source.attributed(), Some(ip("198.51.100.4")));
    assert_ne!(source.attributed(), Some(ip("192.0.2.44")));
}

#[test]
fn zero_hops_attributes_the_peer_and_ignores_the_header() {
    // A DECLARED zero is not the same fact as no declaration: this deployment
    // says it is exposed directly, so the socket's remote address IS the client's
    // and is honestly attributable.
    let source = Source::resolve(TrustBoundary::Hops(0), peer(), &xff("203.0.113.7"));
    assert_eq!(source.attributed(), Some(ip(PEER)));
    assert_ne!(source.attributed(), Some(ip("203.0.113.7")));
}

#[test]
fn entries_spread_across_several_header_lines_are_one_chain_in_order() {
    // `HeaderMap::get` returns only the first line. Reading one line here would
    // see a chain of length two, take index `2 - 1 = 1`, and attribute the
    // request to 198.51.100.4 — a caller-written entry.
    let mut headers = HeaderMap::new();
    headers.append(X_FORWARDED_FOR, "192.0.2.9, 198.51.100.4".parse().unwrap());
    headers.append(X_FORWARDED_FOR, "203.0.113.7".parse().unwrap());
    let source = Source::resolve(TrustBoundary::Hops(1), peer(), &headers);
    assert_eq!(source.attributed(), Some(ip("203.0.113.7")));
    assert_ne!(source.attributed(), Some(ip("198.51.100.4")));
}

// ---- Every failure to attribute refuses, and still keys ------------------

#[test]
fn a_chain_shorter_than_the_declared_depth_is_not_attributable() {
    let source = Source::resolve(TrustBoundary::Hops(3), peer(), &xff("203.0.113.7"));
    assert_eq!(source.attributed(), None);
    // BUT STILL THROTTLEABLE. Stripping entries must not buy an unthrottled
    // login — that would be a bypass rather than caution.
    assert_eq!(source.key(), Some(ip(PEER)));
}

#[test]
fn a_missing_header_under_a_declared_boundary_is_not_attributable() {
    let source = Source::resolve(TrustBoundary::Hops(1), peer(), &HeaderMap::new());
    assert_eq!(source.attributed(), None);
    assert_eq!(source.key(), Some(ip(PEER)));
}

#[test]
fn an_entry_that_is_not_an_address_is_not_attributable() {
    let source = Source::resolve(TrustBoundary::Hops(1), peer(), &xff("203.0.113.7, unknown"));
    assert_eq!(source.attributed(), None);
    assert_eq!(source.key(), Some(ip(PEER)));
}

#[test]
fn an_undecodable_header_line_discards_the_whole_chain() {
    // One line this process cannot decode. Skipping it would shorten the chain by
    // the caller's choice, which moves the index counted from the right.
    let mut headers = HeaderMap::new();
    headers.append(
        X_FORWARDED_FOR,
        axum::http::HeaderValue::from_bytes(b"\xff\xfe").expect("a valid header value"),
    );
    headers.append(X_FORWARDED_FOR, "203.0.113.7".parse().unwrap());
    let source = Source::resolve(TrustBoundary::Hops(1), peer(), &headers);
    assert_eq!(source.attributed(), None);
    assert_eq!(source.key(), Some(ip(PEER)));
}

#[test]
fn an_empty_header_is_not_a_chain() {
    let source = Source::resolve(TrustBoundary::Hops(1), peer(), &xff(""));
    assert_eq!(source.attributed(), None);
}

#[test]
fn a_bracketed_ipv6_entry_is_read() {
    let source = Source::resolve(TrustBoundary::Hops(1), peer(), &xff("[2001:db8::7]"));
    assert_eq!(source.attributed(), Some(ip("2001:db8::7")));
}

// ---- Reading the declaration ---------------------------------------------

#[test]
fn an_unset_boundary_is_undeclared_rather_than_zero() {
    // THE DISTINCTION THE WHOLE MODULE RESTS ON. If an empty string parsed as
    // `Hops(0)` every unconfigured deployment behind an ingress would attribute
    // every request to the proxy, which is a wrong address rather than none.
    assert_eq!(
        TrustBoundary::parse("").expect("empty parses"),
        TrustBoundary::Undeclared
    );
    assert_eq!(
        TrustBoundary::parse("   ").expect("blank parses"),
        TrustBoundary::Undeclared
    );
    assert_eq!(
        TrustBoundary::parse("0").expect("zero parses"),
        TrustBoundary::Hops(0)
    );
}

#[test]
fn a_declared_count_is_read() {
    assert_eq!(
        TrustBoundary::parse("1").expect("one parses"),
        TrustBoundary::Hops(1)
    );
    assert_eq!(
        TrustBoundary::parse(" 2 ").expect("padded parses"),
        TrustBoundary::Hops(2)
    );
}

#[test]
fn a_boundary_that_is_not_a_number_is_refused_rather_than_defaulted() {
    // REFUSED AT BOOT, not silently taken as `Undeclared`: a typo that turned
    // into the refusing default would look exactly like a deployment that had not
    // configured this, and the operator who set it would never learn.
    assert!(matches!(
        TrustBoundary::parse("one"),
        Err(TrustBoundaryError::NotANumber(_))
    ));
    assert!(matches!(
        TrustBoundary::parse("-1"),
        Err(TrustBoundaryError::NotANumber(_))
    ));
}

#[test]
fn a_boundary_deeper_than_any_real_chain_is_refused() {
    assert!(matches!(
        TrustBoundary::parse("17"),
        Err(TrustBoundaryError::TooDeep(17))
    ));
    assert_eq!(
        TrustBoundary::parse("16").expect("the bound itself parses"),
        TrustBoundary::Hops(16)
    );
}
