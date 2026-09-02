//! Where a request came from, and whether this deployment can vouch for it
//! (ADR-0491, D80).
//!
//! ADR-0491 requires a source address on every authentication event including
//! failures, "read from `X-Forwarded-For` and trusted only from the known proxy".
//! **Nothing declared the known proxy.** No resource anywhere named a trusted hop
//! count or a trusted range, so the gateway had no basis on which to decide which
//! entry of an `X-Forwarded-For` list was the real client rather than one the
//! caller wrote.
//!
//! # The trust boundary belongs HERE, not to an ingress-specific resource (D80)
//!
//! An earlier revision of this work prescribed an Envoy Gateway
//! `ClientTrafficPolicy` and was retracted: it would make the integrity of an
//! audit record a property of running Envoy, and yadgar must run on EKS, AKS, GKE
//! and behind NGINX, Traefik, HAProxy, an ALB or an Application Gateway. Every
//! ingress worth deploying behind appends to `X-Forwarded-For`; what differs is
//! only how many entries it adds and whether it sanitises what arrived. That
//! difference is the one number an operator declares, once, for whichever ingress
//! they run — and this module is where it is read and applied.
//!
//! Loose coupling is not licence to weaken the check. The mechanism moved inside
//! our boundary; the property did not soften.
//!
//! # The default REFUSES, and that is the whole point
//!
//! Unconfigured means UNKNOWN, so an unconfigured deployment records no address
//! rather than believing the header. This is the one place where the safe default
//! and the convenient default point opposite ways: taking the LEFTMOST
//! `X-Forwarded-For` entry is what a naive implementation does, and it is
//! precisely the entry the caller controls.
//!
//! **An audit record carrying a forged address is worse than one carrying none**,
//! because the empty field is honestly empty while the forged one reads as
//! evidence.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;

/// The header every ingress in the list above appends to.
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// The socket's own remote address, if this server was wired to know one.
///
/// **INFALLIBLE, AND THAT IS THE WHOLE REASON IT EXISTS.** `ConnectInfo<SocketAddr>`
/// is a `FromRequestParts` whose rejection is a 500, and axum 0.8 has no
/// `OptionalFromRequestParts` for it — so a handler naming it directly would
/// answer 500 to every request that reached the router without
/// `into_make_service_with_connect_info`. Every test in this crate drives
/// `router()` through `oneshot`, which is exactly that case: the extractor would
/// turn a suite that asserts status codes into a suite that asserts 500.
///
/// So absence is a VALUE here rather than a rejection, and it means what it says:
/// this process never had an address for this request. `main` always wires the
/// connect info, so in the shipped binary the `None` arm is unreachable; it is
/// what a test sees, and [`Source::Unknown`] is what it resolves to — which
/// refuses, in both directions.
pub struct PeerAddr(pub Option<IpAddr>);

impl<S> FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip()),
        ))
    }
}

/// The largest hop count this accepts.
///
/// A BOUND RATHER THAN A FREE NUMBER: a declared count larger than this is a typo
/// or a misunderstanding, and both produce the same outcome — every list is
/// shorter than the declared depth, so nothing is ever attributable and the audit
/// column is silently always empty. Refusing at boot is how that gets noticed.
/// Sixteen is far past any real ingress chain and still small enough to be
/// obviously wrong when exceeded.
const MAX_HOPS: u32 = 16;

/// How many proxies stand between a client and this gateway.
///
/// **THREE STATES, NOT TWO, and the third is the one that is easy to miss.**
/// `Undeclared` and `Hops(0)` are different facts, not two spellings of the same
/// caution: `Hops(0)` is a deployment that says there is NO proxy in front, for
/// which the peer address genuinely IS the client's and is honestly attributable.
/// Collapsing the two would make a directly-exposed deployment permanently
/// unattributable for no reason at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBoundary {
    /// Nobody has said. The gateway cannot attribute a request to anyone, and
    /// says so rather than guessing.
    Undeclared,
    /// `n` proxies append to `X-Forwarded-For` before this gateway sees it.
    /// `Hops(0)` means the gateway is exposed directly.
    Hops(u32),
}

#[derive(Debug, thiserror::Error)]
pub enum TrustBoundaryError {
    #[error(
        "{0:?} is not a whole number of proxy hops. It is how many proxies append \
         to X-Forwarded-For between a client and this gateway — 0 for a gateway \
         exposed directly, 1 behind a single ingress. Leave it UNSET to say \
         nobody knows, which records no source address at all (ADR-0491)."
    )]
    NotANumber(String),
    #[error(
        "{0} proxy hops is more than the {MAX_HOPS} this accepts. A count deeper \
         than any real ingress chain makes every X-Forwarded-For list too short, \
         so nothing is ever attributable and the audit record's address column is \
         silently always empty."
    )]
    TooDeep(u32),
}

impl TrustBoundary {
    /// Read the declared boundary. An EMPTY string is `Undeclared`, which is a
    /// real answer rather than a missing one — see this module's header.
    pub fn parse(raw: &str) -> Result<Self, TrustBoundaryError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(Self::Undeclared);
        }
        let hops: u32 = raw
            .parse()
            .map_err(|_| TrustBoundaryError::NotANumber(raw.to_string()))?;
        if hops > MAX_HOPS {
            return Err(TrustBoundaryError::TooDeep(hops));
        }
        Ok(Self::Hops(hops))
    }
}

/// What this gateway knows about where one request came from.
///
/// **The two `Some` arms answer DIFFERENT questions, and conflating them is the
/// defect this type exists to prevent.**
///
/// - [`Source::Attributed`] is a claim about the CLIENT, and it is only ever
///   built when the declared trust boundary was actually met. It is the only arm
///   an audit record may carry.
/// - [`Source::Observed`] is the nearest hop this process itself saw on the
///   socket. Behind a proxy that is the PROXY, not the client — so it is honest
///   as a throttle key (it really is the entity holding the connection, and no
///   caller can forge it) and dishonest as an audit record of who logged in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The client's own address, vouched for by the declared boundary.
    Attributed(IpAddr),
    /// The nearest hop this process observed. NOT the client behind a proxy.
    Observed(IpAddr),
    /// Nothing at all: no peer address and no boundary that could supply one.
    Unknown,
}

impl Source {
    /// Resolve one request.
    ///
    /// `peer` is the socket's own remote address — `None` only where the server
    /// was not wired with `ConnectInfo`, which in this binary means a test
    /// driving the router directly.
    ///
    /// **Every failure to attribute falls back to [`Source::Observed`] rather
    /// than to [`Source::Unknown`], and that is deliberate.** A list shorter than
    /// the declared depth, an entry that is not an address, a header this process
    /// cannot decode — each is a request this gateway cannot attribute, and each
    /// is also a request a caller can produce ON PURPOSE. Falling back to
    /// `Unknown` would mean stripping `X-Forwarded-For` bought the caller an
    /// unthrottled login, which is a bypass rather than caution. The audit half
    /// still refuses, because `Observed` is not attributable.
    pub fn resolve(boundary: TrustBoundary, peer: Option<IpAddr>, headers: &HeaderMap) -> Self {
        let Some(peer) = peer else {
            return Self::Unknown;
        };
        let hops = match boundary {
            TrustBoundary::Undeclared => return Self::Observed(peer),
            // NO PROXY IN FRONT, so the socket's own remote address is the
            // client's and `X-Forwarded-For` is ignored entirely. A header on
            // this path is a caller writing one, and there is no hop that could
            // have appended it.
            TrustBoundary::Hops(0) => return Self::Attributed(peer),
            TrustBoundary::Hops(n) => n as usize,
        };
        let Some(chain) = forwarded_for(headers) else {
            return Self::Observed(peer);
        };
        // COUNTED FROM THE RIGHT, WHICH IS THE WHOLE MECHANISM. Each proxy
        // APPENDS the address it saw, so the rightmost entry was written by the
        // hop nearest this gateway and the leftmost by the hop nearest — or by —
        // the caller. With one trusted proxy the client is the last entry; with
        // two it is the second from last. Everything to the LEFT of that index is
        // text the caller could have sent, and is never read.
        let Some(index) = chain.len().checked_sub(hops) else {
            // The chain is SHORTER than the boundary says it should be, so the
            // entry at the declared depth does not exist. Either the request did
            // not come through the declared chain or the chain is misdeclared;
            // neither is something to guess about.
            return Self::Observed(peer);
        };
        match parse_address(chain[index]) {
            Some(client) => Self::Attributed(client),
            None => Self::Observed(peer),
        }
    }

    /// The address an AUDIT RECORD may carry, and `None` when there is none.
    ///
    /// The refusing default lives here: everything but [`Source::Attributed`]
    /// answers `None`, so an unconfigured deployment writes an honestly empty
    /// field rather than the caller's own value.
    pub fn attributed(&self) -> Option<IpAddr> {
        match self {
            Self::Attributed(ip) => Some(*ip),
            Self::Observed(_) | Self::Unknown => None,
        }
    }

    /// The address a THROTTLE may key on, and `None` when there is none.
    ///
    /// Wider than [`Self::attributed`] on purpose — see [`Source::Observed`]. A
    /// bucket keyed here is keyed on something the caller cannot choose, which is
    /// the property a limiter needs; whether it names the client or the proxy in
    /// front of them decides the RATE rather than whether there is one.
    pub fn key(&self) -> Option<IpAddr> {
        match self {
            Self::Attributed(ip) | Self::Observed(ip) => Some(*ip),
            Self::Unknown => None,
        }
    }
}

/// Every `X-Forwarded-For` entry, in order, or `None` if the header cannot be
/// used.
///
/// **`get_all`, NOT `get`.** A single logical `X-Forwarded-For` may legitimately
/// arrive as several header LINES, and `HeaderMap::get` returns only the first of
/// them. Reading one line silently drops entries — which shortens the chain, which
/// moves the index counted from the right, which attributes the request to the
/// wrong hop. That is a correctness bug that looks like a working implementation.
///
/// **PRESENT AND UNDECODABLE IS PRESENT AND INVALID**, so one unreadable line
/// discards the whole chain rather than the line. This is `http::readable`'s rule,
/// applied to a header being VALIDATED rather than merely claimed: skipping the
/// bad line would let a caller shorten the chain by choice, which is the index
/// shift above, on demand.
fn forwarded_for(headers: &HeaderMap) -> Option<Vec<&str>> {
    let mut chain = Vec::new();
    let mut any = false;
    for value in headers.get_all(X_FORWARDED_FOR) {
        any = true;
        let text = value.to_str().ok()?;
        chain.extend(text.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }
    (any && !chain.is_empty()).then_some(chain)
}

/// One entry as an address, or `None`.
///
/// STRICT, and the strictness is safe: an entry this cannot read makes the
/// request unattributable, which refuses rather than guesses. Brackets are
/// stripped because RFC 7239's `[::1]` form appears in the wild; a trailing port
/// is not stripped, because `1.2.3.4:5` and a truncation of it are not
/// distinguishable and an address is what the chain is defined to hold.
fn parse_address(entry: &str) -> Option<IpAddr> {
    entry
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

#[cfg(test)]
mod tests;
