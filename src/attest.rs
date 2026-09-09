//! Caller identity, and the only place in the system a [`Scope`] is built.
//!
//! `yadgar/common/v1/common.proto` says of `Scope`: "attested by the gateway from
//! the request's credentials. Never supplied by the caller itself." That sentence
//! is a claim the contract makes on this module's behalf, and nothing else
//! enforces it — so it is enforced here, by there being exactly one constructor.
//!
//! **Why one function rather than a rule.** A rule spread across handlers can
//! only be asserted; a single construction site can be CHECKED — `grep 'Scope {'`
//! over this repository returns one hit, and a reviewer can confirm the property
//! in a second. That is the difference between a claim and an invariant. Two
//! identity sources did NOT become two literals: both arms call [`scope`], which
//! holds the only `Scope { … }` in the tree.
//!
//! **WHICH PART OF AN IDENTITY THE CALLER MAY STILL NAME.** ADR-0488 requires the
//! scope to be minted here and never supplied, and the three fields are not alike:
//!
//!   - `user_id` — RESOLVED, from the bearer token, through
//!     `iam.ResolveCredential`. A self-asserted username is forgeable by anyone
//!     holding any valid token, so under [`Attestation::Iam`] there is no header
//!     that can reach it. [`from_resolved`], which builds the scope on that path,
//!     takes no claimed user at all: the property is in the signature rather than
//!     in a rule.
//!   - `project_id` — CLAIMED, and legitimately so. It is a workspace fact, it
//!     changes as a person moves between checkouts, and a token cannot carry it.
//!   - `instance_id` — CLAIMED, for the same reason, and it is a session marker
//!     rather than an identity.
//!
//! **Why the SECURE source is the default.** This module used to refuse to boot
//! unless one of two variables was set, because the only available default was
//! trusting the caller. That is no longer the only one: iam-backed attestation is
//! implemented, so an unset environment now selects it, and
//! `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=1` is an explicit, named opt-OUT for
//! development. There is no unconfigured state left to refuse — a stronger reading
//! of D69 than the boot gate was, because a deployment can no longer reach the
//! trusting path by forgetting something.
//!
//! **THE LOOKUP IS CACHED, AND THE CACHE IS WHERE THE REVOCATION WINDOW LIVES.**
//! D72 and ADR-0491 both say the gateway reads a credential "through a cache keyed
//! on the token hash and invalidated by a broker event, never by calling iam per
//! request". The cache and the key are here; the broker event is consumed by
//! [`crate::invalidate`], which calls [`Credentials::forget_user`] for both of the
//! subjects `iam` publishes.
//!
//! [`Credentials::ttl`] is therefore the BACKSTOP for a missed event rather than
//! the mechanism — but it is still what bounds a revoked credential whenever the
//! broker is unreachable, so it stays a security parameter and not a tuning knob.
//! That is why the default is short and why a long one is refused at boot.
//!
//! **FOR ADR-0522'S SETTING THE TTL IS THE ONLY BOUND, NOT THE BACKSTOP, AND
//! THAT IS A PROPERTY OF THE DESIGN RATHER THAN A DEFECT HERE.** The setting
//! arrives on `ResolveCredentialResponse` and is therefore cached with the rest
//! of it, so a change to it binds when the entry expires. No event closes that
//! window sooner, at either level:
//!
//!   - `iam`'s `SetInheritedSetting` publishes NOTHING. Neither level has a
//!     subject, so a team override changes with no notification either.
//!   - Both subjects `iam` does publish carry a `user_id` payload and
//!     [`crate::invalidate`] evicts a PERSON. An organisation-level write names
//!     no person, so there is no payload it could even be published under —
//!     the gap is in the subject's shape, not in a missing call.
//!
//! Closing it needs a subject keyed on something other than a user, which is a
//! contract change in `iam` rather than an edit here. Until then the bound is
//! [`DEFAULT_TTL_SECONDS`], and the direction of the stale answer is whichever
//! way the policy moved — a tightened policy stays loose for up to that long.

use std::fmt;
use std::time::Duration;

use crate::limit::{ConfigError, Overrides};
use crate::pb::yadgar::common::v1::Scope;

mod cache;
mod resolve;

pub use cache::{Credentials, CACHE};
pub use resolve::attest;

/// The environment variable is named for WHAT IT DOES, not for where it runs.
///
/// `DEV=1` tells a reader nothing about what it switches off. This name cannot be
/// set by accident and cannot be misread in a manifest.
const TRUST_HEADERS: &str = "YADGAR_TRUST_UNAUTHENTICATED_HEADERS";

/// How long one credential lookup may take before the call is answered without it.
///
/// **Much shorter than `/auth/login`'s, and the difference is which path it sits
/// on.** A login happens once per person per machine and pays for Argon2id; this
/// runs on EVERY `tools/call`, including `recall`, which D25 calls the
/// latency-critical path. A stalled `iam` must cost one bounded wait rather than
/// hold every request in the system open, so this is sized for a lookup that is
/// slow rather than for one that is expensive.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(5);

/// Why a request has no attested identity.
///
/// **The `Display` text is for the LOG.** `http::attest_answer` decides what the
/// caller is told, and for anything derived from `iam` that is a constant — the
/// same discipline `http::login_answer` follows, for the same reason: a message
/// that varied with the upstream would be a channel sitting behind a status line
/// that was deliberately made opaque.
///
/// **[`MissingWorkspace`](AttestError::MissingWorkspace) IS A SEPARATE VARIANT
/// FROM THE OTHER TWO, AND THAT SEPARATION IS THE POINT OF THE ENUM.** A missing
/// credential and a missing workspace are not the same failure: one is about who
/// the caller is, the other is about which workspace the caller is addressing, and
/// only the first has anything to do with authentication. They were one variant
/// once, and a caller holding a perfectly good token was told it was
/// unauthenticated — sent to re-authenticate against a condition re-authenticating
/// cannot fix. `http::attest_answer` reads this distinction rather than
/// re-deriving it from the header name, because a match on a string literal is a
/// distinction the type system cannot keep.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("request is missing the {0} header, which identifies the caller")]
    MissingIdentity(&'static str),

    /// No workspace was named. NOT an authentication failure.
    ///
    /// **The header, and no other source.** A workspace is not a fact about a
    /// credential and the token cannot carry it — `from_resolved` says so at
    /// length — so an absent `x-yadgar-project` is the caller having omitted a
    /// required field of its own request, which is the definition of a caller
    /// error. `yadgar/project/v1/project.proto` states the rule this variant
    /// exists to keep: "IT IS A CALLER ERROR AND MUST NOT BE RENDERED AS `401`."
    ///
    /// **IT IS RAISED FROM BOTH ATTESTATION ARMS**, which is easy to miss and was
    /// missed: `attest` refuses it inline on the trusted-headers arm, and the
    /// DEFAULT `Iam` arm refuses it by delegating to [`from_resolved`]. A reader
    /// who opens one arm, finds no refusal in its own body and concludes the other
    /// is inert has read half the call.
    #[error("request is missing the {0} header, which names the workspace to act in")]
    MissingWorkspace(&'static str),

    #[error("request carries no `Authorization: Bearer <token>` header")]
    MissingCredential,

    #[error("iam answered {0:?} to ResolveCredential")]
    Upstream(tonic::Code),

    #[error("the resolved credential carries a rate limit this gateway cannot enforce: {0}")]
    Unenforceable(#[from] ConfigError),
}

/// How this process decided who the caller is. Chosen ONCE at boot.
#[derive(Debug, Clone, Default)]
pub enum Attestation {
    /// A real credential, resolved against `iam`.
    ///
    /// **The default, and it names no address.** The channel is the one
    /// `AppState` already holds, built from `IAM_HOST`/`IAM_PORT`. Two settings
    /// that both read as "where iam is" is one too many, and the deleted
    /// `YADGAR_IAM_ADDR` was the second.
    #[default]
    Iam,
    /// Development only: identity is whatever the request says it is.
    TrustedHeaders,
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustedHeaders => write!(f, "UNAUTHENTICATED (headers trusted)"),
            Self::Iam => write!(f, "iam.ResolveCredential"),
        }
    }
}

impl Attestation {
    /// Decide the identity source.
    ///
    /// Called from `main` before the listener is bound. It no longer returns a
    /// `Result`: the only failure it could report was "nothing is configured", and
    /// that state is gone — an unset environment now selects the SECURE source
    /// rather than the trusting one.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the
    /// decision that picks between a verified credential and a header the caller
    /// wrote could not be tested at all without this.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        // Exactly "1". A permissive parse here — "0", "false", "no" all enabling
        // it — is how a setting meant to be off ends up on.
        if lookup(TRUST_HEADERS).as_deref() == Some("1") {
            return Self::TrustedHeaders;
        }
        Self::Iam
    }
}

/// What the caller said about itself, before any of it is believed.
///
/// Deliberately a separate type from [`Scope`]: it is impossible to pass one of
/// these where a scope is wanted, so "unverified claim" and "attested fact"
/// cannot be confused at a call site.
///
/// **The bearer token is NOT in here**, and that is the shape rather than an
/// oversight. This type is what the caller ASSERTS; a credential is a thing to be
/// verified, so it arrives at [`attest`] as its own argument and leaves as a
/// resolved answer.
#[derive(Debug, Default)]
pub struct Claimed<'a> {
    /// Read ONLY by [`Attestation::TrustedHeaders`]. Under `Iam` it is ignored
    /// rather than refused: clients already in flight send it, an ignored forged
    /// header is inert, and refusing one would add a rollout failure that buys
    /// nothing.
    pub user_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub instance_id: Option<&'a str>,
}

/// What one lookup established about the caller.
///
/// **Identity and spending limits together, because D74 says they travel
/// together**: `ResolveCredentialResponse` carries the per-user overrides, so the
/// gateway learns who you are and what you may spend in one lookup, invalidated
/// together. Two lookups would mean two cache lifetimes and a window in which a
/// tightened limit is not yet in force.
///
/// **ADR-0522'S SETTING IS ON THE CACHED HALF, AND IT BELONGS THERE.** It arrives
/// on the same response for the same reason the limits do — one lookup answers
/// everything needed to build a `Scope` — so it is a credential fact and not a
/// per-request one. What follows from that is stated in this module's header: it
/// binds by TTL, and no invalidation event exists that could shorten the wait.
///
/// **THIS TYPE IS NOT WHAT [`Credentials`] HOLDS, and it must not be.** The
/// requirement is that identity and spending limits share one entry and one
/// lifetime, and they do — `ResolveCredentialResponse` carries both and is cached
/// as one value. What this type ADDS is per-request: `scope.request_id` is minted
/// per call (see [`crate::request_id`]), and `scope.project_id` and
/// `scope.instance_id` are the caller's own headers on this request. Caching a
/// composed `Attested` would serve one caller's correlation id and workspace to the
/// next caller holding the same token — a D12 scoping defect and a broken D67
/// join key, from a cache that looked like it was doing what it was asked. So the
/// cached value is what `iam` ANSWERED and this is composed from it every time.
#[derive(Debug)]
pub struct Attested {
    pub scope: Scope,
    /// The caller's per-user bucket overrides (D74).
    ///
    /// Filled from `ResolveCredentialResponse.rate_limit_overrides` on the `Iam`
    /// path, and EMPTY on the trusted-header path — where it is the honest answer
    /// rather than a stub, because no credential was resolved and no header could
    /// carry a limit. A caller who could name its own limits would raise them,
    /// which is the same reason `team_ids` is never taken from the caller.
    pub limits: Overrides,
    /// D73's administrative flag, from `ResolveCredentialResponse.is_admin`.
    ///
    /// **AUTHORITY, AND THEREFORE NOT ON [`Scope`].** `Scope` is a proto message
    /// this gateway MINTS and forwards to every module (ADR-0511), and what a
    /// caller may do administratively is no part of what a module needs to serve
    /// a task. It is read by `/admin`'s handlers and by nothing else, so it lives
    /// on the type the gateway keeps rather than on the one it sends.
    ///
    /// **FALSE ON THE TRUSTED-HEADER PATH, on `limits`' and `team_ids`' own
    /// argument.** Nothing was resolved there and no header could carry authority
    /// — a caller able to write `X-Yadgar-Admin: true` would write it. So a
    /// development gateway has no administrator reachable through a credential,
    /// and the bootstrap token is the only administrative authority on it. That is
    /// the case ADR-0492 minted the bootstrap token for, so it is a gap the design
    /// already fills rather than one this default opens.
    pub is_admin: bool,
}
#[cfg(test)]
mod tests;
