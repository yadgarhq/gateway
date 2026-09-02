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

use std::fmt;
use std::time::Duration;

use tonic::transport::Channel;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::limit::{kind_str, Bucket, ConfigError, Overrides};
use crate::pb::yadgar::common::v1::Scope;
use crate::pb::yadgar::iam::v1::{
    iam_service_client::IamServiceClient, RateLimitOverride, ResolveCredentialRequest,
    ResolveCredentialResponse,
};

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
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("request is missing the {0} header, which identifies the caller")]
    MissingIdentity(&'static str),

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
}

/// Build the attested scope for one request.
///
/// `credential` is the `Authorization` header verbatim, and `request_id` is passed
/// in rather than read from the caller — see [`crate::request_id`].
///
/// The `iam` channel is borrowed rather than held on [`Attestation`] so the enum
/// stays a decision and not a resource. It is the same lazy channel `/auth/login`
/// uses; an `iam` that is not deployed yet costs a bounded failure per call rather
/// than a boot that never completes.
pub async fn attest(
    how: &Attestation,
    iam: &Channel,
    credential: Option<&str>,
    claimed: Claimed<'_>,
    request_id: String,
) -> Result<Attested, AttestError> {
    match how {
        Attestation::TrustedHeaders => Ok(Attested {
            limits: Overrides::default(),
            scope: scope(
                claimed
                    .user_id
                    .ok_or(AttestError::MissingIdentity("X-Yadgar-User"))?
                    .to_string(),
                claimed
                    .project_id
                    .ok_or(AttestError::MissingIdentity("X-Yadgar-Project"))?
                    .to_string(),
                claimed.instance_id.unwrap_or_default().to_string(),
                // Team membership comes from iam. Empty means "no team
                // visibility", which is the restrictive answer and the right
                // default while the only identity source is a header the caller
                // wrote.
                Vec::new(),
                request_id,
            ),
        }),

        Attestation::Iam => {
            let token = bearer(credential).ok_or(AttestError::MissingCredential)?;
            let mut client = IamServiceClient::new(iam.clone());
            let rpc = client.resolve_credential(ResolveCredentialRequest {
                // As PRESENTED, never hashed here. The contract is explicit that
                // hashing is `iam`'s job: a caller that hashed first would have to
                // agree on the algorithm forever, and changing it would then be a
                // breaking change to every caller rather than an implementation
                // detail there.
                token: token.to_string(),
            });
            let resolved = match tokio::time::timeout(RESOLVE_DEADLINE, rpc).await {
                Ok(Ok(r)) => r.into_inner(),
                // `e.code()` is kept and `e` is dropped. The message belongs in
                // the log line `http` writes, not in an answer to a caller whose
                // credential has just failed to resolve.
                Ok(Err(e)) => return Err(AttestError::Upstream(e.code())),
                // Through the SAME variant as any other upstream problem, so a
                // stall is not a third answer somebody has to remember to keep
                // opaque.
                Err(_elapsed) => return Err(AttestError::Upstream(tonic::Code::DeadlineExceeded)),
            };
            from_resolved(
                resolved,
                claimed.project_id,
                claimed.instance_id,
                request_id,
            )
        }
    }
}

/// The attested identity, from a credential `iam` has already resolved.
///
/// **THERE IS NO CLAIMED-USER PARAMETER, and that is the security property.** The
/// user id can only come from `resolved`, so no later edit to [`attest`] can route
/// a header into it without changing this signature — a visible act, rather than a
/// line that looks like the two beside it. A rule saying "do not trust the header"
/// would have been as true and as easy to break.
///
/// `project_id` and `instance_id` ARE claimed, and stay so: a workspace is not a
/// fact about a credential, and the token cannot carry it.
///
/// **`iam` ANSWERS `Ok` FOR A CREDENTIAL THAT DOES NOT RESOLVE, and reading that
/// as a success is an authentication bypass.** `iam-db` returns an empty response
/// for a token that is unknown, revoked, expired, or belongs to a soft-deleted
/// person, and `iamdb.proto` says why in as many words:
///
/// > Empty user_id means no live credential matched. NOT an error: "no such
/// > credential" and "the store is broken" are different outcomes and a caller
/// > must be able to tell them apart — one is a 401, the other is a 503.
///
/// **THIS GATEWAY IS THE CALLER THAT OWES THE 401**, and nothing downstream would
/// catch a miss: no service checks for an empty `user_id` on a read path, and
/// every bypasser would share `user_id: ""`, collapsing D12's per-user scoping
/// into a single namespace. Revocation and expiry would both be inert. The check
/// belongs at this boundary because this is the last place the distinction still
/// exists.
///
/// **The rule is not in the proto this crate vendors**, which is how it was
/// missed: `yadgar/iam/v1/iam.proto` describes `user_id` only as "Identity and
/// AUTHORITY" and never documents the negative answer. Only `yadgar/iamdb/v1`
/// states it, and the gateway deliberately does not vendor that file — it is
/// `iam`'s own upstream, not this one's. So the rule is written down HERE, beside
/// the code that depends on it.
///
/// **TWO SIGNALS, and either one refuses.** `iam` sets
/// `valid_for_seconds: if resolved { 300 } else { 0 }`, so a negative answer
/// carries both an empty user and a zero lifetime. Checking both means an `iam`
/// that regresses on one of them is still refused rather than believed. The cost
/// of the second check, stated so that changing it stays deliberate: an `iam` that
/// later returned `valid_for_seconds: 0` on a VALID credential, to mean "do not
/// cache this one", would be refused here. Fail-closed is the right direction for
/// an identity check that has been bypassed once, and a gateway with no cache has
/// no use for a zero it cannot tell from a refusal.
fn from_resolved(
    resolved: ResolveCredentialResponse,
    claimed_project: Option<&str>,
    claimed_instance: Option<&str>,
    request_id: String,
) -> Result<Attested, AttestError> {
    if resolved.user_id.is_empty() || resolved.valid_for_seconds <= 0 {
        // THROUGH THE UPSTREAM VARIANT, carrying the code `iam` would have used
        // had this outcome been an error, so it reaches `opaque_status` and
        // becomes the same 401 as any other refusal — no new variant, and no
        // answer that tells a caller working through stolen tokens which of them
        // exists.
        return Err(AttestError::Upstream(tonic::Code::Unauthenticated));
    }
    Ok(Attested {
        limits: overrides_from(resolved.rate_limit_overrides)?,
        scope: scope(
            resolved.user_id,
            claimed_project
                .ok_or(AttestError::MissingIdentity("X-Yadgar-Project"))?
                .to_string(),
            claimed_instance.unwrap_or_default().to_string(),
            // FROM THE RESPONSE, and reachable no other way. Teams decide what a
            // TEAM-visible record is readable by (D12), so a caller that could
            // name its own teams could read other people's records.
            resolved.team_ids,
            request_id,
        ),
    })
}

/// D74's per-user buckets, as this gateway's limiter keys them.
///
/// **An override that cannot be enforced REFUSES THE CREDENTIAL** rather than
/// being dropped — [`Overrides::from_pairs`] states the argument: skipping a
/// bucket silently applies the configured default instead, and for an override
/// that TIGHTENS a limit that is the limit-nobody-notices-is-gone shape.
///
/// **A deliberate `rate = 0, burst = 0` is the contract's way of saying DENY this
/// bucket, and it refuses the credential too.** That is broader than the contract
/// asks — the person loses every bucket rather than one — and it is the honest
/// answer available here: `limit::Bucket` has no representation for a denial, and
/// `limit::validate` refuses a zero rate because the script turns it into a
/// permanent lockout with a 24-hour `Retry-After`. Refusing loudly fails in the
/// direction the admin intended; applying the default would silently undo them. A
/// narrower denial needs a `Decision::Denied` in `limit.rs`, which is a change to
/// the script rather than to this mapping.
///
/// An entry whose `limit` is UNSET is skipped, on the contract's own instruction:
/// an unset limit is how an override is CLEARED, so one still in the list is a
/// server bug that "must be read as no override for that bucket rather than as a
/// denial". `unwrap_or_default()` is the plausible-looking line that reads it as
/// exactly the denial the contract says it is not.
fn overrides_from(list: Vec<RateLimitOverride>) -> Result<Overrides, ConfigError> {
    let mut pairs = Vec::with_capacity(list.len());
    for entry in list {
        // FIRST, BEFORE ANY OTHER CHECK ON THE ENTRY. A cleared override is not an
        // override at all, so nothing else about it can be wrong — and reaching a
        // refusal on its `kind` or its `module` first would turn "no override for
        // that bucket" into a denial of the whole credential, which is precisely
        // the reading the contract forbids.
        let Some(limit) = entry.limit else {
            continue;
        };
        let kind = Kind::try_from(entry.kind)
            .map_err(|_| ConfigError::UnknownKind(entry.kind.to_string()))?;
        // `kind_str` names all five and only three of them are buckets. D74 puts
        // KIND_JOB outside this mechanism and KIND_UNSPECIFIED is a zero value
        // nothing should construct, so either is a server bug rather than a
        // configuration this gateway can honour. Accepting one would mint a key
        // `Limits::effective` is never asked for — an override that looks applied
        // and is not.
        if !matches!(kind, Kind::Read | Kind::Write | Kind::Generate) {
            return Err(ConfigError::UnknownKind(kind_str(kind).to_string()));
        }
        if entry.module.is_empty() {
            return Err(ConfigError::Shape(format!(".{}", kind_str(kind))));
        }
        // The key `Limits::effective` looks a bucket up by, built exactly as
        // `Limits::parse` builds it. A key in any other shape is an override
        // nothing ever reads.
        pairs.push((
            format!("{}.{}", entry.module, kind_str(kind)),
            Bucket {
                rate: limit.rate,
                burst: f64::from(limit.burst),
            },
        ));
    }
    Overrides::from_pairs(pairs)
}

/// The ONE place a [`Scope`] is constructed.
///
/// Private, and it takes strings rather than headers or a response: everything
/// that decides WHERE a value came from has already happened by the time control
/// reaches here, so this function cannot be the place a claim is mistaken for a
/// fact. `grep 'Scope {' src/` returning one hit is what makes the contract's
/// claim checkable, and that grep points at this body.
fn scope(
    user_id: String,
    project_id: String,
    instance_id: String,
    team_ids: Vec<String>,
    request_id: String,
) -> Scope {
    Scope {
        user_id,
        project_id,
        // A session identifier, not an identity — D46 throttles on it and D39
        // addresses notices with it. Absent is legitimate: a one-shot client has
        // no session.
        instance_id,
        team_ids,
        request_id,
    }
}

/// The token out of an `Authorization` header, or nothing.
///
/// The scheme is compared case-insensitively because RFC 9110 says it is, and a
/// client sending `bearer` would otherwise be refused for a reason no error
/// message explains. An empty token after the scheme is no credential at all, and
/// is treated as one missing rather than sent upstream to be refused.
fn bearer(header: Option<&str>) -> Option<&str> {
    let (scheme, token) = header?.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::yadgar::iam::v1::RateLimit;

    /// A lookup over a fixed table, standing in for the process environment.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// A channel to a closed port.
    ///
    /// `connect_lazy` needs a reactor in scope even though it dials nothing, so
    /// every caller is a `#[tokio::test]`.
    fn nowhere() -> Channel {
        tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy()
    }

    /// **`..Default::default()` rather than a full literal, deliberately.**
    /// `ResolveCredentialResponse` gained two fields at contract v1.6.0, and an
    /// exhaustive literal in a fixture turns the next additive contract change
    /// into a compile error in a test that does not care about the new field.
    /// A LIVE credential, as `iam` returns one.
    ///
    /// `valid_for_seconds` is set explicitly and is load-bearing: `iam` writes
    /// `if resolved { 300 } else { 0 }`, and `from_resolved` refuses a zero. A
    /// fixture that left it at its `Default` would be the negative answer, and
    /// every test built on it would assert against a refusal.
    fn resolved(user_id: &str) -> ResolveCredentialResponse {
        ResolveCredentialResponse {
            user_id: user_id.to_string(),
            team_ids: vec!["team-a".to_string()],
            valid_for_seconds: 300,
            ..Default::default()
        }
    }

    #[test]
    fn only_the_exact_string_one_enables_trusted_headers() {
        // MUTATION THIS CATCHES: `== Some("1")` relaxed to `.is_some()`, or to any
        // truthiness parse. Under it, `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=0` —
        // written by somebody deliberately turning the setting OFF — turns
        // authentication off instead, and the gateway trusts whatever the caller
        // claims.
        assert!(matches!(
            Attestation::from_lookup(env(&[(TRUST_HEADERS, "1")])),
            Attestation::TrustedHeaders
        ));
        for off in ["0", "false", "no", "", "true", "yes"] {
            assert!(
                matches!(
                    Attestation::from_lookup(env(&[(TRUST_HEADERS, off)])),
                    Attestation::Iam
                ),
                "{off:?} must not enable trusted headers"
            );
        }
    }

    #[test]
    fn an_unset_environment_attests_against_iam() {
        // THE DIRECTION OF THIS TEST IS THE POINT, and it is the opposite of what
        // it used to assert. An unconfigured process once refused to start,
        // because the only default available was trusting the caller. The default
        // is the verified source now, so forgetting a variable can no longer reach
        // the trusting one — which is what makes the boot gate unnecessary rather
        // than merely removed.
        assert!(matches!(
            Attestation::from_lookup(env(&[])),
            Attestation::Iam
        ));
        assert!(matches!(Attestation::default(), Attestation::Iam));
    }

    #[test]
    fn the_user_comes_from_the_resolved_credential() {
        // A value no header in this process could have supplied and no default
        // could produce.
        let attested = from_resolved(
            resolved("u-from-the-token"),
            Some("acme/demo"),
            Some("i-1"),
            "REQ-1".to_string(),
        )
        .expect("a resolved credential attests");
        assert_eq!(attested.scope.user_id, "u-from-the-token");
        assert_eq!(attested.scope.request_id, "REQ-1");
        // CLAIMED, and still claimed: a workspace is not a fact about a credential.
        assert_eq!(attested.scope.project_id, "acme/demo");
        assert_eq!(attested.scope.instance_id, "i-1");
        // From the response, and reachable no other way (D12).
        assert_eq!(attested.scope.team_ids, vec!["team-a".to_string()]);
    }

    #[test]
    fn the_negative_answer_is_a_refusal_and_never_an_attestation() {
        // `iam` reports "no live credential" as `Ok` with an empty response, and
        // reading that as a success was an authentication bypass: `Bearer
        // <anything>` attested as `user_id: ""`. `iamdb.proto`: "Empty user_id
        // means no live credential matched. NOT an error… one is a 401, the other
        // is a 503." This gateway is the one that owes the 401.
        //
        // Asserted at the DEFAULT, which is the exact shape `iam` sends: an
        // `is_empty()` check written against a hand-built fixture would pass while
        // missing the response actually on the wire.
        let err = from_resolved(
            ResolveCredentialResponse::default(),
            Some("acme/demo"),
            None,
            "REQ-6".to_string(),
        )
        .expect_err("an unresolvable credential must not attest");
        assert!(
            matches!(err, AttestError::Upstream(tonic::Code::Unauthenticated)),
            "the negative answer is a refusal, not an outage; got {err:?}"
        );

        // EITHER SIGNAL ALONE REFUSES. `iam` writes both together today, and
        // checking both is what keeps a regression on one of them from being
        // believed.
        for answer in [
            ResolveCredentialResponse {
                user_id: String::new(),
                valid_for_seconds: 300,
                ..Default::default()
            },
            ResolveCredentialResponse {
                user_id: "u".to_string(),
                valid_for_seconds: 0,
                ..Default::default()
            },
        ] {
            assert!(
                matches!(
                    from_resolved(answer, Some("acme/demo"), None, "REQ-7".to_string()),
                    Err(AttestError::Upstream(tonic::Code::Unauthenticated))
                ),
                "half a negative answer is still a negative answer"
            );
        }
    }

    #[test]
    fn a_resolved_credential_without_a_project_is_refused_rather_than_defaulted() {
        // An empty project reads as "everything", not as "none": D12 scopes
        // records by it, so defaulting one is a widening nobody asked for.
        let err = from_resolved(resolved("u"), None, None, "REQ-2".to_string())
            .expect_err("a missing project must not become an empty one");
        assert!(matches!(err, AttestError::MissingIdentity(_)));
    }

    #[test]
    fn overrides_arrive_under_the_key_the_limiter_looks_them_up_by() {
        // MUTATION THIS CATCHES: keying on the proto's enum NAME (`Write`,
        // `KIND_WRITE`) instead of `kind_str`. Nothing fails — the override is
        // simply never found, and a limit an admin set does nothing at all. So
        // this asserts THROUGH `Limits::effective`, the only reader that matters,
        // rather than against the string this code chose for itself.
        let overrides = overrides_from(vec![RateLimitOverride {
            module: "task".to_string(),
            kind: Kind::Write as i32,
            limit: Some(RateLimit {
                rate: 3.0,
                burst: 7,
            }),
        }])
        .expect("a well-formed override is enforceable");
        let limits = crate::limit::Limits::parse("task.write=1:1", "1:1").expect("limits parse");
        let effective = limits.effective("task", Kind::Write, &overrides);
        assert_eq!(effective.rate, 3.0);
        assert_eq!(effective.burst, 7.0);
        // And the bucket NOBODY overrode still comes from configuration.
        assert_eq!(limits.effective("task", Kind::Read, &overrides).rate, 1.0);
    }

    #[test]
    fn an_override_that_cannot_be_enforced_refuses_the_whole_credential() {
        // `rate = 0` is the contract's DENY. `limit::validate` refuses it because
        // the script turns a zero rate into a permanent lockout with a 24-hour
        // `Retry-After`, so it cannot be honoured as written — and dropping it
        // would apply the configured default instead, silently undoing an admin.
        let err = overrides_from(vec![RateLimitOverride {
            module: "task".to_string(),
            kind: Kind::Write as i32,
            limit: Some(RateLimit {
                rate: 0.0,
                burst: 0,
            }),
        }])
        .expect_err("a bucket this gateway cannot enforce must not be dropped");
        assert!(matches!(err, ConfigError::NotPositive(_, _)));
    }

    #[test]
    fn an_entry_with_no_limit_is_no_override_and_not_a_denial() {
        // THE CONTRACT'S OWN INSTRUCTION: an unset `limit` is how an override is
        // CLEARED, so one still in the list is a server bug that "must be read as
        // no override for that bucket rather than as a denial". Reading it as a
        // denial is what `unwrap_or_default()` does — rate 0, burst 0 — and it
        // would refuse the credential outright.
        let overrides = overrides_from(vec![RateLimitOverride {
            module: "task".to_string(),
            kind: Kind::Write as i32,
            limit: None,
        }])
        .expect("a cleared override is not an error");
        assert!(overrides.is_empty());

        // AND NOTHING ELSE ABOUT A CLEARED ENTRY CAN BE WRONG, which is why the
        // `limit` check runs FIRST. It used to run after the kind and module
        // checks, so a cleared override carrying `KIND_JOB` — a server bug in a
        // field that no longer means anything — refused the whole credential,
        // turning "no override for that bucket" into exactly the denial the
        // contract says it must not be read as.
        let odd = overrides_from(vec![RateLimitOverride {
            module: String::new(),
            kind: Kind::Job as i32,
            limit: None,
        }])
        .expect("a cleared override is skipped before anything else is judged");
        assert!(odd.is_empty());
    }

    #[test]
    fn a_kind_this_gateway_has_no_bucket_for_is_refused() {
        // KIND_JOB is outside D74's mechanism and KIND_UNSPECIFIED is a zero value
        // nothing should construct. Accepting either mints a key
        // `Limits::effective` can never be asked for.
        for kind in [Kind::Job, Kind::Unspecified] {
            let err = overrides_from(vec![RateLimitOverride {
                module: "task".to_string(),
                kind: kind as i32,
                limit: Some(RateLimit {
                    rate: 1.0,
                    burst: 1,
                }),
            }])
            .expect_err("this kind has no bucket");
            assert!(matches!(err, ConfigError::UnknownKind(_)), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn scope_carries_the_request_id_it_was_given() {
        let attested = attest(
            &Attestation::TrustedHeaders,
            &nowhere(),
            None,
            Claimed {
                user_id: Some("max"),
                project_id: Some("acme/demo"),
                instance_id: Some("i-1"),
            },
            "REQ-3".to_string(),
        )
        .await
        .expect("complete claim attests");
        assert_eq!(attested.scope.request_id, "REQ-3");
        assert_eq!(attested.scope.user_id, "max");
        // No override arrives on this path and none can: see `Attested::limits`.
        assert!(attested.limits.is_empty());
        // Team membership is never taken from the caller, and there is no header
        // that could carry it — this assertion exists so that adding one is a
        // deliberate act rather than an oversight.
        assert!(attested.scope.team_ids.is_empty());
    }

    #[tokio::test]
    async fn an_incomplete_claim_is_refused_rather_than_defaulted() {
        let err = attest(
            &Attestation::TrustedHeaders,
            &nowhere(),
            None,
            Claimed {
                user_id: None,
                project_id: Some("acme/demo"),
                instance_id: None,
            },
            "REQ-4".to_string(),
        )
        .await
        .expect_err("a missing user must not become an empty one");
        assert!(matches!(err, AttestError::MissingIdentity(_)));
    }

    #[test]
    fn a_bearer_token_is_the_only_credential_this_gateway_reads() {
        assert_eq!(bearer(None), None);
        assert_eq!(bearer(Some("token-with-no-scheme")), None);
        assert_eq!(bearer(Some("Basic dXNlcjpwdw==")), None);
        assert_eq!(bearer(Some("Bearer ")), None, "an empty token is none");
        assert_eq!(bearer(Some("Bearer t0ken")), Some("t0ken"));
        // RFC 9110 makes the scheme case-insensitive, and a client sending the
        // lowercase form would otherwise be refused for a reason no message
        // explains.
        assert_eq!(bearer(Some("bearer t0ken")), Some("t0ken"));
    }

    #[tokio::test]
    async fn a_credentialless_request_under_iam_never_reaches_the_upstream() {
        // The channel points at a closed port, so an RPC would take the transport
        // path and come back `Upstream`. `MissingCredential` proves the refusal
        // happened HERE — which is what keeps an unauthenticated flood off `iam`.
        let err = attest(
            &Attestation::Iam,
            &nowhere(),
            None,
            Claimed {
                user_id: Some("forged-by-the-caller"),
                project_id: Some("acme/demo"),
                instance_id: None,
            },
            "REQ-5".to_string(),
        )
        .await
        .expect_err("a header is not a credential");
        assert!(
            matches!(err, AttestError::MissingCredential),
            "a self-asserted user must not stand in for a token; got {err:?}"
        );
    }
}
