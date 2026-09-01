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
//! in a second. That is the difference between a claim and an invariant.
//!
//! **Why an unconfigured trust boundary refuses to boot.** D69 makes a missing
//! capability fail startup rather than fail later, and identity is a capability.
//! If neither a real credential source nor the explicit development override is
//! configured, this process exits — because the alternative, defaulting to
//! trusting whatever the caller claims, is a gateway that attests nothing while
//! its own contract says it does, and it would go green in a development cluster
//! and stay green.

use std::fmt;

use crate::limit::Overrides;
use crate::pb::yadgar::common::v1::Scope;

/// The environment variable is named for WHAT IT DOES, not for where it runs.
///
/// `DEV=1` tells a reader nothing about what it switches off. This name cannot be
/// set by accident and cannot be misread in a manifest.
const TRUST_HEADERS: &str = "YADGAR_TRUST_UNAUTHENTICATED_HEADERS";

/// Where a real credential lives once `iam` exists (ledger 452). Reserved now so
/// the boot check can distinguish "not configured" from "configured insecurely".
const IAM_ADDR: &str = "YADGAR_IAM_ADDR";

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error(
        "neither {TRUST_HEADERS}=1 nor {IAM_ADDR} is set. \
         The gateway attests caller identity and will not start without a source \
         for it: defaulting to trusting the caller would make Scope a claim the \
         caller controls. Set {IAM_ADDR} for a real deployment, or \
         {TRUST_HEADERS}=1 for local development."
    )]
    Unconfigured,

    #[error("request is missing the {0} header, which identifies the caller")]
    MissingIdentity(&'static str),

    #[error(
        "{IAM_ADDR} is set to {0}, and iam-backed attestation is not implemented \
         yet (ledger 452). This refuses at BOOT rather than accepting the \
         setting: the alternative is a process that logs \"attesting caller \
         identity\", binds its listener, passes readiness, and then panics on the \
         first tools/call — which inverts the D69 rule this module exists to \
         follow, and turns a deploy-time misconfiguration into an outage under \
         load. Unset {IAM_ADDR} until iam-backed attestation lands, or set \
         {TRUST_HEADERS}=1 for local development."
    )]
    IamUnimplemented(String),
}

/// How this process decided who the caller is. Chosen ONCE at boot.
#[derive(Debug, Clone)]
pub enum Attestation {
    /// Development only: identity is whatever the request says it is.
    TrustedHeaders,
    /// A real credential, verified against `iam`. Not yet implemented — the
    /// variant exists so the boot check can already tell the two apart, and so
    /// adding `iam` changes this file and nothing else.
    Iam { addr: String },
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustedHeaders => write!(f, "UNAUTHENTICATED (headers trusted)"),
            Self::Iam { addr } => write!(f, "iam at {addr}"),
        }
    }
}

impl Attestation {
    /// Decide the identity source, or refuse to start.
    ///
    /// Called from `main` BEFORE the listener is bound, so a misconfigured
    /// deployment never accepts a request it cannot attest.
    pub fn from_env() -> Result<Self, AttestError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the boot
    /// gate — the thing standing between a deployment and trusting whatever the
    /// caller claims — could not be tested at all without this. `from_env` is the
    /// one-line adapter; everything decided here is decided once.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, AttestError> {
        if let Some(addr) = lookup(IAM_ADDR).filter(|a| !a.is_empty()) {
            // REFUSED AT BOOT. The variant exists so this file can already tell
            // "not configured" from "configured for iam", and so that adding iam
            // changes this file and nothing else — but until `attest` can honour
            // it, accepting the setting means a green boot and a panic on the
            // first call.
            return Err(AttestError::IamUnimplemented(addr));
        }
        // Exactly "1". A permissive parse here — "0", "false", "no" all enabling
        // it — is how a setting meant to be off ends up on.
        if lookup(TRUST_HEADERS).as_deref() == Some("1") {
            return Ok(Self::TrustedHeaders);
        }
        Err(AttestError::Unconfigured)
    }
}

/// What the caller said about itself, before any of it is believed.
///
/// Deliberately a separate type from [`Scope`]: it is impossible to pass one of
/// these where a scope is wanted, so "unverified claim" and "attested fact"
/// cannot be confused at a call site.
#[derive(Debug, Default)]
pub struct Claimed<'a> {
    pub user_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub instance_id: Option<&'a str>,
}

/// What one lookup established about the caller.
///
/// **Identity and spending limits together, because D74 says they travel
/// together**: `ResolveCredentialResponse` carries the effective buckets, so the
/// gateway learns who you are and what you may spend in one lookup, cached
/// together and invalidated together. Two lookups would mean two cache lifetimes
/// and a window in which a tightened limit is not yet in force.
#[derive(Debug)]
pub struct Attested {
    pub scope: Scope,
    /// The caller's per-user bucket overrides (D74).
    ///
    /// **Empty on every path today, and that is the honest answer rather than a
    /// stub.** Overrides come from `iam`, the contract does not carry them yet,
    /// and there is no header that could: a caller who could name its own limits
    /// would raise them, which is the same reason `team_ids` is never taken from
    /// the caller. Empty means "no override", and the limiter then applies the
    /// configured default — which is what the deployment should do while no user
    /// has one.
    pub limits: Overrides,
}

/// Build the attested scope for one request.
///
/// `request_id` is passed in rather than read from the caller, and that is the
/// whole point — see [`crate::request_id`].
pub fn attest(
    how: &Attestation,
    claimed: Claimed<'_>,
    request_id: String,
) -> Result<Attested, AttestError> {
    match how {
        Attestation::TrustedHeaders => Ok(Attested {
            limits: Overrides::default(),
            scope: Scope {
                user_id: claimed
                    .user_id
                    .ok_or(AttestError::MissingIdentity("X-Yadgar-User"))?
                    .to_string(),
                project_id: claimed
                    .project_id
                    .ok_or(AttestError::MissingIdentity("X-Yadgar-Project"))?
                    .to_string(),
                // A session identifier, not an identity — D46 throttles on it
                // and D39 addresses notices with it. Absent is legitimate: a
                // one-shot client has no session.
                instance_id: claimed.instance_id.unwrap_or_default().to_string(),
                // Team membership comes from iam. Empty means "no team
                // visibility", which is the restrictive answer and the right
                // default while the only identity source is a header the caller
                // wrote.
                team_ids: Vec::new(),
                request_id,
            },
        }),

        // An ERROR rather than a fallback to the trusted-header path, which would
        // mean a deployment that believes it is authenticating while it is not —
        // and rather than the `unimplemented!()` that used to stand here, which
        // panicked the process on the first call. `from_lookup` already refuses
        // this variant at boot, so reaching here means somebody constructed it
        // directly; the answer is still a refusal, not a crash.
        Attestation::Iam { addr } => Err(AttestError::IamUnimplemented(addr.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup over a fixed table, standing in for the process environment.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn only_the_exact_string_one_enables_trusted_headers() {
        // MUTATION THIS CATCHES: `== Ok("1")` relaxed to `.is_ok()`, or to any
        // truthiness parse. Under it, `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=0` —
        // written by somebody deliberately turning the setting OFF — turns
        // authentication off instead, and the gateway trusts whatever the caller
        // claims. Nothing sat behind this gate before.
        assert!(matches!(
            Attestation::from_lookup(env(&[(TRUST_HEADERS, "1")])),
            Ok(Attestation::TrustedHeaders)
        ));
        for off in ["0", "false", "no", "", "true", "yes"] {
            assert!(
                matches!(
                    Attestation::from_lookup(env(&[(TRUST_HEADERS, off)])),
                    Err(AttestError::Unconfigured)
                ),
                "{off:?} must not enable trusted headers"
            );
        }
    }

    #[test]
    fn an_unset_environment_refuses_to_start() {
        // The default must be a refusal. Defaulting to trusting the caller is a
        // gateway that attests nothing while its contract says it does, and it
        // would go green in a development cluster and stay green.
        assert!(matches!(
            Attestation::from_lookup(env(&[])),
            Err(AttestError::Unconfigured)
        ));
    }

    #[test]
    fn an_iam_address_is_refused_at_boot_rather_than_panicking_on_the_first_call() {
        // MUTATION THIS CATCHES — and the bug this test was written for:
        // `Ok(Self::Iam { addr })`. The process then logs "attesting caller
        // identity", binds its listener, passes readiness, and panics inside
        // `attest` on the first tools/call.
        let err = Attestation::from_lookup(env(&[(IAM_ADDR, "iam:50052")]))
            .expect_err("an unimplemented identity source must not boot");
        assert!(matches!(err, AttestError::IamUnimplemented(a) if a == "iam:50052"));

        // An EMPTY value is not a configuration, and must fall through to the
        // ordinary refusal rather than being reported as an iam deployment.
        assert!(matches!(
            Attestation::from_lookup(env(&[(IAM_ADDR, "")])),
            Err(AttestError::Unconfigured)
        ));
    }

    #[test]
    fn attesting_under_iam_is_an_error_and_never_a_panic() {
        let err = attest(
            &Attestation::Iam {
                addr: "iam:50052".into(),
            },
            Claimed::default(),
            "REQ-0".to_string(),
        )
        .expect_err("iam-backed attestation is not implemented");
        assert!(matches!(err, AttestError::IamUnimplemented(_)));
    }

    #[test]
    fn scope_carries_the_request_id_it_was_given() {
        let scope = attest(
            &Attestation::TrustedHeaders,
            Claimed {
                user_id: Some("max"),
                project_id: Some("acme/demo"),
                instance_id: Some("i-1"),
            },
            "REQ-1".to_string(),
        )
        .expect("complete claim attests");
        assert_eq!(scope.scope.request_id, "REQ-1");
        assert_eq!(scope.scope.user_id, "max");
        // No override arrives on this path and none can: see `Attested::limits`.
        assert!(scope.limits.is_empty());
    }

    #[test]
    fn team_ids_are_never_taken_from_the_caller() {
        // There is no header for team membership, and this test exists so that
        // adding one is a deliberate act rather than an oversight: teams decide
        // what a TEAM-visible record is reachable by (D12), so a caller that
        // could name its own teams could read other people's records.
        let scope = attest(
            &Attestation::TrustedHeaders,
            Claimed {
                user_id: Some("max"),
                project_id: Some("acme/demo"),
                instance_id: None,
            },
            "REQ-2".to_string(),
        )
        .expect("complete claim attests");
        assert!(scope.scope.team_ids.is_empty());
    }

    #[test]
    fn an_incomplete_claim_is_refused_rather_than_defaulted() {
        let err = attest(
            &Attestation::TrustedHeaders,
            Claimed {
                user_id: None,
                project_id: Some("acme/demo"),
                instance_id: None,
            },
            "REQ-3".to_string(),
        )
        .expect_err("a missing user must not become an empty one");
        assert!(matches!(err, AttestError::MissingIdentity(_)));
    }
}
