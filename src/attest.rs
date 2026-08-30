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
        if let Ok(addr) = std::env::var(IAM_ADDR) {
            if !addr.is_empty() {
                return Ok(Self::Iam { addr });
            }
        }
        // Exactly "1". A permissive parse here — "0", "false", "no" all enabling
        // it — is how a setting meant to be off ends up on.
        if std::env::var(TRUST_HEADERS).as_deref() == Ok("1") {
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

/// Build the attested scope for one request.
///
/// `request_id` is passed in rather than read from the caller, and that is the
/// whole point — see [`crate::request_id`].
pub fn attest(
    how: &Attestation,
    claimed: Claimed<'_>,
    request_id: String,
) -> Result<Scope, AttestError> {
    match how {
        Attestation::TrustedHeaders => Ok(Scope {
            user_id: claimed
                .user_id
                .ok_or(AttestError::MissingIdentity("X-Yadgar-User"))?
                .to_string(),
            project_id: claimed
                .project_id
                .ok_or(AttestError::MissingIdentity("X-Yadgar-Project"))?
                .to_string(),
            // A session identifier, not an identity — D46 throttles on it and
            // D39 addresses notices with it. Absent is legitimate: a one-shot
            // client has no session.
            instance_id: claimed.instance_id.unwrap_or_default().to_string(),
            // Team membership comes from iam. Empty means "no team visibility",
            // which is the restrictive answer and the right default while the
            // only identity source is a header the caller wrote.
            team_ids: Vec::new(),
            request_id,
        }),

        // Deliberately unimplemented rather than silently falling back to the
        // trusted-header path. A fallback here would mean a deployment that
        // believes it is authenticating while it is not.
        Attestation::Iam { .. } => {
            unimplemented!("iam-backed attestation lands with ledger 452")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(scope.request_id, "REQ-1");
        assert_eq!(scope.user_id, "max");
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
        assert!(scope.team_ids.is_empty());
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
