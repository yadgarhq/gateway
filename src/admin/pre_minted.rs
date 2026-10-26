//! The fail-closed switch on the pre-minted `user_id` arm of bootstrap
//! `create-user` (team access stage 3b; Max, 2026-10-24).
//!
//! The chart renders it from `adminBootstrap.refusePreMintedUserId`. The
//! shipped value is `false`, which keeps the arm open, as before this switch.
//! `true` refuses the arm before the token is compared, so an operator can
//! close it without a new image while the version gates in front of it do not
//! hold.

use super::{Ask, Verb};

/// The environment variable that chooses [`PreMintedIds`].
pub const REFUSE_PRE_MINTED_USER_ID: &str = "YADGAR_ADMIN_REFUSE_PRE_MINTED_USER_ID";

/// What the switch answers when it refuses. A deployment posture, and it does
/// not depend on the id, so it names the knob rather than hiding behind the
/// opaque 503 body. It has the 503 status of "the bootstrap token is not
/// configured", for that answer's reason: nothing the caller did is wrong.
pub const SWITCHED_OFF_BODY: &str = r#"{"error":"pre-minted user ids are switched off on this gateway (chart: adminBootstrap.refusePreMintedUserId)"}"#;

/// Whether this deployment admits the pre-minted arm.
///
/// **NO `Default`, AND NO COMPILED-IN DEFAULT IS READ (ADR-0569).** An absent
/// or unknown value refuses the boot naming the variable and the chart key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreMintedIds {
    /// `"0"`: the switch is not engaged. The arm is open.
    Admitted,
    /// `"1"`: the switch is engaged. The arm is refused before the comparison.
    Refused,
}

impl PreMintedIds {
    /// Resolve the switch from this process's environment.
    ///
    /// # Errors
    ///
    /// See [`Self::from_lookup`].
    pub fn from_env() -> Result<Self, PreMintedIdsError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Resolve the switch from an injected lookup (a test seam, as
    /// `OrgGrants::from_lookup` is).
    ///
    /// # Errors
    ///
    /// An absent value, and any value that is not exactly `"1"` or `"0"`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, PreMintedIdsError> {
        match lookup(REFUSE_PRE_MINTED_USER_ID).as_deref() {
            None => Err(PreMintedIdsError::Absent),
            Some("1") => Ok(Self::Refused),
            Some("0") => Ok(Self::Admitted),
            Some(other) => Err(PreMintedIdsError::Unknown(other.to_string())),
        }
    }

    /// Whether this switch refuses a bootstrap request for `verb` with `ask`.
    /// Only the pre-minted `create-user` arm is in its reach: the enrolment
    /// is not.
    pub fn refuses(self, verb: Verb, ask: Ask) -> bool {
        self == Self::Refused && verb == Verb::CreateUser && ask.pre_minted_id
    }
}

/// A switch this deployment did not state, or stated in a word not accepted.
#[derive(Debug, thiserror::Error)]
pub enum PreMintedIdsError {
    #[error(
        "{REFUSE_PRE_MINTED_USER_ID} is not set. It chooses whether the bootstrap token may \
         create the pre-minted first administrator, and there is no compiled-in default \
         (ADR-0569). Set it to \"0\" (chart: adminBootstrap.refusePreMintedUserId: false, the \
         shipped value) or to \"1\" to refuse that arm."
    )]
    Absent,

    #[error(
        "{REFUSE_PRE_MINTED_USER_ID} is {0:?}, and only \"1\" or \"0\" are accepted (chart: \
         adminBootstrap.refusePreMintedUserId). A value outside the two is refused rather than \
         read as either."
    )]
    Unknown(String),
}
