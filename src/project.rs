//! The claimed workspace, resolved against the registry — and, in this release,
//! REFUSED FOR NOBODY.
//!
//! `attest` says of `project_id`: "CLAIMED, and legitimately so. It is a
//! workspace fact, it changes as a person moves between checkouts, and a token
//! cannot carry it." Legitimately claimed is not the same as unexamined, and
//! until this module existed it was both: the header was stamped into the
//! `Scope` and bound into a task row without anything asking the registry
//! whether the named project exists. A caller could name any string on a write,
//! and the row landed with it — a corruption of the partition key, which D52
//! says no later pass can merge back and D58 makes impossible to clean across
//! modules.
//!
//! **THIS RELEASE RESOLVES, CLASSIFIES AND COUNTS. IT REFUSES NOTHING.** That
//! is the deliverable rather than a caveat. `plans/project-validation.md` puts
//! a counted stage between the resolution and the enforcement for one measured
//! reason: the registry holds ONE row today (ledger 829 — 18 of 19
//! repositories absent), so a gateway that enforced on the day it learned how
//! would refuse essentially every call in the estate. The counter is what tells
//! an operator, before anything breaks, whether the canonicalisation refuses
//! anybody legitimate.
//!
//! So [`Mode::Counting`] is the shipped value, every terminal state increments
//! its counter, and the call then proceeds EXACTLY as it did before this module
//! existed — including the `Scope` it is stamped with. Counting never stamps:
//! a call that returns its normal answer while writing into a different
//! `project_id` than it did yesterday has not "proceeded as before". Under
//! [`Mode::Enforcing`] the resolved path REPLACES the claim (see [`Stamp`]), so
//! the flip is the one behaviour change and the one thing to revert.
//!
//! **THE FIVE TERMINAL STATES** are the plan's taxonomy. `MISSING_WORKSPACE` —
//! no header at all — shipped long ago and is [`crate::attest::AttestError`]'s
//! and not this module's. The four here are [`Reason`], plus a fifth condition
//! that is not a refusal of the CALLER at all: see [`Reason::RegistryUnavailable`].
//!
//! **A SIXTH, ADR-0941's, TURNS ON WHAT THE CALL DOES.** A claim that RESOLVES
//! to an archived project is refused for a write and served for a read — see
//! [`Reason::Archived`] and [`Access`]. Every other state is decided from the
//! claim alone.
//!
//! **TWO OBSERVABLES, AND THE SECOND ONE IS WHAT MAKES THE FLIP DECIDABLE.**
//! [`REFUSALS`] counts what would be refused; [`RESOLUTIONS`] counts what
//! resolved. The stage-5 gate reads the first as ZERO over a window and the
//! second as NONZERO over the same window — so with only the refusal counter
//! shipped, a gateway serving no traffic at all reads identically to one whose
//! canonicalisation is perfect. Greenfield makes that indistinguishable
//! reading the likely one.

use std::fmt;

mod account;
mod classify;
mod grants;
mod listing;
mod member;
mod mode;
mod poll;
mod registry;
mod remediate;
mod retry;

pub use account::{account_segment, is_canonical_user_id};
pub use classify::{classify, is_well_formed, Match, Outcome, Registered};
pub use grants::{
    Level, OrgGrants, OrgGrantsError, Shadow, GRANT_SHADOW, ORG_GRANTS,
    ORG_ROWS_WITHOUT_EFFECTIVE_GRANT,
};
pub use listing::Listed;
pub use mode::{Mode, ModeError, MODE};
pub use poll::{poll_from_env, poll_from_lookup, RetryError, POLL};
pub use registry::{Loaded, Registry, LOADED, PRIVATE_WITHOUT_OWNER};

/// Every terminal state this module can reach, counted by reason.
///
/// **`yadgar_gateway_project_refusal_total{reason}` IS ONE COUNTER ACROSS BOTH
/// MODES**, deliberately: the flip changes what the caller is told and nothing
/// about what is measured, so a dashboard reads continuously across it and the
/// gate's before-and-after are the same series.
pub const REFUSALS: &str = "yadgar_gateway_project_refusal_total";

/// Every successful resolution, by whether the claim had a row of its own.
///
/// `outcome` is `exact` or `ancestor`. The second value is D52's soft landing,
/// which is a normal answer rather than a degraded one — a monorepo subpath
/// declared by a `.yadgar/project-id` marker (D53) is EXPECTED to be deeper
/// than any registered row, so `ancestor` is the designed case and not the
/// tolerated one.
pub const RESOLUTIONS: &str = "yadgar_gateway_project_resolution_total";

/// Why a claimed workspace was refused, or would have been.
///
/// The `reason` label on [`REFUSALS`] and the machine token in
/// `error.data.reason`. A CLOSED SET, per ADR-0558: a hand-written label
/// outside the mapping's own values is the defect that ADR fixed, and this enum
/// is what keeps the metric's cardinality bounded by the type system rather
/// than by attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The value is not a project path at all (grammar).
    ///
    /// Decided BEFORE any resolution, and its prose never repeats the value —
    /// see [`classify`]'s module comment.
    Invalid,

    /// The nearest registered ancestor is a single-segment namespace ANCHOR
    /// (ADR-0673).
    ///
    /// The repository is not registered. The anchor is read through to name the
    /// repository whose PR flow governs the namespace, and nothing lands on it.
    UnregisteredOrg,

    /// A `local/` path with no registered ancestor (ADR-0605).
    ///
    /// The ONLY class whose remediation ends in creating something, which is
    /// why it is reachable only beneath the one reserved namespace where
    /// self-creation exists.
    UnregisteredPersonal,

    /// No registered ancestor at all, and not under `local/`.
    ///
    /// **NO REMEDIATION, AND THAT IS THE POINT OF THE CLASS.** With two classes
    /// every unclassifiable input is forced into a remediation that ends in a
    /// mutation — a PR, or a minted project — so the failure mode of
    /// misclassification is a WRITE. With this class it is a refused call and a
    /// human conversation, which is recoverable.
    Unresolvable,

    /// The registry has never loaded, so no claim can be checked (ADR-0674).
    ///
    /// **NOT A JUDGEMENT ABOUT THE CALLER, AND ITS REASON IS DISTINCT FOR THAT
    /// REASON.** ADR-0674 requires that an operator can tell "your project is
    /// unregistered" from "this gateway has no registry yet"; sharing a token
    /// with any of the four above would send somebody to register a project
    /// that is registered already.
    ///
    /// **IT RIDES [`REFUSALS`] ANYWAY, and that placement is load-bearing.**
    /// The stage-5 gate flips enforcement only while the refusal counter's
    /// increase over the window is zero — so counting this here makes the flip
    /// UNFLIPPABLE while the registry is down, which is exactly the desired
    /// interlock. A separate counter would let the gate read clean during the
    /// one condition under which enforcement refuses everybody.
    RegistryUnavailable,

    /// The claim RESOLVED, to an ARCHIVED project, and the call writes
    /// (ADR-0941).
    ///
    /// **THE ONLY CLASS DECIDED BY THE CALL AS WELL AS THE CLAIM.** A read of
    /// the same project resolves normally: archive keeps history (ADR-0934's
    /// archive-not-delete), so it must stay readable. A claim BENEATH an
    /// archived project lands on it by D52's soft landing and is refused the
    /// same way — the resolved project is archived.
    ///
    /// **IT FOLLOWS THE MODE LIKE EVERY OTHER CLASS**: counted and served under
    /// [`Mode::Counting`], answered under [`Mode::Enforcing`]. ADR-0941 leaves
    /// that open ("confirm with Max"); the reading here is that the stage-5 gate
    /// should see archived writes the way it sees every other would-be refusal.
    Archived,

    /// The claim RESOLVED, to a PRIVATE (`local/…`) project the caller does not
    /// own, for a read or a write (`plans/project-membership.md`, ADR-0947).
    ///
    /// **ONE ANSWER FOR EVERY NON-OWNER.** Decided before [`Self::Archived`] on a
    /// private row (Max's ruling E), so a non-owner learns nothing about the
    /// row's status, and the same 403 answers a read and a write. See
    /// [`member`] for the subtree rule and why a missing owner fails closed.
    ///
    /// **ALSO AN ORG ROW NO TEAM OF THE CALLER'S IS GRANTED (ADR-0962)**, under
    /// `orgGrants: enforcing` — decided before archived, so the same body
    /// answers an org non-member and a private non-owner (ADR-0963 (2)).
    NotMember,

    /// The claim RESOLVED to an ORG row on which the caller's teams hold only
    /// a `read` grant, and the call writes (ADR-0963 (3)).
    ///
    /// Decided after the grant step and before [`Self::Archived`]: a caller
    /// with no grant at all is [`Self::NotMember`], and a read-only member is
    /// told about the level before the archive state. Counted here only under
    /// `orgGrants: enforcing`; under `counting` the same call moves
    /// [`GRANT_SHADOW`]`{verdict="read_only"}` and is served.
    ReadOnly,
}

impl Reason {
    /// The metric label and the `error.data.reason` token, which are the same
    /// string on purpose: a client branches on the token and an operator
    /// branches on the label, and two spellings of one condition is how a
    /// dashboard and an incident report stop agreeing.
    pub fn token(self) -> &'static str {
        match self {
            Self::Invalid => "PROJECT_INVALID",
            Self::UnregisteredOrg => "PROJECT_UNREGISTERED_ORG",
            Self::UnregisteredPersonal => "PROJECT_UNREGISTERED_PERSONAL",
            Self::Unresolvable => "PROJECT_UNRESOLVABLE",
            Self::RegistryUnavailable => "PROJECT_REGISTRY_UNAVAILABLE",
            Self::Archived => "PROJECT_ARCHIVED",
            Self::NotMember => "PROJECT_NOT_MEMBER",
            Self::ReadOnly => "PROJECT_READ_ONLY",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Whether a call reads or writes, as far as ADR-0941 is concerned.
///
/// An enum rather than a `bool` so a call site says which it means. Derived from
/// the TOOL NAME at dispatch (`crate::tools::is_write`), the same derivation
/// that decides `CallRecord.kind` — one rule for "is this a write", not two.
///
/// **THE DEFAULT IS `Write`**, because the default is what a site that forgot to
/// say gets, and forgetting must not let a write into an archived project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Access {
    Read,
    #[default]
    Write,
}

/// One classified refusal, before any prose is composed for it.
///
/// **THE ANCHOR IS CARRIED AND THE REMEDIATION IS NOT.** Composing
/// `PROJECT_UNREGISTERED_ORG`'s remediation needs the anchor row's
/// `source_repo`, which the LOADED set does not carry and deliberately will not
/// — `RegisteredPath` is `path`, `status` and `aliases`, and widening every
/// registry load with a field the hot path never reads would promote the load
/// into a classification surface. So the classification carries the anchor's
/// path, and the fallback rpc is dialled for the rest, on the refusal path
/// only. See [`remediate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: Reason,
    /// The single-segment anchor the claim resolved to, for
    /// [`Reason::UnregisteredOrg`] and nothing else.
    pub anchor: Option<String>,
}

impl Refusal {
    /// A refusal that needs nothing looked up.
    pub(crate) fn bare(reason: Reason) -> Self {
        Self {
            reason,
            anchor: None,
        }
    }

    /// A claim whose nearest registered ancestor is a namespace anchor.
    pub(crate) fn under_anchor(anchor: &str) -> Self {
        Self {
            reason: Reason::UnregisteredOrg,
            anchor: Some(anchor.to_string()),
        }
    }
}

/// What the caller is told, once something has decided to tell them.
///
/// Built ONLY in [`Mode::Enforcing`]: in counting mode nothing is composed,
/// nothing is dialled, and the call proceeds. See [`Validator::check`].
///
/// **THE `Display` FORM IS FOR THE LOG**, the same split `attest::AttestError`
/// makes: `http::attest_answer` decides what the caller is told. It carries the
/// reason token and the prose and — like every sentence in [`remediate`] — never
/// the caller's claimed value.
#[derive(Debug, thiserror::Error)]
#[error("{reason}: {prose}")]
pub struct Denied {
    pub reason: Reason,
    /// The sentence a person reads. Never contains the caller's claimed value.
    pub prose: String,
}

/// What an ENFORCING resolution stamps on the call (stage 5, D52).
///
/// `path` is the REGISTERED spelling of the row the claim landed on, and
/// replaces the claim in the `Scope`; `exact` is false on a soft landing and
/// rides back in the tool result. Never built under [`Mode::Counting`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub path: String,
    pub exact: bool,
}

/// The registry, the mode, and the channel a refusal is composed over.
///
/// Held on [`crate::http::AppState`] for the reason the credential cache is:
/// the loaded set is process state, and one built per request would resolve
/// against nothing.
pub struct Validator {
    registry: Registry,
    mode: Mode,
    /// Whether an org-row grant miss is refused or only shadow-counted.
    org_grants: OrgGrants,
    /// The `project` logic tier, for the FALLBACK rpc only.
    ///
    /// **NOT the hot path, and this channel carries no per-request traffic at
    /// all.** `plans/project-registry-callers.md` §1-2 makes `ResolveProject`
    /// contractually the fallback, and the loaded set answers every
    /// classification without it. One dial happens per ANSWERED refusal, to
    /// fetch what the remediation names — which in counting mode is never.
    project: crate::upstream::ProjectUpstream,
}

impl Validator {
    pub fn new(registry: Registry, mode: Mode, project: crate::upstream::ProjectUpstream) -> Self {
        Self {
            registry,
            mode,
            org_grants: OrgGrants::default(),
            project,
        }
    }

    /// This validator with the `orgGrants` knob set (ADR-0963 (4)). Without
    /// it a validator judges as the shipped chart does: `counting`.
    #[must_use]
    pub fn with_org_grants(self, org_grants: OrgGrants) -> Self {
        Self { org_grants, ..self }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn org_grants(&self) -> OrgGrants {
        self.org_grants
    }

    /// The rows the caller may reach (`list_projects`, §8), or `None` while
    /// the registry has never loaded.
    pub fn listing(&self, user_id: &str, team_ids: &[String]) -> Option<Vec<Listed>> {
        Some(self.registry.loaded()?.listing(user_id, team_ids))
    }

    /// Resolve one claimed workspace, count the outcome, and refuse only if
    /// this deployment says to.
    ///
    /// **THE COUNTER MOVES IN BOTH MODES AND THE ANSWER MOVES IN ONE.** Every
    /// path through this function increments exactly one series before it
    /// decides anything about the caller, so the flip cannot change what is
    /// measured — which is the property that makes the gate's before-and-after
    /// comparable at all.
    ///
    /// # Errors
    ///
    /// Only in [`Mode::Enforcing`], and then once per terminal state.
    ///
    /// `access` says whether the call writes: a write to an ARCHIVED project is a
    /// refusal of its own (ADR-0941), and a read of one is an ordinary
    /// resolution.
    ///
    /// `user_id` is the attested caller, compared with a private row's stored
    /// owner — see [`member`].
    ///
    /// `team_ids` are the attested caller's teams, from iam only, matched
    /// against an org row's effective grants (ADR-0962) — see [`grants`].
    ///
    /// `request_id` is the call's D67 id, carried to `project` if a refusal
    /// dials it (ledger 1248).
    pub async fn check(
        &self,
        claimed: &str,
        access: Access,
        user_id: &str,
        team_ids: &[String],
        request_id: &str,
    ) -> Result<(), Denied> {
        let resolved = self.resolve(claimed, access, user_id, team_ids, request_id);
        resolved.await.map(drop)
    }

    /// [`Self::check`], answering the [`Stamp`] — `Some` only under enforcement.
    pub async fn resolve(
        &self,
        claimed: &str,
        access: Access,
        user_id: &str,
        team_ids: &[String],
        request_id: &str,
    ) -> Result<Option<Stamp>, Denied> {
        let Some(loaded) = self.registry.loaded() else {
            // THE REGISTRY HAS NEVER LOADED (ADR-0674). Counted, because the
            // gate must not flip while this is happening; refused only under
            // enforcement, because a counting gateway that answered this would
            // take down every scoped call in the estate the moment `project`
            // was unreachable — which is the enforcement this release exists
            // not to perform.
            return self
                .decide(Refusal::bare(Reason::RegistryUnavailable), request_id)
                .await;
        };

        // A CLAIM INTO ANOTHER ACCOUNT'S `local/` SEGMENT IS REFUSED BEFORE ANYTHING
        // IN THE LOADED SET IS CONSULTED (ADR-0954, Max's ruling on F3). Registered or
        // not, soft landing or not, it is one answer — so the answer cannot
        // say which of another account's paths exist.
        if member::is_foreign_private(claimed, user_id) {
            return self
                .decide(Refusal::bare(Reason::NotMember), request_id)
                .await;
        }

        let (path, exact, archived, owner, private) = match classify(loaded.as_ref(), claimed) {
            Outcome::Resolved {
                path,
                exact,
                archived,
                owner,
                private,
            } => (path, exact, archived, owner, private),
            Outcome::Refused(refusal) => return self.decide(refusal, request_id).await,
        };
        let landed = member::Landed {
            path: &path,
            exact,
            archived,
            owner: &owner,
            private,
        };
        // A REFUSAL IS NOT A RESOLUTION, so a membership or archived refusal
        // moves the refusal series ONLY: exactly one series per call, as above.
        let org = || self.org_gate(loaded.as_ref(), &landed, access, team_ids);
        match member::verdict(loaded.as_ref(), &landed, access, user_id, org) {
            member::Verdict::Refuse(reason) => self.decide(Refusal::bare(reason), request_id).await,
            member::Verdict::Resolution { exact } => {
                metrics::counter!(
                    RESOLUTIONS,
                    "outcome" => if exact { "exact" } else { "ancestor" },
                )
                .increment(1);
                Ok((self.mode == Mode::Enforcing).then_some(Stamp { path, exact }))
            }
        }
    }

    /// The grant step on an ORG row (§3 steps 1-2), as this knob judges it.
    ///
    /// Under `enforcing` the miss is a refusal reason. Under `counting` it is
    /// one [`GRANT_SHADOW`] increment and no reason, so the call goes on to be
    /// judged as org-is-everyone judges it — an archived write still counts
    /// `PROJECT_ARCHIVED` (red 17).
    fn org_gate(
        &self,
        loaded: &Loaded,
        landed: &member::Landed<'_>,
        access: Access,
        team_ids: &[String],
    ) -> Option<Reason> {
        let shadow = match loaded.effective(landed.path, team_ids) {
            None => Shadow::NoGrant,
            Some(Level::Read) if access == Access::Write => Shadow::ReadOnly,
            Some(_) => return None,
        };
        match self.org_grants {
            OrgGrants::Enforcing => Some(match shadow {
                Shadow::NoGrant => Reason::NotMember,
                Shadow::ReadOnly => Reason::ReadOnly,
            }),
            OrgGrants::Counting => {
                metrics::counter!(GRANT_SHADOW, "verdict" => shadow.token()).increment(1);
                None
            }
        }
    }

    /// Count one refusal, and answer it only under enforcement.
    async fn decide(&self, refusal: Refusal, request_id: &str) -> Result<Option<Stamp>, Denied> {
        metrics::counter!(REFUSALS, "reason" => refusal.reason.token()).increment(1);

        if self.mode == Mode::Counting {
            // THE WHOLE OF THIS RELEASE'S BEHAVIOUR. The classification is
            // recorded and the call goes on to be served exactly as it was
            // before this module existed.
            //
            // NOTHING IS DIALLED HERE EITHER, and that is not merely saved
            // work: with the registry as recalled, nearly every call in the
            // estate reaches this line, so composing a remediation would put
            // one `ResolveProject` round trip on every request in the system —
            // through the very channel the loaded set exists to keep off the
            // hot path.
            tracing::debug!(
                reason = %refusal.reason,
                "the claimed workspace would be refused under enforcement; counted and served"
            );
            return Ok(None);
        }

        Err(remediate::compose(&self.project, refusal, request_id, self.org_grants).await)
    }
}

#[cfg(test)]
mod tests;
