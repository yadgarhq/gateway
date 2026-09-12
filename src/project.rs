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
//! existed — including the `Scope` it is stamped with. The resolved path is
//! deliberately NOT substituted for the claim here: a call that returns its
//! normal answer while writing into a different `project_id` than it did
//! yesterday has not "proceeded as before", and a silent change of partition
//! key is the harm this whole plan exists to prevent. Stamping the resolved
//! path moves with the flip, so the flip is the one behaviour change and the
//! one thing to revert.
//!
//! **THE FIVE TERMINAL STATES** are the plan's taxonomy. `MISSING_WORKSPACE` —
//! no header at all — shipped long ago and is [`crate::attest::AttestError`]'s
//! and not this module's. The four here are [`Reason`], plus a fifth condition
//! that is not a refusal of the CALLER at all: see [`Reason::RegistryUnavailable`].
//!
//! **TWO OBSERVABLES, AND THE SECOND ONE IS WHAT MAKES THE FLIP DECIDABLE.**
//! [`REFUSALS`] counts what would be refused; [`RESOLUTIONS`] counts what
//! resolved. The stage-5 gate reads the first as ZERO over a window and the
//! second as NONZERO over the same window — so with only the refusal counter
//! shipped, a gateway serving no traffic at all reads identically to one whose
//! canonicalisation is perfect. Greenfield makes that indistinguishable
//! reading the likely one.

use std::fmt;

use tonic::transport::Channel;

mod classify;
mod registry;
mod remediate;

pub use classify::{classify, is_well_formed, Outcome, Registered};
pub use registry::{poll_from_env, poll_from_lookup, Loaded, Registry, RetryError, LOADED, POLL};

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
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
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

/// Whether a classified refusal is answered or only counted.
///
/// **NO COMPILED-IN DEFAULT (ADR-0569).** An absent or unrecognised value
/// refuses the boot naming the variable, because the two values differ by
/// whether the estate's calls are served — and a mode nobody chose, applied as
/// if somebody had, is exactly what that rule exists to delete. The flip to
/// [`Self::Enforcing`] is a one-line change to this gateway's own deployment,
/// revertable by the same line, gated on the two counters above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Resolve, classify, count — and serve the call anyway. The shipped value.
    #[default]
    Counting,
    /// Answer the refusal. Reachable only by naming it (stage 5).
    Enforcing,
}

/// The environment variable that chooses the mode.
pub const MODE: &str = "YADGAR_PROJECT_VALIDATION_MODE";

impl Mode {
    /// Resolve the mode from this process's environment.
    ///
    /// # Errors
    ///
    /// See [`Self::from_lookup`], which this is: no fallback, and no parameter a
    /// fallback could sit in (ADR-0569).
    pub fn from_env() -> Result<Self, ModeError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Resolve the mode from an injected lookup.
    ///
    /// **A SEAM, for `Attestation::from_lookup`'s reason**: environment
    /// variables are process-global, so a test that set one would steer every
    /// other test in the same binary — and the decision this one makes is
    /// whether the estate's calls are refused.
    ///
    /// # Errors
    ///
    /// An absent value, and any value that is not one of the two names.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ModeError> {
        match lookup(MODE).as_deref().map(str::trim) {
            None => Err(ModeError::Absent),
            Some("counting") => Ok(Self::Counting),
            Some("enforcing") => Ok(Self::Enforcing),
            // THE VALUE IS ECHOED HERE and nowhere a caller can read it: this
            // is a boot refusal naming a deployment's own mistake, on the
            // operator's terminal, and a typo an operator cannot see is a
            // refusal they cannot fix.
            Some(other) => Err(ModeError::Unknown(other.to_string())),
        }
    }
}

/// A mode this deployment did not state, or stated in a word this binary does
/// not know.
#[derive(Debug, thiserror::Error)]
pub enum ModeError {
    #[error(
        "{MODE} is not set. It chooses whether a claimed workspace that resolves to nothing is \
         REFUSED or merely counted, and there is no compiled-in default (ADR-0569) because the \
         two answers differ by whether this estate's calls are served. Set it to \"counting\" \
         — the value every deployment ships until the flip gate in \
         plans/project-validation.md is read — or to \"enforcing\"."
    )]
    Absent,

    #[error(
        "{MODE} is {0:?}, which is neither \"counting\" nor \"enforcing\". A value outside the \
         two names is refused rather than read as the safer one: a deployment that meant to \
         enforce and misspelled it would otherwise enforce nothing, silently, for ever."
    )]
    Unknown(String),
}

/// The registry, the mode, and the channel a refusal is composed over.
///
/// Held on [`crate::http::AppState`] for the reason the credential cache is:
/// the loaded set is process state, and one built per request would resolve
/// against nothing.
pub struct Validator {
    registry: Registry,
    mode: Mode,
    /// The `project` logic tier, for the FALLBACK rpc only.
    ///
    /// **NOT the hot path, and this channel carries no per-request traffic at
    /// all.** `plans/project-registry-callers.md` §1-2 makes `ResolveProject`
    /// contractually the fallback, and the loaded set answers every
    /// classification without it. One dial happens per ANSWERED refusal, to
    /// fetch what the remediation names — which in counting mode is never.
    project: Channel,
}

impl Validator {
    pub fn new(registry: Registry, mode: Mode, project: Channel) -> Self {
        Self {
            registry,
            mode,
            project,
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
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
    pub async fn check(&self, claimed: &str) -> Result<(), Denied> {
        let Some(loaded) = self.registry.loaded() else {
            // THE REGISTRY HAS NEVER LOADED (ADR-0674). Counted, because the
            // gate must not flip while this is happening; refused only under
            // enforcement, because a counting gateway that answered this would
            // take down every scoped call in the estate the moment `project`
            // was unreachable — which is the enforcement this release exists
            // not to perform.
            return self
                .decide(Refusal::bare(Reason::RegistryUnavailable))
                .await;
        };

        match classify(loaded.as_ref(), claimed) {
            Outcome::Resolved { exact, .. } => {
                metrics::counter!(
                    RESOLUTIONS,
                    "outcome" => if exact { "exact" } else { "ancestor" },
                )
                .increment(1);
                Ok(())
            }
            Outcome::Refused(refusal) => self.decide(refusal).await,
        }
    }

    /// Count one refusal, and answer it only under enforcement.
    async fn decide(&self, refusal: Refusal) -> Result<(), Denied> {
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
            return Ok(());
        }

        Err(remediate::compose(&self.project, refusal).await)
    }
}

#[cfg(test)]
mod tests;
