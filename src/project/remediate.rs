//! What a refused caller is told, and the ONE round trip composing it costs.
//!
//! **THE PROSE IS COMPOSED FROM THE REASON, NEVER FROM THE CLAIM.** No sentence
//! in this module interpolates the caller's value. `project-db`'s `validate`
//! refuses an over-long value without echoing it — a refusal that repeats an
//! unbounded caller string lets the caller decide how large this service's log
//! lines are — and a grammar failure is by definition a value that may hold
//! anything at all.
//!
//! **THE REMEDIATION FOR AN UNREGISTERED ORGANISATION PATH COMES FROM DATA.**
//! ADR-0673: the namespace anchor is read THROUGH, far enough to name the
//! repository whose PR flow governs the namespace, and nothing ever lands on it.
//! That datum is not in the loaded set — `RegisteredPath` carries `path`,
//! `status` and `aliases`, and `plans/project-validation.md` keeps it that way
//! deliberately, because widening every registry load with a field the hot path
//! never reads would promote the load into a classification surface. So the
//! refusal path, and only the refusal path, dials the FALLBACK rpc.
//!
//! **AND IF THAT DIAL FAILS, THE REFUSAL STILL STANDS.** The classification came
//! from the loaded set, not from the call, so the answer stays a 400 carrying
//! its reason token and only the PROSE degrades. It must never become a 500: the
//! caller's request was already invalid before anything was dialled, and
//! answering with an availability failure would hide a correctness one — the
//! caller would retry for ever against a condition retrying cannot fix.
//!
//! **THE DATUM ARRIVES ON THE ANSWER, AND AN EMPTY STRING IS ITS ABSENCE.**
//! `ProjectServiceResolveProjectResponse` carries `source_repo` from
//! `PROTO_VERSION` v1.15.0, so [`compose`] passes the resolver's own value to
//! [`sentence`] and BOTH of that function's branches are now reached over the
//! wire rather than only from a test that hands them arguments.
//!
//! That field is a bare proto3 `string`, which has no presence bit, so a row
//! with no source repository arrives as `""` and not as nothing at all. Reading
//! it as a value would compose "open a pull request against , which governs this
//! namespace" — an empty interpolation inside a remediation, which is worse than
//! the degraded sentence it replaced. [`present`] is the ONE place that decision
//! is made, for every string field of the answer, and its own comment says why it
//! is one place.

use tonic::transport::Channel;

use crate::pb::yadgar::project::v1::{
    project_service_client::ProjectServiceClient, ProjectServiceResolveProjectRequest,
};

use super::{Denied, Reason, Refusal};

/// How long the fallback may take before the refusal is answered without it.
///
/// A bound and not a knob, sized the way `attest`'s credential deadline is: this
/// runs while a caller waits for a 400 it is going to get either way, so a
/// stalled `project` must cost one bounded wait rather than hold the answer
/// open.
const FALLBACK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

/// The answer for one classified refusal, dialling the fallback where the
/// remediation needs data the loaded set does not hold.
pub(super) async fn compose(project: &Channel, refusal: Refusal) -> Denied {
    let Some(anchor) = refusal.anchor.as_deref() else {
        // EVERY OTHER CLASS IS COMPOSED FROM THE REASON ALONE, so nothing is
        // dialled for it. A grammar failure, an unregistered private path and an
        // unresolvable one all state what they state without asking the registry
        // anything.
        return Denied {
            reason: refusal.reason,
            prose: sentence(refusal.reason, None, None),
        };
    };

    let resolved = resolve(project, anchor).await;
    Denied {
        reason: refusal.reason,
        prose: sentence(
            refusal.reason,
            // THE ANCHOR THIS GATEWAY WALKED TO IS THE FALLBACK, for a resolver
            // that answered nothing as much as for one that could not be
            // reached: the classification was already made from the loaded set.
            Some(resolved.path.as_deref().unwrap_or(anchor)),
            resolved.source_repo.as_deref(),
        ),
    }
}

/// What the resolver said, with proto3's empty strings already read as absence.
///
/// A struct rather than a pair because each field carries a different meaning of
/// `None` and each needs saying: this module's voice names its data, and
/// `(Option<String>, Option<String>)` at the call site would put the reader on
/// tuple order instead.
struct Resolved {
    /// The row the tier's own resolver names, which is the authority on aliases
    /// and on the column's collation.
    path: Option<String>,
    /// The repository whose pull-request flow governs that row's namespace.
    source_repo: Option<String>,
}

impl Resolved {
    /// The answer for a resolver that said nothing usable.
    ///
    /// ONE VALUE FOR BOTH FAILURES AND FOR A ROW THAT SIMPLY HAS NEITHER FIELD:
    /// the caller composes the degraded sentence from the anchor either way, so
    /// distinguishing them here would be a distinction no reader of the prose can
    /// observe. The log lines below are where the difference is recorded.
    fn absent() -> Self {
        Self {
            path: None,
            source_repo: None,
        }
    }
}

/// A proto3 `string` read as presence: empty is ABSENT, never a value.
///
/// **THIS IS WHERE THAT IS DECIDED, and it is deliberately the only place.**
/// Neither `resolved_path` nor `source_repo` is declared `optional`, so neither
/// carries a presence bit and an unpopulated one arrives as `""`. Every reader of
/// the answer therefore has to make this call, and a reader that made it
/// differently would interpolate an empty string into a sentence a person is
/// meant to act on.
///
/// `project.proto` states the same contract from the producer's side: an empty
/// `source_repo` means the resolved row HAS no source repository, either because
/// the row is private-class — `ck_project_class` gives such a row
/// `owner_user_id` and never `source_repo` — or because the store predates the
/// column being populated. Neither is an error, and neither may be rendered.
fn present(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

/// Ask the store's resolver which row the claim actually lands on.
///
/// **THE ANSWER IS CONFIRMATION, NEVER THE DECISION.** The classification is
/// already made, from the loaded set; what this adds is the row as the tier's own
/// resolver names it — which is the authority on aliases and on the column's
/// collation — plus the repository the remediation names. [`Resolved::absent`]
/// means the tier could not be reached, and the caller above falls back to the
/// anchor this gateway walked to.
async fn resolve(project: &Channel, anchor: &str) -> Resolved {
    let mut client = ProjectServiceClient::new(project.clone());
    let rpc = client.resolve_project(ProjectServiceResolveProjectRequest {
        candidate_path: anchor.to_string(),
    });
    match tokio::time::timeout(FALLBACK_DEADLINE, rpc).await {
        Ok(Ok(answer)) => {
            let answer = answer.into_inner();
            Resolved {
                path: present(answer.resolved_path),
                source_repo: present(answer.source_repo),
            }
        }
        // BOTH FAILURES ARE THE SAME FAILURE HERE, and neither changes the
        // status the caller gets. The reason goes to the log, where an operator
        // can read it; the caller gets the 400 its request had already earned.
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e,
                "the project registry could not be reached to name the repository this refusal \
                 should point at; answering the refusal with degraded prose"
            );
            Resolved::absent()
        }
        Err(_elapsed) => {
            tracing::warn!(
                deadline_secs = FALLBACK_DEADLINE.as_secs(),
                "the project registry did not answer within the fallback deadline; answering the \
                 refusal with degraded prose"
            );
            Resolved::absent()
        }
    }
}

/// The sentence for one reason, with whatever data was available for it.
///
/// Pure, and separate from the dial for that reason: both the composed and the
/// degraded form of every class are then assertable without a server.
pub(super) fn sentence(reason: Reason, anchor: Option<&str>, source_repo: Option<&str>) -> String {
    match reason {
        // THE GRAMMAR, AND NOT THE VALUE. See this module's header.
        Reason::Invalid => "the workspace named in x-yadgar-project is not a project path. A \
                            path is slash-separated segments of A-Z a-z 0-9 . _ - , neither \
                            \".\" nor \"..\", with no leading or trailing slash and at most 255 \
                            characters. The value is not repeated here."
            .to_string(),

        Reason::UnregisteredOrg => match (anchor, source_repo) {
            (_, Some(repo)) => format!(
                "this repository is not registered as a project. Registration is an \
                 administrative act and never an agent operation (D52): open a pull request \
                 against {repo}, which governs this namespace. A namespace is resolved through \
                 and never worked in (ADR-0673), so work cannot land at the namespace level \
                 instead."
            ),
            (Some(namespace), None) => format!(
                "this repository is not registered as a project. The namespace {namespace} is \
                 registered and is resolved through rather than worked in (ADR-0673), and the \
                 registry could not be reached to name the repository whose pull-request flow \
                 governs it — ask your operator which repository registers projects in \
                 {namespace}."
            ),
            (None, None) => "this repository is not registered as a project, and the registry \
                             could not be reached to name the repository whose pull-request flow \
                             governs its namespace. Ask your operator."
                .to_string(),
        },

        // THE ONE CLASS WHOSE REMEDIATION ENDS IN CREATING SOMETHING, and it
        // names no account segment: how an account is rendered into a
        // `local/<account>/…` id is ADR-0605's open choice, owned by ledger 641,
        // and inventing one here would hand a caller an id the store refuses.
        Reason::UnregisteredPersonal => "this private workspace is not registered. Declare it \
                                         with a .yadgar/project-id file at the directory you \
                                         mean to be its root, then register it with the \
                                         project-create tool — private projects are the one \
                                         namespace a caller may create in (ADR-0605)."
            .to_string(),

        // NO REMEDIATION. Everything this gateway could suggest here ends in a
        // mutation, and the failure mode of guessing wrong is a write into a
        // namespace nobody checked. Fail toward "ask a human".
        Reason::Unresolvable => "the workspace named in x-yadgar-project resolves to no \
                                 registered project and to no registered namespace. Nothing is \
                                 created automatically. Ask your operator which project this \
                                 checkout should be registered as."
            .to_string(),

        // NOT ABOUT THE CALLER AT ALL (ADR-0674), and the sentence says so
        // plainly: an operator reading this next to the four above must not have
        // to guess which of the two conditions they are in.
        Reason::RegistryUnavailable => "this gateway has not loaded the project registry yet, so \
                                        it cannot check which project this call names. Nothing \
                                        is wrong with the workspace or the credential. Retry; if \
                                        it persists, the project registry is unreachable from \
                                        this gateway."
            .to_string(),
    }
}
