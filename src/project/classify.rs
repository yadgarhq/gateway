//! The grammar, the ancestor walk, and which of the five terminal states a
//! claimed workspace reaches.
//!
//! Split out of [`super`] for the file-size ceiling. This is the DECISION;
//! [`super`] owns the modes and the metrics that observe it, and
//! [`super::registry`] owns the set it decides against.
//!
//! **THE WALK IS OVER THE LOADED SET, AND THE STORE'S WALK IS THE SPEC.**
//! `project-db/src/read.rs` resolves a candidate by taking the DEEPEST match in
//! its segment-wise ancestor chain, having first dropped the bare reserved
//! segment from that chain, comparing ASCII-case-insensitively because the
//! column collates `utf8mb4_general_ci`. Three properties, and this module
//! reproduces all three — a walk that answered a different path than
//! `ResolveProject` answers for the same candidate would make the refusal
//! depend on which route a caller's request happened to take.
//!
//! **THE GRAMMAR IS A SECOND COPY OF `project-db`'s `validate`, and it is one
//! knowingly.** This gateway compiles against `ProjectService` and not against
//! that function, so the only alternative is a round trip per request to ask
//! whether a string is a path at all — which is the per-request call the loaded
//! set exists to avoid. The drift between the two copies is held down by the
//! table in [`super::tests`], whose rows are the store's own refusal cases.
//!
//! **WHAT THE PROSE MAY NOT CONTAIN.** `validate` refuses an over-long value
//! WITHOUT echoing it, on the ground that a caller must not decide how large
//! this service's log lines are. The same rule applies here and is applied more
//! widely: no refusal composed from a `PROJECT_INVALID` ever repeats the
//! caller's value, because the value is by definition something that failed the
//! grammar and may hold anything at all.

use super::{Reason, Refusal};

/// The width of `project.path`, and therefore of anything that could ever be
/// registered.
///
/// The same number `project-db/src/path.rs` declares as `MAX_LEN`, for the same
/// reason: a longer value cannot be a registered path, so refusing it here
/// answers the same question one hop earlier.
const MAX_LEN: usize = 255;

/// The one segment reserved from the organisation namespace (ADR-0605).
///
/// `project-db/src/path.rs::RESERVED_ROOT`, by literal rather than through an
/// import this crate cannot have. ADR-0599's rule cuts the other way for an
/// interface string — this one is pinned by the table in [`super::tests`],
/// which spells `local/` in its own rows.
const RESERVED_ROOT: &str = "local";

/// What one claimed workspace resolves to, or why it does not.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A registered ancestor was found and is a landing site.
    ///
    /// `exact` is false when the claim had no row of its own — D52's soft
    /// landing, which `ResolveProject` reports under the same name.
    Resolved { path: String, exact: bool },
    /// One of the four refusal classes.
    Refused(Refusal),
}

/// Whether *claimed* is in the PRIVATE class — `local/<account>/<path>`.
///
/// THE SEGMENT, NEVER THE PREFIX, for `project-db`'s own reason: `locals` is a
/// different organisation that merely shares five characters, and
/// `starts_with("local")` files its work under the reserved root.
fn is_private_class(claimed: &str) -> bool {
    claimed
        .split_once('/')
        .is_some_and(|(root, _)| root.eq_ignore_ascii_case(RESERVED_ROOT))
}

/// Every character a path segment may contain, as `project-db`'s
/// `segment_is_legal` admits them.
fn segment_is_legal(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Whether *claimed* is a project path at all.
///
/// Returns a bool rather than a message: the message is composed in
/// [`super::remediate`] from the reason alone, so there is no path by which the
/// caller's value can reach the prose.
pub fn is_well_formed(claimed: &str) -> bool {
    !claimed.is_empty()
        && claimed.len() <= MAX_LEN
        && !claimed.starts_with('/')
        && !claimed.ends_with('/')
        && claimed.split('/').all(segment_is_legal)
}

/// The claim and every ancestor of it, DEEPEST FIRST, with the bare reserved
/// segment dropped.
///
/// **THE FILTER IS `project-db/src/read.rs`'s, AND IT IS NOT AN OPTIMISATION.**
/// "The reserved segment is not an ancestor of anything, even if a row sits on
/// it": a row at `local` would otherwise be the nearest registered ancestor of
/// every private path in the estate, and every private write would be stamped
/// with one partition key. The tier already refuses to emit such a row
/// (`project.proto` on `ProjectServiceListProjectsResponse`), so this is the
/// second half of a guard neither half closes alone — a row an earlier build
/// accepted is still in the store.
fn chain(claimed: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = claimed;
    loop {
        if !rest.eq_ignore_ascii_case(RESERVED_ROOT) {
            out.push(rest);
        }
        match rest.rfind('/') {
            Some(cut) => rest = &rest[..cut],
            None => return out,
        }
    }
}

/// Decide one claim against the loaded set.
///
/// `registered` answers whether one exact path is registered, folded to ASCII
/// case — see [`super::registry::Registered`], which holds live paths and
/// aliases together because the store's walk binds both.
///
/// **THE ORDER IS THE TAXONOMY'S: grammar, then resolution.** A malformed value
/// walked first would fall through into whichever unregistered class its first
/// bytes suggest, and a value beginning `local/` would then be handed the
/// remediation that ends in CREATING a project — for garbage.
///
/// **THE ANCHOR RULE IS READ OFF THE MATCH, NOT OFF A COLUMN (ADR-0673).** A
/// registered row whose path is a SINGLE SEGMENT is a namespace anchor: it is
/// resolved THROUGH, to name the repository whose PR flow governs the
/// namespace, and nothing ever lands on it. The loaded set carries no class
/// field — `RegisteredPath` is `path`, `status` and `aliases` — and it needs
/// none: `project-db`'s `ck_project_class_path` makes a single segment imply
/// org class, because a single segment cannot match `local/%`.
pub fn classify(registered: &impl Registered, claimed: &str) -> Outcome {
    if !is_well_formed(claimed) {
        return Outcome::Refused(Refusal::bare(Reason::Invalid));
    }

    // THE DEEPEST MATCH WINS, and the chain is a chain of strict prefixes
    // ordered deepest first, so the FIRST hit is the deepest one. `max_by_key`
    // on length is the store's spelling of the same thing over an unordered SQL
    // result set; here the order is already the answer.
    //
    // THE ANSWER IS THE REGISTERED SPELLING AND NOT THE CANDIDATE'S, which is
    // what `ProjectDbService.ResolveProject` answers too: it returns the ROW's
    // path. The two differ whenever the fold matched — and the resolved path is
    // what a later release stamps on the record, so answering the caller's
    // spelling would mint a second spelling of one partition key, which is the
    // failure the registry exists to prevent.
    let matched = chain(claimed)
        .into_iter()
        .find_map(|ancestor| registered.registered_as(ancestor));

    let Some(matched) = matched else {
        // NO REGISTERED ANCESTOR. Which refusal that is depends on the
        // namespace, and only `local/` has a remediation that ends in creating
        // something — so anything outside it takes the class with no
        // remediation at all. Fail toward "ask a human".
        return Outcome::Refused(Refusal::bare(if is_private_class(claimed) {
            Reason::UnregisteredPersonal
        } else {
            Reason::Unresolvable
        }));
    };

    // A NAMESPACE ANCHOR IS NEVER A LANDING SITE (ADR-0673), and an EXACT match
    // on one is refused too: the claim `yadgarhq` names a namespace, and a
    // namespace has no task counter of its own that work may join.
    if !matched.contains('/') {
        return Outcome::Refused(Refusal::under_anchor(&matched));
    }

    Outcome::Resolved {
        exact: matched.eq_ignore_ascii_case(claimed),
        path: matched,
    }
}

/// What [`classify`] needs from a loaded registry, and no more.
///
/// A trait rather than the concrete set, so the table in [`super::tests`] can
/// state its rows as literal paths instead of building a load response — and so
/// that nothing in this module can reach for a field the real loaded set does
/// not carry.
pub trait Registered {
    /// The REGISTERED spelling of this exact path, comparing ASCII case folded,
    /// or `None` when no row holds it.
    ///
    /// It answers the spelling rather than a bool because the fold makes them
    /// differ, and the registered one is what the store's own resolver returns —
    /// see [`classify`]. A `bool` here is what let an earlier revision answer
    /// the CALLER's spelling as the resolved path.
    fn registered_as(&self, path: &str) -> Option<String>;
}
