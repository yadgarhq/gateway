//! Who may reach a resolved project: membership, decided from the loaded set
//! (`plans/project-membership.md` §3, ADR-0947).
//!
//! Split out of [`super`] for the file-size ceiling. [`super::classify`] decides
//! WHICH row a claim lands on; this decides whether the CALLER may reach it, and
//! [`super::Validator::check`] counts what this answers.
//!
//! **MEMBERSHIP IS DERIVED, NOT STORED.** An org row admits every attested user
//! (Max's ruling 3: an org project is the whole organisation). A private
//! (`local/…`) row admits exactly its stored owner, for reads AND writes
//! (ruling A). Nothing else is consulted: no team, no grant table.
//!
//! **THE CLASS IS THE PATH, NEVER "AN OWNER ARRIVED".** A private row whose
//! owner loads empty — a `project` older than car P2, or a store defect — stays
//! private, matches nobody, and counts `PROJECT_NOT_MEMBER` on every call into
//! it. Deriving the class from the owner would read that row as org and admit
//! everybody, silently. The owner comparison also requires a NON-EMPTY owner,
//! so a trusted-headers caller who sent no user cannot match an empty one.
//!
//! **THE CLASS IS THE ROW'S, NOT THE SPELLING'S.** A private row with an alias
//! spelled outside `local/` is still private when claimed through the alias;
//! either the row's path or the matched spelling being under `local/` makes it
//! private, so a cross-class alias can only fail closed.
//!
//! **THE SUBTREE, NOT JUST THE ROW.** task-db scopes a read, an edit and a
//! transition to the claimed project AND everything beneath it
//! (`Reach::within`). While ledger 641 lets a `local/<account>/…` row be
//! registered by someone other than `<account>`, a foreign private row can sit
//! beneath a caller's own, so a caller is a member only if it owns the resolved
//! row and every private row strictly beneath it. A create cannot reach a
//! deeper row, but `Access` cannot tell a create from an edit, so creates take
//! the same rule and fail closed (plan §3, "The read path"). An ORG row takes
//! the subtree half too: no org path lies under `local/`, so the beneath set is
//! empty and every attested user is admitted, unless a private row's alias is
//! spelled beneath it — and then the org claim would reach that private row.

use std::collections::BTreeSet;

use super::account::account_segment;
use super::classify::{is_private_class, is_well_formed, Registered};
use super::{Access, Reason};

/// Whether `claimed` is a well-formed `local/<seg>/…` claim whose account
/// segment is NOT the caller's own (ADR-0954, Max's ruling on F3).
///
/// **DECIDED FROM THE CLAIM AND THE CALLER ALONE, NEVER FROM THE REGISTRY.**
/// That is what hides existence: a foreign claim is refused the same way
/// whether the path is registered, unregistered or soft-lands on a registered
/// ancestor, so no answer depends on another account's rows.
///
/// - A malformed claim is NOT decided here: the grammar refusal comes first,
///   as everywhere (`classify`), and never echoes the value.
/// - Bare `local` is not a private-class claim (no segment), so it keeps
///   today's `PROJECT_UNRESOLVABLE`.
/// - The segment compares ASCII-CASE-INSENSITIVELY, as the store's
///   `utf8mb4_general_ci` collation compares the path: an upper-cased spelling
///   of the caller's own segment names the caller's own rows, and an
///   upper-cased spelling of anybody else's is still foreign.
/// - A caller whose `user_id` is not canonical has no segment, so every
///   `local/<seg>/…` claim is foreign to it ([`account_segment`]).
pub(super) fn is_foreign_private(claimed: &str, user_id: &str) -> bool {
    if !is_well_formed(claimed) || !is_private_class(claimed) {
        return false;
    }
    let segment = claimed.split('/').nth(1).unwrap_or_default();
    account_segment(user_id).is_none_or(|own| !own.eq_ignore_ascii_case(segment))
}

/// What one resolved claim comes to, before anything is counted.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Served as a resolution; `exact` is the `outcome` label.
    Resolution { exact: bool },
    /// Counted under this reason, and answered only under enforcement.
    Refuse(Reason),
}

/// The row a claim resolved to, as [`super::classify`] answered it.
pub(super) struct Landed<'a> {
    pub path: &'a str,
    pub exact: bool,
    pub archived: bool,
    pub owner: &'a str,
    /// The landed row's class, from the row's own path at load.
    pub private: bool,
}

/// Decide one resolved claim for one caller.
///
/// **THE ORDER DIFFERS BY CLASS (rulings D and E).** On an org row archived
/// comes first, and there is no membership step to follow it. On a private row
/// ownership comes first, for every `Access`, so a non-owner gets one answer
/// whether the row is archived or not and learns nothing about its status;
/// only the owner is then told that a write hits an archived row.
pub(super) fn verdict(
    registered: &impl Registered,
    landed: &Landed<'_>,
    access: Access,
    user_id: &str,
) -> Verdict {
    if !is_member(registered, landed, user_id) {
        return Verdict::Refuse(Reason::NotMember);
    }
    if landed.archived && access == Access::Write {
        return Verdict::Refuse(Reason::Archived);
    }
    Verdict::Resolution {
        exact: landed.exact,
    }
}

/// Whether `user_id` may reach the landed row: it owns every private row
/// strictly beneath it, and, when the landed row is itself private, that row.
///
/// EXACT BYTES, no case fold: a user id is an iam-issued identifier, not a
/// path, and nothing in this estate folds it.
fn is_member(registered: &impl Registered, landed: &Landed<'_>, user_id: &str) -> bool {
    let owns = |owner: &str| !owner.is_empty() && owner == user_id;
    let private = landed.private || is_private_class(landed.path);
    (!private || owns(landed.owner))
        && registered
            .private_owners_beneath(landed.path)
            .into_iter()
            .all(owns)
}

/// The private spellings of one load with their rows' owners, sorted by
/// folded path, built once per load.
///
/// **SORTED SO "BENEATH" IS ONE RANGE.** Every path strictly beneath `p` starts
/// with `p/`, and in a sorted map those keys are contiguous — so a lookup is a
/// range scan, not a walk of the whole set on every call.
///
/// **A SET OF `(path, owner)` PAIRS, NOT A MAP FROM PATH.** Two spellings may
/// fold to one path, and each keeps its owner here.
#[derive(Debug, Default)]
pub struct PrivateIndex {
    by_path: BTreeSet<(String, String)>,
}

impl PrivateIndex {
    /// Index every spelling of a private row — paths and aliases alike, an
    /// alias spelled outside `local/` included — with its row's owner.
    /// `private` is the row's class; a spelling under `local/` is indexed
    /// whatever its row says, so a cross-class alias fails closed.
    pub fn build<'a>(spellings: impl IntoIterator<Item = (&'a str, &'a str, bool)>) -> Self {
        Self {
            by_path: spellings
                .into_iter()
                .filter(|(path, _, private)| *private || is_private_class(path))
                .map(|(path, owner, _)| (path.to_ascii_lowercase(), owner.to_string()))
                .collect(),
        }
    }

    /// The owners of every indexed spelling strictly beneath `path`, folded.
    ///
    /// **THE RANGE STARTS AT `path/`, WITH THE SLASH.** `-` and `.` sort before
    /// `/`, so a range on the bare prefix would admit `local/a/notes-x` as
    /// beneath `local/a/notes` — a sibling, which no call into `notes` reaches.
    ///
    /// A trailing slash on `path` is dropped first: ranging on `p//` would
    /// find nothing, and "nothing beneath" is a pass.
    pub fn beneath(&self, path: &str) -> Vec<&str> {
        let prefix = format!("{}/", path.trim_end_matches('/').to_ascii_lowercase());
        self.by_path
            .range((prefix.clone(), String::new())..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(_, owner)| owner.as_str())
            .collect()
    }
}
