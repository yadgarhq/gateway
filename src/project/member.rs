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
//! **THE SUBTREE, NOT JUST THE ROW.** task-db scopes a read, an edit and a
//! transition to the claimed project AND everything beneath it
//! (`Reach::within`). While ledger 641 lets a `local/<account>/…` row be
//! registered by someone other than `<account>`, a foreign private row can sit
//! beneath a caller's own, so a caller is a member only if it owns the resolved
//! row and every private row strictly beneath it. A create cannot reach a
//! deeper row, but `Access` cannot tell a create from an edit, so creates take
//! the same rule and fail closed (plan §3, "The read path").

use std::collections::BTreeMap;

use super::classify::{is_private_class, Registered};
use super::{Access, Reason};

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
    if is_private_class(landed.path) && !is_member(registered, landed, user_id) {
        return Verdict::Refuse(Reason::NotMember);
    }
    if landed.archived && access == Access::Write {
        return Verdict::Refuse(Reason::Archived);
    }
    Verdict::Resolution {
        exact: landed.exact,
    }
}

/// Whether `user_id` owns the landed private row and every private row
/// strictly beneath it.
///
/// EXACT BYTES, no case fold: a user id is an iam-issued identifier, not a
/// path, and nothing in this estate folds it.
fn is_member(registered: &impl Registered, landed: &Landed<'_>, user_id: &str) -> bool {
    let owns = |owner: &str| !owner.is_empty() && owner == user_id;
    owns(landed.owner)
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
#[derive(Debug, Default)]
pub struct PrivateIndex {
    by_path: BTreeMap<String, String>,
}

impl PrivateIndex {
    /// Index every private spelling — paths and aliases alike — with its row's
    /// owner. Org spellings are dropped: no org path lies under `local/`.
    pub fn build<'a>(spellings: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self {
            by_path: spellings
                .into_iter()
                .filter(|(path, _)| is_private_class(path))
                .map(|(path, owner)| (path.to_ascii_lowercase(), owner.to_string()))
                .collect(),
        }
    }

    /// The owners of every indexed spelling strictly beneath `path`, folded.
    ///
    /// **THE RANGE STARTS AT `path/`, WITH THE SLASH.** `-` and `.` sort before
    /// `/`, so a range on the bare prefix would admit `local/a/notes-x` as
    /// beneath `local/a/notes` — a sibling, which no call into `notes` reaches.
    pub fn beneath(&self, path: &str) -> Vec<&str> {
        let prefix = format!("{}/", path.to_ascii_lowercase());
        self.by_path
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(_, owner)| owner.as_str())
            .collect()
    }
}
