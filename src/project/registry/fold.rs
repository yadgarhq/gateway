//! Folding every loaded spelling into [`super::Loaded`]'s lookup map.
//!
//! Split out of [`super`] for the file-size ceiling. Two spellings that fold to
//! one ASCII-lowercased key are one entry, and this decides what that entry says.

use std::collections::BTreeMap;

use super::Match;

/// Insert one spelling, resolving a folded collision toward REFUSAL, and
/// answer whether the collision left a key nobody can reach that a row's
/// owner could reach before.
///
/// Only the row PATH keeps the last row's. Everything an authorization reads
/// resolves toward refusal, whatever order the rows loaded in:
///
/// - the OWNER: two rows of different owners under one key make the key
///   ambiguous, and an ambiguous owner is nobody's — admitting whichever row
///   loaded last would hand one account the other's project;
/// - the CLASS: private if either row is, so an org row loaded after a
///   private row's alias cannot turn that key into an org one;
/// - the STATUS: archived if either row is, so a write is refused.
pub(super) fn merge(folded: &mut BTreeMap<String, Match>, key: String, m: Match) -> bool {
    let Some(prev) = folded.remove(&key) else {
        folded.insert(key, m);
        return false;
    };
    let private = prev.private || m.private;
    let owner = if prev.owner == m.owner {
        m.owner.clone()
    } else {
        String::new()
    };
    let made_ownerless =
        private && owner.is_empty() && !(prev.owner.is_empty() && m.owner.is_empty());
    let merged = Match {
        private,
        owner,
        archived: prev.archived || m.archived,
        ..m
    };
    folded.insert(key, merged);
    made_ownerless
}
