//! The per-user project listing behind the `list_projects` tool (ADR-0962
//! ruling 8, ADR-0963 (8), `plans/team-access.md` §8).
//!
//! **A VIEW COMPUTED PER CALL, NOT A FILTER ON THE LOAD.** The load stays
//! unfiltered (`registry.rs`); this reads it with the caller's attested user
//! and teams, and answers only the rows the caller may reach:
//!
//! - every org row where the effective level is non-empty, with that level;
//! - every private row whose stored owner is the caller, as `owner`.
//!
//! **THE GRANT RULE APPLIES EVEN WHILE `orgGrants` IS `counting`.** This is a
//! new surface and it refuses nothing, so it brings no surprise refusal; it
//! only hides what the caller cannot reach.

use super::grants::GrantIndex;

/// One loaded ROW (not a spelling), as the listing needs it.
#[derive(Debug, Clone)]
pub struct Row {
    /// The row's canonical path, as the tier answered it.
    pub path: String,
    pub archived: bool,
    /// Non-empty only on a private row whose owner loaded.
    pub owner: String,
    pub private: bool,
}

/// One entry the caller may reach.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Listed {
    pub path: String,
    /// `active` or `archived`.
    pub status: &'static str,
    /// `root` (a single-segment org row), `project` or `private`.
    pub kind: &'static str,
    /// `read`, `readWrite` or `owner`.
    pub access: &'static str,
}

/// Every row the caller may reach, sorted by folded path.
///
/// EXACT BYTES for the owner, as `member::is_member` compares it: an empty
/// owner matches nobody, so a caller with no user id lists no private row.
pub(super) fn list(
    rows: &[Row],
    grants: &GrantIndex,
    user_id: &str,
    team_ids: &[String],
) -> Vec<Listed> {
    let mut out: Vec<(String, Listed)> = rows
        .iter()
        .filter_map(|row| {
            let access = if row.private {
                (!row.owner.is_empty() && row.owner == user_id).then_some("owner")?
            } else {
                grants.effective(&row.path, team_ids)?.token()
            };
            let kind = match (row.private, row.path.contains('/')) {
                (true, _) => "private",
                (false, false) => "root",
                (false, true) => "project",
            };
            let status = if row.archived { "archived" } else { "active" };
            Some((
                row.path.to_ascii_lowercase(),
                Listed {
                    path: row.path.clone(),
                    status,
                    kind,
                    access,
                },
            ))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.into_iter().map(|(_, l)| l).collect()
}
