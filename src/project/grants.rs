//! Team grants on org rows: the per-load index, the effective level, and the
//! `orgGrants` knob that decides whether a miss is refused or only counted
//! (ADR-0962, ADR-0963, `plans/team-access.md` §3 and §5).
//!
//! **A GRANT IS A FACT ABOUT A ROW, AND IT INHERITS DOWN THE TREE (ruling 3).**
//! `RegisteredPath.grants` carries each row's OWN grants. A row's EFFECTIVE
//! grants are its own plus those of every registered row whose path is a
//! segment-wise proper prefix of its canonical path, archived rows included.
//! The index is keyed on the folded canonical row path, never on an alias, so a
//! claim through an alias is judged by its row's canonical ancestors.
//!
//! **PRIVATE ROWS ARE NEVER INDEXED (ruling 7).** No grant can be declared on a
//! `local/` row, so one that arrives is a store defect, and it is ignored:
//! private rows stay owner-only (ADR-0952).
//!
//! **A MISSING HALF FAILS CLOSED.** A grant naming a team no caller holds
//! matches nobody; a level this build does not know is dropped at load rather
//! than read as `read`; a `project` that predates grants sends none, and then
//! every org row has no effective grant, which the
//! [`ORG_ROWS_WITHOUT_EFFECTIVE_GRANT`] gauge makes loud.

use std::collections::{BTreeMap, BTreeSet};

use crate::pb::yadgar::project::v1::{GrantLevel, RegisteredPath};

use super::classify::is_private_class;

/// Org-row grant misses that `orgGrants: counting` SERVED, by verdict.
///
/// `verdict` is `no_grant` or `read_only`, a closed set ([`Shadow`]). It moves
/// ONLY under [`OrgGrants::Counting`]; after the flip the same calls count on
/// `yadgar_gateway_project_refusal_total` as `PROJECT_NOT_MEMBER` and
/// `PROJECT_READ_ONLY` instead (ADR-0963 (4)). A separate series, so the
/// counting window cannot mix served org misses with refused private ones.
pub const GRANT_SHADOW: &str = "yadgar_gateway_project_grant_shadow_total";

/// Org rows in the last load with no effective grant at all: none of their
/// own and none on any registered ancestor. Each matches nobody, so a relay
/// gap (a `project` that drops `RegisteredPath.grants`) reads as a number here
/// rather than as a quiet lockout. After stage 9 the expected value is 0.
pub const ORG_ROWS_WITHOUT_EFFECTIVE_GRANT: &str =
    "yadgar_gateway_project_registry_org_rows_without_effective_grant";

/// How much a grant admits. Ordered, so the effective level is the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Read,
    ReadWrite,
}

impl Level {
    /// The `access` value `list_projects` answers.
    pub fn token(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "readWrite",
        }
    }
}

/// A wire level, or nothing. `UNSPECIFIED` and any value this build does not
/// know are NOT a read grant: reading the zero value as the narrower level
/// would turn a dropped field into a silent grant.
fn level_of(raw: i32) -> Option<Level> {
    match GrantLevel::try_from(raw) {
        Ok(GrantLevel::Read) => Some(Level::Read),
        Ok(GrantLevel::ReadWrite) => Some(Level::ReadWrite),
        Ok(GrantLevel::Unspecified) | Err(_) => None,
    }
}

/// Every org row's own grants, keyed on the folded canonical row path.
#[derive(Debug, Default)]
pub struct GrantIndex {
    by_row: BTreeMap<String, Vec<(String, Level)>>,
}

impl GrantIndex {
    /// Index the own grants of every ORG row. Private rows are skipped.
    ///
    /// **A FOLDED COLLISION ADMITS NOBODY THROUGH THAT KEY.** Two rows whose
    /// canonical paths fold to one key cannot both exist in the store
    /// (`utf8mb4_general_ci`), so a load carrying both is a defect, and
    /// uniting their grants would widen access by an accident of the load.
    /// The key keeps no grant, as `fold::merge` resolves toward refusal.
    pub fn build<'a>(rows: impl IntoIterator<Item = &'a RegisteredPath>) -> Self {
        let mut by_row: BTreeMap<String, Vec<(String, Level)>> = BTreeMap::new();
        let mut collided = BTreeSet::new();
        for row in rows.into_iter().filter(|r| !is_private_class(&r.path)) {
            let key = row.path.to_ascii_lowercase();
            if by_row.contains_key(&key) {
                collided.insert(key.clone());
            }
            let own = row
                .grants
                .iter()
                .filter_map(|g| level_of(g.level).map(|l| (g.team_id.clone(), l)))
                .collect();
            by_row.insert(key, own);
        }
        for key in collided {
            by_row.insert(key, Vec::new());
        }
        Self { by_row }
    }

    /// The grants on `path`'s row and on every registered proper ancestor.
    fn chain<'a>(&'a self, path: &str) -> impl Iterator<Item = &'a (String, Level)> + 'a {
        let folded = path.to_ascii_lowercase();
        let mut prefixes: Vec<String> = folded
            .match_indices('/')
            .map(|(cut, _)| folded[..cut].to_string())
            .collect();
        prefixes.push(folded);
        prefixes
            .into_iter()
            .filter_map(|p| self.by_row.get(&p))
            .flatten()
    }

    /// The caller's effective level on the org row at `path`, or `None`.
    ///
    /// Team ids compare as EXACT BYTES: an iam-issued identifier, not a path.
    pub fn effective(&self, path: &str, team_ids: &[String]) -> Option<Level> {
        self.chain(path)
            .filter(|(team, _)| team_ids.iter().any(|t| t == team))
            .map(|(_, level)| *level)
            .max()
    }

    /// Whether ANY team holds an effective grant on the org row at `path`.
    pub fn any_effective(&self, path: &str) -> bool {
        self.chain(path).next().is_some()
    }
}

/// What a served org-row miss counts as under [`OrgGrants::Counting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shadow {
    /// No effective grant (enforced: `PROJECT_NOT_MEMBER`).
    NoGrant,
    /// A write under an effective `read` grant (enforced: `PROJECT_READ_ONLY`).
    ReadOnly,
}

impl Shadow {
    /// The `verdict` label on [`GRANT_SHADOW`].
    pub fn token(self) -> &'static str {
        match self {
            Self::NoGrant => "no_grant",
            Self::ReadOnly => "read_only",
        }
    }
}

/// Whether an org-row grant miss is refused or only counted (ADR-0963 (4)).
///
/// **INDEPENDENT OF [`super::Mode`], AND NARROWER.** `enforcing` here with
/// `counting` there refuses to boot (`crate::boot`): no order can enforce the
/// narrower rule before the wider one.
///
/// **NO COMPILED-IN DEFAULT IS READ (ADR-0569).** An absent or unknown value
/// refuses the boot naming the variable. `Default` exists only so a
/// [`super::Validator`] built in a test judges as the shipped chart does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrgGrants {
    /// Evaluate, count the shadow verdict, and serve as org-is-everyone would.
    #[default]
    Counting,
    /// Refuse with `PROJECT_NOT_MEMBER` or `PROJECT_READ_ONLY`.
    Enforcing,
}

/// The environment variable that chooses [`OrgGrants`]; the chart renders it
/// from `projectValidation.orgGrants`.
pub const ORG_GRANTS: &str = "YADGAR_PROJECT_VALIDATION_ORG_GRANTS";

impl OrgGrants {
    /// Resolve the knob from this process's environment.
    ///
    /// # Errors
    ///
    /// See [`Self::from_lookup`].
    pub fn from_env() -> Result<Self, OrgGrantsError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Resolve the knob from an injected lookup (a test seam, as
    /// `Mode::from_lookup` is).
    ///
    /// # Errors
    ///
    /// An absent value, and any value that is not one of the two names.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, OrgGrantsError> {
        match lookup(ORG_GRANTS).as_deref().map(str::trim) {
            None => Err(OrgGrantsError::Absent),
            Some("counting") => Ok(Self::Counting),
            Some("enforcing") => Ok(Self::Enforcing),
            Some(other) => Err(OrgGrantsError::Unknown(other.to_string())),
        }
    }
}

/// A knob this deployment did not state, or stated in an unknown word.
#[derive(Debug, thiserror::Error)]
pub enum OrgGrantsError {
    #[error(
        "{ORG_GRANTS} is not set. It chooses whether an org-project call by a caller whose \
         teams hold no grant (or only a read grant, for a write) is REFUSED or merely counted, \
         and there is no compiled-in default (ADR-0569). Set it to \"counting\" (chart: \
         projectValidation.orgGrants, the shipped value) or to \"enforcing\"."
    )]
    Absent,

    #[error(
        "{ORG_GRANTS} is {0:?}, which is neither \"counting\" nor \"enforcing\". A value outside \
         the two names is refused rather than read as the safer one."
    )]
    Unknown(String),
}
