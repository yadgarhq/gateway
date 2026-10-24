//! Team grants on org rows (`plans/team-access.md` stage 8, ADR-0962,
//! ADR-0963): the effective level, the `orgGrants` knob, the shadow counter
//! and the gauge. One test per red, named after its number.
//!
//! **LITERALS, per [`super`]'s rule (ADR-0599):** series names, label values
//! and reason tokens are spelled out, never read through the constant under
//! test.

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

use super::super::registry::install;
use super::*;
use crate::pb::yadgar::project::v1::{DeclaredGrant, GrantLevel};
use crate::test_accounts::{id, path};

const REFUSED: &str = "yadgar_gateway_project_refusal_total";
const RESOLVED: &str = "yadgar_gateway_project_resolution_total";
const SHADOW: &str = "yadgar_gateway_project_grant_shadow_total";
const GAUGE: &str = "yadgar_gateway_project_registry_org_rows_without_effective_grant";

const ADMINS: &str = "yadgar:team:administrators";
const READERS: &str = "yadgar:team:readers";
const ALPHA: &str = "yadgar:team:alpha";

fn grant(team: &str, level: GrantLevel) -> DeclaredGrant {
    DeclaredGrant {
        team_id: team.to_string(),
        level: level as i32,
    }
}

fn wire(
    p: &str,
    owner: &str,
    status: ProjectStatus,
    aliases: &[&str],
    grants: Vec<DeclaredGrant>,
) -> RegisteredPath {
    RegisteredPath {
        path: path(p),
        status: status as i32,
        aliases: aliases.iter().map(|a| path(a)).collect(),
        owner_user_id: if owner.is_empty() {
            String::new()
        } else {
            id(owner)
        },
        grants,
    }
}

/// The estate corner every red below reads.
///
/// - `yadgarhq`: administrators read-write, readers read.
/// - `yadgarhq/docs`, `yadgarhq/x/y`, `yadgarhq/old` (archived): no own grant.
/// - `yadgarhq/new`: no own grant, and an ALIAS spelled `other/a/legacy`,
///   beneath alpha's grant: the alias must not borrow alpha's ancestors.
/// - `other/a`: alpha read-write. `other/b`: no grant, no granted ancestor.
/// - `local/alice/solo`: alice's, loaded WITH a grant (a store defect).
fn rows() -> Vec<RegisteredPath> {
    use GrantLevel::{Read, ReadWrite};
    const A: ProjectStatus = ProjectStatus::Active;
    vec![
        wire(
            "yadgarhq",
            "",
            A,
            &[],
            vec![grant(ADMINS, ReadWrite), grant(READERS, Read)],
        ),
        wire("yadgarhq/docs", "", A, &[], vec![]),
        wire("yadgarhq/x/y", "", A, &[], vec![]),
        wire("yadgarhq/old", "", ProjectStatus::Archived, &[], vec![]),
        wire("yadgarhq/new", "", A, &["other/a/legacy"], vec![]),
        wire("other/a", "", A, &[], vec![grant(ALPHA, ReadWrite)]),
        wire("other/b", "", A, &[], vec![]),
        wire(
            "local/alice/solo",
            "alice",
            A,
            &[],
            vec![grant(ADMINS, ReadWrite)],
        ),
    ]
}

/// `(series, label, n)` for every counter one call moved.
type Counts = Vec<(String, String, u64)>;

/// What one call counted.
fn counted(snapshotter: &Snapshotter) -> Counts {
    let mut out: Vec<_> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| match value {
            DebugValue::Counter(n) if n > 0 => Some((
                key.key().name().to_string(),
                key.key()
                    .labels()
                    .map(|l| l.value().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                n,
            )),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// One `check` by a caller holding `teams`, with the answer and the counts.
fn call(
    org_grants: OrgGrants,
    access: Access,
    user: &str,
    teams: &[&str],
    claimed: &str,
) -> (Result<(), Denied>, Counts) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let teams: Vec<String> = teams.iter().map(|t| (*t).to_string()).collect();
    let answer = metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            Validator::new(
                Registry::loaded_from(rows()),
                Mode::Enforcing,
                dead_channel(),
            )
            .with_org_grants(org_grants)
            .check(&path(claimed), access, &id(user), &teams, "a-request-id")
            .await
        })
    });
    (answer, counted(&snapshotter))
}

fn one(series: &str, label: &str) -> (String, String, u64) {
    (series.to_string(), label.to_string(), 1)
}

fn token(answer: Result<(), Denied>) -> &'static str {
    answer.expect_err("refused").reason.token()
}

use Access::{Read, Write};
use OrgGrants::{Counting, Enforcing};

#[test]
fn red_01_counting_a_caller_in_no_granted_team_writes_and_is_served_with_a_shadow_count() {
    let (answer, counts) = call(Counting, Write, "bob", &[], "yadgarhq/docs");
    assert!(answer.is_ok(), "served: {:?}", answer.err());
    assert_eq!(
        counts,
        vec![one(SHADOW, "no_grant"), one(RESOLVED, "exact")],
        "shadow +1 beside the resolution; refusal_total unchanged"
    );
}

#[test]
fn red_02_enforcing_a_caller_in_no_granted_team_is_refused_not_member() {
    let (answer, counts) = call(Enforcing, Write, "bob", &[], "yadgarhq/docs");
    assert_eq!(token(answer), "PROJECT_NOT_MEMBER");
    assert_eq!(counts, vec![one(REFUSED, "PROJECT_NOT_MEMBER")]);
}

#[test]
fn red_03_a_read_grant_on_the_root_refuses_a_write_beneath_it_read_only() {
    let (answer, counts) = call(Counting, Write, "rita", &[READERS], "yadgarhq/docs");
    assert!(answer.is_ok(), "counting serves: {:?}", answer.err());
    assert_eq!(
        counts,
        vec![one(SHADOW, "read_only"), one(RESOLVED, "exact")]
    );

    let (answer, counts) = call(Enforcing, Write, "rita", &[READERS], "yadgarhq/docs");
    assert_eq!(token(answer), "PROJECT_READ_ONLY");
    assert_eq!(counts, vec![one(REFUSED, "PROJECT_READ_ONLY")]);
}

#[test]
fn red_04_a_read_grant_admits_a_read() {
    for knob in [Counting, Enforcing] {
        let (answer, counts) = call(knob, Read, "rita", &[READERS], "yadgarhq/docs");
        assert!(answer.is_ok(), "{knob:?}: {:?}", answer.err());
        assert_eq!(counts, vec![one(RESOLVED, "exact")], "{knob:?}");
    }
}

#[test]
fn red_05_a_root_grant_admits_a_claim_three_segments_deep() {
    let (answer, counts) = call(Enforcing, Write, "max", &[ADMINS], "yadgarhq/x/y");
    assert!(answer.is_ok(), "{:?}", answer.err());
    assert_eq!(counts, vec![one(RESOLVED, "exact")]);

    let (answer, counts) = call(Enforcing, Write, "max", &[ADMINS], "yadgarhq/docs/a/b");
    assert!(answer.is_ok(), "{:?}", answer.err());
    assert_eq!(counts, vec![one(RESOLVED, "ancestor")]);
}

#[test]
fn red_06_a_grant_on_a_sibling_is_no_grant() {
    let (answer, counts) = call(Enforcing, Read, "ann", &[ALPHA], "other/b");
    assert_eq!(token(answer), "PROJECT_NOT_MEMBER");
    assert_eq!(counts, vec![one(REFUSED, "PROJECT_NOT_MEMBER")]);

    let (answer, _) = call(Enforcing, Write, "ann", &[ALPHA], "other/a");
    assert!(answer.is_ok(), "alpha's own row: {:?}", answer.err());
}

#[test]
fn red_07_an_archived_row_beneath_a_grant_reads_and_refuses_the_write_archived() {
    let (answer, counts) = call(Enforcing, Read, "max", &[ADMINS], "yadgarhq/old");
    assert!(answer.is_ok(), "ruling 3: {:?}", answer.err());
    assert_eq!(counts, vec![one(RESOLVED, "exact")]);

    let (answer, counts) = call(Enforcing, Write, "max", &[ADMINS], "yadgarhq/old");
    assert_eq!(token(answer), "PROJECT_ARCHIVED");
    assert_eq!(counts, vec![one(REFUSED, "PROJECT_ARCHIVED")]);
}

#[test]
fn red_08_a_non_member_writing_an_archived_row_learns_nothing_about_its_status() {
    let (write, counts) = call(Enforcing, Write, "bob", &[], "yadgarhq/old");
    assert_eq!(counts, vec![one(REFUSED, "PROJECT_NOT_MEMBER")]);
    let (read, _) = call(Enforcing, Read, "bob", &[], "yadgarhq/old");
    let (write, read) = (write.expect_err("refused"), read.expect_err("refused"));
    assert_eq!(write.reason.token(), "PROJECT_NOT_MEMBER");
    assert_eq!(
        (write.reason, &write.prose),
        (read.reason, &read.prose),
        "one answer for the archived write and the read"
    );
}

#[test]
fn red_09_a_claim_through_an_alias_is_judged_by_the_rows_canonical_ancestors() {
    // `other/a/legacy` is spelled beneath alpha's grant, but its row is
    // `yadgarhq/new`, whose ancestor grants administrators.
    let (answer, _) = call(Enforcing, Write, "max", &[ADMINS], "other/a/legacy");
    assert!(answer.is_ok(), "{:?}", answer.err());
    let (answer, counts) = call(Enforcing, Write, "ann", &[ALPHA], "other/a/legacy");
    assert_eq!(token(answer), "PROJECT_NOT_MEMBER");
    assert_eq!(counts, vec![one(REFUSED, "PROJECT_NOT_MEMBER")]);
}

#[test]
fn red_10_a_grant_for_a_team_the_caller_lacks_does_not_raise_its_level() {
    let teams = [READERS, "yadgar:team:nope"];
    let (answer, _) = call(Enforcing, Read, "rita", &teams, "yadgarhq/docs");
    assert!(answer.is_ok(), "{:?}", answer.err());
    let (answer, _) = call(Enforcing, Write, "rita", &teams, "yadgarhq/docs");
    assert_eq!(token(answer), "PROJECT_READ_ONLY");
}

/// Red 10, the other direction: the effective level is the HIGHEST the
/// caller's teams hold, so a read grant beside a read-write one on the same
/// chain never narrows the read-write one.
#[test]
fn red_10_the_highest_level_the_callers_teams_hold_wins() {
    let teams = [READERS, ADMINS];
    let (answer, _) = call(Enforcing, Write, "rita", &teams, "yadgarhq/docs");
    assert!(answer.is_ok(), "{:?}", answer.err());
}

#[test]
fn red_11_a_grant_on_a_private_row_is_ignored() {
    for knob in [Counting, Enforcing] {
        let (answer, counts) = call(knob, Read, "bob", &[ADMINS], "local/alice/solo");
        assert_eq!(token(answer), "PROJECT_NOT_MEMBER", "{knob:?}");
        assert_eq!(
            counts,
            vec![one(REFUSED, "PROJECT_NOT_MEMBER")],
            "{knob:?}: no shadow count on a private row"
        );
        let (answer, counts) = call(knob, Write, "alice", &[], "local/alice/solo");
        assert!(answer.is_ok(), "{knob:?}: the owner: {:?}", answer.err());
        assert_eq!(counts, vec![one(RESOLVED, "exact")], "{knob:?}");
    }
}

/// Red 11 at the index itself: a private row's grant is never indexed, so no
/// reader of the index (the check, the gauge, the listing) can see it, even
/// one that forgot to ask the row's class first.
#[test]
fn red_11_the_grant_index_never_holds_a_private_row() {
    let rows = rows();
    let index = crate::project::grants::GrantIndex::build(&rows);
    let private = crate::test_accounts::path("local/alice/solo");
    assert_eq!(index.effective(&private, &[ADMINS.to_string()]), None);
    assert!(!index.any_effective(&private));
}

#[test]
fn red_12_an_org_row_with_no_effective_grant_is_denied_and_moves_the_gauge() {
    let (answer, _) = call(Enforcing, Read, "max", &[ADMINS], "other/b");
    assert_eq!(token(answer), "PROJECT_NOT_MEMBER");
    let (answer, _) = call(Enforcing, Read, "max", &[ADMINS], "yadgarhq/docs");
    assert!(answer.is_ok(), "the sibling inherits: {:?}", answer.err());

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || install(&Registry::never_loaded(), rows()));
    let gauge = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .find(|(key, ..)| key.key().name() == GAUGE)
        .map(|(_, _, _, value)| value);
    assert_eq!(
        gauge,
        Some(DebugValue::Gauge(1.0.into())),
        "only `other/b`: yadgarhq/docs inherits, the private row is not org"
    );
}

#[test]
fn red_13_a_caller_with_no_teams_is_denied_every_org_row() {
    let org = [
        "yadgarhq/docs",
        "yadgarhq/x/y",
        "yadgarhq/old",
        "yadgarhq/new",
        "other/a",
        "other/b",
        "other/a/legacy",
    ];
    for claimed in org {
        for access in [Read, Write] {
            let (answer, _) = call(Enforcing, access, "max", &[], claimed);
            assert_eq!(token(answer), "PROJECT_NOT_MEMBER", "{access:?} {claimed}");
        }
    }
}

/// THE TABLE: one series on the resolution and refusal counters per call,
/// across every arm, and at most one shadow increment beside it.
#[test]
fn red_16_one_series_per_call_and_at_most_one_shadow_increment() {
    let arms: [(Access, &str, &[&str], &str); 10] = [
        (Write, "bob", &[], "yadgarhq/docs"),
        (Read, "bob", &[], "yadgarhq/docs"),
        (Write, "rita", &[READERS], "yadgarhq/docs"),
        (Read, "rita", &[READERS], "yadgarhq/docs"),
        (Write, "max", &[ADMINS], "yadgarhq/old"),
        (Write, "bob", &[], "yadgarhq/old"),
        (Write, "rita", &[READERS], "yadgarhq/old"),
        (Read, "bob", &[ADMINS], "local/alice/solo"),
        (Write, "ann", &[ALPHA], "other/b"),
        (Write, "ann", &[ALPHA], "yadgarhq"),
    ];
    for knob in [Counting, Enforcing] {
        for (access, user, teams, claimed) in arms {
            let what = format!("{knob:?} {access:?} {user} {claimed}");
            let (_, counts) = call(knob, access, user, teams, claimed);
            let sum = |name: &str| {
                counts
                    .iter()
                    .filter(|(series, ..)| series == name)
                    .map(|(.., n)| n)
                    .sum::<u64>()
            };
            assert_eq!(sum(REFUSED) + sum(RESOLVED), 1, "{what}: {counts:?}");
            assert!(sum(SHADOW) <= 1, "{what}: {counts:?}");
            if knob == Enforcing {
                assert_eq!(sum(SHADOW), 0, "{what}: no shadow after the flip");
            }
        }
    }
}

#[test]
fn red_17_counting_a_non_member_archived_write_counts_shadow_and_archived() {
    let (answer, counts) = call(Counting, Write, "bob", &[], "yadgarhq/old");
    assert_eq!(token(answer), "PROJECT_ARCHIVED");
    assert_eq!(
        counts,
        vec![one(SHADOW, "no_grant"), one(REFUSED, "PROJECT_ARCHIVED")]
    );

    let (answer, counts) = call(Enforcing, Write, "bob", &[], "yadgarhq/old");
    assert_eq!(token(answer), "PROJECT_NOT_MEMBER");
    assert_eq!(counts, vec![one(REFUSED, "PROJECT_NOT_MEMBER")]);
}

/// A level this build does not know, and `UNSPECIFIED`, are NOT a read grant.
#[test]
fn an_unspecified_or_unknown_level_grants_nothing() {
    let loaded = Loaded::from_registered(vec![
        wire(
            "acme",
            "",
            ProjectStatus::Active,
            &[],
            vec![grant(ALPHA, GrantLevel::Unspecified)],
        ),
        wire(
            "acme/a",
            "",
            ProjectStatus::Active,
            &[],
            vec![DeclaredGrant {
                team_id: ALPHA.to_string(),
                level: 99,
            }],
        ),
    ]);
    assert_eq!(loaded.effective("acme/a", &[ALPHA.to_string()]), None);
    assert_eq!(loaded.org_rows_without_effective_grant(), 2);
}

/// Two rows whose canonical paths fold to one key keep NO grant there.
#[test]
fn a_folded_collision_of_two_rows_admits_nobody_through_that_key() {
    let loaded = Loaded::from_registered(vec![
        wire(
            "acme/a",
            "",
            ProjectStatus::Active,
            &[],
            vec![grant(ALPHA, GrantLevel::ReadWrite)],
        ),
        wire(
            "ACME/A",
            "",
            ProjectStatus::Active,
            &[],
            vec![grant(READERS, GrantLevel::Read)],
        ),
    ]);
    for team in [ALPHA, READERS] {
        assert_eq!(
            loaded.effective("acme/a", &[team.to_string()]),
            None,
            "{team}"
        );
    }
}

/// The knob has no compiled-in default: absent and unknown refuse.
#[test]
fn the_org_grants_knob_parses_two_words_and_nothing_else() {
    let at = |v: Option<&str>| {
        OrgGrants::from_lookup(|key| {
            assert_eq!(key, "YADGAR_PROJECT_VALIDATION_ORG_GRANTS");
            v.map(str::to_string)
        })
    };
    assert_eq!(at(Some("counting")).ok(), Some(Counting));
    assert_eq!(at(Some(" enforcing ")).ok(), Some(Enforcing));
    assert!(matches!(at(None), Err(OrgGrantsError::Absent)));
    assert!(matches!(
        at(Some("Enforcing")),
        Err(OrgGrantsError::Unknown(_))
    ));
}
