//! Membership (`plans/project-membership.md` car P3, ADR-0947): an org project
//! admits every attested user, a private (`local/…`) project admits only its
//! stored owner for reads AND writes, and every miss is counted as
//! `PROJECT_NOT_MEMBER` before it refuses.
//!
//! **LITERALS, per [`super`]'s rule (ADR-0599):** every token and series name
//! below is spelled out rather than read through the constant under test.
//!
//! **OWNERS ARE STATED BESIDE THE ROWS** through `Registry::loaded_owned`,
//! because the wire field (`RegisteredPath.owner_user_id`, car P0) is not
//! tagged yet: the real load answers `""` for every owner, and one case below
//! drives that real load path to prove it fails closed.

use std::collections::BTreeSet;

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

use super::super::registry::install;
use super::*;

const ACTIVE: ProjectStatus = ProjectStatus::Active;
const ARCHIVED: ProjectStatus = ProjectStatus::Archived;

/// A registry from literal `(path, owner, status)` rows.
fn owned(rows: &[(&str, &str, ProjectStatus)]) -> Registry {
    Registry::loaded_owned(
        rows.iter()
            .map(|(path, owner, status)| ((*owner).to_string(), row(path, *status, &[])))
            .collect(),
    )
}

/// One corner of an estate with private rows in every shape the rule meets.
///
/// - `local/alice/notes/deep` is a MIS-REGISTERED row beneath alice's own
///   (ledger 641 lets it exist), owned by mallory.
/// - `local/alice/solo-x` shares `local/alice/solo`'s prefix and is NOT beneath
///   it: `-` sorts before `/`, so an index that ranged on the bare prefix
///   would count it.
/// - `local/bob/blank` loaded with no owner, the pre-P0 shape.
/// - `LOCAL/max/x` is registered upper-case; the store folds ASCII case.
fn members() -> Registry {
    owned(&[
        ("yadgarhq", "", ACTIVE),
        ("yadgarhq/docs", "", ACTIVE),
        ("yadgarhq/old", "", ARCHIVED),
        ("local/alice/notes", "alice", ACTIVE),
        ("local/alice/notes/deep", "mallory", ACTIVE),
        ("local/alice/solo", "alice", ACTIVE),
        ("local/alice/solo-x", "mallory", ACTIVE),
        ("local/alice/attic", "alice", ARCHIVED),
        ("local/bob/blank", "", ACTIVE),
        ("LOCAL/max/x", "max", ACTIVE),
    ])
}

/// Run one `check` as `user` and return its answer beside the snapshot.
fn as_user(
    registry: Registry,
    mode: Mode,
    access: Access,
    user: &str,
    claimed: &str,
) -> (Result<(), Denied>, Snapshotter) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let answer = metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            Validator::new(registry, mode, dead_channel())
                .check(claimed, access, user, "a-request-id")
                .await
        })
    });
    (answer, snapshotter)
}

/// Every `(series, label value)` one call incremented, with its count.
fn series(snapshotter: &Snapshotter) -> Vec<(String, String, u64)> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| match value {
            DebugValue::Counter(n) => Some((
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
        .collect()
}

/// What one call counted, as exactly ONE `(series, label)` — the property
/// `Validator::check` promises on every path.
fn the_one_series(snapshotter: &Snapshotter) -> (String, String) {
    let all = series(snapshotter);
    assert_eq!(
        all.iter().map(|(_, _, n)| n).sum::<u64>(),
        1,
        "exactly one series per call: {all:?}"
    );
    let (name, label, _) = all.into_iter().next().expect("one series");
    (name, label)
}

const REFUSED: &str = "yadgar_gateway_project_refusal_total";
const RESOLVED: &str = "yadgar_gateway_project_resolution_total";

fn refused(reason: &str) -> (String, String) {
    (REFUSED.to_string(), reason.to_string())
}

/// One arm of the rule: who calls, what, how, and the one series it counts.
struct Arm {
    user: &'static str,
    claimed: &'static str,
    access: Access,
    counts: (&'static str, &'static str),
}

fn arm(
    user: &'static str,
    claimed: &'static str,
    access: Access,
    counts: (&'static str, &'static str),
) -> Arm {
    Arm {
        user,
        claimed,
        access,
        counts,
    }
}

const NOT_MEMBER: (&str, &str) = (REFUSED, "PROJECT_NOT_MEMBER");
const EXACT: (&str, &str) = (RESOLVED, "exact");

/// **THE TABLE.** Every arm in plan car P3's red list that `check` alone can
/// decide, each asserted to count exactly one series in COUNTING and to be
/// served there — and, where it refuses, to be refused under ENFORCING with the
/// same reason.
///
/// MUTATIONS THIS CATCHES: ignore `user_id`; compare owners case-folded; read
/// the class from "owner present" instead of from the path; check archived
/// before ownership on a private row; let `""` match `""`; drop the subtree
/// rule; range the subtree index on the bare prefix.
#[test]
fn every_membership_arm_counts_one_series_and_refuses_only_under_enforcement() {
    use Access::{Read, Write};
    let arms = [
        // org rows admit every attested user (ruling 3), reads and writes.
        arm("bob", "yadgarhq/docs", Write, EXACT),
        arm("bob", "yadgarhq/docs", Read, EXACT),
        // a private row admits its owner.
        arm("alice", "local/alice/solo", Write, EXACT),
        arm("alice", "local/alice/solo", Read, EXACT),
        // ...and nobody else, for writes AND reads (ruling A).
        arm("bob", "local/alice/solo", Write, NOT_MEMBER),
        arm("bob", "local/alice/solo", Read, NOT_MEMBER),
        // the subtree rule: alice owns the row, mallory owns one beneath it.
        arm("alice", "local/alice/notes", Read, NOT_MEMBER),
        arm("alice", "local/alice/notes", Write, NOT_MEMBER),
        // archived private row (ruling E): ownership first.
        arm("bob", "local/alice/attic", Read, NOT_MEMBER),
        arm("bob", "local/alice/attic", Write, NOT_MEMBER),
        arm(
            "alice",
            "local/alice/attic",
            Write,
            (REFUSED, "PROJECT_ARCHIVED"),
        ),
        arm("alice", "local/alice/attic", Read, EXACT),
        // archived org row (ruling D): archived, for anybody.
        arm("bob", "yadgarhq/old", Write, (REFUSED, "PROJECT_ARCHIVED")),
        // claims above any private row never reach membership.
        arm("bob", "local", Read, (REFUSED, "PROJECT_UNRESOLVABLE")),
        arm(
            "bob",
            "local/carol",
            Write,
            (REFUSED, "PROJECT_UNREGISTERED_PERSONAL"),
        ),
        // a private row loaded with no owner is nobody's: fail closed.
        arm("bob", "local/bob/blank", Read, NOT_MEMBER),
        arm("bob", "local/bob/blank", Write, NOT_MEMBER),
        arm("", "local/bob/blank", Write, NOT_MEMBER),
        // the path fold: `LOCAL/` is the private root too.
        arm("max", "local/max/x", Write, EXACT),
        arm("bob", "local/max/x", Write, NOT_MEMBER),
        // soft landing under a private row checks the LANDED row's owner.
        arm(
            "alice",
            "local/alice/solo/sub",
            Write,
            (RESOLVED, "ancestor"),
        ),
        arm("bob", "local/alice/solo/sub", Write, NOT_MEMBER),
    ];
    for a in arms {
        let what = format!("{} {:?} {}", a.user, a.access, a.claimed);
        let (answer, snapshotter) = as_user(members(), Mode::Counting, a.access, a.user, a.claimed);
        assert!(
            answer.is_ok(),
            "{what}: counting serves: {:?}",
            answer.err()
        );
        assert_eq!(
            the_one_series(&snapshotter),
            (a.counts.0.to_string(), a.counts.1.to_string()),
            "{what}"
        );

        let (answer, _) = as_user(members(), Mode::Enforcing, a.access, a.user, a.claimed);
        match a.counts {
            (RESOLVED, _) => assert!(answer.is_ok(), "{what}: {:?}", answer.err()),
            (_, reason) => assert_eq!(answer.expect_err(&what).reason.token(), reason, "{what}"),
        }
    }
}

/// The `create_task` shape: a WRITE under a row with a foreign private row
/// beneath it is refused too, deliberately.
///
/// A create lands at the resolved path only and could not reach the deeper
/// row, but `Access` cannot tell a create from an edit, and the plan rules
/// that this fails closed rather than growing a third `Access` value for a
/// shape that needs ledger 641's defect to exist (§3, "The read path").
#[test]
fn a_create_under_a_foreign_private_row_is_refused_too_strictly_on_purpose() {
    let (answer, _) = as_user(
        members(),
        Mode::Enforcing,
        Access::Write,
        "alice",
        "local/alice/notes",
    );
    assert_eq!(
        answer.expect_err("refused, deliberately").reason.token(),
        "PROJECT_NOT_MEMBER"
    );
}

/// THE SUBTREE INDEX ITSELF: strictly beneath, folded, and not a prefix match.
#[test]
fn the_index_answers_owners_strictly_beneath_a_path() {
    let registry = members();
    let loaded = registry.loaded().expect("loaded");
    assert_eq!(
        loaded.private_owners_beneath("local/alice/notes"),
        vec!["mallory"]
    );
    assert_eq!(
        loaded.private_owners_beneath("LOCAL/Alice/Notes"),
        vec!["mallory"]
    );
    assert!(
        loaded.private_owners_beneath("local/alice/solo").is_empty(),
        "`local/alice/solo-x` shares a prefix and is not beneath"
    );
    assert!(
        loaded
            .private_owners_beneath("local/alice/notes/deep")
            .is_empty(),
        "strictly beneath: a row is not beneath itself"
    );
    let mut under_alice = loaded.private_owners_beneath("local/alice");
    under_alice.sort_unstable();
    assert_eq!(
        under_alice,
        vec!["alice", "alice", "alice", "mallory", "mallory"]
    );
    assert_eq!(loaded.private_owners_beneath("local/bob"), vec![""]);
    assert!(loaded.private_owners_beneath("yadgarhq").is_empty());
}

/// A non-owner's read and write of one private row get ONE answer.
///
/// Ruling E: the same reason, the same prose, whether or not the row is
/// archived, so a non-owner learns nothing about the row.
#[test]
fn a_non_owner_gets_one_answer_for_reads_writes_and_archived_rows() {
    let prose: BTreeSet<String> = [
        (Access::Read, "local/alice/solo"),
        (Access::Write, "local/alice/solo"),
        (Access::Read, "local/alice/attic"),
        (Access::Write, "local/alice/attic"),
    ]
    .into_iter()
    .map(|(access, claimed)| {
        let (answer, _) = as_user(members(), Mode::Enforcing, access, "bob", claimed);
        let denied = answer.expect_err("a non-owner is refused");
        assert_eq!(denied.reason.token(), "PROJECT_NOT_MEMBER");
        denied.prose
    })
    .collect();
    assert_eq!(
        prose.len(),
        1,
        "one sentence for every non-owner: {prose:?}"
    );
}

/// THE PROSE NEVER CARRIES THE CLAIM, THE OWNER OR THE CALLER.
#[test]
fn the_not_member_prose_repeats_nothing_the_caller_or_the_row_said() {
    let (answer, _) = as_user(
        members(),
        Mode::Enforcing,
        Access::Write,
        "sentinel-caller",
        "local/alice/solo/sentinel-sub",
    );
    let prose = answer.expect_err("refused").prose;
    for leaked in ["sentinel", "alice", "solo"] {
        assert!(!prose.contains(leaked), "{leaked} leaked into: {prose}");
    }
}

/// THE REAL LOAD PATH FAILS CLOSED, and the gauge says so.
///
/// `install` loads through `Loaded::from_registered`, whose owner mapping is a
/// stub answering `""` until car P0 tags the wire field. So a private row
/// loaded this way is nobody's: its owner's own write counts
/// `PROJECT_NOT_MEMBER`, and the gauge reads 1 — the loud answer §5 step 3
/// requires before the observation window opens.
#[test]
fn a_private_row_loaded_without_its_owner_fails_closed_and_moves_the_gauge() {
    let registry = Registry::never_loaded();
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        install(
            &registry,
            vec![
                row("yadgarhq/docs", ACTIVE, &[]),
                row("local/bob/x", ACTIVE, &["local/bob/x-old"]),
            ],
        );
    });
    let gauge = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .find(|(key, _, _, _)| {
            key.key().name() == "yadgar_gateway_project_registry_private_without_owner"
        })
        .map(|(_, _, _, value)| match value {
            DebugValue::Gauge(g) => g.into_inner(),
            other => panic!("a gauge, got {other:?}"),
        });
    assert_eq!(
        gauge,
        Some(1.0),
        "one private ROW without an owner, its alias not counted twice"
    );

    let (answer, snapshotter) = as_user(
        registry,
        Mode::Counting,
        Access::Write,
        "bob",
        "local/bob/x",
    );
    assert!(answer.is_ok());
    assert_eq!(the_one_series(&snapshotter), refused("PROJECT_NOT_MEMBER"));
}

/// An all-org load reads the gauge as PRESENT and zero.
#[test]
fn an_all_org_load_publishes_the_gauge_as_zero() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        install(
            &Registry::never_loaded(),
            vec![row("yadgarhq/docs", ACTIVE, &[])],
        );
    });
    let present = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .any(|(key, _, _, value)| {
            key.key().name() == "yadgar_gateway_project_registry_private_without_owner"
                && matches!(value, DebugValue::Gauge(g) if g.into_inner() == 0.0)
        });
    assert!(
        present,
        "the gauge must be present and 0 after a clean load"
    );
}

/// No registry: the availability reason only, whoever calls.
#[test]
fn with_no_registry_membership_is_never_reached() {
    let (answer, snapshotter) = as_user(
        Registry::never_loaded(),
        Mode::Counting,
        Access::Read,
        "bob",
        "local/alice/solo",
    );
    assert!(answer.is_ok());
    assert_eq!(
        the_one_series(&snapshotter),
        refused("PROJECT_REGISTRY_UNAVAILABLE")
    );
}

/// THE CLOSED SET (ADR-0558), every token spelled out. A seventh reason that
/// is added without being listed here reds this test.
#[test]
fn the_reason_set_is_closed_and_includes_not_member() {
    let tokens: Vec<&str> = [
        Reason::Invalid,
        Reason::UnregisteredOrg,
        Reason::UnregisteredPersonal,
        Reason::Unresolvable,
        Reason::RegistryUnavailable,
        Reason::Archived,
        Reason::NotMember,
    ]
    .iter()
    .map(|r| match r {
        // EXHAUSTIVE on purpose: a new variant fails to compile here.
        Reason::Invalid
        | Reason::UnregisteredOrg
        | Reason::UnregisteredPersonal
        | Reason::Unresolvable
        | Reason::RegistryUnavailable
        | Reason::Archived
        | Reason::NotMember => r.token(),
    })
    .collect();
    assert_eq!(
        tokens,
        vec![
            "PROJECT_INVALID",
            "PROJECT_UNREGISTERED_ORG",
            "PROJECT_UNREGISTERED_PERSONAL",
            "PROJECT_UNRESOLVABLE",
            "PROJECT_REGISTRY_UNAVAILABLE",
            "PROJECT_ARCHIVED",
            "PROJECT_NOT_MEMBER",
        ]
    );
}
