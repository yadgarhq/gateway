//! Membership (`plans/project-membership.md` car P3, ADR-0947): an org project
//! admits every attested user, a private (`local/…`) project admits only its
//! stored owner for reads AND writes, and every miss is counted as
//! `PROJECT_NOT_MEMBER` before it refuses.
//!
//! **LITERALS, per [`super`]'s rule (ADR-0599):** every token and series name
//! below is spelled out rather than read through the constant under test.
//!
//! **OWNERS ARRIVE ON THE WIRE** (`RegisteredPath.owner_user_id`, proto
//! v1.20.0), so every registry here loads through the real mapping in
//! `Loaded::from_registered`.

use std::collections::BTreeSet;

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

use super::super::registry::install;
use super::*;
use crate::test_accounts::{id, path};

/// One row as `ListProjects` answers it, with handles rendered (ADR-0954).
fn rendered(p: &str, owner: &str, status: ProjectStatus, aliases: &[&str]) -> RegisteredPath {
    let aliases: Vec<String> = aliases.iter().map(|a| path(a)).collect();
    let aliases: Vec<&str> = aliases.iter().map(String::as_str).collect();
    RegisteredPath {
        owner_user_id: id(owner),
        ..row(&path(p), status, &aliases)
    }
}

const ACTIVE: ProjectStatus = ProjectStatus::Active;
const ARCHIVED: ProjectStatus = ProjectStatus::Archived;

/// A registry from literal `(path, owner, status)` rows.
fn owned(rows: &[(&str, &str, ProjectStatus)]) -> Registry {
    Registry::loaded_from(
        rows.iter()
            .map(|(p, owner, status)| rendered(p, owner, *status, &[]))
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
/// - `local/bob/blank` loaded with no owner, the shape a pre-P2 `project` sends.
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
                .check(&path(claimed), access, &id(user), &[], "a-request-id")
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
///
/// **THE RESOLUTION AND REFUSAL SERIES ONLY.** Since team access stage 8 an
/// org call under `orgGrants: counting` also moves the grant SHADOW counter
/// (none of these fixtures declares a grant), and the promise is one series
/// on those two counters with at most one shadow increment BESIDE it — which
/// `grants::red_16_...` asserts. This table is about membership.
fn the_one_series(snapshotter: &Snapshotter) -> (String, String) {
    let all: Vec<_> = series(snapshotter)
        .into_iter()
        .filter(|(name, ..)| name == REFUSED || name == RESOLVED)
        .collect();
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
            "local/bob",
            Write,
            (REFUSED, "PROJECT_UNREGISTERED_PERSONAL"),
        ),
        // another account's unregistered segment (ADR-0954).
        arm("bob", "local/carol", Write, NOT_MEMBER),
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
        loaded.private_owners_beneath(&path("local/alice/notes")),
        vec![id("mallory")]
    );
    assert_eq!(
        loaded.private_owners_beneath(&path("LOCAL/Alice/Notes")),
        vec![id("mallory")]
    );
    assert!(
        loaded
            .private_owners_beneath(&path("local/alice/solo"))
            .is_empty(),
        "`local/alice/solo-x` shares a prefix and is not beneath"
    );
    assert!(
        loaded
            .private_owners_beneath(&path("local/alice/notes/deep"))
            .is_empty(),
        "strictly beneath: a row is not beneath itself"
    );
    let mut under_alice = loaded.private_owners_beneath(&path("local/alice"));
    under_alice.sort_unstable();
    let (a, m) = (id("alice"), id("mallory"));
    let mut expected = vec![a.as_str(), a.as_str(), a.as_str(), m.as_str(), m.as_str()];
    expected.sort_unstable();
    assert_eq!(under_alice, expected);
    assert_eq!(loaded.private_owners_beneath(&path("local/bob")), vec![""]);
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
/// `install` loads through `Loaded::from_registered`, and these rows carry an
/// empty `owner_user_id` — what a `project` older than car P2 sends. So a
/// private row loaded this way is nobody's: its would-be owner's write counts
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
                rendered("yadgarhq/docs", "", ACTIVE, &[]),
                rendered("local/bob/x", "", ACTIVE, &["local/bob/x-old"]),
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

/// THE CLOSED SET (ADR-0558), every token spelled out. An eighth reason that
/// is added without being listed here reds this test; `PROJECT_READ_ONLY` is
/// team access red 16's addition (ADR-0963 (3)).
#[test]
fn red_16_the_reason_set_is_closed_and_includes_not_member_and_read_only() {
    let tokens: Vec<&str> = [
        Reason::Invalid,
        Reason::UnregisteredOrg,
        Reason::UnregisteredPersonal,
        Reason::Unresolvable,
        Reason::RegistryUnavailable,
        Reason::Archived,
        Reason::NotMember,
        Reason::ReadOnly,
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
        | Reason::NotMember
        | Reason::ReadOnly => r.token(),
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
            "PROJECT_READ_ONLY",
        ]
    );
}

// ---------------------------------------------------------------------------
// The registry load maps `RegisteredPath.owner_user_id` (proto v1.20.0, P0).
// ---------------------------------------------------------------------------

/// One row as `ListProjects` answers it, owner on the wire.
fn wire(p: &str, owner: &str) -> RegisteredPath {
    rendered(p, owner, ACTIVE, &[])
}

/// A private row LOADED FROM THE WIRE carries its owner, so its owner is
/// served — the mapping is real, not the empty stub.
///
/// MUTATION THIS CATCHES: map every owner to `""` (the P3a stub) — the owner
/// is then refused and the row counts as owned by nobody.
#[test]
fn a_private_row_loaded_from_the_wire_carries_its_owner() {
    let loaded = Loaded::from_registered(vec![wire("local/alice/x", "alice")]);
    assert_eq!(
        loaded
            .registered_as(&path("local/alice/x"))
            .map(|m| m.owner),
        Some(id("alice"))
    );
    assert_eq!(loaded.private_rows(), 1);
    assert_eq!(loaded.private_rows_without_owner(), 0);

    let registry = Registry::loaded_from(vec![wire("local/alice/x", "alice")]);
    let (answer, snapshotter) = as_user(
        registry,
        Mode::Enforcing,
        Access::Write,
        "alice",
        "local/alice/x",
    );
    assert!(answer.is_ok(), "{:?}", answer.err());
    assert_eq!(
        the_one_series(&snapshotter),
        (RESOLVED.to_string(), "exact".to_string())
    );
}

/// An org row carries `""`, and every attested user reaches it.
#[test]
fn an_org_row_loaded_from_the_wire_carries_no_owner() {
    let loaded = Loaded::from_registered(vec![wire("yadgarhq/docs", "")]);
    assert_eq!(
        loaded.registered_as("yadgarhq/docs").map(|m| m.owner),
        Some(String::new())
    );
    assert_eq!(loaded.private_rows(), 0);
    let (answer, _) = as_user(
        Registry::loaded_from(vec![wire("yadgarhq/docs", "")]),
        Mode::Enforcing,
        Access::Write,
        "bob",
        "yadgarhq/docs",
    );
    assert!(answer.is_ok());
}

/// A private row that arrives from the wire with an EMPTY owner fails closed:
/// nobody reaches it, not even a caller who sent no user.
#[test]
fn a_private_row_loaded_from_the_wire_without_an_owner_fails_closed() {
    let loaded = Loaded::from_registered(vec![
        wire("local/bob/x", ""),
        wire("local/alice/y", "alice"),
    ]);
    assert_eq!(loaded.private_rows(), 2);
    assert_eq!(loaded.private_rows_without_owner(), 1);
    for user in ["bob", ""] {
        let (answer, _) = as_user(
            Registry::loaded_from(vec![wire("local/bob/x", "")]),
            Mode::Enforcing,
            Access::Read,
            user,
            "local/bob/x",
        );
        assert_eq!(
            answer.expect_err("nobody owns it").reason.token(),
            "PROJECT_NOT_MEMBER",
            "user {user:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Security review (adversarial pass on `member.rs`).
// ---------------------------------------------------------------------------

/// A row with its owner and aliases on the wire.
fn wire_aliased(p: &str, owner: &str, aliases: &[&str]) -> RegisteredPath {
    rendered(p, owner, ACTIVE, aliases)
}

/// HOLE 1: the class was read from the MATCHED SPELLING, so an alias of a
/// private row spelled outside `local/` made that row org for anybody who
/// claimed the alias. The class is the ROW's path.
///
/// MUTATION THIS CATCHES: decide the class from the landed spelling only.
#[test]
fn an_org_spelled_alias_of_a_private_row_is_still_private() {
    let registry = || {
        Registry::loaded_from(vec![
            wire_aliased("acme/anchor", "", &[]),
            wire_aliased("local/alice/p", "alice", &["acme/p"]),
        ])
    };
    for access in [Access::Read, Access::Write] {
        let (answer, snapshotter) = as_user(registry(), Mode::Counting, access, "bob", "acme/p");
        assert!(answer.is_ok());
        assert_eq!(
            the_one_series(&snapshotter),
            refused("PROJECT_NOT_MEMBER"),
            "{access:?}"
        );
        let (answer, _) = as_user(registry(), Mode::Enforcing, access, "alice", "acme/p");
        assert!(
            answer.is_ok(),
            "the owner still reaches it: {:?}",
            answer.err()
        );
    }
}

/// HOLE 2: an ORG row skipped the subtree rule, so a private row reachable
/// beneath it through an org-spelled alias was read by anybody claiming the
/// org row. Every row, org included, requires owning every private row
/// beneath it.
#[test]
fn an_org_row_with_a_private_row_beneath_it_takes_the_subtree_rule() {
    let registry = || {
        Registry::loaded_from(vec![
            wire_aliased("acme/team", "", &[]),
            wire_aliased("local/alice/q", "alice", &["acme/team/q"]),
        ])
    };
    let (answer, _) = as_user(
        registry(),
        Mode::Enforcing,
        Access::Read,
        "bob",
        "acme/team",
    );
    assert_eq!(
        answer
            .expect_err("bob would reach alice's row")
            .reason
            .token(),
        "PROJECT_NOT_MEMBER"
    );
    let (answer, _) = as_user(
        registry(),
        Mode::Enforcing,
        Access::Read,
        "alice",
        "acme/team",
    );
    assert!(answer.is_ok(), "{:?}", answer.err());
}

/// CHECKED, NOT A HOLE: malformed private claims never resolve, `Local/` is
/// private, and `local/alice` is not a prefix of `local/alicex`.
#[test]
fn malformed_folded_and_prefix_claims_never_admit_a_non_owner() {
    let registry = || {
        Registry::loaded_from(vec![
            wire_aliased("local/alice/p", "alice", &[]),
            wire_aliased("local/alicex/p", "mallory", &[]),
        ])
    };
    let dot = ".";
    for claimed in [
        "local/alice/p/".to_string(),
        "local//alice/p".to_string(),
        format!("local/alice/{dot}/p"),
        format!("local/alice/{dot}{dot}/alice/p"),
    ] {
        let (answer, _) = as_user(registry(), Mode::Enforcing, Access::Read, "bob", &claimed);
        assert_eq!(
            answer.expect_err(&claimed).reason.token(),
            "PROJECT_INVALID",
            "{claimed}"
        );
    }
    for claimed in ["Local/alice/p", "LOCAL/ALICE/P"] {
        let (answer, _) = as_user(registry(), Mode::Enforcing, Access::Read, "bob", claimed);
        assert_eq!(
            answer.expect_err(claimed).reason.token(),
            "PROJECT_NOT_MEMBER"
        );
    }
    let (answer, _) = as_user(
        registry(),
        Mode::Enforcing,
        Access::Read,
        "alice",
        "local/alice/p",
    );
    assert!(
        answer.is_ok(),
        "mallory's local/alicex/p is not beneath: {:?}",
        answer.err()
    );
}

// ---------------------------------------------------------------------------
// Security review 2: the loaded set and the private-owner index stay one state.
// ---------------------------------------------------------------------------

/// HOLE 3: two spellings that FOLD TO ONE KEY kept only the last row's owner,
/// in the path map and in the index alike. A foreign owner beneath a caller's
/// row could be dropped by an alias collision, and the subtree rule then
/// passed. Every owner of every spelling must stay in the index, whatever
/// order the rows arrive in.
#[test]
fn a_folded_collision_beneath_a_row_keeps_every_owner_in_the_index() {
    let rows = vec![
        wire_aliased("local/alice/notes", "alice", &[]),
        wire_aliased("local/alice/notes/deep", "mallory", &[]),
        wire_aliased("local/alice/other", "alice", &["LOCAL/alice/notes/deep"]),
    ];
    for order in [rows.clone(), rows.into_iter().rev().collect()] {
        let (answer, _) = as_user(
            Registry::loaded_from(order),
            Mode::Enforcing,
            Access::Read,
            "alice",
            "local/alice/notes",
        );
        assert_eq!(
            answer.expect_err("mallory's row is beneath").reason.token(),
            "PROJECT_NOT_MEMBER"
        );
    }
}

/// HOLE 4: when two rows of DIFFERENT owners fold to the claimed key, the
/// last one loaded won, so whoever owned it was admitted to the other's row.
/// An ambiguous owner is nobody's.
#[test]
fn a_claim_whose_spelling_two_owners_share_admits_nobody() {
    let rows = vec![
        wire_aliased("local/alice/p", "alice", &[]),
        wire_aliased("local/bob/q", "bob", &["Local/Alice/P"]),
    ];
    for order in [rows.clone(), rows.into_iter().rev().collect::<Vec<_>>()] {
        for user in ["alice", "bob"] {
            let (answer, _) = as_user(
                Registry::loaded_from(order.clone()),
                Mode::Enforcing,
                Access::Write,
                user,
                "local/alice/p",
            );
            assert_eq!(
                answer.expect_err(user).reason.token(),
                "PROJECT_NOT_MEMBER",
                "{user}"
            );
        }
    }
}

/// HOLE 5: `private_owners_beneath` with a trailing slash ranged on `p//`
/// and found nothing, which reads as "nobody beneath" — a pass. Not reachable
/// through `classify` today (the grammar refuses a trailing slash), closed so
/// no later caller can open it.
#[test]
fn the_index_ignores_a_trailing_slash_on_the_queried_path() {
    let registry = members();
    let loaded = registry.loaded().expect("loaded");
    assert_eq!(
        loaded.private_owners_beneath(&format!("{}/", path("local/alice/notes"))),
        vec![id("mallory")]
    );
}

/// CHECKED: an ARCHIVED foreign row beneath still blocks — status is not
/// filtered out of the index, so archiving a row never opens its subtree.
#[test]
fn an_archived_foreign_row_beneath_still_blocks() {
    let registry = owned(&[
        ("local/alice/notes", "alice", ACTIVE),
        ("local/alice/notes/deep", "mallory", ARCHIVED),
    ]);
    let (answer, _) = as_user(
        registry,
        Mode::Enforcing,
        Access::Read,
        "alice",
        "local/alice/notes",
    );
    assert_eq!(
        answer.expect_err("blocked").reason.token(),
        "PROJECT_NOT_MEMBER"
    );
}

/// CHECKED: an EMPTY load refuses a private claim under enforcement, and
/// counts it under counting. It never admits.
#[test]
fn an_empty_load_fails_closed_for_private_claims() {
    let (answer, _) = as_user(
        Registry::loaded_from(Vec::new()),
        Mode::Enforcing,
        Access::Read,
        "alice",
        "local/alice/notes",
    );
    assert_eq!(
        answer.expect_err("nothing loaded").reason.token(),
        "PROJECT_UNREGISTERED_PERSONAL"
    );
}

/// CHECKED: a reload swaps the path map AND the index together. After a
/// second load adds a foreign row beneath, the owner of the parent is refused
/// and the new row resolves — neither half lags the other.
#[test]
fn a_reload_swaps_the_paths_and_the_index_as_one_state() {
    let registry = Registry::never_loaded();
    let recorder = DebuggingRecorder::new();
    metrics::with_local_recorder(&recorder, || {
        install(
            &registry,
            vec![wire_aliased("local/alice/notes", "alice", &[])],
        );
    });
    let (answer, _) = as_user(
        registry.clone(),
        Mode::Enforcing,
        Access::Read,
        "alice",
        "local/alice/notes",
    );
    assert!(answer.is_ok(), "{:?}", answer.err());

    metrics::with_local_recorder(&recorder, || {
        install(
            &registry,
            vec![
                wire_aliased("local/alice/notes", "alice", &[]),
                wire_aliased("local/alice/notes/deep", "mallory", &[]),
                wire_aliased("local/alice/fresh", "alice", &[]),
            ],
        );
    });
    let (answer, _) = as_user(
        registry.clone(),
        Mode::Enforcing,
        Access::Read,
        "alice",
        "local/alice/notes",
    );
    assert_eq!(
        answer.expect_err("refused").reason.token(),
        "PROJECT_NOT_MEMBER"
    );
    // THE PATH MAP RELOADED: `local/alice/fresh` exists only in the second
    // load, so alice's claim of it resolves EXACTLY. A stale path map would
    // answer `PROJECT_UNREGISTERED_PERSONAL`. The refusal above shows the
    // INDEX reloaded (mallory's row beneath `notes` is new); this shows the
    // MAP did, so neither half can lag the other unnoticed.
    let (answer, snapshotter) = as_user(
        registry,
        Mode::Counting,
        Access::Write,
        "alice",
        "local/alice/fresh",
    );
    assert!(answer.is_ok());
    assert_eq!(
        the_one_series(&snapshotter),
        (RESOLVED.to_string(), "exact".to_string())
    );
}

// ---------------------------------------------------------------------------
// Review of #121 at 68d8f30: F1, F2, F4, F5.
// ---------------------------------------------------------------------------

/// Both load orders of `rows`.
fn both_orders(rows: Vec<RegisteredPath>) -> [Vec<RegisteredPath>; 2] {
    let reversed = rows.iter().cloned().rev().collect();
    [rows, reversed]
}

/// F1, DIFFERENT-OWNER ARM: an org row and a private row's alias fold to one
/// non-`local/` key. Whichever loads last, the merged key stays PRIVATE and
/// ownerless, so nobody — the org's users or the private owner — is admitted.
///
/// MUTATION THIS CATCHES: drop `private: prev.private || m.private` from the
/// different-owner arm of `merge` — with the org row last the key reads as an
/// org row and admits everyone.
#[test]
fn an_org_row_colliding_with_an_owned_private_alias_admits_nobody_in_either_order() {
    for order in both_orders(vec![
        wire_aliased("acme/team", "", &[]),
        wire_aliased("local/alice/p", "alice", &["acme/team"]),
    ]) {
        for user in ["bob", "alice"] {
            let (answer, _) = as_user(
                Registry::loaded_from(order.clone()),
                Mode::Enforcing,
                Access::Read,
                user,
                "acme/team",
            );
            assert_eq!(answer.expect_err(user).reason.token(), "PROJECT_NOT_MEMBER");
        }
    }
}

/// F1, SAME-OWNER ARM, and the LIVE shape: project v0.3.7 sends `""` for every
/// owner, so an org row and a private row's alias collide with EQUAL owners.
///
/// MUTATION THIS CATCHES: drop `private: prev.private || m.private` from the
/// same-owner arm — with the org row last the key reads as org and admits
/// everyone.
#[test]
fn an_org_row_colliding_with_an_ownerless_private_alias_admits_nobody_in_either_order() {
    for order in both_orders(vec![
        wire_aliased("acme/team", "", &[]),
        wire_aliased("local/alice/p", "", &["acme/team"]),
    ]) {
        let (answer, _) = as_user(
            Registry::loaded_from(order),
            Mode::Enforcing,
            Access::Write,
            "bob",
            "acme/team",
        );
        assert_eq!(
            answer.expect_err("bob").reason.token(),
            "PROJECT_NOT_MEMBER"
        );
    }
}

/// F2: a collision of an ARCHIVED and an ACTIVE row resolves toward refusal in
/// either order — a write is `PROJECT_ARCHIVED`, never served.
#[test]
fn a_collision_with_an_archived_row_refuses_writes_in_either_order() {
    for order in both_orders(vec![
        RegisteredPath {
            owner_user_id: String::new(),
            grants: Vec::new(),
            ..row("acme/x", ARCHIVED, &[])
        },
        wire_aliased("acme/y", "", &["acme/x"]),
    ]) {
        let (answer, _) = as_user(
            Registry::loaded_from(order),
            Mode::Enforcing,
            Access::Write,
            "bob",
            "acme/x",
        );
        assert_eq!(
            answer.expect_err("archived").reason.token(),
            "PROJECT_ARCHIVED"
        );
    }
}

/// F4: the gauge counts EVERY spelling nobody can reach, not only private rows
/// by path: an org row carrying a `local/` alias, and a key `merge` made
/// ownerless.
#[test]
fn the_gauge_counts_org_rows_with_local_aliases_and_keys_made_ownerless() {
    for order in both_orders(vec![
        wire_aliased("acme/docs", "", &["local/carol/docs"]),
        wire_aliased("local/alice/p", "alice", &[]),
        wire_aliased("local/bob/q", "bob", &["Local/Alice/P"]),
    ]) {
        let loaded = Loaded::from_registered(order);
        assert_eq!(
            loaded.private_rows_without_owner(),
            2,
            "one org row with a local/ alias, one key two owners share"
        );
    }
}

/// F5: an ORG claim refused under the subtree rule is not told that its own
/// project is personal; the sentence fits both cases and still leaks nothing.
#[test]
fn the_not_member_prose_fits_an_org_claim_too() {
    let (answer, _) = as_user(
        Registry::loaded_from(vec![
            wire_aliased("acme/crew", "", &[]),
            wire_aliased("local/alice/q", "alice", &["acme/crew/q"]),
        ]),
        Mode::Enforcing,
        Access::Read,
        "bob",
        "acme/crew",
    );
    let prose = answer.expect_err("refused").prose;
    assert!(
        !prose.contains("this personal project"),
        "an org claim is not a personal project: {prose}"
    );
    for leaked in ["acme", "crew", "alice", "bob"] {
        assert!(!prose.contains(leaked), "{leaked} leaked into: {prose}");
    }
}

// ---------------------------------------------------------------------------
// ADR-0954 (ledger 1651): another account's `local/` segment hides existence.
// ---------------------------------------------------------------------------

/// Alice's and Bob's ids as `iam-db` mints them, and Alice's segment.
const ALICE: &str = "yadgar:user:0192f0a0-0000-7000-8000-00000000a11c";
const BOB: &str = "yadgar:user:0192f0a0-0000-7000-9000-000000000b0b";
const SEG_A: &str = "0192f0a0-0000-7000-8000-00000000a11c";

/// Alice's registered private row, under her own segment.
fn alice_estate() -> Registry {
    Registry::loaded_from(vec![
        wire_aliased("yadgarhq/docs", "", &[]),
        wire_aliased(&format!("local/{SEG_A}/reg"), ALICE, &[]),
    ])
}

fn under_a(rest: &str) -> String {
    format!("local/{SEG_A}/{rest}")
}

/// The segment is the id minus `yadgar:user:`, and only for the canonical id.
#[test]
fn the_account_segment_is_the_canonical_id_without_its_prefix() {
    assert_eq!(account_segment(ALICE), Some(SEG_A));
    for not_canonical in [
        "",
        "alice",
        SEG_A,
        "yadgar:user:0192F0A0-0000-7000-8000-00000000A11C",
        "YADGAR:USER:0192f0a0-0000-7000-8000-00000000a11c",
        "yadgar:user:0192f0a0-0000-4000-8000-00000000a11c",
        "yadgar:user: 0192f0a0-0000-7000-8000-00000000a11c",
        "yadgar:user:0192f0a0-0000-7000-8000-00000000a11c ",
    ] {
        assert_eq!(account_segment(not_canonical), None, "{not_canonical:?}");
    }
}

/// ANOTHER ACCOUNT'S UNREGISTERED PATH: one 403 `PROJECT_NOT_MEMBER`, counted
/// as such — no longer `PROJECT_UNREGISTERED_PERSONAL`, which would tell Bob
/// the path is free.
#[test]
fn another_accounts_unregistered_path_is_not_member() {
    let (answer, snapshotter) = as_user(
        alice_estate(),
        Mode::Counting,
        Access::Read,
        BOB,
        &under_a("nothere"),
    );
    assert!(answer.is_ok());
    assert_eq!(the_one_series(&snapshotter), refused("PROJECT_NOT_MEMBER"));
    let (answer, _) = as_user(
        alice_estate(),
        Mode::Enforcing,
        Access::Write,
        BOB,
        &under_a("nothere"),
    );
    assert_eq!(
        answer.expect_err("refused").reason.token(),
        "PROJECT_NOT_MEMBER"
    );
}

/// REGISTERED, UNREGISTERED AND SOFT-LANDED claims into another account's
/// segment get the SAME reason and the SAME sentence.
#[test]
fn another_accounts_registered_unregistered_and_landed_paths_answer_alike() {
    let answers: BTreeSet<(String, String)> = ["nothere", "reg", "reg/deeper", "nothere/deeper"]
        .into_iter()
        .map(|rest| {
            let (answer, _) = as_user(
                alice_estate(),
                Mode::Enforcing,
                Access::Read,
                BOB,
                &under_a(rest),
            );
            let denied = answer.expect_err(rest);
            (denied.reason.token().to_string(), denied.prose)
        })
        .collect();
    assert_eq!(answers.len(), 1, "one answer: {answers:?}");
    assert_eq!(answers.iter().next().expect("one").0, "PROJECT_NOT_MEMBER");
}

/// THE CALLER'S OWN SEGMENT IS UNCHANGED: unregistered stays
/// `PROJECT_UNREGISTERED_PERSONAL`, registered resolves, soft landing lands.
#[test]
fn the_callers_own_segment_keeps_todays_answers() {
    let (answer, _) = as_user(
        alice_estate(),
        Mode::Enforcing,
        Access::Write,
        ALICE,
        &under_a("nothere"),
    );
    assert_eq!(
        answer.expect_err("own, unregistered").reason.token(),
        "PROJECT_UNREGISTERED_PERSONAL"
    );
    let (answer, snapshotter) = as_user(
        alice_estate(),
        Mode::Counting,
        Access::Write,
        ALICE,
        &under_a("reg"),
    );
    assert!(answer.is_ok());
    assert_eq!(
        the_one_series(&snapshotter),
        (RESOLVED.to_string(), "exact".to_string())
    );
    let (answer, snapshotter) = as_user(
        alice_estate(),
        Mode::Counting,
        Access::Write,
        ALICE,
        &under_a("reg/deeper"),
    );
    assert!(answer.is_ok());
    assert_eq!(
        the_one_series(&snapshotter),
        (RESOLVED.to_string(), "ancestor".to_string())
    );
}

/// CASE-VARIANT SEGMENTS. The store folds ASCII case, so an upper-cased
/// segment names the same account: Alice's own upper-cased claim lands on her
/// row, and Bob's is foreign however it is cased — `LOCAL/` included.
#[test]
fn a_case_variant_segment_is_compared_as_the_store_compares_it() {
    let upper = SEG_A.to_ascii_uppercase();
    for claimed in [
        format!("local/{upper}/reg"),
        format!("LOCAL/{upper}/nothere"),
        format!("Local/{SEG_A}/reg"),
    ] {
        let (answer, _) = as_user(alice_estate(), Mode::Enforcing, Access::Read, BOB, &claimed);
        assert_eq!(
            answer.expect_err(&claimed).reason.token(),
            "PROJECT_NOT_MEMBER",
            "{claimed}"
        );
    }
    let (answer, _) = as_user(
        alice_estate(),
        Mode::Enforcing,
        Access::Read,
        ALICE,
        &format!("local/{upper}/reg"),
    );
    assert!(answer.is_ok(), "{:?}", answer.err());
}

/// AN EMPTY OR NON-CANONICAL `user_id` NAMES NO ACCOUNT: every `local/<seg>/…`
/// claim is foreign to it, Alice's included, even spelled as Alice's id in
/// upper case. Org claims are unaffected.
#[test]
fn an_empty_or_non_canonical_user_id_owns_no_segment() {
    for user in [
        "",
        "not-an-id",
        SEG_A,
        "yadgar:user:0192F0A0-0000-7000-8000-00000000A11C",
    ] {
        for rest in ["reg", "nothere"] {
            let (answer, _) = as_user(
                alice_estate(),
                Mode::Enforcing,
                Access::Read,
                user,
                &under_a(rest),
            );
            assert_eq!(
                answer.expect_err(user).reason.token(),
                "PROJECT_NOT_MEMBER",
                "{user:?} {rest}"
            );
        }
        let (answer, _) = as_user(
            alice_estate(),
            Mode::Enforcing,
            Access::Read,
            user,
            "yadgarhq/docs",
        );
        assert!(answer.is_ok(), "{user:?}: {:?}", answer.err());
    }
}

/// BARE `local` KEEPS TODAY'S ANSWER, and a two-segment foreign claim is
/// foreign like any other.
#[test]
fn bare_local_is_unchanged_and_a_bare_foreign_segment_is_not_member() {
    let (answer, _) = as_user(alice_estate(), Mode::Enforcing, Access::Read, BOB, "local");
    assert_eq!(
        answer.expect_err("bare").reason.token(),
        "PROJECT_UNRESOLVABLE"
    );
    let (answer, _) = as_user(
        alice_estate(),
        Mode::Enforcing,
        Access::Read,
        BOB,
        &format!("local/{SEG_A}"),
    );
    assert_eq!(
        answer.expect_err("segment").reason.token(),
        "PROJECT_NOT_MEMBER"
    );
}

/// RULING E, ON A NON-OWNER WHO STILL REACHES `verdict`. Every claim into
/// another account's segment now stops at the ADR-0954 foreign check, so the
/// ownership-before-archived order needs cases the foreign check admits:
///
/// - an ARCHIVED, OWNERLESS row in the caller's OWN segment (a pre-P2 load),
///   written by the segment's own account;
/// - an ORG-SPELLED ALIAS of another account's ARCHIVED private row, written
///   through the alias.
///
/// Both are non-members, so both answer `PROJECT_NOT_MEMBER` — never
/// `PROJECT_ARCHIVED`, which would tell a non-owner the row's status.
///
/// MUTATION THIS CATCHES: swap the two `if`s in `member::verdict` (archived
/// before membership) — both cases then answer `PROJECT_ARCHIVED`.
#[test]
fn ruling_e_holds_for_non_owners_the_foreign_check_admits() {
    let registry = || {
        owned(&[
            ("acme/anchor", "", ACTIVE),
            ("local/bob/attic", "", ARCHIVED),
            ("local/alice/vault", "alice", ARCHIVED),
        ])
    };
    let aliased = || {
        Registry::loaded_from(vec![
            rendered("acme/anchor", "", ACTIVE, &[]),
            rendered("local/alice/vault", "alice", ARCHIVED, &["acme/vault"]),
        ])
    };
    for (registry, claimed) in [(registry(), "local/bob/attic"), (aliased(), "acme/vault")] {
        for mode in [Mode::Counting, Mode::Enforcing] {
            let (answer, snapshotter) =
                as_user(registry.clone(), mode, Access::Write, "bob", claimed);
            match mode {
                Mode::Counting => {
                    assert!(answer.is_ok());
                    assert_eq!(
                        the_one_series(&snapshotter),
                        refused("PROJECT_NOT_MEMBER"),
                        "{claimed}"
                    );
                }
                Mode::Enforcing => assert_eq!(
                    answer.expect_err(claimed).reason.token(),
                    "PROJECT_NOT_MEMBER",
                    "{claimed}"
                ),
            }
        }
    }
}

/// An org row carrying an alias, and an org row carrying a `local/` alias.
fn aliased() -> Registry {
    Registry::loaded_from(vec![
        rendered("acme", "", ACTIVE, &[]),
        rendered("acme/docs", "", ACTIVE, &["acme/old-docs"]),
        rendered("acme/wiki", "", ACTIVE, &["local/carol/wiki"]),
    ])
}

/// COUNTING MOVES THE SAME SERIES IT DID BEFORE STAMPING, for alias claims.
///
/// A bare alias claim is EXACT, as `ResolveProject` answers it (`via_alias`):
/// the claim matched a registered spelling at depth zero. An alias subpath is
/// a soft landing. MUTATION THIS CATCHES: computing `exact` from the row's
/// canonical path, which turns a bare alias into `ancestor` (gateway#125).
#[test]
fn under_counting_a_bare_alias_claim_counts_exact_and_its_subpath_ancestor() {
    for (claimed, outcome) in [("acme/old-docs", "exact"), ("acme/old-docs/x", "ancestor")] {
        let (answer, snapshotter) =
            as_user(aliased(), Mode::Counting, Access::Read, "carol", claimed);
        assert!(answer.is_ok(), "{claimed}: counting serves");
        assert_eq!(
            the_one_series(&snapshotter),
            (RESOLVED.to_string(), outcome.to_string()),
            "{claimed}"
        );
    }
}

/// An org row's `local/` alias reaches nobody, and a claim spelled with it is
/// `PROJECT_NOT_MEMBER`: the spelling is private by its path, whichever row it
/// names. MUTATION THIS CATCHES: reading the class off the row's canonical
/// path only, which admits the claim (gateway#125).
#[test]
fn an_org_rows_local_alias_is_refused_as_not_member() {
    let claimed = "local/carol/wiki";
    let (answer, snapshotter) = as_user(aliased(), Mode::Counting, Access::Read, "carol", claimed);
    assert!(answer.is_ok(), "counting serves");
    assert_eq!(the_one_series(&snapshotter), refused("PROJECT_NOT_MEMBER"));

    let (answer, _) = as_user(aliased(), Mode::Enforcing, Access::Read, "carol", claimed);
    assert_eq!(
        answer.expect_err("refused").reason.token(),
        "PROJECT_NOT_MEMBER"
    );
}

/// Aliases that make an ANCHOR out of either side of a match: `olddocs` is a
/// single-segment alias of a deep row, and `yadgarhq-old/ns` is a
/// multi-segment alias of the anchor `yadgarhq`.
fn anchor_aliased() -> Registry {
    Registry::loaded_from(vec![
        rendered("yadgarhq", "", ACTIVE, &["yadgarhq-old/ns"]),
        rendered("yadgarhq/docs", "", ACTIVE, &["olddocs"]),
    ])
}

/// THE ANCHOR RULE READS BOTH SIDES OF A MATCH (ADR-0673): the spelling that
/// hit, and the row it names. A single segment on EITHER side is an anchor,
/// and nothing lands on an anchor.
///
/// MUTATIONS THIS CATCHES: the row-only rule (`olddocs` would land on
/// `yadgarhq/docs`), and the hit-only rule (`yadgarhq-old/ns` would land on
/// the anchor `yadgarhq` itself).
#[test]
fn under_counting_an_alias_on_either_side_of_an_anchor_is_unregistered_org() {
    for claimed in [
        "olddocs",
        "olddocs/x",
        "yadgarhq-old/ns",
        "yadgarhq-old/ns/x",
    ] {
        let (answer, snapshotter) = as_user(
            anchor_aliased(),
            Mode::Counting,
            Access::Read,
            "carol",
            claimed,
        );
        assert!(answer.is_ok(), "{claimed}: counting serves");
        assert_eq!(
            the_one_series(&snapshotter),
            refused("PROJECT_UNREGISTERED_ORG"),
            "{claimed}"
        );
    }
}

/// The anchor a refusal names is the single-segment side: the alias that hit
/// when the ROW is deep, the row when the row is the anchor. The remediation
/// is composed from it.
///
/// MUTATION THIS CATCHES: always naming the row, which names `yadgarhq/docs` —
/// not an anchor at all — for `olddocs`.
#[test]
fn the_refusal_names_the_single_segment_side_as_the_anchor() {
    let registry = anchor_aliased();
    for (claimed, anchor) in [("olddocs/x", "olddocs"), ("yadgarhq-old/ns", "yadgarhq")] {
        assert_eq!(
            outcome(&registry, claimed),
            Outcome::Refused(Refusal {
                reason: Reason::UnregisteredOrg,
                anchor: Some(anchor.to_string()),
            }),
            "{claimed}"
        );
    }
}
