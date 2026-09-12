//! Tests for [`super`]: the taxonomy, the two counters, the boot gauge, and the
//! one property this whole release is for — that NOTHING is refused.
//!
//! **THE METRIC AND REASON STRINGS ARE LITERALS HERE, never `super::REFUSALS`.**
//! ADR-0599: an interface string asserted THROUGH its own constant renames to a
//! green suite, and these three names are read by a Prometheus scrape and by the
//! stage-5 gate — outside this repository, where a rename is silent.
//!
//! **THE EXPECTED VALUES IN THE TABLE ARE LITERALS TOO**, never computed by the
//! walk under test: a fixture that derives its expectation from the code it
//! checks asserts that the code agrees with itself.

use std::collections::BTreeSet;
use std::time::Duration;

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

use super::*;

/// A registry holding exactly the paths a test names.
///
/// `Registry::loaded_with` in one line, and separate from it so the table below
/// reads as paths rather than as construction.
fn registered(paths: &[&str]) -> Registry {
    Registry::loaded_with(paths.iter().map(|p| (*p).to_string()))
}

/// The estate as stage 3 will seed a corner of it: one namespace ANCHOR, one org
/// project beneath it, one private project.
fn estate() -> Registry {
    registered(&["yadgarhq", "yadgarhq/docs", "local/max/git/alpha"])
}

/// A channel to a port nothing listens on.
///
/// Every fallback dial in this file therefore FAILS, which is the case worth
/// covering: the refusal must stand anyway.
///
/// **BUILT INSIDE A RUNTIME, always.** `connect_lazy` registers with the tokio
/// reactor, so calling this outside `block_on` panics with "there is no reactor
/// running" — which is how the first run of this file failed, before any
/// assertion was reached.
fn dead_channel() -> tonic::transport::Channel {
    tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy()
}

/// Classify one claim against `registry`, with no metrics and no dial.
fn outcome(registry: &Registry, claimed: &str) -> Outcome {
    let loaded = registry.loaded().expect("the registry is loaded");
    classify(loaded.as_ref(), claimed)
}

// ---------------------------------------------------------------------------
// The taxonomy. One table, literal expectations.
// ---------------------------------------------------------------------------

/// An exact match lands, and says it was exact.
#[test]
fn an_exactly_registered_path_resolves_to_itself() {
    assert_eq!(
        outcome(&estate(), "yadgarhq/docs"),
        Outcome::Resolved {
            path: "yadgarhq/docs".to_string(),
            exact: true,
        }
    );
}

/// D53's MONOREPO SUBPATH, which is the case an exact-match check would refuse.
///
/// `plans/project-validation.md` is explicit that a marker-declared subpath is
/// the DESIGNED shape and is expected to be deeper than any registered row on
/// the day it is written. An exact-match implementation refuses exactly this and
/// then hands it the remediation that mints a project shadowing a subpath of an
/// existing one.
///
/// MUTATION THIS CATCHES: replace the ancestor walk in `classify` with an exact
/// lookup — this test reds naming `yadgarhq/docs/plans`.
#[test]
fn a_subpath_resolves_to_its_nearest_registered_ancestor() {
    assert_eq!(
        outcome(&estate(), "yadgarhq/docs/plans"),
        Outcome::Resolved {
            path: "yadgarhq/docs".to_string(),
            exact: false,
        }
    );
}

/// THE WALK IS SEGMENT-WISE, NEVER BY STRING PREFIX.
///
/// `yadgarhq/docs` is not an ancestor of `yadgarhq/docsx`, and a `starts_with`
/// implementation says it is — filing one project's work under a project that
/// merely shares its first thirteen characters.
#[test]
fn a_sibling_sharing_a_prefix_is_not_a_descendant() {
    assert_eq!(
        outcome(&estate(), "yadgarhq/docsx/sub"),
        Outcome::Refused(Refusal {
            reason: Reason::UnregisteredOrg,
            anchor: Some("yadgarhq".to_string()),
        })
    );
}

/// An unregistered repository in a registered namespace (ADR-0673).
#[test]
fn an_unregistered_repository_refuses_through_its_namespace_anchor() {
    assert_eq!(
        outcome(&estate(), "yadgarhq/gateway"),
        Outcome::Refused(Refusal {
            reason: Reason::UnregisteredOrg,
            anchor: Some("yadgarhq".to_string()),
        })
    );
}

/// AN EXACT MATCH ON AN ANCHOR IS STILL A REFUSAL (ADR-0673).
///
/// The anchor is resolved THROUGH and is never a landing site, so naming it
/// directly is not a shortcut into the namespace's own bucket. Without this,
/// every unregistered repository in the estate could soft-land at one
/// `task_counter` by claiming the org root.
#[test]
fn the_namespace_anchor_is_never_a_landing_site_even_when_named_exactly() {
    assert_eq!(
        outcome(&estate(), "yadgarhq"),
        Outcome::Refused(Refusal {
            reason: Reason::UnregisteredOrg,
            anchor: Some("yadgarhq".to_string()),
        })
    );
}

/// No registered ancestor, and not private: the class with NO remediation.
#[test]
fn a_path_under_no_registered_namespace_is_unresolvable() {
    assert_eq!(
        outcome(&estate(), "acme/forecast"),
        Outcome::Refused(Refusal::bare(Reason::Unresolvable))
    );
}

/// A private path with no registered ancestor — the one class that may create.
#[test]
fn an_unregistered_private_path_refuses_as_personal() {
    assert_eq!(
        outcome(&estate(), "local/max/git/beta"),
        Outcome::Refused(Refusal::bare(Reason::UnregisteredPersonal))
    );
}

/// A private path DEEPER than a registered private project lands on it.
#[test]
fn a_private_subpath_resolves_to_its_registered_ancestor() {
    assert_eq!(
        outcome(&estate(), "local/max/git/alpha/crates/thing"),
        Outcome::Resolved {
            path: "local/max/git/alpha".to_string(),
            exact: false,
        }
    );
}

/// THE BARE RESERVED SEGMENT IS AN ANCESTOR OF NOTHING, even with a row on it.
///
/// `project-db/src/read.rs` drops it from the chain, so a private path never
/// soft-lands at `local` — which would make one partition key the nearest
/// registered ancestor of every private path in the estate.
#[test]
fn a_row_at_the_reserved_segment_catches_nothing() {
    let squatted = registered(&["local"]);
    assert_eq!(
        outcome(&squatted, "local/max/git/beta"),
        Outcome::Refused(Refusal::bare(Reason::UnregisteredPersonal))
    );
    // And the claim that IS the bare segment resolves to nothing either. It is
    // well formed, so it is not a grammar failure; it has no registered ancestor
    // once the segment is dropped, and it is not in the private class — `local`
    // has no `/` to split on — so it takes the class with no remediation.
    assert_eq!(
        outcome(&squatted, "local"),
        Outcome::Refused(Refusal::bare(Reason::Unresolvable))
    );
}

/// ASCII CASE IS FOLDED, on both sides, exactly as the store's collation folds
/// it.
///
/// A byte comparison answers `exact: false` about a row the store matched
/// exactly — and the caller of that answer is told to register an id
/// `RegisterProject` refuses as `ALREADY_EXISTS`, for ever.
#[test]
fn the_walk_folds_ascii_case_in_both_directions() {
    assert_eq!(
        outcome(&estate(), "YadgarHQ/Docs"),
        Outcome::Resolved {
            path: "yadgarhq/docs".to_string(),
            exact: true,
        }
    );
    // THE ROW'S SPELLING, NOT THE CALLER'S. The store's resolver answers the
    // ROW's `path`, and the resolved path is what a later release stamps on the
    // record — so answering the caller's spelling would mint a second spelling
    // of one partition key.
    assert_eq!(
        outcome(&registered(&["Acme/Forecast"]), "acme/forecast/api"),
        Outcome::Resolved {
            path: "Acme/Forecast".to_string(),
            exact: false,
        }
    );
}

/// The grammar, and it is checked BEFORE any resolution.
///
/// The last row is the one the ordering exists for: a malformed value beginning
/// `local/` would otherwise be handed the CREATE remediation for garbage.
#[test]
fn a_value_that_is_not_a_project_path_is_refused_before_resolution() {
    let estate = estate();
    for claimed in [
        "",
        "/yadgarhq/docs",
        "yadgarhq/docs/",
        "yadgarhq//docs",
        "yadgarhq/../docs",
        "yadgarhq/.",
        "debugging opsecrets nixos-quinyx",
        "yadgarhq/docs plans",
        "local/max/../alpha",
    ] {
        assert_eq!(
            outcome(&estate, claimed),
            Outcome::Refused(Refusal::bare(Reason::Invalid)),
            "expected a grammar refusal"
        );
    }
    // The width of `project.path`: one character over is refused, and the limit
    // itself is not.
    let at_limit = format!("yadgarhq/{}", "a".repeat(255 - 9));
    let over = format!("yadgarhq/{}", "a".repeat(255 - 8));
    assert_eq!(at_limit.len(), 255);
    assert_eq!(over.len(), 256);
    assert!(is_well_formed(&at_limit));
    assert!(!is_well_formed(&over));
}

// ---------------------------------------------------------------------------
// The counters, and the property that nothing is refused.
// ---------------------------------------------------------------------------

/// Run one `check` under a local recorder and return the snapshot beside its
/// answer.
///
/// A local recorder rather than `metrics::set_global_recorder`, and a plain
/// `#[test]` driving a current-thread runtime: `with_local_recorder` is
/// THREAD-LOCAL and this binary runs its tests in parallel, so a global one
/// would race every other emitter.
fn checked(registry: Registry, mode: Mode, claimed: &str) -> (Result<(), Denied>, Snapshotter) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let answer = metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            Validator::new(registry, mode, dead_channel())
                .check(claimed)
                .await
        })
    });
    (answer, snapshotter)
}

/// What one named series holding one named label was incremented to.
///
/// `None` means the series was never registered at all, which is a different
/// observation from zero and is asserted as such by every caller.
fn counted(snapshotter: Snapshotter, name: &str, label: (&str, &str)) -> Option<u64> {
    let emitted = snapshotter.snapshot().into_vec();
    // LENGTH FIRST, for the reason `http::tests` gives: a `metrics-util`
    // resolving against another `metrics` major links a SECOND facade, and then
    // this snapshot is empty and every assertion built on it passes vacuously —
    // most dangerously the `== 0` ones.
    assert!(
        !emitted.is_empty(),
        "the recorder saw no metric at all, which is what a second metrics facade in the tree \
         looks like"
    );
    emitted
        .iter()
        .filter(|(key, _, _, _)| {
            key.key().name() == name
                && key
                    .key()
                    .labels()
                    .any(|l| l.key() == label.0 && l.value() == label.1)
        })
        .map(|(_, _, _, value)| match value {
            DebugValue::Counter(n) => *n,
            other => panic!("{name} is a counter, got {other:?}"),
        })
        .reduce(|a, b| a + b)
}

/// **THE PROPERTY THIS WHOLE RELEASE EXISTS FOR.** A call whose project would be
/// refused under enforcement is SERVED, and the counter says it would have been
/// refused.
///
/// The registry holds one row today (ledger 829), so a gateway that refused here
/// would refuse essentially every call in the estate. Asserting only the counter
/// would not catch that: the counter increments in BOTH modes, so the load-bearing
/// half of this test is `is_ok()`.
///
/// MUTATION THIS CATCHES: ship `Mode::Enforcing` — or read the knob's absence as
/// enforcing — and this test reds on the `is_ok` assertion.
#[test]
fn a_call_whose_project_would_be_refused_is_still_served_and_counted() {
    let (answer, snapshotter) = checked(estate(), Mode::Counting, "yadgarhq/gateway");
    assert!(
        answer.is_ok(),
        "counting mode must refuse nobody: {:?}",
        answer.err()
    );
    assert_eq!(
        counted(
            snapshotter,
            "yadgar_gateway_project_refusal_total",
            ("reason", "PROJECT_UNREGISTERED_ORG")
        ),
        Some(1),
        "the would-be refusal must be counted even though the call was served"
    );
}

/// The same claim, enforced: now it is answered.
///
/// This is the OTHER half of the mode being a real control. Without it, counting
/// mode could be implemented by never classifying anything at all.
#[test]
fn the_same_claim_is_refused_under_enforcement() {
    let (answer, snapshotter) = checked(estate(), Mode::Enforcing, "yadgarhq/gateway");
    let denied = answer.expect_err("enforcing mode refuses");
    assert_eq!(denied.reason.token(), "PROJECT_UNREGISTERED_ORG");
    assert_eq!(
        counted(
            snapshotter,
            "yadgar_gateway_project_refusal_total",
            ("reason", "PROJECT_UNREGISTERED_ORG")
        ),
        Some(1),
        "the flip changes what the caller is told and nothing about what is measured"
    );
}

/// A legitimate call moves the RESOLUTION counter and leaves the refusal counter
/// untouched.
///
/// That pair is the stage-5 gate: refusals zero over the window, resolutions
/// nonzero over the same window. Without the second series a gateway serving no
/// traffic reads identically to one whose canonicalisation is perfect.
///
/// MUTATION THIS CATCHES: delete the resolution counter and this test reds on
/// `None`.
#[test]
fn a_resolution_is_counted_by_whether_it_was_exact() {
    let (answer, snapshotter) = checked(estate(), Mode::Counting, "yadgarhq/docs");
    assert!(answer.is_ok());
    let snapshot = snapshotter.snapshot().into_vec();
    assert!(!snapshot.is_empty(), "the recorder saw no metric at all");
    let series: BTreeSet<(String, String)> = snapshot
        .iter()
        .flat_map(|(key, _, _, _)| {
            key.key()
                .labels()
                .map(|l| (key.key().name().to_string(), l.value().to_string()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        series.contains(&(
            "yadgar_gateway_project_resolution_total".to_string(),
            "exact".to_string()
        )),
        "an exact resolution must be counted as exact: {series:?}"
    );
    assert!(
        !series
            .iter()
            .any(|(name, _)| name == "yadgar_gateway_project_refusal_total"),
        "a legitimate call must not touch the refusal counter: {series:?}"
    );

    let (answer, snapshotter) = checked(estate(), Mode::Counting, "yadgarhq/docs/plans");
    assert!(answer.is_ok());
    assert_eq!(
        counted(
            snapshotter,
            "yadgar_gateway_project_resolution_total",
            ("outcome", "ancestor")
        ),
        Some(1),
        "a soft landing is a resolution and is labelled as an ancestor one"
    );
}

/// Each of the four refusal classes moves its OWN label.
///
/// One deliberate probe per class is the first leg of the stage-4 gate, and a
/// gate whose counter cannot move measures nothing.
#[test]
fn every_refusal_class_increments_its_own_reason() {
    for (claimed, reason) in [
        ("not a path", "PROJECT_INVALID"),
        ("yadgarhq/gateway", "PROJECT_UNREGISTERED_ORG"),
        ("local/max/git/beta", "PROJECT_UNREGISTERED_PERSONAL"),
        ("acme/forecast", "PROJECT_UNRESOLVABLE"),
    ] {
        let (answer, snapshotter) = checked(estate(), Mode::Counting, claimed);
        assert!(answer.is_ok(), "counting mode refuses nobody");
        assert_eq!(
            counted(
                snapshotter,
                "yadgar_gateway_project_refusal_total",
                ("reason", reason)
            ),
            Some(1),
            "{claimed} must count under {reason}"
        );
    }
}

// ---------------------------------------------------------------------------
// ADR-0674: no registry, and the gauge that says so.
// ---------------------------------------------------------------------------

/// A gateway that has never loaded the registry SERVES, and says so in a reason
/// of its own.
///
/// ADR-0674's window, and the counting half of it: with the registry absent
/// nothing can be checked, and answering would take down every scoped call in
/// the estate — which is the enforcement this release exists not to perform.
#[test]
fn with_no_registry_a_scoped_call_is_served_and_counted_under_its_own_reason() {
    let (answer, snapshotter) = checked(Registry::never_loaded(), Mode::Counting, "yadgarhq/docs");
    assert!(answer.is_ok(), "counting mode refuses nobody");
    assert_eq!(
        counted(
            snapshotter,
            "yadgar_gateway_project_refusal_total",
            ("reason", "PROJECT_REGISTRY_UNAVAILABLE")
        ),
        Some(1),
        "the unloaded registry counts under a reason distinct from every refusal (ADR-0674)"
    );
}

/// Under enforcement the same state is an AVAILABILITY answer, and its reason is
/// distinct from all four refusals.
///
/// An operator must be able to tell "your project is unregistered" from "this
/// gateway has no registry yet"; sharing a token would send somebody to register
/// a project that is registered already.
#[test]
fn the_unloaded_registry_reason_is_distinct_from_every_refusal_reason() {
    let (answer, _) = checked(Registry::never_loaded(), Mode::Enforcing, "yadgarhq/docs");
    let denied = answer.expect_err("enforcing mode answers");
    assert_eq!(denied.reason.token(), "PROJECT_REGISTRY_UNAVAILABLE");
    let refusals: BTreeSet<&str> = [
        Reason::Invalid,
        Reason::UnregisteredOrg,
        Reason::UnregisteredPersonal,
        Reason::Unresolvable,
    ]
    .iter()
    .map(|r| r.token())
    .collect();
    assert!(
        !refusals.contains(denied.reason.token()),
        "the availability reason must not be one of the refusal reasons"
    );
}

/// **THE GAUGE IS PUBLISHED FROM BOOT, NOT FROM THE POLL LOOP** (ledger 601).
///
/// The load runs behind `start`, so this reads the series with no sleep at all:
/// a gauge published only on success — or only on the loop's first tick — is
/// ABSENT for the whole first interval, which is exactly the window an operator
/// is looking at it for. Absence and zero are the same observation otherwise, so
/// this asserts the value is PRESENT and is `0`.
///
/// MUTATION THIS CATCHES: delete the `gauge!(LOADED).set(0.0)` line in
/// `Registry::start` and this test reds naming a missing series.
#[test]
fn the_never_loaded_gauge_is_published_before_the_first_load_attempt() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    // INSIDE the runtime, because `start` spawns — and inside the recorder,
    // because that is what this test reads.
    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let registry = Registry::start(dead_channel(), Duration::from_secs(3600));
            assert!(
                registry.loaded().is_none(),
                "nothing has loaded yet, and boot was not gated on it"
            );
        });
    });

    let emitted = snapshotter.snapshot().into_vec();
    assert!(!emitted.is_empty(), "the recorder saw no metric at all");
    let value = emitted
        .iter()
        .find(|(key, _, _, _)| key.key().name() == "yadgar_gateway_project_registry_loaded")
        .map(|(_, _, _, value)| match value {
            DebugValue::Gauge(g) => g.into_inner(),
            other => panic!("the registry gauge is a gauge, got {other:?}"),
        });
    assert_eq!(
        value,
        Some(0.0),
        "the gauge must be PRESENT and zero before the first load: absent and zero are the same \
         observation to a scrape"
    );
}

/// A loaded set answers the walk, and the len is what the boot line reports.
#[test]
fn a_loaded_set_drops_the_bare_reserved_segment_it_should_never_have_been_sent() {
    let loaded = Loaded::from_paths(
        ["yadgarhq", "local", "LOCAL", "yadgarhq/docs"]
            .iter()
            .map(|p| (*p).to_string()),
    );
    assert_eq!(loaded.len(), 2, "both spellings of the reserved root go");
    assert!(!loaded.is_empty());
    assert_eq!(
        loaded.registered_as("YADGARHQ").as_deref(),
        Some("yadgarhq"),
        "the walk answers the spelling the tier registered, folding the candidate's case"
    );
    assert_eq!(loaded.registered_as("local"), None);
}

// ---------------------------------------------------------------------------
// The knobs. ADR-0569: one source, no compiled-in default.
// ---------------------------------------------------------------------------

#[test]
fn the_mode_has_no_compiled_in_default() {
    assert!(matches!(
        Mode::from_lookup(|_| None),
        Err(ModeError::Absent)
    ));
    assert_eq!(
        Mode::from_lookup(|_| Some("counting".to_string())).expect("counting parses"),
        Mode::Counting
    );
    assert_eq!(
        Mode::from_lookup(|_| Some(" enforcing ".to_string())).expect("enforcing parses"),
        Mode::Enforcing
    );
    // A MISSPELLING IS REFUSED RATHER THAN READ AS THE SAFER VALUE: a deployment
    // that meant to enforce and typed `enforce` would otherwise enforce nothing,
    // silently, for ever.
    assert!(matches!(
        Mode::from_lookup(|_| Some("enforce".to_string())),
        Err(ModeError::Unknown(v)) if v == "enforce"
    ));
}

#[test]
fn the_load_cadence_has_no_compiled_in_default() {
    assert!(matches!(
        poll_from_lookup(|_| None),
        Err(RetryError::Absent)
    ));
    assert!(matches!(
        poll_from_lookup(|_| Some("  ".to_string())),
        Err(RetryError::Empty)
    ));
    assert!(matches!(
        poll_from_lookup(|_| Some("often".to_string())),
        Err(RetryError::Unparsable { .. })
    ));
    assert!(matches!(
        poll_from_lookup(|_| Some("0".to_string())),
        Err(RetryError::Zero)
    ));
    assert_eq!(
        poll_from_lookup(|_| Some("60".to_string())).expect("a cadence parses"),
        Duration::from_secs(60)
    );
}

// ---------------------------------------------------------------------------
// The prose, and the fallback that composes half of it.
// ---------------------------------------------------------------------------

/// The org remediation names the repository WHEN THE DATA IS THERE, and says it
/// could not be named when it is not.
///
/// **THIS ASSERTS THE PURE FUNCTION AND NOTHING ABOUT THE WIRE.** It stays green
/// for a [`remediate::compose`] that passes `None` for the source repository for
/// ever, which is what it did before `PROTO_VERSION` v1.15.0 carried the field —
/// so the two tests below drive `compose` against a SERVED `ProjectService`
/// instead. This one is kept for what it does cover: the branch selection itself,
/// with no transport in the way.
#[test]
fn the_org_remediation_is_composed_from_data_and_degrades_without_it() {
    let composed = remediate::sentence(
        Reason::UnregisteredOrg,
        Some("yadgarhq"),
        Some("yadgarhq/estate"),
    );
    assert!(
        composed.contains("yadgarhq/estate"),
        "the remediation names the repository whose PR flow governs the namespace: {composed}"
    );

    let degraded = remediate::sentence(Reason::UnregisteredOrg, Some("yadgarhq"), None);
    assert!(
        degraded.contains("yadgarhq") && degraded.contains("could not be reached"),
        "without the datum the refusal stands and only the prose degrades: {degraded}"
    );
}

/// THE GRAMMAR REFUSAL NEVER REPEATS THE VALUE.
///
/// `project-db`'s `validate` applies the same rule, on the ground that a refusal
/// interpolating an unbounded caller string lets the caller decide how large this
/// service's log lines are — and a value that failed the grammar may hold
/// anything at all.
#[test]
fn the_grammar_refusal_does_not_echo_the_callers_value() {
    let claimed = "sentinel value/that must not be echoed";
    let (answer, _) = checked(estate(), Mode::Enforcing, claimed);
    let denied = answer.expect_err("a malformed path is refused under enforcement");
    assert_eq!(denied.reason.token(), "PROJECT_INVALID");
    assert!(
        !denied.prose.contains("sentinel"),
        "the prose must not repeat the claim: {}",
        denied.prose
    );
    assert!(
        !denied.to_string().contains("sentinel"),
        "nor may the Display form, which is what reaches the log: {denied}"
    );
}

/// **A DEAD FALLBACK MUST NOT TURN A 400 INTO A 500.**
///
/// The classification came from the loaded set, not from the call, so a refusal
/// stands whether or not `project` answers. Answering with an availability
/// failure instead would hide a correctness one, and the caller would retry for
/// ever against a condition retrying cannot fix.
///
/// The channel here points at a closed port, so the dial really fails rather
/// than being stubbed.
#[test]
fn a_refusal_stands_when_the_fallback_rpc_cannot_be_reached() {
    let (answer, _) = checked(estate(), Mode::Enforcing, "yadgarhq/gateway");
    let denied = answer.expect_err("the refusal stands");
    assert_eq!(
        denied.reason.token(),
        "PROJECT_UNREGISTERED_ORG",
        "the reason is the one the loaded set decided, not an availability failure"
    );
    assert!(
        denied.prose.contains("could not be reached"),
        "the prose degrades and says so: {}",
        denied.prose
    );
}

// ---------------------------------------------------------------------------
// The same prose, composed OVER THE WIRE.
//
// **WHY A SERVED STUB AND NOT THE PURE FUNCTION.** Every assertion above this
// line either hands `remediate::sentence` its arguments or points the fallback at
// a closed port, so all of them stay green for a `compose` that passes `None` for
// the source repository for ever — which is exactly what it did before
// `PROTO_VERSION` v1.15.0 carried the field. A test that cannot red for the
// mutation "stop reading the answer" is not measuring the wire.
//
// **THE PATTERN IS `http::tests`'s AND THE STUB IS NECESSARILY NEW.** `stub_iam`
// there is private to that module and answers `IamService`, so nothing about it
// is shareable; what is reused is its mechanism — `TcpIncoming::bind` on port 0,
// which takes an ephemeral port and KEEPS the listener so there is no window
// between discovering the port and serving on it.
// ---------------------------------------------------------------------------

/// A `ProjectService` answering `ResolveProject` with one canned response.
///
/// `ListProjects` is refused rather than implemented: the registry these tests
/// classify against is built by `Registry::loaded_with`, so a test that reached
/// the boot load would be asserting something this stub was never built to say.
struct StubProject {
    answer: crate::pb::yadgar::project::v1::ProjectServiceResolveProjectResponse,
}

#[tonic::async_trait]
impl crate::pb::yadgar::project::v1::project_service_server::ProjectService for StubProject {
    async fn resolve_project(
        &self,
        _: tonic::Request<crate::pb::yadgar::project::v1::ProjectServiceResolveProjectRequest>,
    ) -> Result<
        tonic::Response<crate::pb::yadgar::project::v1::ProjectServiceResolveProjectResponse>,
        tonic::Status,
    > {
        Ok(tonic::Response::new(self.answer.clone()))
    }

    async fn list_projects(
        &self,
        _: tonic::Request<crate::pb::yadgar::project::v1::ProjectServiceListProjectsRequest>,
    ) -> Result<
        tonic::Response<crate::pb::yadgar::project::v1::ProjectServiceListProjectsResponse>,
        tonic::Status,
    > {
        Err(tonic::Status::unimplemented(
            "this stub answers ResolveProject and nothing else",
        ))
    }
}

/// Serve one `ResolveProject` answer, and return a channel pointed at it.
async fn stub_project(
    answer: crate::pb::yadgar::project::v1::ProjectServiceResolveProjectResponse,
) -> tonic::transport::Channel {
    let incoming = tonic::transport::server::TcpIncoming::bind(
        "127.0.0.1:0".parse().expect("a loopback address"),
    )
    .expect("the stub binds");
    let addr = incoming.local_addr().expect("a bound port");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                crate::pb::yadgar::project::v1::project_service_server::ProjectServiceServer::new(
                    StubProject { answer },
                ),
            )
            .serve_with_incoming(incoming)
            .await
    });
    tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy()
}

/// One `ResolveProject` answer for the anchor these tests refuse beneath.
///
/// **THE LITERAL IS EXHAUSTIVE ON PURPOSE.** A `..Default::default()` here would
/// absorb the next field the contract grows, silently, in the one fixture whose
/// job is to say what the resolver answered.
fn answered(
    resolved_path: &str,
    source_repo: &str,
) -> crate::pb::yadgar::project::v1::ProjectServiceResolveProjectResponse {
    crate::pb::yadgar::project::v1::ProjectServiceResolveProjectResponse {
        resolved_path: resolved_path.to_string(),
        exact: true,
        via_alias: false,
        status: crate::pb::yadgar::project::v1::ProjectStatus::Active as i32,
        source_repo: source_repo.to_string(),
    }
}

/// THE REMEDIATION NAMES THE REPOSITORY THE SERVED ANSWER CARRIED.
///
/// The mutation this exists to red is "pass `None` for the third argument of
/// `sentence`" — the shape `compose` had while the contract had no field. Every
/// other assertion in this file survives it.
#[tokio::test]
async fn the_served_source_repo_reaches_the_composed_remediation() {
    let project = stub_project(answered("yadgarhq", "yadgarhq/estate")).await;
    let denied = remediate::compose(&project, Refusal::under_anchor("yadgarhq")).await;

    assert_eq!(
        denied.reason.token(),
        "PROJECT_UNREGISTERED_ORG",
        "the reason is the one the loaded set decided"
    );
    assert!(
        denied.prose.contains("yadgarhq/estate"),
        "the repository the resolver named must reach the prose: {}",
        denied.prose
    );
    assert!(
        denied.prose.contains("open a pull request against"),
        "and it is the COMPOSED branch that names it, not a coincidental substring: {}",
        denied.prose
    );
}

/// AN EMPTY `source_repo` IS ABSENT, AND THE PROSE DEGRADES RATHER THAN
/// INTERPOLATING NOTHING.
///
/// **THE DEFECT THIS EXISTS TO RED IS A ONE-LINE NAIVE FIX.** `source_repo` is a
/// bare proto3 `string` with no presence bit, so `Some(&answer.source_repo)` takes
/// the COMPOSED branch for a row that has no repository and emits "open a pull
/// request against , which governs this namespace". Both assertions below red for
/// that output: the first because the composed branch never says "could not be
/// reached", the second because the empty interpolation is inside the composed
/// branch's own literal.
///
/// The registry serves this legitimately — `ck_project_class` gives a
/// private-class row `owner_user_id` and never `source_repo` — so this is a
/// normal answer and not a malformed one.
#[tokio::test]
async fn an_empty_served_source_repo_degrades_instead_of_interpolating_nothing() {
    let project = stub_project(answered("yadgarhq", "")).await;
    let denied = remediate::compose(&project, Refusal::under_anchor("yadgarhq")).await;

    assert!(
        denied
            .prose
            .contains("the registry could not be reached to name the repository"),
        "an empty source_repo is the ABSENT case, so the degraded sentence is composed: {}",
        denied.prose
    );
    assert!(
        !denied.prose.contains("which governs this namespace"),
        "the composed branch must not be reached with nothing to interpolate: {}",
        denied.prose
    );
    assert!(
        denied.prose.contains("yadgarhq"),
        "the namespace is still named, so the caller knows who to ask: {}",
        denied.prose
    );
}

/// AN EMPTY `resolved_path` IS ABSENT TOO, and the anchor this gateway walked to
/// is what the sentence names.
///
/// The field one along from the one this change is about, and a bare proto3
/// `string` for the same reason. Without the same reading, `Some("")` reaches
/// `sentence` as the namespace and composes "The namespace  is registered" — the
/// identical empty interpolation, in the branch meant to be the safe one.
#[tokio::test]
async fn an_empty_served_resolved_path_falls_back_to_the_walked_anchor() {
    let project = stub_project(answered("", "")).await;
    let denied = remediate::compose(&project, Refusal::under_anchor("yadgarhq")).await;

    assert!(
        denied
            .prose
            .contains("The namespace yadgarhq is registered"),
        "an empty resolved_path falls back to the anchor rather than being interpolated: {}",
        denied.prose
    );
}
