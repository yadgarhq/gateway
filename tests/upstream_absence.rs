//! Every upstream this gateway dials publishes the absence gauge — `iam`
//! included.
//!
//! **THE SILENCE THIS CLOSES.** ADR-0532 made both dials lazy, so a gateway
//! whose upstream does not exist is `1/1 Running`, Argo-`Healthy`, and wrong.
//! `deploy`'s `DialUpstreamNeverResolved` rule exists to say so, and it reads
//! `yadgar_dial_upstream_never_resolved` — a gauge emitted from INSIDE
//! `yadgar_dial`. A hop that does not go through that crate emits nothing, and
//! `connect_iam` was that hop: measured against the live store on 2026-09-05,
//! six series existed with `upstream` values `task`, `task-db` and `iam-db`,
//! and no `iam`. The one hop carrying every login, enrolment and `tools/call`
//! attestation was the one hop the alert could not cover.
//!
//! **THE NAME AND THE LABEL ARE STRING LITERALS HERE, deliberately, and
//! `yadgar_dial::UPSTREAM_NEVER_RESOLVED` is NOT used.** Asserting a key
//! against the constant that produced it is self-referential: it passes
//! straight through a rename at the next pin move, and a renamed metric is the
//! one change where every consumer still compiles while the dashboard and the
//! alert both blank. The literals below are what `deploy`'s rule actually
//! queries, so a rename lands here as a failure rather than as silence.
//!
//! **A SEPARATE TEST BINARY**, because a global recorder can be installed once
//! per process and `tests/telemetry.rs` already installs one.

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use tonic::transport::Channel;
use yadgar_gateway::upstream;

/// What `deploy`'s alert rule queries, spelled out rather than imported.
const GAUGE: &str = "yadgar_dial_upstream_never_resolved";

/// The one label that gauge carries.
const LABEL: &str = "upstream";

/// Hosts under `.invalid`, reserved by RFC 6761: no resolver answers them and
/// no wildcard in a search domain can make one. Two DISTINCT sentinels, so a
/// series can be attributed to the call that produced it rather than to
/// whichever call ran first.
const ABSENT_IAM: &str = "gateway-absent-iam-4b7e21.invalid";
const ABSENT_TASK: &str = "gateway-absent-task-4b7e21.invalid";

/// The one name that resolves without touching `/etc/hosts`. Nothing listens on
/// the port; the gauge reports RESOLUTION, not reachability, so no server is
/// needed.
const PRESENT_IAM: &str = "localhost";

/// Read every `GAUGE` series out of ONE snapshot, and report how large that
/// snapshot was.
///
/// `Snapshotter::snapshot` DRAINS the registry, so it is called exactly once
/// and the result is read many times. A second call would return nothing and
/// every assertion built on it would pass vacuously.
fn gauges(snapshotter: &Snapshotter) -> (usize, Vec<(String, f64)>) {
    let snapshot = snapshotter.snapshot().into_vec();
    let total = snapshot.len();
    let series = snapshot
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let key = key.key();
            if key.name() != GAUGE {
                return None;
            }
            let upstream = key.labels().find(|l| l.key() == LABEL)?;
            match value {
                DebugValue::Gauge(v) => Some((upstream.value().to_string(), v.into_inner())),
                _ => None,
            }
        })
        .collect();
    (total, series)
}

/// THE CASE THE WHOLE CHANGE IS FOR.
///
/// **`connect_task` IS THE CONTROL, and it is what makes the failure
/// attributable.** A test that dialled `iam` alone would go red with an EMPTY
/// snapshot if the facade were unlinked — a `metrics-util` resolving against a
/// different `metrics` major links a second registry, and every assertion built
/// on an empty snapshot passes for free in the other direction. The task hop
/// has published this gauge since `dial` v0.2.1, so its series being present
/// proves the recorder is installed, the facade is the one `dial` writes
/// through, and the snapshot is non-empty — which is exactly what the red run
/// must show while the `iam` assertion fails.
///
/// **AND `PRESENT_IAM` IS THE VALUE CONTROL.** Without it, `1.0` could be the
/// only number this gauge ever holds and the assertion would say nothing about
/// what it means. A name that resolves must report `0.0` on the SAME code path,
/// so the gauge is shown to discriminate rather than merely to exist.
///
/// **EVERY CHANNEL IS HELD PAST THE SNAPSHOT.** `dial`'s refresh loop forces
/// the gauge to `0` when it exits, and it exits when the channel is dropped —
/// so a channel dropped early would rewrite the value this test reads, and the
/// `1.0` assertions would fail for a reason that has nothing to do with
/// absence.
///
/// **IT ALSO PROVES THE WRITE IS AT BOOT rather than on a tick.** Nothing here
/// sleeps: the snapshot is taken the moment the three dials return, and
/// `RERESOLVE` is five seconds away. An implementation that published only from
/// the refresh loop would find every series missing.
#[tokio::test]
async fn every_upstream_publishes_the_absence_gauge() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("install the test recorder");

    let absent_task: Channel = upstream::connect_task(ABSENT_TASK, 50051, None)
        .await
        .expect("an absent task must not fail the dial (ADR-0532)");
    let absent_iam: Channel = upstream::connect_iam(ABSENT_IAM, 50052, None)
        .await
        .expect("an absent iam must not fail the dial");
    let present_iam: Channel = upstream::connect_iam(PRESENT_IAM, 50052, None)
        .await
        .expect("localhost resolves");

    let (total, series) = gauges(&snapshotter);
    assert!(
        total > 0,
        "the snapshot is empty, so nothing below could fail for the right reason: the recorder \
         is not installed, or `metrics-util` resolved against a different `metrics` facade"
    );

    let value = |host: &str| {
        series
            .iter()
            .find(|(upstream, _)| upstream == host)
            .map(|(_, v)| *v)
    };

    assert_eq!(
        value(ABSENT_TASK),
        Some(1.0),
        "the control: the task hop has published {GAUGE} since dial v0.2.1. Snapshot held {total} \
         series; {GAUGE} series were {series:?}"
    );
    assert_eq!(
        value(ABSENT_IAM),
        Some(1.0),
        "the iam hop carries every login, enrolment and attestation, and DialUpstreamNeverResolved \
         cannot fire for an upstream that publishes no series. Snapshot held {total} series; \
         {GAUGE} series were {series:?}"
    );
    assert_eq!(
        value(PRESENT_IAM),
        Some(0.0),
        "a name that RESOLVES must report 0, or `1` is just the only value this gauge ever holds \
         and the assertions above mean nothing. {GAUGE} series were {series:?}"
    );

    // HELD UNTIL HERE, not a moment earlier. See the doc comment: dropping a
    // channel ends its refresh loop, and the loop writes 0 on the way out.
    drop((absent_task, absent_iam, present_iam));
}
