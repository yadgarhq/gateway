//! The first load retries sooner than the poll (ledger 1668).
//!
//! Measured on a cold install: every replica's FIRST `ListProjects` timed out
//! before the seeder had run and before `project` was ready, and the replica
//! then waited the whole 60 s poll before asking again. Under Enforcing every
//! claim in that window is refused. These tests hold the schedule that closes
//! most of that window, and the steady-state cadence it must leave alone.
//!
//! **EXPECTED DELAYS ARE LITERALS** (ADR-0599, [`super`]'s rule): a schedule
//! asserted through the function under test agrees with itself.

use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use tokio::time::Instant;

use super::super::retry::{drive, next_delay};
use super::*;

const POLL: Duration = Duration::from_secs(60);

#[test]
fn a_never_loaded_registry_retries_on_a_doubling_schedule_capped_at_the_poll() {
    let delays: Vec<u64> = (0..9)
        .map(|failures| next_delay(true, failures, POLL).as_secs())
        .collect();
    assert_eq!(delays, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
}

#[test]
fn the_first_retry_is_sooner_than_the_poll_interval() {
    assert!(next_delay(true, 0, POLL) < POLL);
}

#[test]
fn the_schedule_never_exceeds_a_short_poll() {
    let short = Duration::from_secs(3);
    let delays: Vec<u64> = (0..4)
        .map(|failures| next_delay(true, failures, short).as_secs())
        .collect();
    assert_eq!(delays, vec![1, 2, 3, 3]);
    assert_eq!(
        next_delay(true, 0, Duration::from_millis(500)),
        Duration::from_millis(500)
    );
}

#[test]
fn a_huge_failure_count_saturates_at_the_poll_rather_than_overflowing() {
    assert_eq!(next_delay(true, u32::MAX, POLL), POLL);
}

#[test]
fn once_loaded_every_retry_waits_the_whole_poll() {
    for failures in [0, 1, 5, u32::MAX] {
        assert_eq!(next_delay(false, failures, POLL), POLL);
    }
}

/// Make the log callsites of `report` safe to share between parallel tests.
///
/// **ROOT CAUSE OF LEDGER 1752.** `tracing` decides once per callsite whether
/// anybody listens. While NO dispatcher exists, a callsite is judged from the
/// registering thread's own (empty) default and cached. Registering the first
/// dispatcher rebuilds that cache, but a callsite that a parallel test is
/// registering at that instant is missed by the rebuild and stays "never".
/// The only `set_default` in this test binary is in
/// `the_logged_retry_secs_is_the_real_delay_before_the_next_load`, so it was
/// the first dispatcher, it raced the sibling tests that also reach `report`,
/// and the `("WARN", 60)` event was dropped about a third of the time.
///
/// A process-wide dispatcher installed ONCE, before any test thread registers
/// those callsites, removes the race: every callsite is then judged against a
/// dispatcher that listens, and the per-test `set_default` only chooses where
/// the events go. Every test that reaches `report` calls this first.
fn listen_for_logs() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let sink = tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::set_global_default(sink).expect("no other global subscriber");
    });
}

/// Run [`drive`] against a scripted loader and return the instant of each call,
/// relative to the first.
async fn call_times(script: Vec<bool>, registry: Registry) -> Vec<u64> {
    listen_for_logs();
    let calls = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let script = Arc::new(Mutex::new(script.into_iter()));
    let recorded = Arc::clone(&calls);
    let loader = move || {
        let calls = Arc::clone(&recorded);
        let script = Arc::clone(&script);
        async move {
            calls.lock().expect("calls").push(Instant::now());
            let succeed = script.lock().expect("script").next().unwrap_or(false);
            if succeed {
                Ok(vec![row("yadgarhq/docs", ProjectStatus::Active, &[])])
            } else {
                Err(tonic::Status::deadline_exceeded(
                    "ListProjects did not answer",
                ))
            }
        }
    };
    let task = tokio::spawn(drive(loader, POLL, registry));
    // Far enough to cover the scripted calls plus two polls after them.
    tokio::time::sleep(Duration::from_secs(200)).await;
    task.abort();
    let calls = calls.lock().expect("calls");
    let start = calls[0];
    calls.iter().map(|t| (*t - start).as_secs()).collect()
}

#[tokio::test(start_paused = true)]
async fn a_never_loaded_registry_retries_sooner_than_the_poll_then_settles_on_it() {
    let registry = Registry::never_loaded();
    // Fail, fail, fail, succeed — then steady state.
    let times = call_times(vec![false, false, false, true], registry.clone()).await;
    // 0, +1, +2, +4 while never loaded; then +60 each.
    assert_eq!(&times[..6], &[0, 1, 3, 7, 67, 127]);
    assert!(
        registry.loaded().is_some(),
        "the fourth call installed a set"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_refresh_after_a_load_waits_the_whole_poll() {
    let registry = Registry::never_loaded();
    // Succeed first, then every refresh fails: the stale set stays in force and
    // the cadence is the steady one, never the fast first-load schedule.
    let times = call_times(vec![true, false, false, false], registry.clone()).await;
    assert_eq!(&times[..4], &[0, 60, 120, 180]);
    assert!(registry.loaded().is_some(), "the stale set stays in force");
}

#[tokio::test(start_paused = true)]
async fn a_registry_that_never_loads_keeps_retrying_at_the_poll_once_the_backoff_caps() {
    let registry = Registry::never_loaded();
    let times = call_times(vec![], registry.clone()).await;
    // 0 +1 +2 +4 +8 +16 +32 +60 +60 ...
    assert_eq!(&times[..9], &[0, 1, 3, 7, 15, 31, 63, 123, 183]);
    assert!(registry.loaded().is_none());
}

/// A `MakeWriter` that keeps every formatted log line for the test to read.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The `retry_secs` an operator reads is the wait the loop really takes.
///
/// Without this, `report` handed the poll instead of the delay logs
/// `retry_secs=60` while the replica retries after one second, and every other
/// test here stays green.
#[tokio::test(start_paused = true)]
async fn the_logged_retry_secs_is_the_real_delay_before_the_next_load() {
    listen_for_logs();
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(captured.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // Fail, fail (never loaded: 1 s, then 2 s), succeed, then a failed refresh
    // (loaded: the poll).
    let script = Arc::new(Mutex::new(vec![false, false, true, false].into_iter()));
    let loader = move || {
        let script = Arc::clone(&script);
        async move {
            match script.lock().expect("script").next() {
                Some(true) => Ok(vec![row("yadgarhq/docs", ProjectStatus::Active, &[])]),
                _ => Err(tonic::Status::deadline_exceeded(
                    "ListProjects did not answer",
                )),
            }
        }
    };
    // Same task, so the thread-local subscriber sees every event. 70 s covers
    // calls at 0, 1, 3 and 63, and stops before the next one at 123.
    let ran = tokio::time::timeout(
        Duration::from_secs(70),
        drive(loader, POLL, Registry::never_loaded()),
    )
    .await;
    assert!(ran.is_err(), "drive never returns");

    let text = String::from_utf8(captured.0.lock().expect("log buffer").clone()).expect("utf8");
    let logged: Vec<(String, u64)> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|event| {
            let secs = event["fields"]["retry_secs"].as_u64()?;
            Some((event["level"].as_str()?.to_string(), secs))
        })
        .collect();
    assert_eq!(
        logged,
        vec![
            ("ERROR".to_string(), 1),
            ("ERROR".to_string(), 2),
            ("WARN".to_string(), 60),
        ]
    );
}
