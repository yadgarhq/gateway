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

use std::sync::{Arc, Mutex};
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

/// Run [`drive`] against a scripted loader and return the instant of each call,
/// relative to the first.
async fn call_times(script: Vec<bool>, registry: Registry) -> Vec<u64> {
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
