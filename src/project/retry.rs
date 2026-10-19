//! When to ask `project` again: fast until the registry has loaded once, then
//! at the poll for good (ledger 1668).
//!
//! **WHY THE FIRST LOAD GETS ITS OWN SCHEDULE.** Measured on a cold install
//! (chart v0.26.1, gateway v0.12.14): every replica's first `ListProjects` ran
//! before the seeder Job and before `project` was ready, timed out at the 5 s
//! page deadline, and the replica then waited the WHOLE poll — 60 s — before
//! asking again. Under Enforcing every claim in that window is refused with
//! `PROJECT_REGISTRY_UNAVAILABLE`, for a minute that has nothing to do with
//! how often a loaded set needs refreshing. The poll answers "how stale may a
//! loaded set get"; a replica holding NO set is answering a different question,
//! and ADR-0674 already makes that state the one that matters.
//!
//! **THE SCHEDULE IS DERIVED FROM THE POLL, AND ADDS NO KNOB.** It starts at
//! [`FIRST_RETRY`], doubles on each failure, and is capped at the poll, so the
//! deployment's own `YADGAR_PROJECT_REGISTRY_POLL_SECONDS` stays the most this
//! gateway ever waits and the most often it asks once the backoff has capped.
//! With a 60 s poll that is 1, 2, 4, 8, 16, 32, then 60 for good — six asks in
//! the first minute instead of one, and the steady-state load on an unreachable
//! `project` unchanged.
//!
//! **WHAT THAT BUYS, MEASURED FROM THE END OF EACH LOAD.** The wait starts when
//! a load ends, so a load that times out adds its own 5 s: asks land at about
//! 0, 6, 13, 22, 35 and 56 s against a `project` that stalls, and at 0, 1, 3, 7,
//! 15, 31 and 63 s against one that refuses fast. A replica therefore loads at
//! most ONE backoff step plus one load after `project` becomes ready — about
//! 32 s plus load time at worst with a 60 s poll, against up to 60 s before.
//!
//! **AFTER THE FIRST SUCCESS, NEVER AGAIN.** A failed refresh leaves the
//! previous set in force (ADR-0674) and the gateway is not degraded, so it
//! retries at the poll exactly as before. The fast schedule applies only while
//! [`Registry::loaded`] is `None`.
//!
//! **READINESS IS DELIBERATELY UNCHANGED.** ADR-0674 considered gating readiness
//! on the first load and rejected it ("it rebuilds the cascade by another
//! route, withholding endpoints that work"), and the readiness probe is a
//! `tcpSocket` for the reasons `main.rs` gives. This module shortens the
//! never-loaded window; it does not hide it.

use std::future::Future;
use std::time::Duration;

use crate::pb::yadgar::project::v1::RegisteredPath;

use super::registry::{install, report, Registry};

/// The first retry after a failed FIRST load, before doubling.
///
/// A bound rather than a knob: it is always capped at the deployment's own
/// poll, so it can only make a never-loaded replica ask SOONER than the
/// deployment already allows, never later or more often in steady state.
const FIRST_RETRY: Duration = Duration::from_secs(1); // ADR-0569-EXCEPTION(CC): a floor capped at the configured poll, not a tuning knob.

/// How long to wait before the next load.
///
/// `failures` is how many loads in a row have failed while the registry has
/// never loaded. Once a set is held the answer is always the poll.
pub(super) fn next_delay(never_loaded: bool, failures: u32, poll: Duration) -> Duration {
    if !never_loaded {
        return poll;
    }
    // 2^failures, saturating: past 2^31 seconds the cap has long since applied,
    // and a counter that wrapped into a short delay would become a busy loop.
    let factor = 1u32.checked_shl(failures).unwrap_or(u32::MAX);
    FIRST_RETRY.saturating_mul(factor).min(poll)
}

/// Load, then keep loading: on the fast schedule while nothing has loaded,
/// and at the poll after that.
///
/// Generic over the loader so the schedule is tested against a scripted one
/// under paused time, rather than against a live `project`.
pub(super) async fn drive<L, F>(mut load: L, poll: Duration, registry: Registry)
where
    L: FnMut() -> F,
    F: Future<Output = Result<Vec<RegisteredPath>, tonic::Status>>,
{
    let mut failures: u32 = 0;
    loop {
        let delay = match load().await {
            Ok(rows) => {
                install(&registry, rows);
                poll
            }
            Err(e) => {
                let delay = next_delay(registry.loaded().is_none(), failures, poll);
                failures = failures.saturating_add(1);
                report(&registry, &e, delay);
                delay
            }
        };
        tokio::time::sleep(delay).await;
    }
}
