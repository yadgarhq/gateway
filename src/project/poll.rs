//! How often the registry is loaded: the one cadence that retries a failed
//! load and refreshes a successful one (ADR-0674).
//!
//! Split out of [`super::registry`] for the file-size ceiling, along the seam
//! that already existed there: this is configuration read once at boot, and
//! that module is the set and the loop that fills it.

use std::time::Duration;

/// The environment variable naming the load cadence, in seconds.
pub const POLL: &str = "YADGAR_PROJECT_REGISTRY_POLL_SECONDS";

/// ONE cadence, serving two jobs, and ADR-0674 names only the first.
///
/// The ADR requires a retry cadence: a gateway whose load failed asks again.
/// The same interval is also what REFRESHES a set that loaded successfully, and
/// that second job is not a liberty taken with the ruling — it is forced by two
/// facts. `project` publishes no registry-change event yet
/// (`project.proto`: "Only the first of the three is in this release"), so a
/// load is the only way a newly registered project becomes resolvable. And the
/// refusal counter is what GATES the enforcement flip, so a counter computed
/// against the registry as it was at boot would go on counting every repository
/// seeded since — making the gate unreadable until somebody restarted every
/// pod, for a reason nothing would explain.
///
/// **A CEILING, NOT THE ONLY INTERVAL (ledger 1668).** While the registry has
/// NEVER loaded, `super::retry` asks sooner — doubling from one second, capped
/// at this value — because that is the one state in which no claim can be
/// checked. Once a set is held, every load waits exactly this long.
///
/// # Errors
///
/// Absent, empty, not a whole number of seconds, or zero. No compiled-in
/// default (ADR-0569).
/// The same cadence, from this process's environment.
///
/// # Errors
///
/// See [`poll_from_lookup`], which this is.
pub fn poll_from_env() -> Result<Duration, RetryError> {
    poll_from_lookup(|key| std::env::var(key).ok())
}

pub fn poll_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Duration, RetryError> {
    let raw = lookup(POLL).ok_or(RetryError::Absent)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RetryError::Empty);
    }
    let seconds: u64 = trimmed.parse().map_err(|source| RetryError::Unparsable {
        value: trimmed.to_string(),
        source,
    })?;
    if seconds == 0 {
        return Err(RetryError::Zero);
    }
    Ok(Duration::from_secs(seconds))
}

/// A cadence this deployment did not state, or stated unusably.
#[derive(Debug, thiserror::Error)]
pub enum RetryError {
    #[error(
        "{POLL} is not set. It is how often this gateway asks `project` for the registered set — \
         the retry after a failed load and the refresh after a successful one. There is no \
         compiled-in default (ADR-0569): an interval nobody chose decides how long a newly \
         registered project stays unresolvable, and how hard an unreachable `project` is \
         hammered."
    )]
    Absent,

    #[error("{POLL} is set and has no value. That is different from being absent and is reported separately.")]
    Empty,

    #[error("{POLL} is {value:?}, which is not a whole number of seconds.")]
    Unparsable {
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "{POLL} is 0. A load every zero seconds is a busy loop against `project`, so it is \
         refused rather than read as \"never\" or \"as fast as possible\"."
    )]
    Zero,
}
