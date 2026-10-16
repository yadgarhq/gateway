//! [`Limiter::warm`]: the background connect `main` spawns at boot, and the
//! retry that keeps it going until the cache answers (ledger 1430, ledger 1438).
//!
//! Its own file for the file-size ceiling, and a CHILD of [`super`] rather
//! than a sibling so it reaches the private `conn`, `client` and `connected`
//! fields without widening them for anything else.

use std::sync::atomic::Ordering;
use std::time::Duration;

use super::super::script::classify;
use super::super::Degrade;
use super::Limiter;

/// How long `warm` waits before dialling again after the cache did not answer.
///
/// **THE BROKER CLIENTS' NUMBER, ON PURPOSE.** ADR-0893 fixes five seconds for
/// an outage redial, and `crate::invalidate`'s own `RETRY` is the model this
/// copies (ledger 1152 names it). Short, because the window it closes is one
/// where every request on this replica pays a failed connect on the hot path;
/// one attempt costs one TCP connection.
const RETRY: Duration = Duration::from_secs(5); // ADR-0569-EXCEPTION(CC): ADR-0893's outage redial interval, copied from crate::invalidate, not a tuning knob.

/// How long `warm` waits before dialling again after the cache REJECTED the
/// credential it was sent (`WRONGPASS`; a missing one is not seen here — see
/// [`Limiter::warm`]).
///
/// **Far longer than [`RETRY`], because a refusal is not an outage** (ADR-0893).
/// A wrong `requirepass` ends when somebody fixes a Secret, so retrying it at
/// the outage rate only writes an error line every five seconds and spends an
/// AUTH attempt on the cache each time. It is still retried, never treated as
/// terminal: a rotated password reaches the cache and this pod at different
/// moments.
const REFUSED_RETRY: Duration = Duration::from_secs(60); // ADR-0569-EXCEPTION(CC): ADR-0893's refused-credential redial interval, not a tuning knob.

/// The wait after a failed attempt, pulled out as a pure function so the
/// choice is provable without a network. `refused` is whether the cache
/// rejected the credential, as [`classify`] reads it.
fn retry_after(refused: bool) -> Duration {
    if refused {
        REFUSED_RETRY
    } else {
        RETRY
    }
}

/// Say why an attempt failed, in the operator's terms. Its own function so
/// [`Limiter::warm`] stays under the complexity ceiling; the two lines are two
/// DIFFERENT operator instructions — fix a Secret, or find the cache.
fn report_failure(attempt: u64, detail: &str, refused: bool, wait: Duration) {
    if refused {
        // A DEPLOYMENT ERROR, said apart from an outage (ADR-0893).
        tracing::error!(
            attempt,
            error = %detail,
            retry_in_secs = wait.as_secs(),
            "the rate-limit cache REFUSED this gateway's credential; calls are \
             limited by the degraded floor until it is accepted"
        );
    } else {
        tracing::warn!(
            attempt,
            error = %detail,
            retry_in_secs = wait.as_secs(),
            "the rate-limit cache is unreachable; calls are limited by the degraded \
             floor until it answers"
        );
    }
}

impl Limiter {
    /// Connect to the cache in the background, retrying until it answers,
    /// without making boot wait on it (D69/ADR-0555, ledger 1430, ledger 1438).
    ///
    /// **`main` SPAWNS THIS AND NEVER AWAITS IT**, so a gateway whose Valkey is
    /// down, or slow, still binds its listener on schedule. `conn` is still a
    /// [`tokio::sync::OnceCell`], [`Limiter::new`] still does no I/O, and each
    /// attempt is bounded by [`Limiter::connect_config`]'s `connection_timeout`
    /// (`CONNECT_BUDGET`).
    ///
    /// **IT RETRIES UNTIL `conn` IS POPULATED, THEN RETURNS (ledger 1438).**
    /// Before, it made one attempt and gave up, so a Valkey that was absent at
    /// boot was connected only by a request: every call degraded while it
    /// tried a connect inside `rateLimit.timeoutMs`, which in production is
    /// 20 ms and can be too short for a real handshake. Now this task keeps
    /// dialling every [`RETRY`], or every [`REFUSED_RETRY`] after the cache
    /// rejected the credential it was sent. It ends at its next attempt after
    /// `conn` holds a manager, whoever populated it: a request that wins the
    /// race makes that `get_or_try_init` return at once. After that, `redis`'s
    /// own `ConnectionManager` reconnect and [`Limiter::spend`]'s single retry
    /// own recovery, as before.
    ///
    /// **"REFUSED" MEANS A CREDENTIAL THE CACHE REJECTED, AND ONLY THAT.** A
    /// password that was sent and answered `WRONGPASS` fails the connect as
    /// `AuthenticationFailed`, which [`classify`] reads as `Unauthenticated`.
    /// A MISSING credential against a cache that requires one is NOT caught
    /// here: with no password, `redis` 1.7.1 on RESP2 sends no AUTH, the
    /// connect succeeds, and this task ends. That case shows up on calls, as
    /// `NOAUTH` and [`super::super::Decision::Unauthenticated`].
    ///
    /// **A FAILED ATTEMPT IS LOGGED, NEVER RAISED.** Telemetry never fails a
    /// call, and nothing awaits this. `main` aborts the task when serving ends,
    /// so it never outlives shutdown.
    pub async fn warm(&self) {
        let mut attempt: u64 = 0;
        loop {
            attempt += 1;
            let config = self.connect_config();
            // Whether THIS task's connect populated `conn`, rather than a
            // request that won the race — only the former is this task's news.
            let mut dialled = false;
            let error = match self
                .conn
                .get_or_try_init(|| {
                    dialled = true;
                    self.client.get_connection_manager_with_config(config)
                })
                .await
            {
                Ok(_) => {
                    self.connected.store(true, Ordering::Relaxed);
                    // SILENT ON A FIRST-TRY SUCCESS, and when a request had
                    // already connected: neither says anything new.
                    if dialled && attempt > 1 {
                        tracing::info!(attempt, "connected to the rate-limit cache");
                    }
                    return;
                }
                Err(e) => e,
            };
            // WHAT `redis` SAID, read before `classify` consumes it. It names the
            // failure, never the credential.
            let detail = error.to_string();
            let refused = classify(error) == Degrade::Unauthenticated;
            let wait = retry_after(refused);
            report_failure(attempt, &detail, refused, wait);
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{retry_after, REFUSED_RETRY, RETRY};

    /// MUTATION: inlining `true` or `false` for `refused` turns one arm red,
    /// and so does swapping the two constants.
    #[test]
    fn a_refused_credential_backs_off_longer_than_an_outage() {
        assert_eq!(retry_after(false), RETRY);
        assert_eq!(retry_after(true), REFUSED_RETRY);
        assert!(REFUSED_RETRY > RETRY);
    }
}
