//! The in-process floor that applies while the shared cache cannot answer.
//!
//! Split out of [`super`] for the file-size ceiling. This is the FAIL-OPEN half
//! of D74: nothing here coordinates with another replica, deliberately, and the
//! reasoning for why a per-replica share is the only honest bound is on
//! [`Floor`] itself.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::config::Bucket;

/// The in-process bucket that applies while the shared store cannot answer.
///
/// **Per replica, and that is the point rather than an oversight.** Nothing
/// coordinates during a cache outage — coordination is the thing that is
/// missing — so the only number a replica can enforce alone is its own share.
/// Dividing by the largest number of replicas the autoscaler may run makes the
/// aggregate bound hold at every scale: at `maxReplicas` the sum is the
/// configured rate, and below it the floor is tighter than configured, which errs
/// toward refusing rather than toward the multiplication D74 rejects.
///
/// `maxReplicas` is read from the chart (`YADGAR_MAX_REPLICAS`, wired from
/// `autoscaling.maxReplicas`) rather than hardcoded, because a constant here and
/// a number in `values.yaml` are two places that must agree and only one of them
/// gets edited.
///
/// **The burst has a floor of one token**, or a configured burst below
/// `maxReplicas` would divide to less than a token and refuse every call during
/// an outage — turning a fail-open decision into a fail-closed one by arithmetic.
/// The consequence, stated because the aggregate bound above is what makes this
/// acceptable: for a configured burst below `maxReplicas`, the aggregate degraded
/// burst can reach `maxReplicas` tokens rather than the configured burst. That is
/// bounded, small, and only reachable for buckets configured tighter than the
/// replica count.
///
/// **The map is bounded**, because the key includes a caller-supplied user id and
/// an unbounded map here would be the same defect as an unbounded key. When it is
/// full, entries that have refilled to full are dropped — an entry idle for its
/// own refill window holds exactly what an absent one would, so dropping it
/// changes no answer. If that frees nothing, the call is refused rather than
/// allowed untracked: refusing is the safe direction, and it is only reachable
/// with [`FLOOR_CAPACITY`] distinct callers holding non-full buckets on one
/// replica during a cache outage.
pub(super) struct Floor {
    replicas: f64,
    entries: Mutex<HashMap<String, Local>>,
}

/// How many distinct callers one replica tracks while degraded.
pub(super) const FLOOR_CAPACITY: usize = 4096;

/// One caller's degraded-mode bucket.
///
/// `full_at` is stored rather than recomputed so the capacity sweep does not need
/// each entry's own rate and burst — the only question it asks is whether an
/// entry has refilled to full, and that is a time.
#[derive(Debug, Clone, Copy)]
struct Local {
    tokens: f64,
    at: Instant,
    full_at: Instant,
}

impl Floor {
    pub(super) fn new(replicas: u32) -> Self {
        Self {
            replicas: f64::from(replicas.max(1)),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Spend one token from the local floor, or say how long until there is one.
    ///
    /// `now` is injected so the arithmetic is testable without sleeping.
    pub(super) fn check(&self, key: &str, bucket: Bucket, now: Instant) -> Result<(), Duration> {
        let rate = bucket.rate / self.replicas;
        let burst = (bucket.burst / self.replicas).max(1.0);
        // A POISONED LOCK MUST NOT FAIL A CALL. The only writer is this function
        // and it holds no invariant across the boundary, so the recovered map is
        // as usable as any other.
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);

        let mut tokens = match entries.get(key) {
            Some(local) => {
                let elapsed = now.saturating_duration_since(local.at).as_secs_f64();
                burst.min(local.tokens + elapsed * rate)
            }
            None => {
                if entries.len() >= FLOOR_CAPACITY {
                    entries.retain(|_, local| local.full_at > now);
                }
                if entries.len() >= FLOOR_CAPACITY {
                    return Err(seconds(1.0 / rate));
                }
                burst
            }
        };

        let allowed = tokens >= 1.0;
        if allowed {
            tokens -= 1.0;
        }
        entries.insert(
            key.to_string(),
            Local {
                tokens,
                at: now,
                full_at: now + seconds((burst - tokens) / rate),
            },
        );
        if allowed {
            Ok(())
        } else {
            Err(seconds((1.0 - tokens) / rate))
        }
    }
}

/// A duration from seconds, clamped so a slow bucket cannot overflow one.
///
/// `Duration::from_secs_f64` PANICS on a value that does not fit, and the input
/// here is a quotient of configured numbers. The ceiling is the same 86,400 the
/// `retry_after` on the shared path is clamped to, so the two paths cannot
/// disagree about the longest wait this service will name.
fn seconds(n: f64) -> Duration {
    Duration::from_secs_f64(if n.is_finite() {
        n.clamp(0.0, 86_400.0)
    } else {
        86_400.0
    })
}
