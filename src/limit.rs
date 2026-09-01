//! D74's token bucket: one per `(user, module, kind)`, refilled lazily.
//!
//! Every user-attributed call spends a token. A bucket is two numbers — `rate`,
//! the sustained refill per second, and `burst`, its size — so a caller may spend
//! `burst` at once and is then throttled to `rate` forever. **No timer exists,
//! not even a hidden one:** the refill is computed from elapsed time on each
//! request, so nothing runs in the background and there is no job to fail
//! quietly.
//!
//! # The one thing that must not be got wrong
//!
//! **The read-compute-write is one atomic operation in a SHARED store, and that
//! is the whole reason this module is not fifty lines of `HashMap`.** Done as a
//! `GET` then a `SET` from Rust, two gateway replicas both read `tokens = 1`,
//! both allow, and the configured limit is quietly multiplied by the replica
//! count — under exactly the load the limit exists for. So it is a Lua script:
//! one round trip, atomic by construction, the same shape as D58's migration
//! lock. The race appears only under concurrency, which is why it cannot be found
//! by testing against one replica, and why `tests/rate_limit.rs` drives
//! concurrent callers at a real Valkey and counts what was granted.
//!
//! **The clock is Valkey's, never the caller's.** `redis.call('TIME')` inside the
//! script gives every replica one clock. Passing `SystemTime::now()` in from Rust
//! would make the refill depend on each pod's clock skew, so a replica running
//! fast would grant more than its share — the per-replica multiplication defeated
//! above, reintroduced through the time axis. Verified callable in a write script
//! on `valkey/valkey:9.1.1`.
//!
//! # When Valkey cannot answer, the call proceeds
//!
//! See [`Decision::Degraded`]. Argued there rather than here because it is the
//! decision a reader will want to challenge.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use tokio::sync::OnceCell;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

/// The metric this module emits, over and above D67's three.
///
/// Bounded labels only: `reason` comes from [`Degrade`], a closed set of three.
/// **The user is never a label here.** D72 and D77 both keep usernames out of
/// logs and metrics, and a per-user label on a degradation counter is exactly how
/// one gets in — it would also be unbounded, which D67 forbids for its own
/// reason.
pub const DEGRADED: &str = "yadgar_gateway_rate_limit_degraded_total";

/// The key prefix for this service's buckets in the shared cache (D21).
///
/// `gw:` names the service, `rl:` the concern — D77's expansion cache lands
/// alongside as `gw:exp:` rather than having to reorganise this one.
const PREFIX: &str = "gw:rl";

/// One bucket's two numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bucket {
    /// Sustained refill, tokens per second.
    pub rate: f64,
    /// The bucket's size, and therefore the largest burst.
    pub burst: f64,
}

impl Bucket {
    /// How long a full bucket takes to refill from empty.
    ///
    /// This is the key's TTL, and the choice is not arbitrary: after this long an
    /// absent key and a present key describe the same bucket — a full one — so
    /// expiry can never hand anybody tokens they did not have.
    fn refill_seconds(&self) -> f64 {
        if self.rate <= 0.0 {
            return 0.0;
        }
        self.burst / self.rate
    }
}

/// What a limit configuration can be wrong in, refused at boot rather than
/// defaulted.
///
/// **A misparsed limit that silently became the default would be a limit nobody
/// notices is gone** — the D76 failure shape, applied to capacity. D69's rule
/// covers it: a capability that cannot be configured correctly fails startup.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0:?} is not `<module>.<kind>=<rate>:<burst>`")]
    Shape(String),
    #[error("{0:?} in {1:?} is not a positive number")]
    NotPositive(String, String),
    #[error("{0:?} is not a kind; expected one of read, write, generate")]
    UnknownKind(String),
}

/// The configured defaults (D43), and the fallback for a pair nobody named.
///
/// **Configuration has no user axis**, which is what keeps D43 true here: a
/// per-user number is a fact about a person, so it lives in `iam` and arrives as
/// [`Overrides`].
#[derive(Debug, Clone)]
pub struct Limits {
    per_pair: HashMap<String, Bucket>,
    fallback: Bucket,
}

/// `read`, `write`, `generate` — D67's `Kind`, as the bounded string this module
/// keys on.
///
/// Reusing an existing bounded dimension rather than inventing a taxonomy is what
/// keeps the configuration small: `task.write`, `memory.write`, `recall.read`.
pub fn kind_str(kind: Kind) -> &'static str {
    match kind {
        Kind::Read => "read",
        Kind::Write => "write",
        Kind::Generate => "generate",
        // NEITHER REACHES THIS SERVICE, and both are named rather than folded
        // into a wildcard. `Job` is system-initiated work, which D74 puts outside
        // the first cut because it is not user-attributed and needs its own
        // mechanism; `Unspecified` is a Kind nothing should construct. A wildcard
        // would pool whichever appeared into some other kind's bucket.
        Kind::Job => "job",
        Kind::Unspecified => "unspecified",
    }
}

fn parse_kind(s: &str) -> Result<(), ConfigError> {
    match s {
        "read" | "write" | "generate" => Ok(()),
        other => Err(ConfigError::UnknownKind(other.to_string())),
    }
}

fn parse_bucket(spec: &str, whole: &str) -> Result<Bucket, ConfigError> {
    let (rate, burst) = spec
        .split_once(':')
        .ok_or_else(|| ConfigError::Shape(whole.to_string()))?;
    let number = |s: &str| -> Result<f64, ConfigError> {
        s.trim()
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite() && *n > 0.0)
            .ok_or_else(|| ConfigError::NotPositive(s.to_string(), whole.to_string()))
    };
    Ok(Bucket {
        rate: number(rate)?,
        burst: number(burst)?,
    })
}

impl Limits {
    /// Parse `task.write=2:20,task.read=20:200` and a `<rate>:<burst>` fallback.
    ///
    /// The fallback exists because the tool surface grows and the configuration
    /// should not have to grow with it in lockstep. A pair nobody named is
    /// limited rather than unlimited — the opposite default would mean every new
    /// tool ships unprotected until somebody remembers.
    pub fn parse(pairs: &str, fallback: &str) -> Result<Self, ConfigError> {
        let mut per_pair = HashMap::new();
        for entry in pairs.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (name, spec) = entry
                .split_once('=')
                .ok_or_else(|| ConfigError::Shape(entry.to_string()))?;
            let (module, kind) = name
                .trim()
                .split_once('.')
                .ok_or_else(|| ConfigError::Shape(entry.to_string()))?;
            parse_kind(kind)?;
            if module.is_empty() {
                return Err(ConfigError::Shape(entry.to_string()));
            }
            per_pair.insert(format!("{module}.{kind}"), parse_bucket(spec, entry)?);
        }
        Ok(Self {
            per_pair,
            fallback: parse_bucket(fallback, fallback)?,
        })
    }

    /// The bucket in force for one call.
    ///
    /// **The override wins, and its absence is not an error.** `iam` will carry
    /// the effective buckets on `ResolveCredentialResponse` (D74); until the
    /// contract does, [`Overrides`] is empty on every call and this returns the
    /// configured default — which is the degradation the field's absence should
    /// produce, rather than a stub that has to be found and deleted later.
    pub fn effective(&self, module: &str, kind: Kind, overrides: &Overrides) -> Bucket {
        let pair = format!("{module}.{}", kind_str(kind));
        overrides
            .0
            .get(&pair)
            .or_else(|| self.per_pair.get(&pair))
            .copied()
            .unwrap_or(self.fallback)
    }
}

/// The per-user buckets that travel with identity (D74).
///
/// **Empty today, and deliberately not stubbed.** D74 puts the effective buckets
/// on `ResolveCredentialResponse` so the gateway learns who you are and what you
/// may spend in one lookup, cached together and invalidated together. That field
/// does not exist on the contract yet, and the gateway has no `iam` path at all
/// (`attest::Attestation::Iam` is refused at boot). So this type is the shape the
/// field will fill, it is constructed empty, and the effect of empty is the
/// configured default — the deployment behaves exactly as if no user had an
/// override, which is true.
#[derive(Debug, Clone, Default)]
pub struct Overrides(HashMap<String, Bucket>);

impl Overrides {
    /// Build from what a resolved credential carried.
    ///
    /// The call site is `attest`, and the input will be the repeated field D74
    /// describes. Taking `(module.kind, rate, burst)` triples rather than a
    /// generated protobuf type keeps this module off the contract's schedule:
    /// when the proto lands, one `map` in `attest.rs` changes and nothing here
    /// does.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, Bucket)>) -> Self {
        Self(pairs.into_iter().collect())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Why the limiter could not answer. A CLOSED set, because it is a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Degrade {
    /// No connection to the shared cache could be established.
    Unreachable,
    /// A connection exists and the call did not come back in time. **The more
    /// common failure, and the worse one**: a hung round trip puts its latency on
    /// every user-attributed call, at the one hop all traffic passes through.
    Timeout,
    /// It answered, and the answer was an error or a shape this code does not
    /// understand.
    Error,
}

impl Degrade {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for Degrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The answer for one call.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// A token was spent.
    Allowed,
    /// The bucket is empty. `retry_after` is `(1 - tokens) / rate` for THIS
    /// caller's own bucket — exact rather than shared, so a hundred throttled
    /// callers are not all told to return at the same instant, which is a
    /// thundering herd built into the protocol.
    Throttled { retry_after: Duration },
    /// The shared store could not answer, and **the call proceeds unlimited**.
    ///
    /// # Why fail open, when D69 fails closed on a missing capability
    ///
    /// D77 already made this exception for the expansion cache, on the ground
    /// that a cache is not a capability. A rate limiter is a harder question, so
    /// the argument is made rather than inherited.
    ///
    /// **Failing closed makes the least-available component in the installation
    /// into a hard dependency of every user-attributed call.** Valkey is
    /// `replicas: 1`, `strategy: Recreate`, `--save ""` and `--appendonly no`
    /// (`deploy/infra/valkey/valkey.yaml`). Every image bump is a gap with no
    /// standby, and under fail-closed that gap is a total outage of the product
    /// at the one hop everything passes through. The gateway is deliberately not
    /// gated on `task` for the same reason (`main.rs`); gating it on the cache
    /// would be a stricter rule for a weaker dependency.
    ///
    /// **D74 says what this mechanism is: capacity protection, not
    /// authorisation.** Its own words — "a caller with cluster access bypasses
    /// the gateway and therefore bypasses this entirely". Failing closed treats a
    /// non-security control as a security control, and pays a security control's
    /// availability price for it.
    ///
    /// **The failure shapes are not symmetric.** Fail open during an outage: a
    /// looping client can write faster than intended for the length of the
    /// outage, bounded by `task`'s own capacity and visible in D67's counters.
    /// Fail closed during the same outage: every caller gets 429, every client
    /// retries on the `retry-after` it was handed, and the retry storm outlives
    /// the outage that caused it.
    ///
    /// **An in-process fallback bucket is rejected, not overlooked.** It is the
    /// per-replica bucket D74 names as the defect and D18 forbids outright, and
    /// it would silently multiply the limit by the replica count — the exact
    /// thing this module's Lua script exists to prevent, reintroduced on the
    /// error path where nobody looks.
    ///
    /// **The condition is that this is LOUD.** A silent fail-open is the D76
    /// shape: a dead mechanism that reads healthy. So every degraded call
    /// increments [`DEGRADED`] under its reason and logs at warn.
    Degraded(Degrade),
}

/// The atomic read-compute-write.
///
/// KEYS[1] the bucket. ARGV: rate, burst, cost, ttl seconds.
/// Returns `{allowed, tokens, retry_after_seconds}`.
///
/// **`tokens` and `retry_after` come back as STRINGS.** Lua-to-Redis conversion
/// truncates a number to an integer, so returning them as numbers would report
/// every fractional wait as `0` and make `retry-after` a lie in the common case.
const SCRIPT: &str = r#"
local key   = KEYS[1]
local rate  = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local cost  = tonumber(ARGV[3])
local ttl   = tonumber(ARGV[4])

-- Valkey's clock, not the caller's: one clock for every replica.
local t   = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000

local state  = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts     = tonumber(state[2])
if tokens == nil or ts == nil then
  -- An absent bucket is a FULL one. The key's TTL is the time a full bucket
  -- takes to refill, so this can never grant more than waiting would have.
  tokens = burst
  ts     = now
end

-- Clamped at zero. Valkey's clock is one clock, but it is not guaranteed
-- monotonic across a restart, and a negative elapsed would DRAIN the bucket.
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(burst, tokens + elapsed * rate)

local allowed = 0
local retry   = 0
if tokens >= cost then
  tokens  = tokens - cost
  allowed = 1
else
  retry = (cost - tokens) / rate
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, ttl)

return {allowed, tostring(tokens), tostring(retry)}
"#;

/// Which degradation a client error actually is.
///
/// **The distinction the counter is for.** A connection this process HAD and then
/// lost reaches here as a command error, not as a failed init — so without this
/// the reconnect case would be filed under `error` and an operator would look for
/// a broken script rather than an absent server.
fn classify(e: redis::RedisError) -> Degrade {
    if e.is_connection_refusal() || e.is_connection_dropped() {
        Degrade::Unreachable
    } else if e.is_timeout() {
        // A server that ANSWERS SLOWLY, which is a different thing to look at
        // from one that is not there. This arm is reachable only because the
        // inner response budget is smaller than the outer one.
        Degrade::Timeout
    } else {
        Degrade::Error
    }
}

/// The token bucket, over the shared cache.
pub struct Limiter {
    client: redis::Client,
    /// Built on FIRST USE, not at boot.
    ///
    /// The gateway must not wait on a downstream to bind its listener — the same
    /// rule `main.rs` states for `task`, and under D68 a pod stuck in startup is
    /// one the autoscaler cannot help. `get_or_try_init` does not cache the
    /// error, so a Valkey that comes back is picked up by the next call rather
    /// than needing a restart.
    conn: OnceCell<ConnectionManager>,
    limits: Limits,
    timeout: Duration,
    script: redis::Script,
}

impl Limiter {
    /// `addr` is `host:port`. No I/O happens here.
    pub fn new(addr: &str, limits: Limits, timeout: Duration) -> Result<Self, redis::RedisError> {
        Ok(Self {
            client: redis::Client::open(format!("redis://{addr}"))?,
            conn: OnceCell::new(),
            limits,
            timeout,
            script: redis::Script::new(SCRIPT),
        })
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Spend one token, or refuse.
    ///
    /// `user_id` reaches the KEY and nothing else — never a log line and never a
    /// metric label (D72, D77).
    pub async fn check(
        &self,
        user_id: &str,
        module: &str,
        kind: Kind,
        overrides: &Overrides,
    ) -> Decision {
        let bucket = self.limits.effective(module, kind, overrides);
        let key = format!("{PREFIX}:{user_id}:{module}:{}", kind_str(kind));
        match tokio::time::timeout(self.timeout, self.spend(&key, bucket)).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(degrade)) => Decision::Degraded(degrade),
            // TIMED OUT, and the reason it timed out decides the label. A Valkey
            // that is simply DOWN would otherwise be reported as "timeout",
            // because the connect attempt outlives this budget and the outer
            // timeout is what fires — so an operator reading the counter would go
            // looking for a slow cache rather than an absent one. If no
            // connection has ever been established, "unreachable" is the true
            // answer; once one has, a later stall really is a stall.
            Err(_elapsed) if self.conn.get().is_none() => Decision::Degraded(Degrade::Unreachable),
            Err(_elapsed) => Decision::Degraded(Degrade::Timeout),
        }
    }

    async fn spend(&self, key: &str, bucket: Bucket) -> Result<Decision, Degrade> {
        // NO RETRIES, AND AN INNER BUDGET SMALLER THAN THE OUTER ONE. Both
        // numbers exist so the REASON survives.
        //
        // The manager's default is a long exponential backoff. Under it every
        // failure outlived `self.timeout`, so the outer timeout was always what
        // fired and every degradation — refused connection, dropped socket, bad
        // reply — arrived labelled `timeout`. An operator reading that counter
        // would go looking for a slow cache while the real one was absent, which
        // is the exact misdirection the label was added to prevent. Two thirds of
        // the budget leaves room for the real error to come back and be named.
        //
        // Retrying inside one call is the wrong place for it besides: the next
        // call reconnects anyway, and a queue of callers all waiting on the same
        // doomed connect is latency at the one hop all traffic passes through.
        let inner = self.timeout.mul_f32(0.66);
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(inner))
            .set_response_timeout(Some(inner))
            .set_number_of_retries(0);

        let mut conn = self
            .conn
            .get_or_try_init(|| self.client.get_connection_manager_with_config(config))
            .await
            .map_err(|_| Degrade::Unreachable)?
            .clone();

        // At least one second: EXPIRE takes whole seconds, and a sub-second TTL
        // rounds to zero, which deletes the key on every write.
        let ttl = bucket.refill_seconds().ceil().max(1.0) as u64;

        let (allowed, _tokens, retry): (i64, String, String) = self
            .script
            .key(key)
            .arg(bucket.rate)
            .arg(bucket.burst)
            .arg(1.0)
            .arg(ttl)
            .invoke_async(&mut conn)
            .await
            .map_err(classify)?;

        if allowed == 1 {
            return Ok(Decision::Allowed);
        }
        let seconds: f64 = retry.parse().map_err(|_| Degrade::Error)?;
        Ok(Decision::Throttled {
            retry_after: Duration::from_secs_f64(seconds.clamp(0.0, 86_400.0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_pair_beats_the_fallback_and_an_override_beats_both() {
        let limits = Limits::parse("task.write=2:20, task.read=50:500", "10:100").expect("parse");

        assert_eq!(
            limits.effective("task", Kind::Write, &Overrides::default()),
            Bucket {
                rate: 2.0,
                burst: 20.0
            }
        );
        // Nobody named `memory.write`, so it is LIMITED rather than unlimited.
        assert_eq!(
            limits.effective("memory", Kind::Write, &Overrides::default()),
            Bucket {
                rate: 10.0,
                burst: 100.0
            }
        );

        let mine = Overrides::from_pairs([(
            "task.write".to_string(),
            Bucket {
                rate: 99.0,
                burst: 999.0,
            },
        )]);
        assert_eq!(
            limits.effective("task", Kind::Write, &mine),
            Bucket {
                rate: 99.0,
                burst: 999.0
            },
            "a per-user override wins over the configured default (D74)"
        );
        // And it overrides only what it names.
        assert_eq!(
            limits.effective("task", Kind::Read, &mine),
            Bucket {
                rate: 50.0,
                burst: 500.0
            }
        );
    }

    #[test]
    fn an_absent_override_field_degrades_to_the_configured_default() {
        // THE DEGRADATION THAT MUST HOLD while `ResolveCredentialResponse` does
        // not carry the buckets yet. An empty `Overrides` is the state every call
        // is in today, and the deployment must behave exactly as if no user had
        // an override — not fall through to unlimited, and not fail.
        let limits = Limits::parse("task.write=2:20", "10:100").expect("parse");
        let none = Overrides::default();
        assert!(none.is_empty());
        assert_eq!(
            limits.effective("task", Kind::Write, &none),
            Bucket {
                rate: 2.0,
                burst: 20.0
            }
        );
    }

    #[test]
    fn a_malformed_limit_refuses_rather_than_defaulting() {
        // MUTATION THIS CATCHES: a parse that skips what it cannot read. Under
        // it, a typo in the chart silently removes one limit and nothing says so
        // — a limit nobody notices is gone, which is the D76 shape applied to
        // capacity.
        for bad in [
            "task.write",         // no bucket
            "task.write=20",      // no rate:burst split
            "taskwrite=2:20",     // no module.kind split
            "task.wrote=2:20",    // not a kind
            "task.write=0:20",    // a rate of zero never refills
            "task.write=-1:20",   // negative
            "task.write=2:abc",   // not a number
            ".write=2:20",        // no module
            "task.write=2:20,,,", // trailing separators are fine
        ] {
            let parsed = Limits::parse(bad, "10:100");
            if bad == "task.write=2:20,,," {
                assert!(parsed.is_ok(), "empty entries are skipped, not an error");
            } else {
                assert!(parsed.is_err(), "{bad:?} must be refused");
            }
        }
        assert!(
            Limits::parse("", "nonsense").is_err(),
            "so must the fallback"
        );
    }

    #[test]
    fn the_ttl_is_the_time_a_full_bucket_takes_to_refill() {
        // A SHORTER TTL WOULD HAND OUT TOKENS. An expired key is read as a full
        // bucket, so the key must not expire before waiting would have refilled
        // it anyway. This is the property, stated as arithmetic.
        assert_eq!(
            Bucket {
                rate: 2.0,
                burst: 20.0
            }
            .refill_seconds(),
            10.0
        );
        assert_eq!(
            Bucket {
                rate: 100.0,
                burst: 100.0
            }
            .refill_seconds(),
            1.0
        );
    }

    #[test]
    fn every_degrade_reason_has_a_bounded_label() {
        // It is a metric label, so the set must be closed and must not include
        // anything derived from an error string or a user.
        let labels: Vec<&str> = [Degrade::Unreachable, Degrade::Timeout, Degrade::Error]
            .iter()
            .map(|d| d.label())
            .collect();
        assert_eq!(labels, ["unreachable", "timeout", "error"]);
    }
}
