//! The token bucket over the shared cache: the Lua that makes it atomic, and the
//! connection that runs it.
//!
//! Split out of [`super`] for the file-size ceiling. What a caller does with the
//! answer, and what the answer MEANS, is [`super::Decision`]'s; this is the
//! implementation behind it.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use tokio::sync::OnceCell;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use super::config::{kind_str, Bucket, Limits, Overrides};
use super::floor::Floor;
use super::{address_component, user_component, Decision, Degrade, PREFIX};

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
  -- An absent bucket is a FULL one. That is sound only while the key outlives
  -- the refill window of the bucket READING it, which is what a TTL fixed for
  -- the whole deployment buys -- see KEY_TTL_SECONDS in this file.
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
-- EXTEND ONLY, NEVER SHORTEN. Two processes may hold different configurations
-- during a rolling deploy, and the shorter TTL must not win: a key whose life
-- is cut expires while its bucket is still empty, and the next read treats
-- absent as full. TTL returns -2 for an absent key and -1 for one with no
-- expiry, and both compare below any real ttl, so both set it.
--
-- Not `EXPIRE key ttl GT`: GT treats a key with no TTL as having an infinite
-- one and refuses to set the first expiry at all, which is exactly the call
-- that must not be skipped.
local current = redis.call('TTL', key)
if current < ttl then
  redis.call('EXPIRE', key, ttl)
end

return {allowed, tostring(tokens), tostring(retry)}
"#;

/// Which degradation a client error actually is.
///
/// **The distinction the counter is for.** A connection this process HAD and then
/// lost reaches here as a command error, not as a failed init — so without this
/// the reconnect case would be filed under `error` and an operator would look for
/// a broken script rather than an absent server.
fn classify(e: redis::RedisError) -> Degrade {
    // FIRST, and before the connection arms, because the two overlap. A wrong
    // password is refused during the handshake, and `redis` reports that as a
    // failed connection attempt — so an auth arm placed after those would never
    // be reached for the case an operator is most likely to create.
    //
    // TWO SHAPES, because `redis` 1.6 produces two. A password this process sent
    // and the server rejected fails inside the handshake and arrives as
    // `ErrorKind::AuthenticationFailed` with no code (`connection.rs`, the AUTH
    // reply check). A password this process never sent, against a server that
    // wanted one, is not a handshake failure at all — the connection is
    // established and the FIRST COMMAND comes back `-NOAUTH`, which `redis` has
    // no known kind for and surfaces as an extension code. Matching only the kind
    // would leave the missing-credential case, which is the whole point of this
    // arm, filed as an ordinary error and failed open.
    if e.kind() == redis::ErrorKind::AuthenticationFailed
        || matches!(e.code(), Some("NOAUTH" | "WRONGPASS" | "NOPERM"))
    {
        Degrade::Unauthenticated
    } else if e.is_connection_refusal() || e.is_connection_dropped() {
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
    /// What applies while `conn` cannot answer. See [`Floor`].
    floor: Floor,
}

impl Limiter {
    /// `addr` is `host:port`. No I/O happens here.
    ///
    /// `password` is the cache's `requirepass`, or `None` for a cache that asks
    /// for none. **It is passed as a value rather than spliced into `addr`**: a
    /// URL carries a password only percent-encoded, so `redis://:{password}@host`
    /// silently truncates at the first `@`, `/` or `#` and sends a DIFFERENT
    /// password than the one in the Secret. `set_password` takes the bytes as
    /// they are, so nothing about the credential's alphabet has to be true.
    ///
    /// `max_replicas` is the largest number of replicas of this Deployment the
    /// autoscaler may run, and it is the divisor of the degraded-mode floor —
    /// see [`Floor`]. It is a parameter rather than a constant because the
    /// authority for it is the chart.
    pub fn new(
        addr: &str,
        password: Option<&str>,
        limits: Limits,
        timeout: Duration,
        max_replicas: u32,
    ) -> Result<Self, redis::RedisError> {
        use redis::IntoConnectionInfo;

        let info = format!("redis://{addr}").into_connection_info()?;
        // NO CONNECTION IS MADE HERE, with or without a password. The credential
        // is only recorded on the handshake this process will perform later, on
        // first use — `conn` is still a `OnceCell`, for the reason on it.
        let info = match password {
            Some(p) => {
                let redis = info.redis_settings().clone().set_password(p);
                info.set_redis_settings(redis)
            }
            None => info,
        };
        Ok(Self {
            client: redis::Client::open(info)?,
            conn: OnceCell::new(),
            limits,
            timeout,
            script: redis::Script::new(SCRIPT),
            floor: Floor::new(max_replicas),
        })
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Spend one token, or refuse.
    ///
    /// `user_id` reaches the KEY and nothing else — never a log line and never a
    /// metric label (D72, D77) — and it reaches the key HASHED, because the key
    /// lives in a cache four other subsystems share and the id is caller-supplied.
    /// See [`user_component`].
    pub async fn check(
        &self,
        user_id: &str,
        module: &str,
        kind: Kind,
        overrides: &Overrides,
    ) -> Decision {
        let bucket = self.limits.effective(module, kind, overrides);
        let key = format!(
            "{PREFIX}:{}:{module}:{}",
            user_component(user_id),
            kind_str(kind)
        );
        self.decide(&key, bucket).await
    }

    /// Spend one token from a bucket keyed on a SOURCE ADDRESS rather than on a
    /// user (task 497).
    ///
    /// # Why this is not [`Self::check`] with an address in the id slot
    ///
    /// [`user_component`] takes an arbitrary `&str`, so an address would hash
    /// through it without complaint — and the result would not be a fix. Two
    /// things make this a different mechanism rather than a different argument:
    ///
    /// 1. **[`Limits::effective`] draws the bucket from `(module, kind)` only.**
    ///    An address-keyed bucket routed through it would inherit a rate designed
    ///    for a user's tool calls, which is a number chosen for a different
    ///    question. So `bucket` is a PARAMETER here: the caller states the rate
    ///    belonging to the thing it is bounding, and `http` picks it from whether
    ///    the address is attributable at all.
    /// 2. **The key space is separate.** `PREFIX:{user}:...` and
    ///    `PREFIX:src:{addr}:...` cannot collide, so a person's tool-call budget
    ///    and an address's login budget are never the same bucket.
    ///
    /// `endpoint` is `&'static str` and a closed set, for [`kind_str`]'s reason: a
    /// key component a caller could choose is a bucket a caller can mint.
    ///
    /// **The address reaches the KEY and nothing else — hashed, and never a log
    /// line or a metric label.** ADR-0491 puts a source address in the audit store
    /// and ONLY there; the shared cache is neither, and D21 puts four other
    /// subsystems in it. See [`address_component`].
    pub async fn check_source(
        &self,
        addr: IpAddr,
        endpoint: &'static str,
        bucket: Bucket,
    ) -> Decision {
        let key = format!("{PREFIX}:src:{}:{endpoint}", address_component(addr));
        self.decide(&key, bucket).await
    }

    /// Everything both entry points do once the key and the bucket are known.
    ///
    /// Split out so the degrade taxonomy, the [`Decision::Unauthenticated`] short
    /// circuit and the floor are decided in ONE place. Two copies would be two
    /// places for the ordering that decision depends on to drift apart.
    async fn decide(&self, key: &str, bucket: Bucket) -> Decision {
        let reason = match tokio::time::timeout(self.timeout, self.spend(key, bucket)).await {
            Ok(Ok(decision)) => return decision,
            Ok(Err(degrade)) => degrade,
            // TIMED OUT, and the reason it timed out decides the label. A Valkey
            // that is simply DOWN would otherwise be reported as "timeout",
            // because the connect attempt outlives this budget and the outer
            // timeout is what fires — so an operator reading the counter would go
            // looking for a slow cache rather than an absent one. If no
            // connection has ever been established, "unreachable" is the true
            // answer; once one has, a later stall really is a stall.
            Err(_elapsed) if self.conn.get().is_none() => Degrade::Unreachable,
            Err(_elapsed) => Degrade::Timeout,
        };
        // BEFORE THE FLOOR, and that ordering is the whole of the change. The
        // floor is what makes failing open acceptable, and it is acceptable only
        // for a failure that ends. See `Decision::Unauthenticated`.
        if reason == Degrade::Unauthenticated {
            return Decision::Unauthenticated;
        }
        // DEGRADED, AND FLOORED. The call proceeds on this replica's own share
        // rather than unlimited — the argument is on `Decision::Degraded`.
        match self.floor.check(key, bucket, Instant::now()) {
            Ok(()) => Decision::Degraded(reason),
            Err(retry_after) => Decision::DegradedThrottled {
                reason,
                retry_after,
            },
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
            // `classify` RATHER THAN a flat `Unreachable`, and this line is where
            // the wrong-password case is actually decided. `redis` performs the
            // AUTH inside the connection setup, so a rejected credential never
            // reaches the command below — it fails here, and the discarded error
            // this line used to throw away was the only thing that said so.
            .map_err(|e| match classify(e) {
                Degrade::Unauthenticated => Degrade::Unauthenticated,
                // EVERYTHING ELSE STAYS `Unreachable`, deliberately. A failure to
                // establish a connection is what that label means, and the
                // distinctions `classify` draws between kinds of command failure
                // do not apply to one.
                _ => Degrade::Unreachable,
            })?
            .clone();

        // A property of the DEPLOYMENT, not of this bucket. See
        // `Bucket::key_ttl_seconds` and `KEY_TTL_SECONDS`.
        let ttl = bucket.key_ttl_seconds();

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
