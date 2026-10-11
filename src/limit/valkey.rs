//! The token bucket over the shared cache: the connection that runs it, and
//! the policy around establishing and retrying that connection.
//!
//! Split out of [`super`] for the file-size ceiling. The Lua itself, and what
//! a client error from running it actually means, is [`super::script`]'s; what
//! a caller does with the answer, and what the answer MEANS, is
//! [`super::Decision`]'s; this is the implementation behind both.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use tokio::sync::OnceCell;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use super::config::{kind_str, Bucket, Limits, Overrides};
use super::floor::Floor;
use super::script::{classify, SCRIPT};
use super::transport;
use super::{address_component, user_component, Decision, Degrade, PREFIX};
use crate::upstream::UpstreamTls;

/// The cache's fixed TLS listener (B-V2, ADR-0852). NOT `rateLimit.addr`'s
/// port — that address stays the plaintext one so B-V3's contract needs no
/// values change — and not a values key either: every valkey in this estate
/// serves TLS on this one port beside its plaintext one, the same way
/// `platform/chart/templates/ingress-policies.yaml` hardcodes it rather than
/// reading it from a key.
const TLS_PORT: u16 = 6380;

/// How long [`Limiter::warm`]'s background connect, started at boot, may run
/// before giving up (ledger 1430).
///
/// **A CONSTANT, NOT A NEW KNOB.** `warm` is fire-and-forget (`main` spawns it
/// and never awaits the handle, D69/ADR-0555), so nothing is WAITING on this
/// number the way every caller of [`Limiter::check`] waits on `self.timeout` —
/// there is no operator-visible latency to tune here, only "how long does one
/// background task linger before it gives up and lets the first real call try
/// again exactly as it would have anyway." A chart value would be a second knob
/// for a question nobody who deploys this needs to answer (ADR-0569's own test:
/// who would ever change it, and why).
///
/// **DELIBERATELY NOT DERIVED FROM `self.timeout`.** [`Limiter::connect_config`]
/// bounds the connect ATTEMPT itself at `self.timeout`'s own `inner` fraction —
/// the same budget every call through this type already uses — so a connection
/// `warm` establishes behaves identically to one a real request established.
/// This constant only bounds how long `warm`'s OWN task keeps the attempt's
/// future alive; a generous number costs nothing since nothing blocks on it.
const CONNECT_BUDGET: Duration = Duration::from_secs(15);

/// `decide`'s choice between `Unreachable` and `Timeout` once ITS OWN outer
/// timeout elapses, pulled out as a pure function so the choice is testable
/// without a network (ledger 1430). `connected` is `self.connected`'s value at
/// that moment: true if the cache answered the last time anything asked it,
/// false otherwise.
fn elapsed_label(connected: bool) -> Degrade {
    if connected {
        Degrade::Timeout
    } else {
        Degrade::Unreachable
    }
}

/// The token bucket, over the shared cache.
pub struct Limiter {
    client: redis::Client,
    /// Populated on FIRST USE if nothing populates it sooner.
    ///
    /// The gateway must not wait on a downstream to bind its listener — the same
    /// rule `main.rs` states for `task`, and under D68 a pod stuck in startup is
    /// one the autoscaler cannot help. `get_or_try_init` does not cache the
    /// error, so a Valkey that comes back is picked up by the next call rather
    /// than needing a restart.
    ///
    /// **`main` also gives this a head start (ledger 1430).** It spawns
    /// [`Limiter::warm`] in the background right after this type is
    /// constructed, WITHOUT awaiting it — so boot still never waits on this
    /// field, exactly as it never did. All `warm` changes is which call ends
    /// up winning the race to populate it: the gateway's own spawned task, if
    /// Valkey answers before the first real request arrives, or that first
    /// request, exactly as before, if it does not.
    conn: OnceCell<ConnectionManager>,
    limits: Limits,
    timeout: Duration,
    script: redis::Script,
    /// What applies while `conn` cannot answer. See [`Floor`].
    floor: Floor,
    /// The cache hop's transport; `None` is the explicit `VALKEY_TLS_ENABLED="0"`.
    tls: Option<UpstreamTls>,
    /// Whether the LAST attempt through `conn` — the initial connect or a
    /// script invocation — actually reached the cache (ledger 1430).
    ///
    /// **NOT THE SAME QUESTION AS `conn.get().is_some()`**, and the difference
    /// is the point. `conn` never clears once populated, so "has a manager ever
    /// existed" stays true forever after the first success — including through
    /// an outage that outlives every connection that manager will ever hold.
    /// `decide` reads THIS flag, not `conn`, to choose between `Unreachable` and
    /// `Timeout` on its own outer timeout elapsing, because that choice is about
    /// whether the cache is live RIGHT NOW, which `conn`'s mere existence cannot
    /// answer once it is more than a few seconds old.
    connected: AtomicBool,
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
    ///
    /// `tls` is the cache hop's resolved, pre-validated transport (B-V3,
    /// ADR-0852) — `None` dials exactly as every deployment of this before
    /// B-V3 did. `Some` dials `rediss://` at [`TLS_PORT`] rather than at
    /// `addr`'s own port: the host half of `addr` still names the cache,
    /// but a TLS dial always reaches it on the cache's TLS listener, never
    /// on the plaintext one the address spells out.
    pub fn new(
        addr: &str,
        password: Option<&str>,
        limits: Limits,
        timeout: Duration,
        max_replicas: u32,
        tls: Option<UpstreamTls>,
    ) -> Result<Self, redis::RedisError> {
        use redis::IntoConnectionInfo;

        let info = match &tls {
            None => format!("redis://{addr}").into_connection_info()?,
            Some(_) => {
                // THE HOST HALF ONLY. `addr` is `host:port` (`rateLimit.addr`),
                // and the port half is never dialled under TLS: the cache's TLS
                // listener is the fixed port above, not whatever plaintext port
                // the address names.
                let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host);
                format!("rediss://{host}:{TLS_PORT}").into_connection_info()?
            }
        };
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
        let client = match &tls {
            None => redis::Client::open(info)?,
            Some(t) => {
                let certificates = transport::certificates(t)?;
                redis::Client::build_with_tls(info, certificates)?
            }
        };
        Ok(Self {
            client,
            conn: OnceCell::new(),
            limits,
            timeout,
            script: redis::Script::new(SCRIPT),
            floor: Floor::new(max_replicas),
            tls,
            connected: AtomicBool::new(false),
        })
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The config every connect THIS TYPE ever makes uses — the first one,
    /// whichever of [`Self::warm`] or [`Self::spend`] wins the race to make
    /// it, and every reconnect `redis`'s own `ConnectionManager` makes after.
    ///
    /// **ONE DEFINITION, because it is baked into the manager at construction
    /// and never re-read.** `redis::aio::ConnectionManager` clones this
    /// config into every future reconnect attempt for the manager's whole
    /// life (`aio/connection_manager.rs`'s `reconnect`), so a caller that built
    /// a DIFFERENT config for its own connect would leave every later call —
    /// including ones [`Self::spend`] makes through the SAME manager — running
    /// under that caller's budget instead of `self.timeout`'s. [`Self::warm`]
    /// gets a generous OUTER deadline of its own ([`CONNECT_BUDGET`]) for
    /// exactly this reason: bounding how long ITS task waits, never changing
    /// what the manager itself is configured with.
    fn connect_config(&self) -> ConnectionManagerConfig {
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
        let inner = self.timeout.mul_f32(0.66); // ADR-0569-EXCEPTION(CC): two thirds of the caller's own budget, not a tuning knob — see the comment above.
        ConnectionManagerConfig::new()
            .set_connection_timeout(Some(inner))
            .set_response_timeout(Some(inner))
            .set_number_of_retries(0) // ADR-0569-EXCEPTION(CC): zero because a retry inside one call is the wrong place for it — see the comment above.
    }

    /// Give the first connect a head start, in the background, without
    /// making boot wait on it (D69/ADR-0555, ledger 1430).
    ///
    /// **`main` SPAWNS THIS AND NEVER AWAITS THE HANDLE.** That is the whole
    /// of what makes it safe to call here: a gateway whose Valkey is down, or
    /// simply slow to answer, still binds its listener on schedule, exactly as
    /// it always has — `conn` is still a [`OnceCell`], [`Self::new`] still does
    /// no I/O, and this function changes nothing about either.
    ///
    /// **WHAT IT FIXES, AND WHAT IT DOES NOT.** This closes the COLD-START gap:
    /// without it, the very first `tools/call` on a freshly-rolled replica pays
    /// the connect itself. It does nothing for a Valkey that restarts once this
    /// replica is already warm — `conn` is already populated by then, and
    /// [`Self::spend`]'s own retry is what gives THAT case a chance to land
    /// before degrading, not this.
    pub async fn warm(&self) {
        let config = self.connect_config();
        let result = tokio::time::timeout(
            CONNECT_BUDGET,
            self.conn
                .get_or_try_init(|| self.client.get_connection_manager_with_config(config)),
        )
        .await;
        // THE FAILURE CASE DOES NOTHING — NOT PANIC, NOT LOG AT ERROR, NOT
        // RETRY: a Valkey that is down at boot and comes back before the
        // first real call is picked up by that call exactly as it always
        // was, which is `conn`'s own `get_or_try_init` not caching the
        // error. This task's only job was to get there first when it could.
        if let Ok(Ok(_)) = result {
            self.connected.store(true, Ordering::Relaxed);
        }
    }

    /// The cache hop's transport, or `None` for cleartext. `crate::rotate`
    /// builds the watch set from this — the resolved configuration, never a
    /// second read of the environment.
    pub fn tls(&self) -> Option<&UpstreamTls> {
        self.tls.as_ref()
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
            // looking for a slow cache rather than an absent one. `self.connected`,
            // not `self.conn.get().is_some()`, answers whether the LAST attempt
            // actually reached the cache — see the field's own comment for why
            // those are different questions once `conn` is more than a few
            // seconds old.
            Err(_elapsed) => elapsed_label(self.connected.load(Ordering::Relaxed)),
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
        let mut conn = self
            .conn
            .get_or_try_init(|| {
                self.client
                    .get_connection_manager_with_config(self.connect_config())
            })
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

        match self.invoke(&mut conn, key, bucket, ttl).await {
            Ok(decision) => {
                self.connected.store(true, Ordering::Relaxed);
                Ok(decision)
            }
            // RETRY EXACTLY ONCE, and ONLY on a connection-class failure
            // (ledger 1430). `invoke_async`'s OWN call above, inside
            // `ConnectionManager::send_packed_command`, already noticed the
            // dropped socket and kicked off a reconnect in the background
            // (`redis`'s `reconnect_if_dropped!` / `reconnect_if_io_error!`,
            // `aio/connection_manager.rs`) BEFORE returning this error — that
            // reconnect is already racing by the time control reaches here.
            // Calling `invoke` again on the SAME `conn` re-reads the manager's
            // (by now possibly already-swapped) current connection future and
            // AWAITS it, which is what actually gives that reconnect a chance
            // to land before this call reports degraded. Bounded by the
            // caller's own `tokio::time::timeout(self.timeout, ..)` in
            // `decide` — this retry carries no budget of its own.
            //
            // NOT RETRIED for `Unauthenticated`, `Timeout` or `Error`: a
            // rejected credential will not be accepted on a second try, and a
            // server that is merely slow or returning bad data is not the
            // "connection was dropped and is already being replaced" case this
            // retry exists for.
            Err(Degrade::Unreachable) => {
                self.connected.store(false, Ordering::Relaxed);
                let decision = self.invoke(&mut conn, key, bucket, ttl).await?;
                self.connected.store(true, Ordering::Relaxed);
                Ok(decision)
            }
            Err(degrade) => Err(degrade),
        }
    }

    /// The one read-compute-write against an already-connected `conn`, with no
    /// retry of its own — [`Self::spend`] decides whether to call this twice.
    async fn invoke(
        &self,
        conn: &mut ConnectionManager,
        key: &str,
        bucket: Bucket,
        ttl: u64,
    ) -> Result<Decision, Degrade> {
        let (allowed, _tokens, retry): (i64, String, String) = self
            .script
            .key(key)
            .arg(bucket.rate)
            .arg(bucket.burst)
            .arg(1.0)
            .arg(ttl)
            .invoke_async(conn)
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
    use super::{elapsed_label, Degrade};

    /// The mapping [`super::Limiter::decide`] applies to its OWN outer
    /// timeout elapsing, pulled out as a pure function so this is provable
    /// without a network (ledger 1430). MUTATION: inlining `true` or `false`
    /// for `connected` turns one arm or the other red.
    #[test]
    fn a_connection_that_has_answered_is_timed_out_an_absent_one_is_unreachable() {
        assert_eq!(elapsed_label(true), Degrade::Timeout);
        assert_eq!(elapsed_label(false), Degrade::Unreachable);
    }
}
