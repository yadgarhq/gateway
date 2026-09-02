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
//! `GET` then a `SET` from Rust, every caller racing inside that window reads
//! the same `tokens` and every one of them allows — so the limit is not
//! multiplied, it is GONE. Measured against a real Valkey on ONE replica: 200
//! concurrent callers against `burst = 20` were granted 200; the Lua script
//! granted 20. So it is a Lua script: one round trip, atomic by construction,
//! the same shape as D58's migration lock.
//!
//! The over-grant scales with callers racing in that window, NOT with the
//! replica count — one replica is enough to lose the limit entirely. D74 said
//! "multiplied by the replica count" and has been amended; that magnitude
//! belongs to a different defect, a per-replica in-process bucket, which is what
//! `Floor` below deliberately accepts in exchange for being bounded. The race
//! appears only under concurrency, which is why a sequential test cannot find
//! it, and why `tests/rate_limit.rs` drives concurrent callers at a real Valkey
//! and counts what was granted.
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
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

/// The metric this module emits, over and above D67's three.
///
/// Bounded labels only: `reason` comes from [`Degrade`], a closed set of three,
/// and `outcome` is `allowed` or `throttled` — whether the degraded call
/// proceeded on this replica's floor or was refused by it. The second label is
/// what makes the floor observable, and the floor is accepted (see
/// [`Decision::Degraded`]) on the ground that it is not silent.
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

/// How long a bucket key lives, **whatever bucket wrote it**.
///
/// # Why this is a constant and not `burst / rate`
///
/// An absent key is read as a full bucket, so a key must outlive the refill
/// window of whichever bucket READS it. Deriving the TTL from the bucket that
/// WROTE it is the same number only while one bucket does both. Loosen a limit —
/// a rolling deploy that changes `YADGAR_RATE_LIMITS`, or a per-user override
/// arriving from `iam` — and keys written under the old, shorter TTL expire
/// before the new refill window has elapsed, and the reader treats absent as
/// full. Measured against a real container before this was a constant: a key
/// drained under `0.5:5` and read twelve seconds later under `0.5:600` handed
/// over **600** tokens where **6** had accrued.
///
/// A TTL derived from the largest bucket the process knows about does not fix it
/// either, because during a rolling deploy the old process does not know the new
/// configuration. Only a lifetime that is a property of the DEPLOYMENT rather
/// than of the bucket survives that, which is what this is.
///
/// # Why an hour
///
/// It is the trade between this invariant and the key-count exposure below. The
/// invariant wants it large — every bucket's refill window must fit inside it,
/// which [`ConfigError::Unrefillable`] enforces at boot. The cache wants it
/// small: a caller under `Attestation::TrustedHeaders` mints one key per user id
/// it invents, and the shared cache runs `--maxmemory 512mb
/// --maxmemory-policy allkeys-lru` with four other subsystems in it. An hour is
/// the point where expiry roughly keeps pace with the rate at which a caller can
/// mint keys: at the autoscaler's own ceiling of six replicas times ten calls a
/// second, an hour of minting is about 216,000 keys, which at the ~150 bytes a
/// two-field hash costs is ~32MB — a slice of the cache rather than the whole of
/// it. A day would be twenty-four times that.
///
/// **The residual, stated rather than implied:** a bucket key still expires, so
/// this narrows the window rather than closing it. Raise the constant itself, or
/// configure a bucket whose refill window exceeds it, and the defect returns —
/// which is why the second of those is refused at boot rather than documented.
const KEY_TTL_SECONDS: f64 = 3600.0;

/// The user id, as a fixed-width component of a key in a SHARED cache.
///
/// **The id is caller-supplied and nothing bounded it.** `http::header` does
/// `to_str().ok()` and no more, so under `Attestation::TrustedHeaders` — which
/// the shipped chart enables — this string is whatever the caller wrote.
/// Measured against the built binary: a 4000-byte id produced a 4017-byte key.
/// `http.rs` already resolves `label` and `module` to bounded values before
/// anything is measured, for exactly this reason, and then the key took the raw
/// header.
///
/// The cache is the reason it matters. D21 puts one Valkey behind the whole
/// system and `deploy/infra/valkey/valkey.yaml` runs it `--maxmemory 512mb
/// --maxmemory-policy allkeys-lru`; the same instance holds D17's caches, D29's
/// conversation tokens, D46's throttle counters and D52's `last_seen_at`. Keys a
/// caller chose the size of evict OTHER tenants, and evicting D46's throttle
/// counters is itself a limit bypass.
///
/// **SHA-256, truncated to 128 bits.** A fast non-cryptographic hash would bound
/// the length just as well, and would let a user who can choose their own name
/// search offline for one whose bucket collides with somebody else's — throttling
/// a stranger. 128 bits leaves collision by accident out of reach.
///
/// **What this does NOT do**, because the difference is the whole finding: it
/// bounds a key's SIZE, not the NUMBER of keys. A caller rotating its id still
/// mints one bucket per id and is still not throttled. That half is inside D74's
/// accepted posture — "capacity protection, not authorisation" — and
/// `tests/rate_limit.rs` asserts it so it stays a decision rather than an
/// assumption.
fn user_component(user_id: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(user_id.as_bytes());
    let mut out = String::with_capacity(32);
    for byte in &digest[..16] {
        // Infallible into a String; the result is discarded rather than
        // unwrapped so a formatting error could never fail a call (D25).
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// One bucket's two numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bucket {
    /// Sustained refill, tokens per second.
    pub rate: f64,
    /// The bucket's size, and therefore the largest burst.
    pub burst: f64,
}

impl Bucket {
    /// How long this bucket takes to refill from empty.
    ///
    /// **This used to be the key's TTL, and that was wrong.** The reasoning is on
    /// [`KEY_TTL_SECONDS`]: the number is a property of the bucket that WROTE a
    /// key, and the correctness argument needs the bucket that READS it. What it
    /// is still good for is stating how long a bucket may take to come back, which
    /// is what [`ConfigError::Unrefillable`] bounds at boot.
    fn refill_seconds(&self) -> f64 {
        if self.rate <= 0.0 {
            return 0.0;
        }
        self.burst / self.rate
    }

    /// The TTL a key gets when this bucket writes it. Whole seconds, because
    /// `EXPIRE` takes whole seconds and a sub-second TTL rounds to zero, which
    /// would delete the key on every write.
    ///
    /// The `max` is belt and braces rather than a live branch: [`validate`]
    /// refuses a bucket whose refill window exceeds [`KEY_TTL_SECONDS`], on both
    /// the configured path and the override path, so this cannot exceed the
    /// constant today. It stays because the invariant it protects — a key
    /// outlives its reader's refill window — should not depend on a validation
    /// somewhere else staying correct.
    fn key_ttl_seconds(&self) -> u64 {
        KEY_TTL_SECONDS.max(self.refill_seconds()).ceil().max(1.0) as u64
    }
}

/// Refuse a bucket that cannot be enforced correctly, on EITHER path into one.
///
/// **`Limits::parse` validated and `Overrides::from_pairs` did not**, and the
/// unvalidated one is the path `iam` will drive. Traced through the script: a
/// `rate` of zero makes the Lua `(cost - tokens) / rate` evaluate to `inf`, which
/// comes back as the string `"inf"`, parses as `f64::INFINITY` and is clamped to
/// 86,400 — no panic anywhere, and a permanent lockout with a 24-hour
/// `Retry-After`.
fn validate(bucket: Bucket, whole: &str) -> Result<Bucket, ConfigError> {
    for (what, n) in [("rate", bucket.rate), ("burst", bucket.burst)] {
        if !n.is_finite() || n <= 0.0 {
            return Err(ConfigError::NotPositive(
                format!("{what} {n}"),
                whole.to_string(),
            ));
        }
    }
    let window = bucket.refill_seconds();
    if window > KEY_TTL_SECONDS {
        return Err(ConfigError::Unrefillable(whole.to_string(), window));
    }
    Ok(bucket)
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
    #[error(
        "{0:?} takes {1:.0}s to refill from empty, and a bucket key lives          {KEY_TTL_SECONDS:.0}s. Beyond that the key expires while the bucket is          still empty and the next call reads absent as FULL, which hands over the          whole burst. Raise `rate` or lower `burst`."
    )]
    Unrefillable(String, f64),
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
    validate(
        Bucket {
            rate: number(rate)?,
            burst: number(burst)?,
        },
        whole,
    )
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
    /// **The override wins, and its absence is not an error.** `iam` carries the
    /// per-user overrides on `ResolveCredentialResponse` (D74), `attest` maps them
    /// into [`Overrides`], and this merges them over the configured defaults —
    /// which is what "effective" means, and why one lookup answers both questions.
    /// Absence is the ordinary case rather than the only one: it is what a caller
    /// with no override gets, and what EVERY caller gets on the trusted-header
    /// path, where no credential is resolved.
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
/// **Filled from a resolved credential, and empty without one.** D74 puts the
/// per-user overrides on `ResolveCredentialResponse` so the gateway learns who you
/// are and what you may spend in one lookup, invalidated together;
/// `attest::attest` is the call site, and it maps the repeated field into this
/// type. On the trusted-header path it stays empty, which is the honest answer
/// rather than a stub: no credential was resolved, and no header could carry a
/// limit. Empty means the configured default applies — the deployment behaves
/// exactly as if no user had an override, which is then true.
#[derive(Debug, Clone, Default)]
pub struct Overrides(HashMap<String, Bucket>);

impl Overrides {
    /// Build from what a resolved credential carried, refusing what cannot be
    /// enforced.
    ///
    /// The call site is `attest::overrides_from`, and the input is the repeated
    /// field D74 describes. Taking `(module.kind, rate, burst)` pairs rather than
    /// a generated protobuf type keeps this module off the contract's schedule —
    /// which is what it bought: `iam.proto` gained the field and `attest.rs`
    /// gained the mapping, and nothing here changed.
    ///
    /// **Validated, because this is the path `iam` drives and it was the
    /// unvalidated one.** `Limits::parse` refuses a `rate` of zero and this did
    /// not; the effect was not a panic but a permanent lockout with a 24-hour
    /// `Retry-After` — see [`validate`].
    ///
    /// **The call site must refuse the credential, not drop the bad bucket.** An
    /// override that cannot be parsed is a limit somebody set on purpose, and
    /// skipping it silently applies the configured default instead — which for an
    /// override that TIGHTENS a limit is the limit-nobody-notices-is-gone shape
    /// D69 and this module's own `ConfigError` both exist to refuse. A refused
    /// credential is an unusable credential, and `attest` already has a shape for
    /// that.
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (String, Bucket)>,
    ) -> Result<Self, ConfigError> {
        pairs
            .into_iter()
            .map(|(pair, bucket)| Ok((pair.clone(), validate(bucket, &pair)?)))
            .collect::<Result<HashMap<_, _>, ConfigError>>()
            .map(Self)
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
    /// The shared store could not answer. **The call proceeds, under this
    /// replica's own floor** — see [`Floor`].
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
    /// **The failure shapes are not symmetric.** Fail closed during an outage:
    /// every caller gets 429, every client retries on the `retry-after` it was
    /// handed, and the retry storm outlives the outage that caused it. Fail open:
    /// a looping client writes faster than intended for the length of the outage,
    /// which is why it is floored rather than left alone.
    ///
    /// # Why a floor rather than nothing, which is the correction to what stood
    /// here
    ///
    /// This used to say an in-process bucket was "the per-replica bucket D74
    /// names as the defect and D18 forbids outright". **The D18 citation was
    /// wrong**, and it was load-bearing: D18 governs cache-coherence mechanisms —
    /// epochs, scope versions, per-id invalidation — and says nothing about
    /// rate-limit state. The borrowed absoluteness is what carried the rejection.
    ///
    /// It also used to say the fail-open cost was "bounded by `task`'s own
    /// capacity". **It is not.** A grep of `yadgarhq/task/src` finds no rate
    /// limit, no semaphore, no concurrency cap and no in-flight bound, so the
    /// phrase resolved to "bounded by MariaDB saturating" — which is the failure
    /// D74 exists to prevent, offered as the mitigation for it.
    ///
    /// What D74 actually objects to in a per-replica bucket is that **the
    /// configured number silently becomes a lie in the primary mechanism**. A
    /// degraded-mode floor is a different thing on each count. It is not silent:
    /// [`DEGRADED`] counts every degraded call under its reason and its outcome,
    /// and a warning is logged. It is not permanent: the connection is a
    /// `OnceCell` that does not cache its error, so a Valkey that comes back is
    /// picked up by the next call with no restart. And it is not unbounded: at
    /// `maxReplicas` replicas each holding `rate / maxReplicas`, the aggregate
    /// never exceeds the configured rate.
    ///
    /// **The condition is that this is LOUD.** A silent fail-open is the D76
    /// shape: a dead mechanism that reads healthy.
    Degraded(Degrade),

    /// The shared store could not answer AND this replica's floor is empty.
    ///
    /// A 429, like [`Decision::Throttled`], and deliberately indistinguishable
    /// from one to a client: the correct client behaviour is the same. It is
    /// distinguished to an OPERATOR, by [`DEGRADED`] carrying `outcome` —
    /// otherwise a floor that has started refusing real traffic is invisible, and
    /// "not silent" is the whole ground on which the floor is accepted above.
    DegradedThrottled {
        reason: Degrade,
        retry_after: Duration,
    },
}

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
struct Floor {
    replicas: f64,
    entries: Mutex<HashMap<String, Local>>,
}

/// How many distinct callers one replica tracks while degraded.
const FLOOR_CAPACITY: usize = 4096;

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
    fn new(replicas: u32) -> Self {
        Self {
            replicas: f64::from(replicas.max(1)),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Spend one token from the local floor, or say how long until there is one.
    ///
    /// `now` is injected so the arithmetic is testable without sleeping.
    fn check(&self, key: &str, bucket: Bucket, now: Instant) -> Result<(), Duration> {
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
    /// What applies while `conn` cannot answer. See [`Floor`].
    floor: Floor,
}

impl Limiter {
    /// `addr` is `host:port`. No I/O happens here.
    ///
    /// `max_replicas` is the largest number of replicas of this Deployment the
    /// autoscaler may run, and it is the divisor of the degraded-mode floor —
    /// see [`Floor`]. It is a parameter rather than a constant because the
    /// authority for it is the chart.
    pub fn new(
        addr: &str,
        limits: Limits,
        timeout: Duration,
        max_replicas: u32,
    ) -> Result<Self, redis::RedisError> {
        Ok(Self {
            client: redis::Client::open(format!("redis://{addr}"))?,
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
        let reason = match tokio::time::timeout(self.timeout, self.spend(&key, bucket)).await {
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
        // DEGRADED, AND FLOORED. The call proceeds on this replica's own share
        // rather than unlimited — the argument is on `Decision::Degraded`.
        match self.floor.check(&key, bucket, Instant::now()) {
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
            .map_err(|_| Degrade::Unreachable)?
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
        )])
        .expect("a usable override");
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
            // A bucket that takes longer to refill than a key lives. The key
            // expires while the bucket is still empty, and the next call reads
            // absent as FULL — the whole burst, handed over. Refused at boot
            // rather than documented, because there is no correct value of
            // KEY_TTL_SECONDS that covers an arbitrary one.
            "task.write=0.001:100",
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
    fn a_keys_lifetime_does_not_depend_on_the_bucket_that_wrote_it() {
        // MUTATION THIS CATCHES: `key_ttl_seconds` going back to
        // `refill_seconds().ceil()`. Under it the TTL is the writer's number
        // while correctness needs the reader's, so loosening a limit lets keys
        // written under the old one expire early and be read as full buckets.
        // Measured against a real container before the fix: 600 tokens handed
        // over where 6 had accrued.
        let tight = Bucket {
            rate: 0.5,
            burst: 5.0,
        };
        let loose = Bucket {
            rate: 0.5,
            burst: 600.0,
        };
        assert_eq!(tight.refill_seconds(), 10.0, "ten seconds apart as buckets");
        assert_eq!(loose.refill_seconds(), 1200.0);
        assert_eq!(
            tight.key_ttl_seconds(),
            loose.key_ttl_seconds(),
            "and the SAME lifetime as keys, or the tighter one's key expires \
             before the looser one's refill window has elapsed"
        );
        assert_eq!(tight.key_ttl_seconds(), KEY_TTL_SECONDS as u64);
    }

    #[test]
    fn every_configurable_bucket_refills_inside_a_keys_lifetime() {
        // The invariant the constant rests on, checked rather than assumed: no
        // bucket that PARSES may outlive the key it writes. If one could, the
        // TTL would have to vary again and the defect above would return.
        for spec in [
            "task.write=2:120",
            "task.read=20:600",
            "memory.write=0.5:600",
            "recall.read=10:300",
        ] {
            let limits = Limits::parse(spec, "10:300").expect("{spec} parses");
            for bucket in limits.per_pair.values().chain([&limits.fallback]) {
                assert!(
                    bucket.refill_seconds() <= KEY_TTL_SECONDS,
                    "{spec}: a bucket that outlives its key would be refused"
                );
                assert_eq!(bucket.key_ttl_seconds(), KEY_TTL_SECONDS as u64);
            }
        }
    }

    #[test]
    fn a_caller_cannot_choose_the_size_of_its_key_in_the_shared_cache() {
        // MUTATION THIS CATCHES: the key taking the raw header again. The id is
        // caller-supplied under `Attestation::TrustedHeaders`, and the key lands
        // in the one Valkey D21 shares with D17, D29, D46 and D52 under
        // `allkeys-lru` — so a caller who picks the key size evicts other
        // tenants' entries, and evicting D46's throttle counters is itself a
        // limit bypass. Measured before the fix: a 4000-byte id, a 4017-byte key.
        let short = user_component("max");
        let huge = user_component(&"x".repeat(4000));
        assert_eq!(short.len(), 32, "128 bits of SHA-256, as hex");
        assert_eq!(huge.len(), short.len(), "whatever the caller wrote");
        assert!(
            short.chars().all(|c| c.is_ascii_hexdigit()),
            "and nothing of the caller's own bytes survives into the key"
        );
        assert_ne!(short, user_component("ada"), "two callers, two buckets");
        // The same id is the same bucket on every replica, which is the whole
        // point of putting it in a shared store.
        assert_eq!(short, user_component("max"));
        // A colon in the id must not be able to forge another component: the
        // hash is hex, so no separator can survive it.
        assert!(!user_component("max:task:write").contains(':'));
    }

    #[test]
    fn an_override_is_validated_like_a_configured_limit() {
        // TRACED, not guessed: `rate = 0` makes the Lua `(cost - tokens) / rate`
        // evaluate to `inf`, which returns as the string "inf", parses as
        // f64::INFINITY and is clamped to 86_400. No panic — a permanent lockout
        // with a 24-hour Retry-After, on the path `iam` will drive.
        for bad in [
            Bucket {
                rate: 0.0,
                burst: 20.0,
            },
            Bucket {
                rate: -1.0,
                burst: 20.0,
            },
            Bucket {
                rate: 2.0,
                burst: 0.0,
            },
            Bucket {
                rate: f64::NAN,
                burst: 20.0,
            },
            Bucket {
                rate: f64::INFINITY,
                burst: 20.0,
            },
            // Refills more slowly than its key lives, exactly as on the
            // configured path.
            Bucket {
                rate: 0.001,
                burst: 100.0,
            },
        ] {
            assert!(
                Overrides::from_pairs([("task.write".to_string(), bad)]).is_err(),
                "{bad:?} must be refused on the override path too"
            );
        }
        assert!(Overrides::from_pairs([(
            "task.write".to_string(),
            Bucket {
                rate: 2.0,
                burst: 20.0
            }
        )])
        .is_ok());
    }

    #[test]
    fn a_degraded_call_is_held_to_this_replicas_share_and_not_to_the_whole_limit() {
        // THE ARITHMETIC THE FLOOR RESTS ON. Twelve tokens a second over six
        // replicas is two a second each, so six replicas sum to the configured
        // twelve and never more — which is the difference between this and the
        // per-replica bucket D74 rejects, where each replica would hold twelve.
        let floor = Floor::new(6);
        let bucket = Bucket {
            rate: 12.0,
            burst: 12.0,
        };
        let t0 = Instant::now();

        for n in 1..=2 {
            assert!(
                floor.check("k", bucket, t0).is_ok(),
                "spend {n} of this replica's burst of 2"
            );
        }
        let wait = floor
            .check("k", bucket, t0)
            .expect_err("the floor is empty");
        assert!(
            wait > Duration::from_millis(400) && wait < Duration::from_millis(600),
            "a floor of 2/s is half a second from its next token; got {wait:?}"
        );

        // It refills at rate/replicas, from elapsed time, exactly as the shared
        // bucket does — no fresh allowance on the next call.
        assert!(floor
            .check("k", bucket, t0 + Duration::from_millis(500))
            .is_ok());
        assert!(floor
            .check("k", bucket, t0 + Duration::from_millis(500))
            .is_err());

        // And it is keyed, so one caller draining it does not refuse another.
        assert!(floor.check("other", bucket, t0).is_ok());
    }

    #[test]
    fn a_burst_smaller_than_the_replica_count_still_grants_one_call() {
        // Two over six replicas is a third of a token, and a floor that granted
        // nothing would turn the fail-OPEN decision into a fail-closed one by
        // arithmetic. The cost is stated on `Floor`: for a configured burst below
        // the replica count, the aggregate degraded burst can reach the replica
        // count rather than the configured burst. Bounded, and small.
        let floor = Floor::new(6);
        let tiny = Bucket {
            rate: 2.0,
            burst: 2.0,
        };
        assert!(floor.check("k", tiny, Instant::now()).is_ok());
    }

    #[test]
    fn the_degraded_map_is_bounded_and_refuses_rather_than_growing() {
        // THE KEY CARRIES A CALLER-SUPPLIED USER ID, so an unbounded map here
        // would be the same defect as an unbounded key, moved into the process.
        let floor = Floor::new(1);
        // A bucket that takes an hour to refill, so nothing sweeps out.
        let slow = Bucket {
            rate: 1.0,
            burst: 3600.0,
        };
        let t0 = Instant::now();
        for n in 0..FLOOR_CAPACITY {
            assert!(floor.check(&format!("caller-{n}"), slow, t0).is_ok());
        }
        assert!(
            floor.check("one-too-many", slow, t0).is_err(),
            "a new caller past the cap is REFUSED, not allowed untracked — refusing is the \
             safe direction and untracked would be a bypass"
        );
        // A caller already tracked is unaffected: the cap bounds how many are
        // remembered, not how the remembered ones are treated.
        assert!(floor.check("caller-0", slow, t0).is_ok());

        // AND THE SWEEP IS WHAT KEEPS IT USABLE. Every entry has refilled to full
        // an hour later, and a full entry holds exactly what an absent one would,
        // so dropping it changes no answer.
        assert!(floor
            .check("one-too-many", slow, t0 + Duration::from_secs(7200))
            .is_ok());
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
