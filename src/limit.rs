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

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};

mod config;
mod floor;
mod valkey;

pub use config::{kind_str, Bucket, ConfigError, Limits, Overrides};
pub use valkey::Limiter;

/// The metric this module emits, over and above D67's three.
///
/// Bounded labels only: `reason` comes from [`Degrade`], a closed set of four,
/// and `outcome` is `allowed`, `throttled` or `refused` — whether the degraded
/// call proceeded on this replica's floor, was refused by it, or never reached it
/// because the cache rejected this gateway's credential. The second label is what
/// makes the floor observable, and the floor is accepted (see
/// [`Decision::Degraded`]) on the ground that it is not silent.
///
/// **`reason = "unauthenticated"` is the one to alert on**, and it is the only
/// value here that does not describe an outage. The other three end by
/// themselves; a rejected credential is a deployment somebody assembled wrong and
/// stays wrong until somebody changes it. It always carries `outcome = "refused"`,
/// because that case never takes the floor — see [`Decision::Unauthenticated`].
///
/// **The user is never a label here.** D72 and D77 both keep usernames out of
/// logs and metrics, and a per-user label on a degradation counter is exactly how
/// one gets in — it would also be unbounded, which D67 forbids for its own
/// reason.
pub const DEGRADED: &str = "yadgar_gateway_rate_limit_degraded_total";

/// The key prefix for this service's buckets in the shared cache (D21).
///
/// `gw:` names the service, `rl:` the concern — D77's expansion cache lands
/// alongside as `gw:exp:` rather than having to reorganise this one.
pub(super) const PREFIX: &str = "gw:rl";

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
pub(super) const KEY_TTL_SECONDS: f64 = 3600.0;

/// The user id, as a fixed-width component of a key in a SHARED cache.
///
/// **The id is caller-supplied and nothing bounded it.** `http::header` does
/// `to_str().ok()` and no more, so under `Attestation::TrustedHeaders` — off
/// by default; the shipped chart leaves `trustUnauthenticatedHeaders` at its
/// `values.yaml` default of `false`, so `YADGAR_TRUST_UNAUTHENTICATED_HEADERS`
/// is unset and `Attestation::from_lookup` resolves that to `Iam` instead —
/// this string is whatever the caller wrote.
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
/// The same digest, over a source address (task 497, ADR-0491).
///
/// **THROUGH [`user_component`] DELIBERATELY, RATHER THAN A SECOND HASH.** One
/// digest means one place the truncation width is chosen, and the collision
/// argument on that function — 128 bits leaves collision by accident out of
/// reach — is the argument this needs too.
///
/// The SIZE half of that comment does not apply: an `IpAddr` renders to at most
/// 45 characters, so nothing here needs bounding. The reason to hash anyway is
/// the other half. ADR-0491 records a source address in the audit store and only
/// there, and D21 puts one Valkey behind the whole system: a plaintext address in
/// a key would put it somewhere ADR-0491 does not allow it, readable by every
/// other tenant of that cache.
///
/// **The rotation residual on [`user_component`] does NOT carry over, which is
/// the point of keying here at all.** A caller rotating a user id mints a bucket
/// per id and escapes. It cannot rotate this: the value comes from the socket, or
/// from the entry a TRUSTED hop appended — `source::Source` never derives it from
/// text the caller wrote. That is what makes an address a usable key where an id
/// is not.
pub(super) fn address_component(addr: IpAddr) -> String {
    user_component(&addr.to_string())
}

pub(super) fn user_component(user_id: &str) -> String {
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
    /// The cache demanded a credential this process could not satisfy: it wanted
    /// a password and none was configured (`NOAUTH`), the one configured is wrong
    /// (`WRONGPASS`, or a failed handshake), or the user it names may not run the
    /// script (`NOPERM`).
    ///
    /// **Alone among these, it is not an outage**, and that is why it does not
    /// share their answer — see [`Decision::Unauthenticated`]. The other three
    /// describe a component that is absent, slow or confused, and all three end
    /// on their own. A rejected credential is a deployment that was assembled
    /// wrong; it will still be wrong on the next call, and on every call after
    /// that, until somebody changes the deployment.
    Unauthenticated,
}

impl Degrade {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::Error => "error",
            Self::Unauthenticated => "unauthenticated",
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
    /// The shared cache refused this process's credential. **The call does NOT
    /// proceed**, and this is the one answer here that is not a 429.
    ///
    /// # Why this one does not fail open
    ///
    /// The argument on [`Decision::Degraded`] is an argument about an OUTAGE: the
    /// least-available component in the installation must not become a hard
    /// dependency of every user-attributed call, because an outage ends and the
    /// floor bounds what happens meanwhile. Every clause of it depends on the
    /// failure being transient.
    ///
    /// A rejected credential is not transient. Nothing about it recovers, the
    /// floor would apply to every call for as long as the deployment stands, and
    /// the state it describes — a gateway talking to a cache that will not have
    /// it — is one somebody built by hand and can unbuild. Failing open here
    /// would mean an operator who set `requirepass` on the cache and forgot the
    /// Secret gets a gateway that serves traffic at `rate / maxReplicas` for ever
    /// while a counter nobody is watching says so. That is precisely the shape
    /// this whole change exists to remove: a control that reads healthy while
    /// enforcing nothing.
    ///
    /// **WHAT THE CACHE'S AUTHENTICATION IS, AND WHAT IT BUYS, IS ARGUED ONCE**
    /// — on `crate::attest::Credentials`, which names where each fact came from
    /// and points on to `tests/valkey_auth.rs` for the half this repository can
    /// measure on every pull request. Nothing here restates it. This arm needs
    /// only the narrow consequence: `requirepass` exists, so a WRONGPASS is a
    /// state a deployment can be in, and it is permanent.
    ///
    /// So it is loud and it is total. A 503 stops the deployment being usable,
    /// which is what makes it get fixed, and a 503 is also honest — this gateway
    /// genuinely cannot do the thing it is for.
    Unauthenticated,
}
#[cfg(test)]
mod tests;
