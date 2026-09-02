//! Caller identity, and the only place in the system a [`Scope`] is built.
//!
//! `yadgar/common/v1/common.proto` says of `Scope`: "attested by the gateway from
//! the request's credentials. Never supplied by the caller itself." That sentence
//! is a claim the contract makes on this module's behalf, and nothing else
//! enforces it — so it is enforced here, by there being exactly one constructor.
//!
//! **Why one function rather than a rule.** A rule spread across handlers can
//! only be asserted; a single construction site can be CHECKED — `grep 'Scope {'`
//! over this repository returns one hit, and a reviewer can confirm the property
//! in a second. That is the difference between a claim and an invariant. Two
//! identity sources did NOT become two literals: both arms call [`scope`], which
//! holds the only `Scope { … }` in the tree.
//!
//! **WHICH PART OF AN IDENTITY THE CALLER MAY STILL NAME.** ADR-0488 requires the
//! scope to be minted here and never supplied, and the three fields are not alike:
//!
//!   - `user_id` — RESOLVED, from the bearer token, through
//!     `iam.ResolveCredential`. A self-asserted username is forgeable by anyone
//!     holding any valid token, so under [`Attestation::Iam`] there is no header
//!     that can reach it. [`from_resolved`], which builds the scope on that path,
//!     takes no claimed user at all: the property is in the signature rather than
//!     in a rule.
//!   - `project_id` — CLAIMED, and legitimately so. It is a workspace fact, it
//!     changes as a person moves between checkouts, and a token cannot carry it.
//!   - `instance_id` — CLAIMED, for the same reason, and it is a session marker
//!     rather than an identity.
//!
//! **Why the SECURE source is the default.** This module used to refuse to boot
//! unless one of two variables was set, because the only available default was
//! trusting the caller. That is no longer the only one: iam-backed attestation is
//! implemented, so an unset environment now selects it, and
//! `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=1` is an explicit, named opt-OUT for
//! development. There is no unconfigured state left to refuse — a stronger reading
//! of D69 than the boot gate was, because a deployment can no longer reach the
//! trusting path by forgetting something.
//!
//! **THE LOOKUP IS CACHED, AND THE CACHE IS WHERE THE REVOCATION WINDOW LIVES.**
//! D72 and ADR-0491 both say the gateway reads a credential "through a cache keyed
//! on the token hash and invalidated by a broker event, never by calling iam per
//! request". Half of that is built here: the cache and the key. The broker event is
//! NOT built — ADR-0491 records the gap itself, and it is ledger 457/467 in `iam`.
//! Until it lands, [`Credentials::ttl`] is the ONLY thing that bounds how long a
//! revoked credential keeps working, which makes it a security parameter and not a
//! tuning knob. That is why the default is short, why a long one is refused at
//! boot, and why [`Credentials::forget_credential`] and
//! [`Credentials::forget_user`] exist and are called by nothing yet: the seam the
//! consumer will attach to is named, tested and visible, rather than a shape
//! somebody has to invent later.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};
// TOKIO'S CLOCK, NOT `std`'s, and the difference is what makes expiry testable.
// `tokio::time::Instant` reads the runtime's clock, so `#[tokio::test(start_paused
// = true)]` plus `tokio::time::advance` can move a cached entry past its TTL
// deterministically. With `std::time::Instant` the only way to observe an expiry
// is to sleep for it, which is the flaky test this repository does not write. In a
// build without tokio's `test-util` this is a thin wrapper over the same monotonic
// clock, so it costs nothing.
use tokio::time::Instant;
use tonic::transport::Channel;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::limit::{kind_str, Bucket, ConfigError, Overrides};
use crate::pb::yadgar::common::v1::Scope;
use crate::pb::yadgar::iam::v1::{
    iam_service_client::IamServiceClient, RateLimitOverride, ResolveCredentialRequest,
    ResolveCredentialResponse,
};

/// The environment variable is named for WHAT IT DOES, not for where it runs.
///
/// `DEV=1` tells a reader nothing about what it switches off. This name cannot be
/// set by accident and cannot be misread in a manifest.
const TRUST_HEADERS: &str = "YADGAR_TRUST_UNAUTHENTICATED_HEADERS";

/// How long one credential lookup may take before the call is answered without it.
///
/// **Much shorter than `/auth/login`'s, and the difference is which path it sits
/// on.** A login happens once per person per machine and pays for Argon2id; this
/// runs on EVERY `tools/call`, including `recall`, which D25 calls the
/// latency-critical path. A stalled `iam` must cost one bounded wait rather than
/// hold every request in the system open, so this is sized for a lookup that is
/// slow rather than for one that is expensive.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(5);

/// Why a request has no attested identity.
///
/// **The `Display` text is for the LOG.** `http::attest_answer` decides what the
/// caller is told, and for anything derived from `iam` that is a constant — the
/// same discipline `http::login_answer` follows, for the same reason: a message
/// that varied with the upstream would be a channel sitting behind a status line
/// that was deliberately made opaque.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("request is missing the {0} header, which identifies the caller")]
    MissingIdentity(&'static str),

    #[error("request carries no `Authorization: Bearer <token>` header")]
    MissingCredential,

    #[error("iam answered {0:?} to ResolveCredential")]
    Upstream(tonic::Code),

    #[error("the resolved credential carries a rate limit this gateway cannot enforce: {0}")]
    Unenforceable(#[from] ConfigError),
}

/// How this process decided who the caller is. Chosen ONCE at boot.
#[derive(Debug, Clone, Default)]
pub enum Attestation {
    /// A real credential, resolved against `iam`.
    ///
    /// **The default, and it names no address.** The channel is the one
    /// `AppState` already holds, built from `IAM_HOST`/`IAM_PORT`. Two settings
    /// that both read as "where iam is" is one too many, and the deleted
    /// `YADGAR_IAM_ADDR` was the second.
    #[default]
    Iam,
    /// Development only: identity is whatever the request says it is.
    TrustedHeaders,
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustedHeaders => write!(f, "UNAUTHENTICATED (headers trusted)"),
            Self::Iam => write!(f, "iam.ResolveCredential"),
        }
    }
}

impl Attestation {
    /// Decide the identity source.
    ///
    /// Called from `main` before the listener is bound. It no longer returns a
    /// `Result`: the only failure it could report was "nothing is configured", and
    /// that state is gone — an unset environment now selects the SECURE source
    /// rather than the trusting one.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the
    /// decision that picks between a verified credential and a header the caller
    /// wrote could not be tested at all without this.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        // Exactly "1". A permissive parse here — "0", "false", "no" all enabling
        // it — is how a setting meant to be off ends up on.
        if lookup(TRUST_HEADERS).as_deref() == Some("1") {
            return Self::TrustedHeaders;
        }
        Self::Iam
    }
}

/// What the caller said about itself, before any of it is believed.
///
/// Deliberately a separate type from [`Scope`]: it is impossible to pass one of
/// these where a scope is wanted, so "unverified claim" and "attested fact"
/// cannot be confused at a call site.
///
/// **The bearer token is NOT in here**, and that is the shape rather than an
/// oversight. This type is what the caller ASSERTS; a credential is a thing to be
/// verified, so it arrives at [`attest`] as its own argument and leaves as a
/// resolved answer.
#[derive(Debug, Default)]
pub struct Claimed<'a> {
    /// Read ONLY by [`Attestation::TrustedHeaders`]. Under `Iam` it is ignored
    /// rather than refused: clients already in flight send it, an ignored forged
    /// header is inert, and refusing one would add a rollout failure that buys
    /// nothing.
    pub user_id: Option<&'a str>,
    pub project_id: Option<&'a str>,
    pub instance_id: Option<&'a str>,
}

/// What one lookup established about the caller.
///
/// **Identity and spending limits together, because D74 says they travel
/// together**: `ResolveCredentialResponse` carries the per-user overrides, so the
/// gateway learns who you are and what you may spend in one lookup, invalidated
/// together. Two lookups would mean two cache lifetimes and a window in which a
/// tightened limit is not yet in force.
///
/// **THIS TYPE IS NOT WHAT [`Credentials`] HOLDS, and it must not be.** The
/// requirement is that identity and spending limits share one entry and one
/// lifetime, and they do — `ResolveCredentialResponse` carries both and is cached
/// as one value. What this type ADDS is per-request: `scope.request_id` is minted
/// per call (see [`crate::request_id`]), and `scope.project_id` and
/// `scope.instance_id` are the caller's own headers on this request. Caching a
/// composed `Attested` would serve one caller's correlation id and workspace to the
/// next caller holding the same token — a D12 scoping defect and a broken D67
/// join key, from a cache that looked like it was doing what it was asked. So the
/// cached value is what `iam` ANSWERED and this is composed from it every time.
#[derive(Debug)]
pub struct Attested {
    pub scope: Scope,
    /// The caller's per-user bucket overrides (D74).
    ///
    /// Filled from `ResolveCredentialResponse.rate_limit_overrides` on the `Iam`
    /// path, and EMPTY on the trusted-header path — where it is the honest answer
    /// rather than a stub, because no credential was resolved and no header could
    /// carry a limit. A caller who could name its own limits would raise them,
    /// which is the same reason `team_ids` is never taken from the caller.
    pub limits: Overrides,
}

/// The environment variable holding the cached lifetime of one resolution.
///
/// Named for the thing whose lifetime it is, in seconds, the same shape as
/// `YADGAR_RATE_LIMIT_TIMEOUT_MS` — the unit is in the name so a manifest cannot
/// be off by a thousand.
const CREDENTIAL_TTL: &str = "YADGAR_CREDENTIAL_TTL_SECONDS";

/// The default lifetime of a cached resolution, in seconds.
///
/// **Short, because it is the whole revocation bound.** With the broker event
/// unbuilt (ledger 457/467) a credential revoked in `iam` keeps working here for
/// up to this long, so the number is chosen against that cost rather than against
/// the hit rate. It buys almost all of the hit rate anyway: an agent making even
/// one call a second serves thirty of them per lookup, and raising this to `iam`'s
/// own 300 would multiply the revocation window by ten to buy the last few percent.
const DEFAULT_TTL_SECONDS: u64 = 30;

/// The largest lifetime this gateway will accept, in seconds.
///
/// **A refusal rather than a clamp**, for the reason `limit::validate` gives about
/// a limit nobody notices is gone: silently shortening a number an operator wrote
/// leaves them believing something that is not true. `iam` declares 300 as a live
/// credential's own lifetime, and a cache entry may not outlive the thing it
/// caches — so nothing above it could be honoured for a live entry in any case,
/// and for a REFUSED one it would be a revocation window measured in minutes with
/// no event able to close it.
const MAX_TTL_SECONDS: u64 = 300;

/// How many resolutions one replica holds, per outcome.
///
/// **Bounded, because the writer is UNAUTHENTICATED.** Attestation runs before
/// D74's limiter — the bucket keys on the resolved user, so there is nothing to
/// spend until the credential is resolved — which means a caller with no valid
/// token still decides how many entries this map gains. `limit::Floor` accepts the
/// same shape at the same size for the same reason. At roughly 400 bytes an entry
/// (a `Scope`'s five strings, the team list and a 32-byte key) two full maps are
/// about 3MB against the chart's 128Mi limit.
const CAPACITY: usize = 4096;

/// Whether the credential lookup was served from this replica's memory.
///
/// **Bounded labels only**: `outcome` is `hit` or `miss` and nothing else. The
/// token never appears, hashed or otherwise, and neither does the user — D72 and
/// D77 keep identities out of metrics, and this counter exists to answer one
/// operational question, which is whether the hop this cache was built to remove
/// is actually gone.
pub const CACHE: &str = "yadgar_gateway_credential_cache_total";

/// What `iam` answered for one token, and when this replica must ask again.
struct Entry {
    answer: ResolveCredentialResponse,
    expires_at: Instant,
}

/// Whether `iam`'s answer names a LIVE credential.
///
/// **One predicate, two readers, and that is deliberate.** [`from_resolved`]
/// refuses everything this rejects and [`Credentials`] files an answer by it, so a
/// future change to what counts as "resolved" cannot make the cache and the
/// security guard disagree — which would be a refusal filed as a success.
fn is_live(answer: &ResolveCredentialResponse) -> bool {
    !answer.user_id.is_empty() && answer.valid_for_seconds > 0
}

/// One replica's memory of what `iam` said about a token.
///
/// # Why in-process rather than in the shared cache
///
/// D21's Valkey is already a hard dependency of this service and would give one
/// place to invalidate, so this is a real choice and not a default. It is NOT what
/// D18 forbids: D18 governs cache-coherence MECHANISMS — "no invalidation signal
/// may be delivered in-process" — and says in as many words that it is "not a
/// standing ban on anything a replica holds alone". The invalidation signal here is
/// D22's broker event, which crosses replicas by construction; the map it will
/// evict from is local. Read wider than that, D18 would also forbid
/// `limit::Floor`, which the same paragraph exists to permit.
///
/// **THE DECIDING ARGUMENT IS THAT VALKEY IS UNAUTHENTICATED.** Read out of
/// `yadgarhq/deploy/infra/valkey/valkey.yaml`, which is the manifest that deploys
/// it: the container's whole `args` list is `--maxmemory 512mb --maxmemory-policy
/// allkeys-lru --save "" --appendonly no`, with **no `--requirepass`**, and
/// `grep -rn 'requirepass\|NetworkPolicy'` over the `deploy` repository matches
/// nothing at all. That is the declared state; no running cluster was inspected
/// for it. Anything on the pod network can therefore write
/// `valkey:6379`. For a rate-limit counter that costs a limit. For THIS cache the
/// entry maps a token hash to a `user_id` and a `team_ids` list, so anyone who can
/// write to that store can MINT AN IDENTITY — the same bypass class that was closed
/// when the gateway stopped trusting `x-yadgar-user`, reopened through a different
/// door. Nothing on this replica's own heap is reachable that way.
///
/// **The second argument is who writes the keys.** Attestation happens BEFORE
/// D74's limiter, so every entry here is minted by a request that has not proved
/// anything yet — a caller with no valid token chooses this keyspace's cardinality.
/// `limit.rs` already records what evicting another tenant of the shared cache
/// costs: "evicting D46's throttle counters is itself a limit bypass". Putting an
/// anonymously-writable keyspace in there turns a token-guessing flood into an
/// eviction attack on four other subsystems. A bounded map on this replica's own
/// heap contains the same flood to this replica's own memory, and [`CAPACITY`] is
/// the bound.
///
/// **What it costs, stated rather than discovered later, and sized against SIX
/// replicas** — `autoscaling.maxReplicas` in this chart, which the reference
/// deployment really does scale to. One token can miss once per replica, so `iam`
/// sees up to six lookups per TTL for one caller instead of one, and the load falls
/// by the request rate PER REPLICA rather than by the request rate overall. At the
/// autoscaler's own threshold of ten calls a second per replica and a 30 second
/// TTL, that is six lookups per 300 calls rather than 300 — the hop is gone in
/// every sense that matters, and the residual is a constant multiple of the replica
/// count rather than of the traffic.
///
/// And when the broker consumer is built it must run on EVERY replica — a fan-out
/// subscription, not a work queue with one consumer — or an eviction reaches one
/// pod and the others serve the revoked credential to its TTL. That requirement is
/// the price of this choice and is written on [`Credentials::forget_credential`]
/// where the consumer's author will read it.
///
/// **D80, applied to this decision.** Nothing here is a platform capability: no
/// ingress feature, no cloud service, no CRD, no operator. A process-local
/// `HashMap` behaves identically on EKS, AKS, GKE and kind, and the one setting an
/// operator has to make is a chart value they write rather than an environment
/// this code reads and trusts. The TTL default comes from the security argument —
/// how long a revoked credential may survive — and not from latency measured on
/// one cluster, because a number tuned against a single-node kind cluster with no
/// network between its pods would be a number correct nowhere else.
pub struct Credentials {
    /// How long one answer is reused. Zero disables the cache entirely.
    ttl: Duration,
    /// Answers that ATTESTED. Keyed by the SHA-256 of the presented token.
    live: Mutex<HashMap<[u8; 32], Entry>>,
    /// Answers that REFUSED, in their own map so that a flood of junk tokens
    /// cannot evict a single working identity. See [`Credentials::put`].
    refused: Mutex<HashMap<[u8; 32], Entry>>,
}

impl Credentials {
    /// The cache this process will use, from the environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same decision over an injected lookup, for the reason
    /// [`Attestation::from_lookup`] gives: a test that sets a real environment
    /// variable steers every other test in the same binary.
    ///
    /// **An unparseable value fails boot rather than falling back to the
    /// default.** That is D69 and it is `main.rs`'s existing rule for
    /// `YADGAR_RATE_LIMIT_TIMEOUT_MS`: a number nobody can read is a deployment
    /// mistake, and quietly substituting one leaves an operator believing a bound
    /// that is not in force.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let seconds = match lookup(CREDENTIAL_TTL).filter(|v| !v.is_empty()) {
            None => DEFAULT_TTL_SECONDS,
            Some(v) => v.parse::<u64>().map_err(|e| {
                format!(
                    "{CREDENTIAL_TTL} is not a whole number of seconds: {e}. It is how long \
                     one resolved credential is reused before iam is asked again, and 0 disables \
                     the cache."
                )
            })?,
        };
        if seconds > MAX_TTL_SECONDS {
            return Err(format!(
                "{CREDENTIAL_TTL} is {seconds}, above the {MAX_TTL_SECONDS} second ceiling. \
                 Nothing publishes the invalidation event this cache is supposed to be cleared \
                 by yet (ADR-0491, ledger 457), so this value is the ONLY bound on how long a \
                 revoked credential keeps working — and iam declares 300 seconds as a live \
                 credential's own lifetime, which a cache of it may not outlive."
            ));
        }
        Ok(Self::new(Duration::from_secs(seconds)))
    }

    /// A cache with an explicit lifetime. `Duration::ZERO` caches nothing.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            live: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
        }
    }

    /// The configured lifetime, for the line `main.rs` logs at boot.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Forget one credential, by the token itself.
    ///
    /// **NOTHING CALLS THIS YET, and that is the state of the world rather than an
    /// oversight.** ADR-0491 decides that revocation publishes a broker event and
    /// records in its own consequences that the publisher does not exist — filed as
    /// ledger 457, with 467 as the `iam` side. This is the seam that consumer
    /// attaches to, named and tested now so the shape is not invented under
    /// pressure later.
    ///
    /// **THE CONSUMER MUST RUN ON EVERY REPLICA.** The map is this pod's own (see
    /// the type comment), so a subscription that delivers each event to exactly one
    /// consumer — a work queue, a shared consumer group — evicts one pod and leaves
    /// every other one serving the revoked credential until its TTL. It needs
    /// fan-out delivery, and that is a property of how the subscription is
    /// declared, not of this function.
    ///
    /// It takes the TOKEN and not a hash, because the event will carry whatever
    /// `iam` holds and the key derivation belongs on this side of the boundary —
    /// the same argument `attest` already makes for not hashing before the RPC. If
    /// the event turns out to carry `iam`'s own stored hash instead, this is where
    /// that mismatch has to be resolved, and it is one function rather than a
    /// convention.
    pub fn forget_credential(&self, token: &str) {
        let key = fingerprint(token);
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
    }

    /// Forget every credential resolved to one user.
    ///
    /// The second half of D72's invalidation: "revocation OR TEAM CHANGE". A team
    /// change names a person, not a token, and this cache is keyed by token — so it
    /// is a scan rather than a lookup. That is affordable precisely because it is
    /// rare and [`CAPACITY`] is small; making it a lookup would need a second index
    /// maintained on the hot path to serve an event that arrives a few times a day.
    ///
    /// Unwired, for the same reason [`Credentials::forget_credential`] is, and it
    /// carries the same fan-out requirement.
    ///
    /// Only live answers are touched: a refusal carries no user to match.
    pub fn forget_user(&self, user_id: &str) {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, entry| entry.answer.user_id != user_id);
    }

    /// What `iam` last said about this token, if it may still be believed.
    fn get(&self, key: &[u8; 32], now: Instant) -> Option<ResolveCredentialResponse> {
        for map in [&self.live, &self.refused] {
            let mut entries = map.lock().unwrap_or_else(PoisonError::into_inner);
            match entries.get(key) {
                Some(entry) if entry.expires_at > now => return Some(entry.answer.clone()),
                // EXPIRED ENTRIES ARE REMOVED ON THE WAY PAST, not merely ignored.
                // Reading one as a miss and leaving it behind is how a map fills
                // with answers nobody will ever believe again, and then refuses to
                // cache the live ones because it is at capacity.
                Some(_) => {
                    entries.remove(key);
                }
                None => {}
            }
        }
        None
    }

    /// File one answer, under the outcome it is.
    ///
    /// **Two maps, so that a refusal can never evict an identity.** A caller with
    /// no credential at all can drive the refusal map to [`CAPACITY`] — it is
    /// reached before D74's limiter — and if the two shared one map that flood
    /// would push out every working session on the replica, turning a guessing run
    /// into a load amplifier on `iam` for everybody else. Separate budgets make
    /// that structurally impossible rather than unlikely.
    ///
    /// **At capacity, this answer is simply not cached.** Expired entries are swept
    /// first; if the map is still full, the request has already been answered
    /// correctly and the only thing lost is the next request's hit. The alternative
    /// — evicting somebody else to make room — is what lets a flood displace live
    /// entries, which is the property the split above exists to hold.
    ///
    /// **A live answer never outlives `iam`'s own declared lifetime.**
    /// `valid_for_seconds` is what `iam` says the credential is good for, so the
    /// entry expires at the sooner of that and the configured TTL. A refusal has no
    /// such number to honour — `iam` sends `valid_for_seconds: 0` with it — so it
    /// gets the configured TTL.
    ///
    /// **Why a refusal may hold the FULL TTL.** The error it could make is refusing
    /// a caller whose credential has become valid, and that is unreachable: `iam`
    /// mints the token string, so a given string cannot go from invalid to valid. A
    /// re-issued credential is a different string and therefore a different key.
    /// What remains is fail-CLOSED — a cached refusal refuses somebody who was
    /// already being refused — which is the safe direction for the one entry an
    /// unauthenticated caller can create.
    fn put(&self, key: [u8; 32], answer: ResolveCredentialResponse, now: Instant) {
        if self.ttl.is_zero() {
            return;
        }
        let (map, ttl) = if is_live(&answer) {
            let declared = Duration::from_secs(answer.valid_for_seconds.max(0) as u64);
            (&self.live, self.ttl.min(declared))
        } else {
            (&self.refused, self.ttl)
        };
        let mut entries = map.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= CAPACITY {
            entries.retain(|_, entry| entry.expires_at > now);
        }
        if entries.len() >= CAPACITY {
            return;
        }
        entries.insert(
            key,
            Entry {
                answer,
                expires_at: now + ttl,
            },
        );
    }
}

/// **SIZES AND THE TTL, NEVER THE CONTENTS.**
///
/// A derived `Debug` would print every cached identity — user ids and team lists —
/// the first time somebody put this struct in a `tracing` field or an `expect`
/// message. D72 and D77 keep identities out of logs, and the way that rule gets
/// broken is a derive nobody thought about rather than a deliberate line. The key
/// is already only a digest; this keeps the value out too.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("ttl", &self.ttl)
            .field(
                "live",
                &self
                    .live
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
            )
            .field(
                "refused",
                &self
                    .refused
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
            )
            .finish()
    }
}

/// The cache key: SHA-256 of the presented token.
///
/// **THE KEY IS THE HASH AND THE TOKEN IS NEVER STORED.** A map keyed on the token
/// itself puts live credentials into a core dump, a heap inspection and anything
/// that ever formats the key — and this is a process a debugger can attach to. The
/// full 256 bits rather than `limit::user_component`'s truncated 128: this key
/// decides WHO the caller is rather than which bucket they spend from, so a
/// collision is an impersonation and there is no length pressure to trade against.
fn fingerprint(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Resolve a token, through the cache.
///
/// `resolve` is the lookup itself, taken as a closure so this — the part that
/// decides whether `iam` is called at all — can be exercised against a fake that
/// COUNTS its calls. A test that only asserted the right identity came back would
/// pass with no cache at all.
///
/// **A miss under concurrency is not collapsed**, and that is a stated residual
/// rather than an oversight: two requests arriving with the same cold token both
/// call `iam`. Single-flighting them needs a per-key waiter map, which is a lock
/// held across an await on the hot path of every call — a worse risk than the
/// duplicate lookup, which is bounded by the number of in-flight requests for one
/// token and is a lookup this gateway made unconditionally until today.
async fn resolve_through<F, Fut>(
    cache: &Credentials,
    token: &str,
    resolve: F,
) -> Result<ResolveCredentialResponse, AttestError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<ResolveCredentialResponse, AttestError>>,
{
    let key = fingerprint(token);
    let now = Instant::now();
    if let Some(answer) = cache.get(&key, now) {
        metrics::counter!(CACHE, "outcome" => "hit").increment(1);
        return Ok(answer);
    }
    metrics::counter!(CACHE, "outcome" => "miss").increment(1);
    // ONLY AN ANSWER IS CACHED, never a failure to obtain one. An unreachable or
    // stalled `iam` is an outage of the upstream, and remembering it would turn a
    // transport blip into a bounded outage of its own — every caller refused until
    // the entry expired, long after `iam` came back.
    let answer = resolve().await?;
    cache.put(key, answer.clone(), now);
    Ok(answer)
}

/// Build the attested scope for one request.
///
/// `credential` is the `Authorization` header verbatim, and `request_id` is passed
/// in rather than read from the caller — see [`crate::request_id`].
///
/// The `iam` channel is borrowed rather than held on [`Attestation`] so the enum
/// stays a decision and not a resource. It is the same lazy channel `/auth/login`
/// uses; an `iam` that is not deployed yet costs a bounded failure per call rather
/// than a boot that never completes.
///
/// **`cache` IS ONLY REACHED ON THE `Iam` PATH**, because it is the only path that
/// resolves anything. A trusted header is not a credential and there is nothing to
/// remember about it.
pub async fn attest(
    how: &Attestation,
    iam: &Channel,
    cache: &Credentials,
    credential: Option<&str>,
    claimed: Claimed<'_>,
    request_id: String,
) -> Result<Attested, AttestError> {
    match how {
        Attestation::TrustedHeaders => Ok(Attested {
            limits: Overrides::default(),
            scope: scope(
                claimed
                    .user_id
                    .ok_or(AttestError::MissingIdentity("X-Yadgar-User"))?
                    .to_string(),
                claimed
                    .project_id
                    .ok_or(AttestError::MissingIdentity("X-Yadgar-Project"))?
                    .to_string(),
                claimed.instance_id.unwrap_or_default().to_string(),
                // Team membership comes from iam. Empty means "no team
                // visibility", which is the restrictive answer and the right
                // default while the only identity source is a header the caller
                // wrote.
                Vec::new(),
                request_id,
            ),
        }),

        Attestation::Iam => {
            let token = bearer(credential).ok_or(AttestError::MissingCredential)?;
            // THROUGH THE CACHE, which is D72's "on a cache miss, never per
            // request". Everything below the closure runs on a MISS only.
            let resolved = resolve_through(cache, token, || async {
                let mut client = IamServiceClient::new(iam.clone());
                let rpc = client.resolve_credential(ResolveCredentialRequest {
                    // As PRESENTED, never hashed here. The contract is explicit
                    // that hashing is `iam`'s job: a caller that hashed first would
                    // have to agree on the algorithm forever, and changing it would
                    // then be a breaking change to every caller rather than an
                    // implementation detail there. The CACHE key is a hash of the
                    // same token and is unrelated to it — that one never leaves
                    // this process, so nothing has to agree about it.
                    token: token.to_string(),
                });
                match tokio::time::timeout(RESOLVE_DEADLINE, rpc).await {
                    Ok(Ok(r)) => Ok(r.into_inner()),
                    // `e.code()` is kept and `e` is dropped. The message belongs in
                    // the log line `http` writes, not in an answer to a caller
                    // whose credential has just failed to resolve.
                    Ok(Err(e)) => Err(AttestError::Upstream(e.code())),
                    // Through the SAME variant as any other upstream problem, so a
                    // stall is not a third answer somebody has to remember to keep
                    // opaque.
                    Err(_elapsed) => Err(AttestError::Upstream(tonic::Code::DeadlineExceeded)),
                }
            })
            .await?;
            // ON EVERY REQUEST, hit or miss. The cache holds what `iam` ANSWERED,
            // and this is what turns that answer into an attestation — including
            // the refusal at the top of it. A cached refusal is re-refused here
            // rather than being remembered as an error, so the guard cannot be
            // skipped by a cache hit.
            from_resolved(
                resolved,
                claimed.project_id,
                claimed.instance_id,
                request_id,
            )
        }
    }
}

/// The attested identity, from a credential `iam` has already resolved.
///
/// **THERE IS NO CLAIMED-USER PARAMETER, and that is the security property.** The
/// user id can only come from `resolved`, so no later edit to [`attest`] can route
/// a header into it without changing this signature — a visible act, rather than a
/// line that looks like the two beside it. A rule saying "do not trust the header"
/// would have been as true and as easy to break.
///
/// `project_id` and `instance_id` ARE claimed, and stay so: a workspace is not a
/// fact about a credential, and the token cannot carry it.
///
/// **`iam` ANSWERS `Ok` FOR A CREDENTIAL THAT DOES NOT RESOLVE, and reading that
/// as a success is an authentication bypass.** `iam-db` returns an empty response
/// for a token that is unknown, revoked, expired, or belongs to a soft-deleted
/// person, and `iamdb.proto` says why in as many words:
///
/// > Empty user_id means no live credential matched. NOT an error: "no such
/// > credential" and "the store is broken" are different outcomes and a caller
/// > must be able to tell them apart — one is a 401, the other is a 503.
///
/// **THIS GATEWAY IS THE CALLER THAT OWES THE 401**, and nothing downstream would
/// catch a miss: no service checks for an empty `user_id` on a read path, and
/// every bypasser would share `user_id: ""`, collapsing D12's per-user scoping
/// into a single namespace. Revocation and expiry would both be inert. The check
/// belongs at this boundary because this is the last place the distinction still
/// exists.
///
/// **The rule is not in the proto this crate vendors**, which is how it was
/// missed: `yadgar/iam/v1/iam.proto` describes `user_id` only as "Identity and
/// AUTHORITY" and never documents the negative answer. Only `yadgar/iamdb/v1`
/// states it, and the gateway deliberately does not vendor that file — it is
/// `iam`'s own upstream, not this one's. So the rule is written down HERE, beside
/// the code that depends on it.
///
/// **TWO SIGNALS, and either one refuses.** `iam` sets
/// `valid_for_seconds: if resolved { 300 } else { 0 }`, so a negative answer
/// carries both an empty user and a zero lifetime. Checking both means an `iam`
/// that regresses on one of them is still refused rather than believed. The cost
/// of the second check, stated so that changing it stays deliberate: an `iam` that
/// later returned `valid_for_seconds: 0` on a VALID credential, to mean "do not
/// cache this one", would be refused here. Fail-closed is the right direction for
/// an identity check that has been bypassed once, and a gateway with no cache has
/// no use for a zero it cannot tell from a refusal.
fn from_resolved(
    resolved: ResolveCredentialResponse,
    claimed_project: Option<&str>,
    claimed_instance: Option<&str>,
    request_id: String,
) -> Result<Attested, AttestError> {
    if !is_live(&resolved) {
        // THROUGH THE UPSTREAM VARIANT, carrying the code `iam` would have used
        // had this outcome been an error, so it reaches `opaque_status` and
        // becomes the same 401 as any other refusal — no new variant, and no
        // answer that tells a caller working through stolen tokens which of them
        // exists.
        return Err(AttestError::Upstream(tonic::Code::Unauthenticated));
    }
    Ok(Attested {
        limits: overrides_from(resolved.rate_limit_overrides)?,
        scope: scope(
            resolved.user_id,
            claimed_project
                .ok_or(AttestError::MissingIdentity("X-Yadgar-Project"))?
                .to_string(),
            claimed_instance.unwrap_or_default().to_string(),
            // FROM THE RESPONSE, and reachable no other way. Teams decide what a
            // TEAM-visible record is readable by (D12), so a caller that could
            // name its own teams could read other people's records.
            resolved.team_ids,
            request_id,
        ),
    })
}

/// D74's per-user buckets, as this gateway's limiter keys them.
///
/// **An override that cannot be enforced REFUSES THE CREDENTIAL** rather than
/// being dropped — [`Overrides::from_pairs`] states the argument: skipping a
/// bucket silently applies the configured default instead, and for an override
/// that TIGHTENS a limit that is the limit-nobody-notices-is-gone shape.
///
/// **A deliberate `rate = 0, burst = 0` is the contract's way of saying DENY this
/// bucket, and it refuses the credential too.** That is broader than the contract
/// asks — the person loses every bucket rather than one — and it is the honest
/// answer available here: `limit::Bucket` has no representation for a denial, and
/// `limit::validate` refuses a zero rate because the script turns it into a
/// permanent lockout with a 24-hour `Retry-After`. Refusing loudly fails in the
/// direction the admin intended; applying the default would silently undo them. A
/// narrower denial needs a `Decision::Denied` in `limit.rs`, which is a change to
/// the script rather than to this mapping.
///
/// An entry whose `limit` is UNSET is skipped, on the contract's own instruction:
/// an unset limit is how an override is CLEARED, so one still in the list is a
/// server bug that "must be read as no override for that bucket rather than as a
/// denial". `unwrap_or_default()` is the plausible-looking line that reads it as
/// exactly the denial the contract says it is not.
fn overrides_from(list: Vec<RateLimitOverride>) -> Result<Overrides, ConfigError> {
    let mut pairs = Vec::with_capacity(list.len());
    for entry in list {
        // FIRST, BEFORE ANY OTHER CHECK ON THE ENTRY. A cleared override is not an
        // override at all, so nothing else about it can be wrong — and reaching a
        // refusal on its `kind` or its `module` first would turn "no override for
        // that bucket" into a denial of the whole credential, which is precisely
        // the reading the contract forbids.
        let Some(limit) = entry.limit else {
            continue;
        };
        let kind = Kind::try_from(entry.kind)
            .map_err(|_| ConfigError::UnknownKind(entry.kind.to_string()))?;
        // `kind_str` names all five and only three of them are buckets. D74 puts
        // KIND_JOB outside this mechanism and KIND_UNSPECIFIED is a zero value
        // nothing should construct, so either is a server bug rather than a
        // configuration this gateway can honour. Accepting one would mint a key
        // `Limits::effective` is never asked for — an override that looks applied
        // and is not.
        if !matches!(kind, Kind::Read | Kind::Write | Kind::Generate) {
            return Err(ConfigError::UnknownKind(kind_str(kind).to_string()));
        }
        if entry.module.is_empty() {
            return Err(ConfigError::Shape(format!(".{}", kind_str(kind))));
        }
        // The key `Limits::effective` looks a bucket up by, built exactly as
        // `Limits::parse` builds it. A key in any other shape is an override
        // nothing ever reads.
        pairs.push((
            format!("{}.{}", entry.module, kind_str(kind)),
            Bucket {
                rate: limit.rate,
                burst: f64::from(limit.burst),
            },
        ));
    }
    Overrides::from_pairs(pairs)
}

/// The ONE place a [`Scope`] is constructed.
///
/// Private, and it takes strings rather than headers or a response: everything
/// that decides WHERE a value came from has already happened by the time control
/// reaches here, so this function cannot be the place a claim is mistaken for a
/// fact. `grep 'Scope {' src/` returning one hit is what makes the contract's
/// claim checkable, and that grep points at this body.
fn scope(
    user_id: String,
    project_id: String,
    instance_id: String,
    team_ids: Vec<String>,
    request_id: String,
) -> Scope {
    Scope {
        user_id,
        project_id,
        // A session identifier, not an identity — D46 throttles on it and D39
        // addresses notices with it. Absent is legitimate: a one-shot client has
        // no session.
        instance_id,
        team_ids,
        request_id,
    }
}

/// The token out of an `Authorization` header, or nothing.
///
/// The scheme is compared case-insensitively because RFC 9110 says it is, and a
/// client sending `bearer` would otherwise be refused for a reason no error
/// message explains. An empty token after the scheme is no credential at all, and
/// is treated as one missing rather than sent upstream to be refused.
fn bearer(header: Option<&str>) -> Option<&str> {
    let (scheme, token) = header?.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::yadgar::iam::v1::RateLimit;

    /// A lookup over a fixed table, standing in for the process environment.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// A channel to a closed port.
    ///
    /// `connect_lazy` needs a reactor in scope even though it dials nothing, so
    /// every caller is a `#[tokio::test]`.
    fn nowhere() -> Channel {
        tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy()
    }

    /// **`..Default::default()` rather than a full literal, deliberately.**
    /// `ResolveCredentialResponse` gained two fields at contract v1.6.0, and an
    /// exhaustive literal in a fixture turns the next additive contract change
    /// into a compile error in a test that does not care about the new field.
    /// A LIVE credential, as `iam` returns one.
    ///
    /// `valid_for_seconds` is set explicitly and is load-bearing: `iam` writes
    /// `if resolved { 300 } else { 0 }`, and `from_resolved` refuses a zero. A
    /// fixture that left it at its `Default` would be the negative answer, and
    /// every test built on it would assert against a refusal.
    fn resolved(user_id: &str) -> ResolveCredentialResponse {
        ResolveCredentialResponse {
            user_id: user_id.to_string(),
            team_ids: vec!["team-a".to_string()],
            valid_for_seconds: 300,
            ..Default::default()
        }
    }

    #[test]
    fn only_the_exact_string_one_enables_trusted_headers() {
        // MUTATION THIS CATCHES: `== Some("1")` relaxed to `.is_some()`, or to any
        // truthiness parse. Under it, `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=0` —
        // written by somebody deliberately turning the setting OFF — turns
        // authentication off instead, and the gateway trusts whatever the caller
        // claims.
        assert!(matches!(
            Attestation::from_lookup(env(&[(TRUST_HEADERS, "1")])),
            Attestation::TrustedHeaders
        ));
        for off in ["0", "false", "no", "", "true", "yes"] {
            assert!(
                matches!(
                    Attestation::from_lookup(env(&[(TRUST_HEADERS, off)])),
                    Attestation::Iam
                ),
                "{off:?} must not enable trusted headers"
            );
        }
    }

    #[test]
    fn an_unset_environment_attests_against_iam() {
        // THE DIRECTION OF THIS TEST IS THE POINT, and it is the opposite of what
        // it used to assert. An unconfigured process once refused to start,
        // because the only default available was trusting the caller. The default
        // is the verified source now, so forgetting a variable can no longer reach
        // the trusting one — which is what makes the boot gate unnecessary rather
        // than merely removed.
        assert!(matches!(
            Attestation::from_lookup(env(&[])),
            Attestation::Iam
        ));
        assert!(matches!(Attestation::default(), Attestation::Iam));
    }

    #[test]
    fn the_user_comes_from_the_resolved_credential() {
        // A value no header in this process could have supplied and no default
        // could produce.
        let attested = from_resolved(
            resolved("u-from-the-token"),
            Some("acme/demo"),
            Some("i-1"),
            "REQ-1".to_string(),
        )
        .expect("a resolved credential attests");
        assert_eq!(attested.scope.user_id, "u-from-the-token");
        assert_eq!(attested.scope.request_id, "REQ-1");
        // CLAIMED, and still claimed: a workspace is not a fact about a credential.
        assert_eq!(attested.scope.project_id, "acme/demo");
        assert_eq!(attested.scope.instance_id, "i-1");
        // From the response, and reachable no other way (D12).
        assert_eq!(attested.scope.team_ids, vec!["team-a".to_string()]);
    }

    #[test]
    fn the_negative_answer_is_a_refusal_and_never_an_attestation() {
        // `iam` reports "no live credential" as `Ok` with an empty response, and
        // reading that as a success was an authentication bypass: `Bearer
        // <anything>` attested as `user_id: ""`. `iamdb.proto`: "Empty user_id
        // means no live credential matched. NOT an error… one is a 401, the other
        // is a 503." This gateway is the one that owes the 401.
        //
        // Asserted at the DEFAULT, which is the exact shape `iam` sends: an
        // `is_empty()` check written against a hand-built fixture would pass while
        // missing the response actually on the wire.
        let err = from_resolved(
            ResolveCredentialResponse::default(),
            Some("acme/demo"),
            None,
            "REQ-6".to_string(),
        )
        .expect_err("an unresolvable credential must not attest");
        assert!(
            matches!(err, AttestError::Upstream(tonic::Code::Unauthenticated)),
            "the negative answer is a refusal, not an outage; got {err:?}"
        );

        // EITHER SIGNAL ALONE REFUSES. `iam` writes both together today, and
        // checking both is what keeps a regression on one of them from being
        // believed.
        for answer in [
            ResolveCredentialResponse {
                user_id: String::new(),
                valid_for_seconds: 300,
                ..Default::default()
            },
            ResolveCredentialResponse {
                user_id: "u".to_string(),
                valid_for_seconds: 0,
                ..Default::default()
            },
        ] {
            assert!(
                matches!(
                    from_resolved(answer, Some("acme/demo"), None, "REQ-7".to_string()),
                    Err(AttestError::Upstream(tonic::Code::Unauthenticated))
                ),
                "half a negative answer is still a negative answer"
            );
        }
    }

    #[test]
    fn a_resolved_credential_without_a_project_is_refused_rather_than_defaulted() {
        // An empty project reads as "everything", not as "none": D12 scopes
        // records by it, so defaulting one is a widening nobody asked for.
        let err = from_resolved(resolved("u"), None, None, "REQ-2".to_string())
            .expect_err("a missing project must not become an empty one");
        assert!(matches!(err, AttestError::MissingIdentity(_)));
    }

    #[test]
    fn overrides_arrive_under_the_key_the_limiter_looks_them_up_by() {
        // MUTATION THIS CATCHES: keying on the proto's enum NAME (`Write`,
        // `KIND_WRITE`) instead of `kind_str`. Nothing fails — the override is
        // simply never found, and a limit an admin set does nothing at all. So
        // this asserts THROUGH `Limits::effective`, the only reader that matters,
        // rather than against the string this code chose for itself.
        let overrides = overrides_from(vec![RateLimitOverride {
            module: "task".to_string(),
            kind: Kind::Write as i32,
            limit: Some(RateLimit {
                rate: 3.0,
                burst: 7,
            }),
        }])
        .expect("a well-formed override is enforceable");
        let limits = crate::limit::Limits::parse("task.write=1:1", "1:1").expect("limits parse");
        let effective = limits.effective("task", Kind::Write, &overrides);
        assert_eq!(effective.rate, 3.0);
        assert_eq!(effective.burst, 7.0);
        // And the bucket NOBODY overrode still comes from configuration.
        assert_eq!(limits.effective("task", Kind::Read, &overrides).rate, 1.0);
    }

    #[test]
    fn an_override_that_cannot_be_enforced_refuses_the_whole_credential() {
        // `rate = 0` is the contract's DENY. `limit::validate` refuses it because
        // the script turns a zero rate into a permanent lockout with a 24-hour
        // `Retry-After`, so it cannot be honoured as written — and dropping it
        // would apply the configured default instead, silently undoing an admin.
        let err = overrides_from(vec![RateLimitOverride {
            module: "task".to_string(),
            kind: Kind::Write as i32,
            limit: Some(RateLimit {
                rate: 0.0,
                burst: 0,
            }),
        }])
        .expect_err("a bucket this gateway cannot enforce must not be dropped");
        assert!(matches!(err, ConfigError::NotPositive(_, _)));
    }

    #[test]
    fn an_entry_with_no_limit_is_no_override_and_not_a_denial() {
        // THE CONTRACT'S OWN INSTRUCTION: an unset `limit` is how an override is
        // CLEARED, so one still in the list is a server bug that "must be read as
        // no override for that bucket rather than as a denial". Reading it as a
        // denial is what `unwrap_or_default()` does — rate 0, burst 0 — and it
        // would refuse the credential outright.
        let overrides = overrides_from(vec![RateLimitOverride {
            module: "task".to_string(),
            kind: Kind::Write as i32,
            limit: None,
        }])
        .expect("a cleared override is not an error");
        assert!(overrides.is_empty());

        // AND NOTHING ELSE ABOUT A CLEARED ENTRY CAN BE WRONG, which is why the
        // `limit` check runs FIRST. It used to run after the kind and module
        // checks, so a cleared override carrying `KIND_JOB` — a server bug in a
        // field that no longer means anything — refused the whole credential,
        // turning "no override for that bucket" into exactly the denial the
        // contract says it must not be read as.
        let odd = overrides_from(vec![RateLimitOverride {
            module: String::new(),
            kind: Kind::Job as i32,
            limit: None,
        }])
        .expect("a cleared override is skipped before anything else is judged");
        assert!(odd.is_empty());
    }

    #[test]
    fn a_kind_this_gateway_has_no_bucket_for_is_refused() {
        // KIND_JOB is outside D74's mechanism and KIND_UNSPECIFIED is a zero value
        // nothing should construct. Accepting either mints a key
        // `Limits::effective` can never be asked for.
        for kind in [Kind::Job, Kind::Unspecified] {
            let err = overrides_from(vec![RateLimitOverride {
                module: "task".to_string(),
                kind: kind as i32,
                limit: Some(RateLimit {
                    rate: 1.0,
                    burst: 1,
                }),
            }])
            .expect_err("this kind has no bucket");
            assert!(matches!(err, ConfigError::UnknownKind(_)), "{kind:?}");
        }
    }

    #[tokio::test]
    async fn scope_carries_the_request_id_it_was_given() {
        let attested = attest(
            &Attestation::TrustedHeaders,
            &nowhere(),
            &Credentials::new(Duration::from_secs(30)),
            None,
            Claimed {
                user_id: Some("max"),
                project_id: Some("acme/demo"),
                instance_id: Some("i-1"),
            },
            "REQ-3".to_string(),
        )
        .await
        .expect("complete claim attests");
        assert_eq!(attested.scope.request_id, "REQ-3");
        assert_eq!(attested.scope.user_id, "max");
        // No override arrives on this path and none can: see `Attested::limits`.
        assert!(attested.limits.is_empty());
        // Team membership is never taken from the caller, and there is no header
        // that could carry it — this assertion exists so that adding one is a
        // deliberate act rather than an oversight.
        assert!(attested.scope.team_ids.is_empty());
    }

    #[tokio::test]
    async fn an_incomplete_claim_is_refused_rather_than_defaulted() {
        let err = attest(
            &Attestation::TrustedHeaders,
            &nowhere(),
            &Credentials::new(Duration::from_secs(30)),
            None,
            Claimed {
                user_id: None,
                project_id: Some("acme/demo"),
                instance_id: None,
            },
            "REQ-4".to_string(),
        )
        .await
        .expect_err("a missing user must not become an empty one");
        assert!(matches!(err, AttestError::MissingIdentity(_)));
    }

    #[test]
    fn a_bearer_token_is_the_only_credential_this_gateway_reads() {
        assert_eq!(bearer(None), None);
        assert_eq!(bearer(Some("token-with-no-scheme")), None);
        assert_eq!(bearer(Some("Basic dXNlcjpwdw==")), None);
        assert_eq!(bearer(Some("Bearer ")), None, "an empty token is none");
        assert_eq!(bearer(Some("Bearer t0ken")), Some("t0ken"));
        // RFC 9110 makes the scheme case-insensitive, and a client sending the
        // lowercase form would otherwise be refused for a reason no message
        // explains.
        assert_eq!(bearer(Some("bearer t0ken")), Some("t0ken"));
    }

    #[tokio::test]
    async fn a_credentialless_request_under_iam_never_reaches_the_upstream() {
        // The channel points at a closed port, so an RPC would take the transport
        // path and come back `Upstream`. `MissingCredential` proves the refusal
        // happened HERE — which is what keeps an unauthenticated flood off `iam`.
        let err = attest(
            &Attestation::Iam,
            &nowhere(),
            &Credentials::new(Duration::from_secs(30)),
            None,
            Claimed {
                user_id: Some("forged-by-the-caller"),
                project_id: Some("acme/demo"),
                instance_id: None,
            },
            "REQ-5".to_string(),
        )
        .await
        .expect_err("a header is not a credential");
        assert!(
            matches!(err, AttestError::MissingCredential),
            "a self-asserted user must not stand in for a token; got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // The cache (D72, ADR-0491).
    //
    // **EVERY ONE OF THESE COUNTS LOOKUPS.** A test that only asserted the right
    // identity came back would pass identically with no cache at all — it is a
    // check that cannot fail, which is the antipattern this repository has now
    // recorded five times. So the assertion is always on the COUNTER, and the
    // fixtures use values no default and no constant in this module could have
    // produced.
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A lookup that counts, standing in for the RPC.
    ///
    /// It is the closure [`resolve_through`] takes, so the code under test is the
    /// production path and only the transport is a fake.
    async fn through(
        cache: &Credentials,
        token: &str,
        calls: &AtomicUsize,
        answer: &ResolveCredentialResponse,
    ) -> ResolveCredentialResponse {
        resolve_through(cache, token, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(answer.clone())
        })
        .await
        .expect("the fake lookup answers")
    }

    /// A TTL long enough that nothing in a test expires by accident.
    const TEST_TTL: Duration = Duration::from_secs(30);

    #[tokio::test(start_paused = true)]
    async fn a_second_request_with_the_same_token_costs_iam_nothing() {
        // THE POINT OF THE WHOLE CHANGE, and the only assertion that can tell a
        // cache from no cache: the count, not the answer.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        // A user id no header, no default and no constant in this module could
        // have produced.
        let answer = resolved("u-9137-known-only-to-iam");

        let first = through(&cache, "tok-sentinel-alpha", &calls, &answer).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the first request must ask"
        );

        let second = through(&cache, "tok-sentinel-alpha", &calls, &answer).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second request must not reach iam at all"
        );
        assert_eq!(first.user_id, "u-9137-known-only-to-iam");
        assert_eq!(second.user_id, first.user_id);
        assert_eq!(second.team_ids, first.team_ids);
    }

    #[tokio::test(start_paused = true)]
    async fn two_tokens_are_two_entries_and_never_one() {
        // MUTATION THIS CATCHES: keying on anything that is not the token — the
        // claimed project, a constant, a truncation short enough to collide. Under
        // it the second caller is served the FIRST caller's identity, which is an
        // impersonation rather than a stale answer.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);

        let a = through(&cache, "tok-alpha", &calls, &resolved("u-alpha-4471")).await;
        let b = through(&cache, "tok-bravo", &calls, &resolved("u-bravo-8802")).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a different token is a different entry"
        );
        assert_eq!(a.user_id, "u-alpha-4471");
        assert_eq!(b.user_id, "u-bravo-8802");

        // AND EACH ONE STILL HITS ITS OWN. Two entries that both exist is not the
        // same property as two entries that are both reachable.
        assert_eq!(
            through(&cache, "tok-alpha", &calls, &resolved("u-must-not-be-used"))
                .await
                .user_id,
            "u-alpha-4471"
        );
        assert_eq!(
            through(&cache, "tok-bravo", &calls, &resolved("u-must-not-be-used"))
                .await
                .user_id,
            "u-bravo-8802"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "both were already known");
    }

    #[tokio::test(start_paused = true)]
    async fn the_entry_is_filed_under_the_tokens_hash_and_never_the_token() {
        // A map keyed on the token itself puts a live credential into every heap
        // dump of this process. Asserted against a digest computed HERE from the
        // token, which is a value this module's own code did not choose.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        through(&cache, "tok-charlie", &calls, &resolved("u-charlie-2265")).await;

        let expected: [u8; 32] = Sha256::digest(b"tok-charlie").into();
        let live = cache.live.lock().expect("not poisoned");
        assert_eq!(live.len(), 1);
        assert!(
            live.contains_key(&expected),
            "the entry must be filed under the token's digest"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_cached_credential_does_not_outlive_its_ttl() {
        // BOTH SIDES OF THE BOUNDARY, because "it expires eventually" is satisfied
        // by a cache that expires immediately, and that is not a cache. Paused time
        // rather than a sleep: deterministic, sub-second, no CI-load dependence.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        let answer = resolved("u-delta-5518");

        through(&cache, "tok-delta", &calls, &answer).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(TEST_TTL - Duration::from_millis(1)).await;
        through(&cache, "tok-delta", &calls, &answer).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "an entry inside its TTL is still served"
        );

        tokio::time::advance(Duration::from_millis(1)).await;
        through(&cache, "tok-delta", &calls, &answer).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "an entry at its TTL is gone, and the TTL is the whole revocation bound"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_cached_credential_never_outlives_iams_own_declared_lifetime() {
        // `valid_for_seconds` is what `iam` says the credential is good for, and a
        // cache of a thing may not outlive the thing. Five seconds is far below
        // TEST_TTL, so a cache that took its own TTL unconditionally would keep
        // serving this for another twenty-five.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        let answer = ResolveCredentialResponse {
            user_id: "u-echo-3390".to_string(),
            valid_for_seconds: 5,
            ..Default::default()
        };

        through(&cache, "tok-echo", &calls, &answer).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        through(&cache, "tok-echo", &calls, &answer).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "iam said five seconds; the configured thirty must not override it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_credential_is_remembered_and_is_still_a_refusal() {
        // TWO PROPERTIES IN ONE TEST, because they are the same decision. Caching
        // the negative is what stops a token-guessing flood being an unthrottled
        // amplifier onto `iam` — attestation runs before D74's limiter, so nothing
        // else throttles it. And a cached negative must NEVER become an
        // attestation: it is re-refused by `from_resolved` on every request,
        // whether it came from `iam` or from this map.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        // Exactly what `iam` sends for a token that is unknown, revoked or expired.
        let refusal = ResolveCredentialResponse::default();

        let first = through(&cache, "tok-guessed", &calls, &refusal).await;
        let second = through(&cache, "tok-guessed", &calls, &refusal).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a repeated junk token must not be a repeated lookup"
        );

        for answer in [first, second] {
            assert!(
                matches!(
                    from_resolved(answer, Some("acme/demo"), None, "REQ-8".to_string()),
                    Err(AttestError::Upstream(tonic::Code::Unauthenticated))
                ),
                "a cached refusal is still a refusal"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_cache_hit_composes_this_requests_workspace_and_correlation_id() {
        // **THE INVARIANT THAT DECIDES WHAT MAY BE CACHED AT ALL.** The entry holds
        // what `iam` ANSWERED — identity and spending limits, one value, one
        // lifetime — and `from_resolved` composes the per-request half on top of it
        // every time. Caching a composed `Attested` instead would serve the FIRST
        // caller's `request_id` and `project_id` to the second: a broken D67 join
        // key, and a D12 scoping widening into somebody else's workspace, from a
        // cache that looked like it was doing exactly what it was asked.
        //
        // Nothing else in this file reaches composition — every other cache test
        // stops at `resolve_through` — so without this the property is prose.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        let answer = resolved("u-november-6612");

        let first = from_resolved(
            through(&cache, "tok-shared", &calls, &answer).await,
            Some("acme/first"),
            Some("i-first"),
            "REQ-FIRST".to_string(),
        )
        .expect("a resolved credential attests");
        let second = from_resolved(
            through(&cache, "tok-shared", &calls, &answer).await,
            Some("zeta/second"),
            Some("i-second"),
            "REQ-SECOND".to_string(),
        )
        .expect("a cached credential attests too");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second request must be a hit, or this test proves nothing"
        );
        // SHARED, because it is what the credential resolved to.
        assert_eq!(second.scope.user_id, "u-november-6612");
        assert_eq!(second.scope.team_ids, first.scope.team_ids);
        // NOT SHARED, because these are facts about THIS request.
        assert_eq!(second.scope.project_id, "zeta/second");
        assert_eq!(second.scope.instance_id, "i-second");
        assert_eq!(second.scope.request_id, "REQ-SECOND");
        assert_ne!(first.scope.request_id, second.scope.request_id);
        assert_ne!(first.scope.project_id, second.scope.project_id);

        // AND D74'S BUCKET IS UNMOVED BY THE CLAIMED WORKSPACE. `limit::check` keys
        // on `scope.user_id`, which can only come from `resolved.user_id` — so a
        // caller changing its project header mints no new bucket, cache hit or not.
        assert_eq!(first.scope.user_id, second.scope.user_id);
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_of_refusals_cannot_deny_the_cache_to_a_real_credential() {
        // WHY THERE ARE TWO MAPS. The writer of a refusal is UNAUTHENTICATED —
        // attestation runs before D74's limiter — so a caller with no credential
        // chooses how many entries the refusal side gains. Sharing one map with the
        // live answers would let that caller fill it, and then every real
        // credential arriving afterwards would be uncacheable and would resolve
        // against `iam` on EVERY request: a guessing run turned into a load
        // amplifier on `iam` for everybody else, which is the failure this whole
        // change exists to stop.
        //
        // **THE FLOOD RUNS FIRST, AND THAT ORDERING IS THE TEST.** Written the
        // other way round — one live entry, then the flood — it passes under a
        // single shared map too, because nothing here evicts: the early entry
        // simply survives and the assertion holds for a reason that is not the
        // property. Confirmed by mutation rather than by reading: collapsing the
        // two maps into one left that ordering green, and leaves this one red.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        let refusal = ResolveCredentialResponse::default();
        for n in 0..CAPACITY + 64 {
            through(&cache, &format!("junk-{n}"), &calls, &refusal).await;
        }

        // A REAL CREDENTIAL, ARRIVING INTO THE FLOOD.
        through(&cache, "tok-foxtrot", &calls, &resolved("u-foxtrot-7724")).await;
        let after_first = calls.load(Ordering::SeqCst);
        assert_eq!(
            through(
                &cache,
                "tok-foxtrot",
                &calls,
                &resolved("u-must-not-be-used")
            )
            .await
            .user_id,
            "u-foxtrot-7724"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            after_first,
            "a real credential must still be cacheable while junk tokens flood in"
        );

        // AND THE FLOOD ITSELF IS BOUNDED. Past capacity the answer is simply not
        // cached; nothing is evicted to make room for it, so the memory an
        // unauthenticated caller can reach has a ceiling.
        assert!(
            cache.refused.lock().expect("not poisoned").len() <= CAPACITY,
            "the refusal map must not grow past its bound"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn forgetting_one_credential_sends_the_next_request_back_to_iam() {
        // THE INVALIDATION SEAM. Nothing calls it yet — ADR-0491 records that
        // revocation publishes no event, filed as ledger 457/467 — so this test is
        // what keeps it from rotting into a function that compiles and does
        // nothing.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        through(&cache, "tok-golf", &calls, &resolved("u-golf-6103")).await;
        through(&cache, "tok-hotel", &calls, &resolved("u-hotel-1547")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        cache.forget_credential("tok-golf");

        through(&cache, "tok-golf", &calls, &resolved("u-golf-6103")).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "the forgotten credential is resolved again"
        );
        through(&cache, "tok-hotel", &calls, &resolved("u-hotel-1547")).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "and nothing else was forgotten with it"
        );

        // A REFUSAL IS FORGETTABLE TOO, and it is on the other map — one that
        // cleared only the live side would leave a revocation half-applied.
        let refusal = ResolveCredentialResponse::default();
        through(&cache, "tok-india", &calls, &refusal).await;
        cache.forget_credential("tok-india");
        through(&cache, "tok-india", &calls, &refusal).await;
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn forgetting_a_user_evicts_every_token_that_resolved_to_them() {
        // D72's other invalidation: "revocation OR TEAM CHANGE". A team change names
        // a person and this cache is keyed by token, so one person's several tokens
        // must all go — leaving one behind means the stale team list is still being
        // served, which is the D12 read-scope defect the event exists to close.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        let same_person = resolved("u-juliet-2038");
        through(&cache, "tok-laptop", &calls, &same_person).await;
        through(&cache, "tok-desktop", &calls, &same_person).await;
        through(&cache, "tok-other", &calls, &resolved("u-kilo-9911")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        cache.forget_user("u-juliet-2038");

        through(&cache, "tok-laptop", &calls, &same_person).await;
        through(&cache, "tok-desktop", &calls, &same_person).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            5,
            "both of that person's tokens are resolved again"
        );
        through(&cache, "tok-other", &calls, &resolved("u-kilo-9911")).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            5,
            "somebody else's token was untouched"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_ttl_disables_the_cache_rather_than_caching_forever() {
        // THE REVERT PATH, and the direction it fails in is the point. `0` must
        // mean "ask every time", not "keep it until the process restarts".
        let cache = Credentials::new(Duration::ZERO);
        let calls = AtomicUsize::new(0);
        let answer = resolved("u-lima-8471");
        through(&cache, "tok-lima", &calls, &answer).await;
        through(&cache, "tok-lima", &calls, &answer).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a zero TTL means every request resolves"
        );
        assert!(cache.live.lock().expect("not poisoned").is_empty());
    }

    #[tokio::test]
    async fn an_upstream_failure_is_never_cached() {
        // A transport blip must not become a bounded outage of our own. If the
        // error were remembered, every caller holding that token would be refused
        // until the entry expired — long after `iam` came back.
        let cache = Credentials::new(TEST_TTL);
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            let err = resolve_through(&cache, "tok-mike", || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(AttestError::Upstream(tonic::Code::Unavailable))
            })
            .await
            .expect_err("the fake lookup fails");
            assert!(matches!(
                err,
                AttestError::Upstream(tonic::Code::Unavailable)
            ));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "an outage is retried, not remembered"
        );
    }

    #[test]
    fn the_cache_counter_reports_a_miss_and_then_a_hit() {
        // [`CACHE`] is the only way an operator can tell whether the hop this
        // change removed is actually gone, and a counter emitted under one label
        // only would show a permanent 100% miss rate — indistinguishable from a
        // cache that does not work. Asserted against a recorder rather than against
        // the call site, the way `DEGRADED`'s bounded labels already are.
        //
        // A LOCAL recorder rather than `install()`: a global one is process-wide
        // and this binary runs its tests in parallel, so installing here would race
        // every other test that emits a metric.
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime");
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let cache = Credentials::new(TEST_TTL);
                let calls = AtomicUsize::new(0);
                let answer = resolved("u-oscar-1180");
                through(&cache, "tok-oscar", &calls, &answer).await;
                through(&cache, "tok-oscar", &calls, &answer).await;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            });
        });

        // ONE SNAPSHOT, READ TWICE. `Snapshotter::snapshot` DRAINS the registry, so
        // taking one per label leaves the second looking at nothing — and the
        // assertion for whichever label was checked second fails while the counter
        // is being emitted perfectly well. Found by printing the snapshot rather
        // than by assuming the counter was wrong.
        let emitted = snapshotter.snapshot().into_vec();
        let counted = |want: &str| {
            emitted.iter().any(|(key, _, _, value)| {
                key.key().name() == CACHE
                    && key
                        .key()
                        .labels()
                        .any(|l| l.key() == "outcome" && l.value() == want)
                    && matches!(
                        value,
                        metrics_util::debugging::DebugValue::Counter(n) if *n >= 1
                    )
            })
        };
        assert!(counted("miss"), "the cold lookup must be counted as a miss");
        assert!(counted("hit"), "the served lookup must be counted as a hit");
    }

    #[test]
    fn the_ttl_is_read_from_the_environment_and_a_bad_one_fails_boot() {
        assert_eq!(
            Credentials::from_lookup(env(&[]))
                .expect("an unset environment takes the default")
                .ttl(),
            Duration::from_secs(DEFAULT_TTL_SECONDS)
        );
        assert_eq!(
            Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "7")]))
                .expect("seven seconds is usable")
                .ttl(),
            Duration::from_secs(7)
        );
        assert!(Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "0")]))
            .expect("zero is the documented way to disable the cache")
            .ttl()
            .is_zero());

        // AN EMPTY VALUE IS SET-BUT-USELESS, which a manifest reaches by
        // `value: ""`. It reads as unset rather than as an error — the same rule
        // `main.rs` applies to YADGAR_VALKEY_ADDR.
        assert_eq!(
            Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "")]))
                .expect("an empty value is unset")
                .ttl(),
            Duration::from_secs(DEFAULT_TTL_SECONDS)
        );

        // A NUMBER NOBODY CAN READ MUST NOT BECOME THE DEFAULT. Substituting one
        // leaves an operator believing a bound that is not in force — `main.rs`
        // already applies this rule to YADGAR_RATE_LIMIT_TIMEOUT_MS.
        for bad in ["30s", "thirty", "-1", "1.5"] {
            assert!(
                Credentials::from_lookup(env(&[(CREDENTIAL_TTL, bad)])).is_err(),
                "{bad:?} must not be accepted"
            );
        }
    }

    #[test]
    fn a_ttl_above_the_ceiling_is_refused_because_nothing_else_bounds_revocation() {
        // MUTATION THIS CATCHES: clamping instead of refusing. A clamp reads as
        // accepted, so an operator who wrote 3600 believes they got it — and the
        // one number that decides how long a revoked credential keeps working is
        // then a number nobody agreed on.
        assert!(
            Credentials::from_lookup(env(&[(CREDENTIAL_TTL, &MAX_TTL_SECONDS.to_string())]))
                .is_ok(),
            "the ceiling itself is usable"
        );
        let err = Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "3600")]))
            .expect_err("an hour-long revocation window must not be accepted silently");
        assert!(
            err.contains("457"),
            "the message must name the ledger task that closes the gap: {err}"
        );
    }
}
