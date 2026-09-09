//! D72's cache in front of the `iam` lookup: what is remembered, for how long,
//! and what evicts it.
//!
//! Split out of [`super`] for the file-size ceiling. The vocabulary this code
//! speaks — [`super::AttestError`], [`super::Attestation`] — stays in [`super`],
//! and so does the reasoning for the whole module.

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

use crate::pb::yadgar::iam::v1::ResolveCredentialResponse;

use super::AttestError;

/// The environment variable holding the cached lifetime of one resolution.
///
/// Named for the thing whose lifetime it is, in seconds, the same shape as
/// `YADGAR_RATE_LIMIT_TIMEOUT_MS` — the unit is in the name so a manifest cannot
/// be off by a thousand.
pub(super) const CREDENTIAL_TTL: &str = "YADGAR_CREDENTIAL_TTL_SECONDS";

/// The default lifetime of a cached resolution, in seconds.
///
/// **Short, because it is the revocation bound whenever the broker is not
/// reachable.** The invalidation event ([`crate::invalidate`]) is the mechanism and
/// this is its backstop, so the number is chosen against the cost of a missed event
/// rather than against the hit rate. It buys almost all of the hit rate anyway: an
/// agent making even one call a second serves thirty of them per lookup, and raising
/// this to `iam`'s own 300 would multiply that window by ten to buy the last few
/// percent.
pub(super) const DEFAULT_TTL_SECONDS: u64 = 30;

/// The largest lifetime this gateway will accept, in seconds.
///
/// **A refusal rather than a clamp**, for the reason `limit::validate` gives about
/// a limit nobody notices is gone: silently shortening a number an operator wrote
/// leaves them believing something that is not true. `iam` declares 300 as a live
/// credential's own lifetime, and a cache entry may not outlive the thing it
/// caches — so nothing above it could be honoured for a live entry in any case,
/// and for a REFUSED one it would be a revocation window measured in minutes with
/// no event able to close it.
pub(super) const MAX_TTL_SECONDS: u64 = 300;

/// How many resolutions one replica holds, per outcome.
///
/// **Bounded, because the writer is UNAUTHENTICATED.** Attestation runs before
/// D74's limiter — the bucket keys on the resolved user, so there is nothing to
/// spend until the credential is resolved — which means a caller with no valid
/// token still decides how many entries this map gains. `limit::Floor` accepts the
/// same shape at the same size for the same reason. At roughly 400 bytes an entry
/// (a `Scope`'s five strings, the team list and a 32-byte key) two full maps are
/// about 3MB against the chart's 128Mi limit. ADR-0522's setting adds a third
/// level to that estimate whose `team_override` map `common.proto` calls unbounded
/// in the team count — it is sparse by construction and, unlike the entry COUNT
/// above, it comes from `iam` rather than from the unauthenticated writer, so it
/// widens the figure without widening who decides it.
pub(super) const CAPACITY: usize = 4096;

/// Whether the credential lookup was served from this replica's memory.
///
/// **Bounded labels only**: `outcome` is `hit` or `miss` and nothing else. The
/// token never appears, hashed or otherwise, and neither does the user — D72 and
/// D77 keep identities out of metrics, and this counter exists to answer one
/// operational question, which is whether the hop this cache was built to remove
/// is actually gone.
pub const CACHE: &str = "yadgar_gateway_credential_cache_total";

/// What `iam` answered for one token, and when this replica must ask again.
pub(super) struct Entry {
    answer: ResolveCredentialResponse,
    expires_at: Instant,
}

/// Whether `iam`'s answer names a LIVE credential.
///
/// **One predicate, two readers, and that is deliberate.** [`from_resolved`]
/// refuses everything this rejects and [`Credentials`] files an answer by it, so a
/// future change to what counts as "resolved" cannot make the cache and the
/// security guard disagree — which would be a refusal filed as a success.
pub(super) fn is_live(answer: &ResolveCredentialResponse) -> bool {
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
/// **THE DECIDING ARGUMENT IS WHO WRITES THE KEYS.** Attestation happens BEFORE
/// D74's limiter, so every entry here is minted by a request that has not proved
/// anything yet — a caller with no valid token chooses this keyspace's cardinality.
/// `limit.rs` already records what evicting another tenant of the shared cache
/// costs: "evicting D46's throttle counters is itself a limit bypass". Putting a
/// keyspace an unauthenticated caller sizes into the one 512mb `allkeys-lru`
/// instance D21 shares with D17, D29, D46 and D52 turns a token-guessing flood
/// into an eviction attack on four other subsystems. A bounded map on this
/// replica's own heap contains the same flood to this replica's own memory, and
/// [`CAPACITY`] is the bound.
///
/// **It decides because it survives an AUTHENTICATED cache.** Two different
/// things in this module are called unauthenticated, and keeping them apart is
/// the whole of the argument. One is the CALLER that mints an entry — the sense
/// [`CAPACITY`] is bounded against, and one no deployment can change. The other
/// is the HOP to the cache, and that one is authenticated now. This gateway holds
/// the cache's password legitimately — `main.rs` reads it and logs whether it has
/// one — so the flood's writes would be authenticated writes made on behalf of an
/// unauthenticated caller, and every one of them would still evict somebody
/// else's key. A credential on the hop makes an eviction no less of an eviction.
///
/// **REACHABILITY IS A SUPPORTING ARGUMENT, AND A REDUCED ONE.** An entry here
/// maps a token hash to a `user_id` and a `team_ids` list, so anyone who can write
/// to that store can MINT AN IDENTITY — the same bypass class that was closed when
/// the gateway stopped trusting `x-yadgar-user`, reopened through a different
/// door. The same write against a rate-limit counter costs only a limit, and that
/// asymmetry is a property of what the entry MEANS rather than of any deployment.
/// The cache's `requirepass` (ledger 518) narrows who can reach the store. Three
/// things it cannot supply are why reachability still argues for a local map:
///
///   - It gates REACHABILITY, not what a writer may do once past the gate. A cache
///     that is compromised, or whose password leaks by any route, still serves
///     attacker-chosen values into the one branch that mints a `Scope`.
///   - It is ONE SHARED SECRET for every tenant rather than per-key authorisation,
///     so each future consumer of D21's cache becomes a full-write principal over
///     this keyspace and the blast radius grows with adoption.
///   - It authenticates the hop; it does not encrypt it. The `redis` client is
///     compiled with no TLS feature at all (`Cargo.toml`), so this is a
///     dependency change rather than a setting, and nothing on this hop is
///     confidential or integrity-protected in transit.
///   - The `valkey-ingress` NetworkPolicy is the hop's OTHER control and it is
///     the ONLY other one. `docs/plans/mtls-and-networkpolicy.md` measured the
///     estate hop by hop and rules on this one in as many words: valkey "has one
///     control, not two… It must not be described as defence in depth." A label
///     admits a pod, and anything that can create a pod carrying that label
///     passes it.
///
/// What it no longer does is decide the question by itself, which is why it is
/// second here rather than first.
///
/// **THIS PARAGRAPH IS THE ONE STATEMENT OF THE VALKEY HOP IN THIS CRATE, and
/// the other two places that need the fact point HERE rather than restating
/// it** — `limit::Decision::Unauthenticated` and the boot warning in `main`.
/// The facts were asserted in three places and named their source in one, which
/// is the arrangement that let a reader who checked the nearest copy feel
/// corroborated by a copy that had never been checked at all. The paragraph
/// below is the proof that the arrangement fails in practice rather than in
/// principle: the deciding fact changed in another repository and every copy of
/// it here stayed exactly as it was.
///
/// **AND THE ARGUMENT MAY NOT REST ON ANOTHER REPOSITORY'S MANIFEST.** This
/// paragraph used to, naming the absence of `--requirepass` in
/// `yadgarhq/deploy/infra/valkey/valkey.yaml` as the DECIDING fact. Ledger 518
/// then added `--requirepass` to that exact file, and the reasoning here went
/// stale with no line of this crate changing — the D80 mistake, made about a
/// decision rather than about a capability. Who mints the entries, and what an
/// entry means, hold on every cluster and on every CNI. What this repository
/// believes about the cache's authentication belongs in `tests/valkey_auth.rs`,
/// which changes in the same commit as the code that depends on it.
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
/// And the broker consumer runs on EVERY replica, because it has to: a work queue
/// with one consumer would evict one pod and leave the others serving the revoked
/// credential to its TTL. [`crate::invalidate`] subscribes with no queue group,
/// which is the fan-out delivery that requirement names.
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
    pub(super) live: Mutex<HashMap<[u8; 32], Entry>>,
    /// Answers that REFUSED, in their own map so that a flood of junk tokens
    /// cannot evict a single working identity. See [`Credentials::put`].
    pub(super) refused: Mutex<HashMap<[u8; 32], Entry>>,
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
                 This value is the bound on how long a revoked credential keeps working \
                 whenever the invalidation event is missed or the broker is unreachable \
                 (D72) — and iam declares 300 seconds as a live credential's own lifetime, \
                 which a cache of it may not outlive."
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
    /// **NO INVALIDATION EVENT REACHES THIS, and that is D72 rather than an
    /// omission.** `iam` holds a credential ID on a revoke and never sees the
    /// token, so neither published subject can name a key in this map — both land
    /// on [`Credentials::forget_user`] instead. This is the by-token eviction for
    /// a caller that holds the token itself.
    ///
    /// It takes the TOKEN and not a hash, because the key derivation belongs on
    /// this side of the boundary — the same argument `attest` already makes for
    /// not hashing before the RPC.
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
    /// **BOTH of D72's invalidation events land here** — `credential.revoked` as
    /// well as `user.teams-changed` — because both name a person and this cache is
    /// keyed by token. So it is a scan rather than a lookup. That is affordable
    /// precisely because it is rare and [`CAPACITY`] is small; making it a lookup
    /// would need a second index maintained on the hot path to serve an event that
    /// arrives a few times a day.
    ///
    /// It over-invalidates, dropping that person's other credentials' entries too.
    /// That costs one resolve each and is the safe direction to be wrong in; the
    /// alternative is a cache the event cannot address at all, which fails by
    /// leaving the revoked credential working. [`crate::invalidate`] is the caller.
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
pub(super) async fn resolve_through<F, Fut>(
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
