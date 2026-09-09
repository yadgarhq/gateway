//! Boot phases 1, 2 and 4: what this process reads out of its environment.
//!
//! Each function is ONE CONTIGUOUS RUN of what `main` already did — see
//! [`super`]. No environment read is reordered here, so the same broken input
//! produces the same FIRST refusal it produced before the split.

use std::path::PathBuf;
use std::time::Duration;

use yadgar_gateway::attest::{Attestation, Credentials};
use yadgar_gateway::http::CredentialLimits;
use yadgar_gateway::invalidate::Broker;
use yadgar_gateway::limit::{Limiter, Limits};
use yadgar_gateway::source::TrustBoundary;

use super::{env_required, env_required_allow_empty, parse_bucket_env, trusted_proxy_hops};

type Boxed = Box<dyn std::error::Error>;

/// PHASE 1. Who this process will believe, and what it remembers about them.
///
/// Attestation FIRST — see `main`'s module comment. The credential cache and the
/// broker that invalidates it are read here too, so a half-configured broker
/// credential exits at boot with the rest of the configuration mistakes. The
/// broker CONNECTION is made later, in [`super::start_invalidation`], once there
/// is a cache to hand it.
pub fn identity() -> Result<(Attestation, Credentials, Duration, Option<Broker>), Boxed> {
    // FIRST. See the module comment.
    let attestation = Attestation::from_env();
    match &attestation {
        // A WARNING, and it stays one. This is the development path: the caller's
        // own headers name the caller, verified by nothing.
        Attestation::TrustedHeaders => tracing::warn!(
            "identity is UNAUTHENTICATED: caller-supplied headers are trusted. \
             Development only — unset YADGAR_TRUST_UNAUTHENTICATED_HEADERS to \
             resolve the bearer token against iam instead."
        ),
        // INFO, because this is the ordinary case now. It used to be a warning
        // saying the source was not implemented.
        source => tracing::info!(%source, "attesting caller identity from the bearer token"),
    }

    // D72's cache in front of that lookup. A bad value EXITS rather than falling
    // back to the default, for the same reason a bad rate limit does: it bounds how
    // long a revoked credential keeps working whenever the invalidation event below
    // is missed, and an operator who wrote a number should never be silently given
    // another.
    let credentials = Credentials::from_env()?;
    let ttl = credentials.ttl();
    if ttl.is_zero() {
        tracing::warn!(
            "the credential cache is DISABLED (YADGAR_CREDENTIAL_TTL_SECONDS=0), so every \
             tools/call resolves its bearer token against iam. Identity is then a per-request \
             round trip and an iam outage stops all MCP traffic — which is what D72's cache \
             exists to prevent. NO INVALIDATION IS CONSUMED either, and the broker is not \
             dialled at all: an event names a person whose cached answer does not exist."
        );
    }
    // What clears that cache when `iam` says an identity has changed (D72). READ
    // HERE, so a half-configured broker credential exits at boot with the rest of
    // the configuration mistakes; the CONNECTION is made further down, once there
    // is a cache to hand it.
    let broker = yadgar_gateway::invalidate::Broker::from_env()?;
    Ok((attestation, credentials, ttl, broker))
}

/// PHASE 2. D74's token buckets, and the connection that holds them.
///
/// The cache password comes back BESIDE the limiter because the PATH it was read
/// from is an ADR-0523 watch-set input, and that set is built from what this
/// process resolved rather than by reading the environment a second time.
pub fn rate_limiting() -> Result<(Limiter, Option<(String, PathBuf)>), Boxed> {
    // D74's token buckets. The ADDRESS is required, and its absence exits —
    // which is NOT the same rule as the runtime one. An unconfigured limiter is a
    // deployment mistake and D69 fails boot on those; an UNREACHABLE Valkey is an
    // outage of one component, and the call proceeds (see `limit::Decision`).
    // Conflating the two would either hide the mistake or turn the outage into
    // one of our own.
    let valkey_addr = std::env::var("YADGAR_VALKEY_ADDR")
        .ok()
        .filter(|a| !a.is_empty())
        .ok_or(
            "YADGAR_VALKEY_ADDR is unset. Every user-attributed call spends a token from a \
             bucket held in the shared cache (D74), and a gateway with nowhere to keep them \
             enforces no capacity limit at all. Set it to the Valkey service, e.g. valkey:6379.",
        )?;
    // A misparsed limit must not become a default: a limit nobody notices is
    // gone is the failure this refusal exists to prevent.
    //
    // `.to_string()` on the way out, and not decoration: `main` returns
    // `Box<dyn Error>`, which Rust prints with DEBUG — so a bare `?` here would
    // put `UnknownKind("wrote")` on the operator's terminal instead of the
    // sentence saying which kinds exist.
    //
    // `YADGAR_RATE_LIMITS` MAY BE EMPTY and that is a real answer: it says no
    // kind carries its own bucket and every kind takes the default below. The
    // default bucket itself may NOT be empty — it is the one that applies when
    // nothing else does.
    //
    // BOTH ARE `env_required`, AND NEITHER NUMBER IS WRITTEN DOWN HERE. This
    // binary once carried its own default bucket beside the chart's and the two
    // disagreed for as long as nobody looked, because a compiled-in default is
    // reachable only when the chart is NOT: the copy that is wrong is exactly
    // the copy no deployment exercises. `chart/values.yaml`'s
    // `rateLimit.default` is the ONE statement of that value.
    //
    // THIS COMMENT DELIBERATELY DOES NOT QUOTE IT, and the omission is the
    // point rather than an economy. A number quoted in a comment is the same
    // two-sources defect with a slower fuse — nothing recompiles when the chart
    // changes, so the quotation rots silently and reads as authoritative while
    // it does. ADR-0569.
    let limits = Limits::parse(
        &env_required_allow_empty("YADGAR_RATE_LIMITS")?,
        &env_required("YADGAR_RATE_LIMIT_DEFAULT")?,
    )
    .map_err(|e| format!("YADGAR_RATE_LIMITS is not usable: {e}"))?;
    // SHORT, and on the hot path of every call. A hung round trip to the cache
    // would otherwise put its latency at the one hop all traffic passes through;
    // a timeout degrades into the same fail-open path as unreachable.
    let limit_timeout = Duration::from_millis(
        env_required("YADGAR_RATE_LIMIT_TIMEOUT_MS")?
            .parse()
            .map_err(|e| format!("YADGAR_RATE_LIMIT_TIMEOUT_MS is not a whole number: {e}"))?,
    );
    // REQUIRED, for the same reason the address is, and it exits for the same
    // reason. It is the divisor of the degraded-mode floor: while Valkey cannot
    // answer, each replica enforces `rate / max_replicas` on its own, and the
    // aggregate bound that makes that acceptable holds only if this number is the
    // real ceiling. Defaulting it to 1 would leave the floor at the full
    // configured rate PER REPLICA — the configured number silently multiplied by
    // the replica count, which is the exact failure D74 names, on the error path
    // where nobody looks. A deployment that cannot say how far it scales cannot
    // have a correct floor, so it does not start.
    let max_replicas: u32 = env_required("YADGAR_MAX_REPLICAS")?
        .parse()
        .ok()
        .filter(|n| (1..=1000).contains(n))
        .ok_or(
            "YADGAR_MAX_REPLICAS is not a whole number between 1 and 1000. It is \
             the largest number of replicas the autoscaler may run, and it divides the local \
             floor this gateway falls back to while the shared cache cannot answer (D74). The \
             chart wires it from autoscaling.maxReplicas.",
        )?;
    let valkey_password = cache_password()?;
    let limiter = Limiter::new(
        &valkey_addr,
        valkey_password.as_ref().map(|(p, _)| p.as_str()),
        limits,
        limit_timeout,
        max_replicas,
    )?;
    tracing::info!(
        addr = %valkey_addr,
        timeout_ms = limit_timeout.as_millis(),
        max_replicas,
        // WHETHER, never WHAT. The value is a credential and this log is shipped.
        authenticated = valkey_password.is_some(),
        "rate limiting enabled (D74)"
    );
    if valkey_password.is_none() {
        // A WARNING RATHER THAN A REFUSAL, because it is the state every
        // deployment is in until the cache gains a password, and refusing here
        // would make this image unrollable before the manifest that gives the
        // cache one. It is loud because the property it names is one somebody
        // must positively choose to leave off.
        //
        // **WHAT THE VALKEY HOP IS AND IS NOT IS ARGUED IN ONE PLACE**, and it is
        // `attest::Credentials`, which points on to `tests/valkey_auth.rs` for
        // what this repository can actually measure. Restating it here is what
        // this comment used to do and it is how it went wrong: the sentence below
        // said "anything on the pod network", which stopped being true when
        // `valkey-ingress` began denying by default, and no copy of the claim in
        // this crate noticed.
        tracing::warn!(
            "the connection to the shared cache is UNAUTHENTICATED: no \
             YADGAR_VALKEY_PASSWORD_FILE is configured, so anything the cache's NetworkPolicy \
             admits can read and rewrite D74's token buckets, and that policy is then the only \
             control the hop has. Set requirepass on the cache and mount its Secret."
        );
    }
    Ok((limiter, valkey_password))
}

/// The cache's `requirepass`, resolved from the FILE the deployment named.
///
/// Its own function because the PATH is an ADR-0523 watch-set input and the
/// value is not: the two travel together out of here, and nothing downstream
/// re-reads the environment to find the file again.
fn cache_password() -> Result<Option<(String, PathBuf)>, Boxed> {
    // The cache's `requirepass`, as a PATH rather than a value — the same shape
    // every other credential in this chart uses, and for the same reason: a
    // deployment that is not the reference one assembles the Secret by hand and
    // neither the chart nor this binary can tell the difference (D80).
    //
    // ABSENCE IS THE DEFAULT, AND IT IS A REAL STATE. Unset means the cache asks
    // for no password, which is what every deployment of this before today was,
    // and it dials exactly as it always did. That is what lets this image be
    // rolled BEFORE the cache gains a password rather than in lockstep with it.
    //
    // SET-BUT-UNUSABLE IS A BOOT FAILURE, naming the path. It is the same rule
    // TASK_TLS_CA_FILE and iam's LISTEN_TLS_CERT_FILE already apply: a deployment
    // that asked for a credential and cannot produce one has a mistake in it, and
    // continuing without the credential would be the silent fall back to an
    // unauthenticated connection this whole change exists to remove. An EMPTY
    // file counts as unusable — a Secret whose key is present and blank is the
    // ordinary way this goes wrong, and `AUTH ""` is not authentication.
    //
    // **The other half of "never falls back" is at runtime and not here**, because
    // it cannot be here: this process does no I/O to the cache at boot, on purpose
    // (`Limiter::conn`), so nothing at boot can know whether the cache demands a
    // password. A cache that demands one this process cannot satisfy is refused at
    // the first call instead — see `limit::Decision::Unauthenticated`, which
    // deliberately does NOT take the fail-open floor an unreachable cache takes.
    //
    // **THE PATH COMES OUT BESIDE THE VALUE**, and that is what puts this file in
    // the ADR-0523 watch set below. The set is built from the configuration this
    // process ACTUALLY RESOLVED and never by reading the environment a second
    // time — a second reading could name a different file from the one opened
    // here. `invalidate::Broker` carries its own path for the same reason.
    Ok(match std::env::var("YADGAR_VALKEY_PASSWORD_FILE") {
        Err(_) => None,
        Ok(path) if path.is_empty() => None,
        Ok(path) => {
            // ADR-0523-WATCHED: cache_password
            let raw = std::fs::read_to_string(&path).map_err(|e| {
                format!(
                    "YADGAR_VALKEY_PASSWORD_FILE names {path}, which cannot be read: {e}. It is \
                     the password this gateway presents to the shared cache (D21/D74). Refusing \
                     to start rather than dialling the cache without one."
                )
            })?;
            // TRAILING NEWLINE ONLY, and this is not tidiness. `kubectl create
            // secret --from-file` of a file a person edited keeps the newline
            // their editor added, and a password with a `\n` on the end is a
            // different password — one that fails against a `requirepass` set
            // from the same 1Password item, as a WRONGPASS nobody can see. Inner
            // whitespace is left alone: it is a legitimate part of a password.
            let password = raw.trim_end_matches(['\n', '\r']).to_string();
            if password.is_empty() {
                return Err(format!(
                    "YADGAR_VALKEY_PASSWORD_FILE names {path}, which is empty. A blank password \
                     is not one, and `AUTH \"\"` is not authentication. Either put the cache's \
                     requirepass in that file or unset the variable, which is how a deployment \
                     says the cache asks for none."
                )
                .into());
            }
            Some((password, PathBuf::from(path)))
        }
    })
}

/// PHASE 4. What the HTTP surface accepts, and from whom.
///
/// AFTER the exporter is installed, exactly as before: nothing here records a
/// measurement, but the order is the one an operator has been reading.
pub fn http_configuration() -> Result<
    (
        Vec<String>,
        TrustBoundary,
        CredentialLimits,
        CredentialLimits,
    ),
    Boxed,
> {
    // Comma-separated, and EMPTY BY DEFAULT. An empty list rejects every browser
    // origin, which is right for a server whose clients are agents: a default
    // that allowed one would be a default nobody chose.
    let allowed_origins: Vec<String> = env_required_allow_empty("YADGAR_ALLOWED_ORIGINS")?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    // HOW MANY PROXIES STAND IN FRONT (D80, ADR-0491), and UNSET IS A REAL
    // ANSWER: it says nobody knows, and an unknown source address is recorded as
    // nothing rather than guessed from a header the caller can write.
    //
    // **A boot failure when it is set to something unreadable, and not a fall
    // back to the default.** The default REFUSES, so a typo that quietly took it
    // would look exactly like a deployment that never configured this — the
    // operator who set the variable would never learn their audit records carry
    // no address. That is D69's rule: a capability that cannot be configured
    // correctly fails startup.
    //
    // `.to_string()` on the way out, for the reason `Limits::parse` gives above.
    let trust = TrustBoundary::parse(&trusted_proxy_hops())
        .map_err(|e| format!("YADGAR_TRUSTED_PROXY_HOPS is not usable: {e}"))?;
    // The two buckets that bound the unauthenticated endpoints (task 497). Read
    // as `<rate>:<burst>` through the SAME parser D74's limits use, so one syntax
    // and one set of refusals covers every bucket this binary configures.
    let credential_limits = CredentialLimits {
        attributed: parse_bucket_env("YADGAR_LOGIN_RATE_LIMIT")?,
        unattributed: parse_bucket_env("YADGAR_LOGIN_UNATTRIBUTED_RATE_LIMIT")?,
    };
    // THE ADMIN SURFACE'S OWN BUCKETS (§3.2), and NOT a share of login's. See
    // `AppState::admin_limits` for why they are separate numbers at all.
    //
    // REQUIRED, LIKE LOGIN'S, and the chart renders both keys. **A default here
    // would have been an ADR-0569 violation the repository's own gate catches**
    // (`no-compiled-in-defaults`): "a knob reader must not accept a fallback".
    // The plan puts the chart keys in step 7; they are here instead, because a
    // required variable no chart renders is a boot failure on every gateway in
    // the estate, and ADR-0569's rule is that a knob is read from ONE source —
    // which obliges the source to exist. See the PR body.
    let admin_limits = CredentialLimits {
        attributed: parse_bucket_env("YADGAR_ADMIN_RATE_LIMIT")?,
        unattributed: parse_bucket_env("YADGAR_ADMIN_UNATTRIBUTED_RATE_LIMIT")?,
    };
    Ok((allowed_origins, trust, credential_limits, admin_limits))
}
