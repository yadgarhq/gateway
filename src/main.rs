//! Wiring, and the one thing that must happen before the listener binds.
//!
//! **Attestation is resolved first, and it can no longer fail.** It used to exit
//! the process when neither identity source was configured, because the only
//! available default was trusting the caller — D69's rule for a missing
//! capability, applied to identity. iam-backed attestation is implemented now, so
//! an unset environment selects THAT, and a deployment reaches the trusting path
//! only by naming it. There is no unconfigured state left to refuse. Resolving it
//! first is still worth the line: the log below says which source this process
//! will use, before it accepts anything.
//!
//! The upstream connection is NOT gated the same way, deliberately — same
//! reasoning as `task`: the twin's own boot is gated, so an unreachable `task`
//! means no endpoint, and failing a request with an upstream error is
//! recoverable where refusing to start is not. Under D68 a pod stuck in startup
//! is one the autoscaler cannot help.
//!
//! **THAT HELD FOR `iam` AND NOT FOR `task` UNTIL `dial` v0.2.0.**
//! `upstream::connect_iam` has always been lazy; `upstream::connect_task` went
//! through `yadgar_dial::connect`, which resolved DNS eagerly and returned an
//! error for an empty answer, and the `?` on it made a `task` Service that did
//! not exist yet a failed boot. ADR-0532 made that dial lazy as well, so the
//! paragraph above now describes both upstreams rather than one — and both by
//! the SAME mechanism, since `connect_iam` goes through `yadgar_dial` too.
//!
//! **WHAT IT COSTS, stated rather than left to be found.** The readiness probe
//! is a `tcpSocket` on the HTTP port, so this pod reports Ready as soon as it is
//! listening: with `task` absent it serves an opaque failure for every task
//! tool, and with `iam` absent it cannot attest at all, which is every
//! `tools/call`. The probe is deliberately NOT changed to gate on an upstream,
//! and the reason is D69's own scope rather than a preference: **D69's
//! boot-failure rule is about a capability of an engine the module OWNS**, which
//! is why the sequence it names is probe, migrate, then listen and why the `-db`
//! services are where that sequence lives. This gateway owns no engine, so the
//! only thing it could gate on is an RPC asking an upstream whether the upstream
//! is up — inference by proxy, which D69's first rule refuses by name, and the
//! cascade this paragraph rejects, moved one layer up.
//!
//! **The discriminator that generalises is whether a RESTART could change the
//! outcome.** An unusable CA bundle, a client certificate that is not mounted, a
//! host that is not a URI authority: a permanent gap, identical after a restart,
//! so fail boot — and all of those still do. An upstream that has not appeared
//! yet: transient, and a restart only costs backoff, so dial lazily.
//!
//! What makes the absent state visible instead is `yadgar_dial`'s refresh loop,
//! which logs at ERROR on every tick while a host has never resolved, distinctly
//! from the warning a blip gets. **That line reaches `kubectl logs` and nothing
//! else today**: `dial` exports no metric for the never-resolved state, no chart
//! here ships a `PrometheusRule`, and nothing ships logs off the node. The
//! signal exists and is not yet alertable.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use yadgar_lifecycle::{drain_within, shutdown, Drain, DRAIN_BUDGET};

use yadgar_gateway::attest::{Attestation, Credentials};
use yadgar_gateway::http::{router, AppState, CredentialLimits};
use yadgar_gateway::limit::{Bucket, Limiter, Limits};
use yadgar_gateway::rotate;
use yadgar_gateway::source::TrustBoundary;
use yadgar_gateway::upstream;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// One `<rate>:<burst>` from the environment, naming the variable when it is
/// wrong.
///
/// The error is stringified for the reason `Limits::parse`'s is: `main` returns
/// `Box<dyn Error>`, which Rust prints with DEBUG — so a bare `?` would put
/// `NotPositive("0", "0:10")` on the operator's terminal instead of the sentence
/// saying which variable is unusable and why.
fn parse_bucket_env(key: &str, default: &str) -> Result<Bucket, String> {
    Bucket::parse(&env_or(key, default)).map_err(|e| format!("{key} is not usable: {e}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        // A DEFAULT, because from_default_env() with RUST_LOG unset enables
        // NOTHING — the service runs silently and its boot sequence and its
        // errors both vanish. Found by deploying: pods Running, `kubectl logs`
        // empty, and the only evidence was the previous container's exit output.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

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
    let limits = Limits::parse(
        &env_or("YADGAR_RATE_LIMITS", ""),
        &env_or("YADGAR_RATE_LIMIT_DEFAULT", "10:100"),
    )
    .map_err(|e| format!("YADGAR_RATE_LIMITS is not usable: {e}"))?;
    // SHORT, and on the hot path of every call. A hung round trip to the cache
    // would otherwise put its latency at the one hop all traffic passes through;
    // a timeout degrades into the same fail-open path as unreachable.
    let limit_timeout = Duration::from_millis(
        env_or("YADGAR_RATE_LIMIT_TIMEOUT_MS", "20")
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
    let max_replicas: u32 = env_or("YADGAR_MAX_REPLICAS", "")
        .parse()
        .ok()
        .filter(|n| (1..=1000).contains(n))
        .ok_or(
            "YADGAR_MAX_REPLICAS is unset or is not a whole number between 1 and 1000. It is \
             the largest number of replicas the autoscaler may run, and it divides the local \
             floor this gateway falls back to while the shared cache cannot answer (D74). The \
             chart wires it from autoscaling.maxReplicas.",
        )?;
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
    let valkey_password = match std::env::var("YADGAR_VALKEY_PASSWORD_FILE") {
        Err(_) => None,
        Ok(path) if path.is_empty() => None,
        Ok(path) => {
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
            Some(password)
        }
    };
    let limiter = Limiter::new(
        &valkey_addr,
        valkey_password.as_deref(),
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
        tracing::warn!(
            "the connection to the shared cache is UNAUTHENTICATED: no \
             YADGAR_VALKEY_PASSWORD_FILE is configured, so anything on the pod network can read \
             and rewrite D74's token buckets. Set requirepass on the cache and mount its Secret."
        );
    }

    // OPT-IN, OFF unless a deployment asks for it, and read PER UPSTREAM so the
    // two can be cut over one at a time. Nothing configured means the cleartext
    // dial this gateway has always done — no module serves TLS yet, so the
    // cut-over is a later change that can be reverted on its own.
    //
    // `.to_string()` on the way out, for the reason `Limits::parse` above gives:
    // `main` returns `Box<dyn Error>`, which Rust prints with DEBUG, so a bare
    // `?` would put `NoCaFile("TASK")` on the operator's terminal instead of the
    // sentence naming the missing variable and saying why cleartext is not the
    // answer.
    let task_tls = upstream::UpstreamTls::from_env(upstream::TASK).map_err(|e| e.to_string())?;
    let iam_tls = upstream::UpstreamTls::from_env(upstream::IAM).map_err(|e| e.to_string())?;

    // STEP 2A OF THE ROTATION-KNOB CUT-OVER (ADR-0569, ADR-0570). The document
    // `yadgarhq/config` renders into the `shared` ConfigMap, mounted at
    // `/etc/yadgar/config/shared/shared.yaml`. There is no compiled-in default
    // behind it any more: an absent, empty, or half-written document refuses the
    // boot and names the file. The chart still sets TLS_ROTATION_POLL_SECS and
    // TLS_ROTATION_SPLAY_MAX_SECS — this binary no longer reads either, but they
    // stay so a rollout that lands this chart before this binary's digest still
    // resolves a schedule on the old one. The runbook is `yadgarhq/deploy`'s
    // MIGRATION_NOTES.md, steps 2a and 2b — NOT this repository's, which has no
    // such section.
    let config = rotate::Configuration::mounted();

    // THE WATCH SET, ASSEMBLED FROM THE RESOLVED CONFIGURATION AND BEFORE THE
    // DIALS (ADR-0523). The baseline is the bytes each file held when this
    // process read them; deferring the first reading to the watcher's first poll
    // would put the rest of boot inside a window where a kubelet swap quietly
    // becomes the baseline, and the real rotation would never be noticed.
    //
    // BOTH UPSTREAMS, AND ONE CLIENT LEAF BETWEEN THEM. `gateway-client-tls` is
    // presented to `task` and to `iam`, so the same two paths arrive twice; the
    // fold de-duplicates, so the pair is hashed once and named once in the line
    // that reports a change.
    //
    // THE MOUNTED DOCUMENT JOINS THE SAME SET, as a fourth `Material` — an
    // operator editing `shared.yaml` now restarts this pod exactly as editing a
    // CA bundle would.
    //
    // ONE CALL, AND THE SAME ONE A TEST MAKES. This used to be two chained
    // builder calls here, where nothing could reach them: no test spawns this
    // binary, so deleting either compiled and passed everything. The list lives
    // in `rotate::watch_set` now and `tests/assembly.rs` calls it.
    let watch_inputs = rotate::watch_set(task_tls.as_ref(), iam_tls.as_ref(), &config);

    // READ FROM THE SAME DOCUMENT THE WATCH SET JUST JOINED, whether or not any
    // TLS is configured. A value the document names and this binary cannot use
    // is a mistake to refuse, not one to paper over with a default nobody
    // chose — and refusing it here means it is refused on a cleartext
    // deployment too, which is where it would otherwise sit unnoticed until the
    // cut-over.
    let schedule = config.schedule().map_err(|e| e.to_string())?;

    let task_host = env_or("TASK_HOST", "task");
    let task_port: u16 = env_or("TASK_PORT", "50052").parse()?;
    let task = upstream::connect_task(&task_host, task_port, task_tls.as_ref())
        .await
        // Same reasoning: `BalanceError`'s messages are paragraphs explaining
        // that an empty bundle trusts nobody and that a missing one is not a
        // reason to connect in cleartext. Debug prints the struct and throws all
        // of that away.
        .map_err(|e| e.to_string())?;
    tracing::info!(host = %task_host, port = task_port, tls = task_tls.is_some(), "connected to task");

    // The upstream for BOTH halves of the credential lifecycle: POST /auth/login
    // and POST /auth/enrol issue a token through this channel (D75, D73), and
    // `attest` resolves one through it on every tools/call.
    //
    // **ONE pair, IAM_HOST/IAM_PORT, matching TASK_HOST/TASK_PORT.** There used to
    // be a second variable, YADGAR_IAM_ADDR, reserving the identity half — and it
    // was a boot-killer, because that half was unimplemented. Both halves are this
    // channel now, so the reservation is deleted rather than honoured: two
    // settings that both read as "where iam is" is one too many, and the one that
    // named a service nothing could reach is the one to lose.
    //
    // LAZY — and no longer the ONLY place this file's opening claim is true.
    // `connect_task` above used to resolve DNS eagerly, with `?` turning a name
    // that did not resolve into a failed boot, so the module comment's "the
    // upstream connection is NOT gated" did not hold for `task`. `dial` v0.2.0
    // makes that dial lazy too (ADR-0532), so BOTH upstreams now cost a bounded
    // failure per request rather than a pod that never starts, and the claim
    // holds for the first time since it was written.
    //
    // **`iam` IS NO LONGER A SECONDARY UPSTREAM, and this comment used to say it
    // was.** It said an absent `iam` cost "a 503 on /auth/login and nothing at all
    // on /", which was true while identity came from headers. Attestation resolves
    // the bearer token through this channel now, so an `iam` outage degrades ALL
    // MCP traffic, not one endpoint. Staying lazy is still right — a pod stuck in
    // startup is one D68's autoscaler cannot help, and a per-request failure is
    // recoverable where a refusal to boot is not — but the cost of the outage it
    // survives is larger than it was, and `attest::Credentials` above is what
    // brings it back down: D72's "on a cache miss, never per request", so an `iam`
    // outage now costs the callers whose entries expire during it rather than
    // every call in flight.
    //
    // `?` still stands on both lines, and what it now covers is configuration
    // rather than reachability: a port that is not a number, a host string that
    // cannot form a URI, and a CA bundle that cannot be used. Those are
    // deployment mistakes, which is exactly the class D69 says should fail boot.
    //
    // **THE CA BUNDLE IS READ HERE even though the channel is lazy**, and the
    // two are not in tension: what stays lazy is the part that depends on `iam`
    // EXISTING. A bundle depends only on the deployment that wrote it, so
    // deferring the read would turn an operator's mistake into a per-request
    // failure found under traffic rather than a refusal to boot.
    let iam_host = env_or("IAM_HOST", "iam");
    let iam_port: u16 = env_or("IAM_PORT", "50052").parse()?;
    let iam = upstream::connect_iam(&iam_host, iam_port, iam_tls.as_ref())
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(
        host = %iam_host,
        port = iam_port,
        tls = iam_tls.is_some(),
        "iam channel ready (connects on first use)"
    );

    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure is
    // logged and ignored: telemetry must never fail a call (D25), and that rule
    // covers the metrics endpoint too.
    let metrics_addr: SocketAddr = env_or("METRICS_LISTEN", "0.0.0.0:9090").parse()?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    // AFTER THE EXPORTER, NEVER BEFORE IT. A value recorded before there is a
    // recorder is a value nobody ever sees. This process serves no certificate,
    // so the only series it publishes is the CLIENT leaf's — which under
    // ADR-0516 is the one whose expiry stops a hop.
    watch_inputs.export_not_after();

    // Comma-separated, and EMPTY BY DEFAULT. An empty list rejects every browser
    // origin, which is right for a server whose clients are agents: a default
    // that allowed one would be a default nobody chose.
    let allowed_origins: Vec<String> = env_or("YADGAR_ALLOWED_ORIGINS", "")
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
    let trust = TrustBoundary::parse(&env_or("YADGAR_TRUSTED_PROXY_HOPS", ""))
        .map_err(|e| format!("YADGAR_TRUSTED_PROXY_HOPS is not usable: {e}"))?;
    // The two buckets that bound the unauthenticated endpoints (task 497). Read
    // as `<rate>:<burst>` through the SAME parser D74's limits use, so one syntax
    // and one set of refusals covers every bucket this binary configures.
    let credential_limits = CredentialLimits {
        attributed: parse_bucket_env(
            "YADGAR_LOGIN_RATE_LIMIT",
            CredentialLimits::DEFAULT_ATTRIBUTED,
        )?,
        unattributed: parse_bucket_env(
            "YADGAR_LOGIN_UNATTRIBUTED_RATE_LIMIT",
            CredentialLimits::DEFAULT_UNATTRIBUTED,
        )?,
    };
    match trust {
        TrustBoundary::Undeclared => tracing::warn!(
            "NO TRUST BOUNDARY IS DECLARED: YADGAR_TRUSTED_PROXY_HOPS is unset, so this \
             gateway cannot tell which X-Forwarded-For entry is the client and which the \
             caller wrote. Two consequences, both deliberate (ADR-0491, D80). Authentication \
             events record NO source address, because a forged one is worse than none. And \
             /auth/login and /auth/enrol are bounded per OBSERVED HOP rather than per client \
             — behind an ingress that is one bucket for everybody, sized to bound Argon2id \
             cost rather than to stop guessing. Set the variable to the number of proxies in \
             front (0 if this gateway is exposed directly) to get per-client limits and an \
             attributable audit record."
        ),
        TrustBoundary::Hops(hops) => tracing::info!(
            hops,
            "trust boundary declared; the source address is read from X-Forwarded-For counting \
             from the right (ADR-0491)"
        ),
    }

    let state = Arc::new(AppState {
        attestation,
        task,
        iam,
        credentials,
        limiter,
        allowed_origins,
        trust,
        credential_limits,
    });

    // D72's invalidation, BEFORE the listener binds. The first dial is awaited so
    // the line below says what is true rather than what was configured: a broker
    // this gateway could not reach must not produce a boot log claiming an
    // invalidation path it does not have. See `invalidate::start` for why an
    // unreachable broker degrades loudly instead of failing the boot.
    //
    // `Arc<AppState>` rather than a share of the cache alone, so `AppState` keeps
    // owning it and no handler changes.
    //
    // **SKIPPED ENTIRELY WHEN THE CACHE IS OFF, and the warning above says so.**
    // With no cache there is nothing an event could evict, so a connection, two
    // subscriptions and a redial loop would all be spent on calling `forget_user`
    // against an empty map. It also keeps `credentialCache.ttlSeconds: 0` the
    // clean revert MIGRATION_NOTES.md says it is: back to a round trip per call,
    // with no dependency on the broker at all. What is NOT skipped is
    // `Broker::from_env` above — a half-configured credential is a deployment
    // mistake at any TTL, and it still fails the boot.
    let consuming = if ttl.is_zero() {
        false
    } else {
        yadgar_gateway::invalidate::start(broker, {
            let state = Arc::clone(&state);
            // BOTH SUBJECTS EVICT A PERSON, never a token: `iam` holds a
            // credential id on a revoke and never sees the token this cache is
            // keyed on. See D72 and `Credentials::forget_user`.
            move |user_id: &str| state.credentials.forget_user(user_id)
        })
        .await
    };
    if !ttl.is_zero() && !consuming {
        // A WARNING, and it is the honest form of the one this used to print
        // unconditionally. It is no longer a statement about what was built; it is
        // a statement about what THIS process managed to connect to.
        tracing::warn!(
            ttl_seconds = ttl.as_secs(),
            "credential cache enabled (D72) with NO INVALIDATION BEING CONSUMED, so a \
             credential revoked in iam keeps working here for up to this long. The TTL is the \
             only bound."
        );
    } else if !ttl.is_zero() {
        tracing::info!(
            ttl_seconds = ttl.as_secs(),
            "credential cache enabled (D72), invalidated by broker events with the TTL as the \
             backstop for a missed one"
        );
    }

    let addr: SocketAddr = env_or("LISTEN", "0.0.0.0:8080").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ARMED BEFORE THE LISTENER IS SERVED, and that ordering is the fix rather
    // than an accident of where the line sits. `yadgar_lifecycle::shutdown`
    // installs both signal handlers when it is CALLED — a SIGTERM arriving between here and
    // the first poll of the future would otherwise take the process's default
    // disposition and kill it outright.
    let signals = shutdown().map_err(|e| {
        format!(
            "the SIGTERM and SIGINT handlers could not be installed: {e}. Refusing to start: a \
             server that cannot hear SIGTERM cannot drain, and Kubernetes ends every pod with one"
        )
    })?;

    tracing::info!(
        %addr,
        protocol = yadgar_gateway::mcp::PROTOCOL_VERSION,
        watching = watch_inputs.watched().len(),
        rotation_poll_secs = schedule.poll().as_secs(),
        rotation_splay_max_secs = schedule.splay_max().as_secs(),
        drain_budget_secs = DRAIN_BUDGET.as_secs(),
        "gateway listening"
    );

    // THE SERVER IS SPAWNED AND ASKED TO STOP THROUGH A CHANNEL, rather than
    // handed the shutdown future directly, because the drain has to be BOUNDED
    // once something other than a signal can start one, and a budget's clock
    // must start when shutdown is REQUESTED. A `timeout` around the serving
    // future itself would bound the server's whole life instead, and end the
    // process one budget after boot, on every boot — the defect `iam` shipped
    // and `yadgar-lifecycle`'s own `tests/drain.rs` keeps dead.
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(
        axum::serve(
            listener,
            // `into_make_service_with_connect_info`, WHICH THIS CALL DID NOT
            // HAVE. Without it nothing populates `ConnectInfo`, so the peer
            // address is not extractable at all and every request resolves to
            // `Source::Unknown` — an unthrottleable, unattributable request. It
            // is the one line that makes the rest reachable in the shipped
            // binary.
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_requested.await;
        })
        .into_future(),
    );

    // TWO WAYS THIS PROCESS STOPS, and only one of them is a signal. The other
    // is a rotated TLS file (ADR-0523), which is why the drain below is bounded
    // at all: kubelet's grace period never runs for a drain kubelet did not
    // start, and tokio has already swallowed the SIGTERM that would otherwise
    // save it.
    let stop = async {
        tokio::select! {
            () = signals => {}
            () = rotate::watch(watch_inputs, schedule) => {}
        }
    };

    match drain_within(serving, ask_to_stop, stop, DRAIN_BUDGET).await {
        Drain::Finished(result) => result?,
        Drain::Overran => tracing::error!(
            budget_secs = DRAIN_BUDGET.as_secs(),
            "the drain did not finish within its budget; ending anyway with calls still in \
             flight. A request blocked this long is the thing to look at"
        ),
    }

    Ok(())
}
