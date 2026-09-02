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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use yadgar_gateway::attest::{Attestation, Credentials};
use yadgar_gateway::http::{router, AppState};
use yadgar_gateway::limit::{Limiter, Limits};
use yadgar_gateway::upstream;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
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
    // back to the default, for the same reason a bad rate limit does: this number
    // is the only bound on how long a revoked credential keeps working, and an
    // operator who wrote one should never be silently given another.
    let credentials = Credentials::from_env()?;
    if credentials.ttl().is_zero() {
        tracing::warn!(
            "the credential cache is DISABLED (YADGAR_CREDENTIAL_TTL_SECONDS=0), so every \
             tools/call resolves its bearer token against iam. Identity is then a per-request \
             round trip and an iam outage stops all MCP traffic — which is what D72's cache \
             exists to prevent."
        );
    } else {
        // A WARNING, not an info line, and it stays one until ledger 457/467 lands.
        // ADR-0491 decides that revocation publishes a broker event; its own
        // consequences record that nothing publishes one yet. So this TTL is the
        // whole revocation bound, and an operator reading the boot log should be
        // told that rather than left to find it in a decision record.
        tracing::warn!(
            ttl_seconds = credentials.ttl().as_secs(),
            "credential cache enabled (D72). NO INVALIDATION EVENT IS CONSUMED YET \
             (ADR-0491, ledger 457/467), so a credential revoked in iam keeps working here \
             for up to this long. The TTL is the only bound."
        );
    }

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
    let limiter = Limiter::new(&valkey_addr, limits, limit_timeout, max_replicas)?;
    tracing::info!(
        addr = %valkey_addr,
        timeout_ms = limit_timeout.as_millis(),
        max_replicas,
        "rate limiting enabled (D74)"
    );

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
    // LAZY, and the one place this file's opening claim is actually true.
    // `connect_task` above resolves DNS eagerly and `?` turns a name that does not
    // resolve into a failed boot — so the module comment's "the upstream
    // connection is NOT gated" does not hold for `task` today. `connect_iam` does
    // not repeat that: no name is resolved here, so an `iam` that is not deployed
    // yet costs a bounded failure per request rather than a pod that never starts.
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
    let iam =
        upstream::connect_iam(&iam_host, iam_port, iam_tls.as_ref()).map_err(|e| e.to_string())?;
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

    // Comma-separated, and EMPTY BY DEFAULT. An empty list rejects every browser
    // origin, which is right for a server whose clients are agents: a default
    // that allowed one would be a default nobody chose.
    let allowed_origins: Vec<String> = env_or("YADGAR_ALLOWED_ORIGINS", "")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let addr: SocketAddr = env_or("LISTEN", "0.0.0.0:8080").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, protocol = yadgar_gateway::mcp::PROTOCOL_VERSION, "gateway listening");

    axum::serve(
        listener,
        router(Arc::new(AppState {
            attestation,
            task,
            iam,
            credentials,
            limiter,
            allowed_origins,
        })),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    })
    .await?;

    Ok(())
}
