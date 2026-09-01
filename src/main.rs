//! Wiring, and the one thing that must happen before the listener binds.
//!
//! **Attestation is resolved first, and a failure here exits.** D69 makes a
//! missing capability fail boot rather than fail later, and identity is a
//! capability: a gateway that cannot say who the caller is has nothing safe to do
//! with a request. Binding first and discovering it later would mean serving
//! traffic under an identity nobody attested.
//!
//! The upstream connection is NOT gated the same way, deliberately — same
//! reasoning as `task`: the twin's own boot is gated, so an unreachable `task`
//! means no endpoint, and failing a request with an upstream error is
//! recoverable where refusing to start is not. Under D68 a pod stuck in startup
//! is one the autoscaler cannot help.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use yadgar_gateway::attest::Attestation;
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

    // FIRST. See the module comment — this is the boot gate.
    let attestation = Attestation::from_env()?;
    match &attestation {
        Attestation::TrustedHeaders => tracing::warn!(
            "identity is UNAUTHENTICATED: caller-supplied headers are trusted. \
             Development only — iam replaces this (ledger 452)."
        ),
        // UNREACHABLE BY CONSTRUCTION, and deliberately still an arm.
        // `Attestation::from_env` refuses YADGAR_IAM_ADDR outright until
        // iam-backed attestation lands (ledger 452), so this process can no
        // longer be in that state. The arm stays so adding iam changes
        // `attest.rs` and this line and nothing else — but it no longer logs
        // "attesting caller identity", which was the sentence that made a boot
        // into an unimplemented identity source look survivable.
        other => tracing::warn!(
            source = %other,
            "identity source is not implemented; this process should not have started"
        ),
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
    let limiter = Limiter::new(&valkey_addr, limits, limit_timeout)?;
    tracing::info!(
        addr = %valkey_addr,
        timeout_ms = limit_timeout.as_millis(),
        "rate limiting enabled (D74)"
    );

    let task_host = env_or("TASK_HOST", "task");
    let task_port: u16 = env_or("TASK_PORT", "50052").parse()?;
    let task = upstream::connect_task(&task_host, task_port).await?;
    tracing::info!(host = %task_host, port = task_port, "connected to task");

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
