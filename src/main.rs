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

use std::net::SocketAddr;
use std::sync::Arc;

use yadgar_gateway::http::AppState;
use yadgar_gateway::source::TrustBoundary;

/// The boot sequence, phase by phase, in the order `main` calls them.
mod boot;

use boot::env_required;

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

    let (attestation, credentials, ttl, broker) = boot::identity()?;

    let (limiter, valkey_password) = boot::rate_limiting()?;

    let boot::Wiring {
        bootstrap,
        watch_inputs,
        schedule,
        task,
        iam,
    } = boot::wiring(&broker, &valkey_password).await?;

    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure is
    // logged and ignored: telemetry must never fail a call (D25), and that rule
    // covers the metrics endpoint too.
    let metrics_addr: SocketAddr = env_required("METRICS_LISTEN")?.parse()?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    // AFTER THE EXPORTER, NEVER BEFORE IT. A value recorded before there is a
    // recorder is a value nobody ever sees. This process serves no certificate,
    // so the only series it publishes is the CLIENT leaf's — which under
    // ADR-0516 is the one whose expiry stops a hop.
    watch_inputs.export_not_after();

    let (allowed_origins, trust, credential_limits, admin_limits) = boot::http_configuration()?;
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
        admin_limits,
        bootstrap,
    });

    boot::start_invalidation(broker, ttl, Arc::clone(&state)).await;

    boot::serve(state, watch_inputs, schedule).await?;

    Ok(())
}
