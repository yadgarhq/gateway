//! Wiring, and the one thing that must happen before the listener binds.
//!
//! **THE METRICS RECORDER IS INSTALLED FIRST, BEFORE ANY OTHER PHASE
//! (ADR-0677).** A `gauge!` or `counter!` reached before it is discarded with no
//! error and no log line, so a component wired above that call publishes a boot
//! value nobody can ever see. The constraint is stated at the call itself, and
//! `tests/boot_ordering.rs` asserts it rather than trusting the sentence.
//!
//! **Attestation is resolved next, and it can no longer fail.** It used to exit
//! the process when neither identity source was configured, because the only
//! available default was trusting the caller — D69's rule for a missing
//! capability, applied to identity. iam-backed attestation is implemented now, so
//! an unset environment selects THAT, and a deployment reaches the trusting path
//! only by naming it. There is no unconfigured state left to refuse. Resolving it
//! ahead of the rest of the wiring is still worth the line: the log below says
//! which source this process will use, before it accepts anything.
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

/// The boot sequence, phase by phase, in the order `run` calls them.
mod boot;

use boot::{env_required, install_logging, log_trust_boundary};

/// The process entry point: run the service, and print a refusal as its SENTENCE.
///
/// **NOT `main() -> Result`** (ledger 1258). Rust prints a `main` that returns
/// `Err` with DEBUG, so even a refusal already converted to its sentence
/// arrived quoted and escaped — `Error: "LISTEN is not a host:port address: \
/// invalid socket address syntax"` — and a bare `.parse()?` that skipped any
/// conversion arrived as the parse error's Debug, e.g. `ParseIntError { kind:
/// InvalidDigit }`. ADR-0569 asks a refusal to name the knob and where it is
/// set; an operator reading a crash loop must get that as plain text.
/// `tests/boot_message.rs` runs the binary and holds it. Shape and wording
/// follow `iam-db`'s `main`.
///
/// The exit status is unchanged: an `Err` from `main` exits 1, and so does
/// `ExitCode::FAILURE`. A drain — after SIGTERM or after a rotation — still
/// returns `Ok(())` and exits 0, which `tests/exit_chain.rs` holds (ledger 748).
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    install_logging();

    // PHASE 0: THE METRICS RECORDER, BEFORE EVERY OTHER PHASE (ADR-0677).
    //
    // NOTHING BELOW THIS LINE MAY MOVE ABOVE IT. `metrics::gauge!` and
    // `metrics::counter!` are accepted whenever no recorder is installed and
    // then DISCARDED SILENTLY — no error, no log line, no panic. A component
    // wired before this call therefore publishes its boot value into nothing,
    // and the series never registers at all.
    //
    // THAT IS NOT HYPOTHETICAL. This call used to sit seven lines BELOW the
    // `boot::wiring` await. `Registry::start` sets
    // `yadgar_gateway_project_registry_loaded` to `0` from inside that await, so
    // the gauge reached a scrape ONLY once the registry had loaded and a replica
    // whose registry had never loaded was indistinguishable from one nobody
    // scraped — the exact failure that gauge's own comment forbids. The absent
    // series is also why the gateway spent a release dialling `project` on
    // `project-db`'s port with nothing saying so. `tests/boot_ordering.rs` is
    // the guard; a scrape of a replica that never loaded is the proof.
    //
    // FIRST, rather than merely above `boot::wiring`, because "above the one
    // phase that publishes at boot today" has to be re-derived every time a
    // phase is added — and stating the constraint at one call site demonstrably
    // did not generalise to the next one. Nothing here depends on a boot phase:
    // the address is one environment variable, and `install_prometheus` binds a
    // listener and installs the global recorder. Two consequences, both
    // accepted: "metrics endpoint listening" is now the first line of the boot
    // log, and an unparseable METRICS_LISTEN fails the boot before the
    // attestation source is resolved.
    //
    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure is
    // logged and ignored: telemetry must never fail a call (D25), and that rule
    // covers the metrics endpoint too.
    let metrics_addr: SocketAddr = env_required("METRICS_LISTEN")?
        .parse()
        .map_err(|e| format!("METRICS_LISTEN is not a host:port address: {e}"))?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    let (attestation, credentials, ttl, broker) = boot::identity()?;

    let (limiter, valkey_password) = boot::rate_limiting()?;

    let boot::Wiring {
        bootstrap,
        watch_inputs,
        schedule,
        tools_poll_interval,
        task,
        iam,
        projects,
    } = boot::wiring(&broker, &valkey_password, limiter.tls()).await?;

    // AFTER THE EXPORTER, NEVER BEFORE IT. A value recorded before there is a
    // recorder is a value nobody ever sees. This process serves no certificate,
    // so the only series it publishes is the CLIENT leaf's — which under
    // ADR-0516 is the one whose expiry stops a hop.
    watch_inputs.export_not_after();

    let (allowed_origins, trust, credential_limits, admin_limits) = boot::http_configuration()?;
    log_trust_boundary(&trust);

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
        tools_poll_interval,
        projects,
    });

    boot::start_invalidation(broker, ttl, Arc::clone(&state)).await;

    boot::serve(state, watch_inputs, schedule).await?;

    Ok(())
}
