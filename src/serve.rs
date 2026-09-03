//! The signal this process drains on before it ends.
//!
//! [`shutdown`] is here rather than in `main` for the same reason the rest of
//! this repository keeps a boot-time decision out of the binary entry point: a
//! decision inside `main` is one no test can reach, and which signals end this
//! process is exactly the kind that fails silently. It listened for SIGINT
//! alone while Kubernetes sends SIGTERM.
//!
//! **No drain budget here, deliberately.** `iam`'s `serve` module pairs
//! `shutdown` with `DRAIN_BUDGET`/`drain_within` because `iam::rotate` can end
//! the serving future on its own, outside any signal, and nothing else would
//! ever bound that self-initiated drain. This gateway has no such watcher —
//! it holds nothing (D47), and nothing here can end the listener except a
//! signal — so the only drain that ever happens is the one
//! `terminationGracePeriodSeconds` already bounds, and `axum::serve` is wired
//! to [`shutdown`] directly through `with_graceful_shutdown`. `task` and
//! `task-db` reached the identical conclusion for the identical reason.
//!
//! **That reasoning has a known expiry date, so read it as dated rather than
//! settled.** ADR-0523 requires an exit-on-rotation watcher in every process
//! that reads security material once at boot, and this one does — `upstream`
//! reads the CA bundles it verifies `iam` and `task` against. When that watcher
//! lands here it brings a self-initiated drain with it, and the budget comes
//! back with it: tokio never unregisters a libc signal handler, so once a
//! non-signal arm wins the `select!` a later SIGTERM is swallowed and only
//! SIGKILL remains. Whoever adds the watcher adds `drain_within` in the same
//! change; the two are one decision, not two.

/// The future `axum::serve`'s `with_graceful_shutdown` drains on: SIGTERM, and
/// SIGINT beside it.
///
/// **SIGTERM IS THE ONE THAT MATTERS, and it was the one missing.** Kubernetes
/// ends a pod by sending SIGTERM and waiting out `terminationGracePeriodSeconds`
/// before SIGKILL; it never sends SIGINT. This binary listened for `ctrl_c()`
/// alone, so on every rolling update the drain was simply never reached — the
/// process ran until the kill, and whatever was in flight died with it. Unlike
/// `iam`, `task` and their `-db` twins, a caller here is not one long-lived
/// HTTP/2 connection carrying everything it will ever send — it is ordinary
/// concurrent HTTP, one connection per in-flight `tools/call` or credential
/// request. A rolling update without this fix drops all of them at once
/// instead of letting each finish.
///
/// SIGINT is kept because it is what a terminal sends, and losing the local
/// behaviour to fix the deployed one would be a poor trade.
///
/// **BOTH HANDLERS ARE REGISTERED BEFORE THIS RETURNS, and that is the reason
/// this is a function returning a future rather than an `async fn`.** Installing
/// a handler is what replaces the signal's default disposition, which for
/// SIGTERM is "terminate the process". An `async fn` registers nothing until it
/// is first polled, so a signal arriving in the window between binding the
/// listener and the executor reaching the shutdown future would kill the
/// process outright — the precise failure this exists to prevent, reintroduced
/// as a race. `tests/shutdown.rs` raises SIGTERM after this call and before the
/// future is awaited, so that window is what it measures.
///
/// The error is an `io::Error` because registration can fail, and `main` refuses
/// to start on it. A server that cannot hear SIGTERM is one that cannot drain,
/// and starting anyway would hide that until the next rollout.
///
/// **Byte-identical to `iam`'s and `task`'s `shutdown`**, which fixed this
/// first. One idea spelled two ways across the estate is its own defect.
/// `task-db`'s `boot::shutdown` is the same shape but not byte-identical — it
/// returns its own `BootError` rather than `std::io::Result`. This is the
/// fifth copy, which is past the point ADR-0523 names for lifting a repeated
/// lifecycle primitive into shared code.
pub fn shutdown() -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    Ok(async move {
        let signal = tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            _ = interrupt.recv() => "SIGINT",
        };
        // NAMED, because the two arrive for different reasons: SIGTERM is a
        // rollout or an eviction and SIGINT is a person at a terminal. An
        // operator reading why a pod went away wants to know which.
        tracing::info!(signal, "draining in-flight requests before shutting down");
    })
}
