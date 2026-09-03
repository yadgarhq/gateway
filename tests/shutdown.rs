//! What happens when Kubernetes ends this pod.
//!
//! **The bug this file exists to keep fixed:** `main` handed
//! `with_graceful_shutdown` a `tokio::signal::ctrl_c()` future and nothing
//! else, so the only signal that ever reached the drain was SIGINT. Kubernetes
//! never sends SIGINT. It sends SIGTERM, waits out
//! `terminationGracePeriodSeconds`, then SIGKILLs — so on every rolling update
//! the drain was skipped entirely and whatever was in flight died with the
//! process: an in-progress `tools/call`, a credential resolution against
//! `iam`, a login.
//!
//! **THIS ASSERTS THE DRAIN, NOT THE REGISTRATION.** A test that only proved a
//! handler exists would pass against a handler wired to the wrong signal,
//! which is precisely the defect. So this runs a REAL server on a real port,
//! sends a real SIGTERM to this very process, and then asserts two things a
//! killed process could not produce: that `axum::serve` RETURNED, and that the
//! port it held stopped accepting afterwards. A process that took SIGTERM's
//! default disposition never reaches either assertion — it is gone.
//!
//! **NO `AppState` IS INVOLVED.** What is under test is the LIFECYCLE of the
//! server, not any handler in it, and an empty `axum::Router` — every request
//! answers 404 — keeps the rig honest about that: it needs no upstream
//! channel, no cache and no attestation source.
//!
//! **ONE TEST IN ITS OWN BINARY, deliberately.** A signal is delivered to a
//! PROCESS, not to a thread, and `cargo test` runs the tests within one file
//! concurrently on one process. A second test here would receive this one's
//! SIGTERM. Cargo compiles each `tests/*.rs` to its own binary, so the
//! isolation this needs is the file itself.
//!
//! Mirrored from `iam/tests/shutdown.rs` and `task-db/tests/shutdown.rs`,
//! which fixed this first — `axum::serve`'s `with_graceful_shutdown` drains on
//! the same future `tonic`'s `serve_with_shutdown` does, so the shape carries
//! over unchanged.

use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;

use yadgar_gateway::serve;

/// Send SIGTERM to this test process.
///
/// **Through `kill(1)` rather than `libc::raise`, because this package FORBIDS
/// unsafe code** — `[lints.rust] unsafe_code = "forbid"` in `Cargo.toml`
/// applies to every target including this one, and `libc::raise` is an unsafe
/// call. The signal is identical either way; only the spelling differs.
///
/// A failure to run `kill` is reported as a RIG failure in its own words, so a
/// missing binary can never be mistaken for a shutdown that did not happen.
fn sigterm_this_process() {
    let pid = std::process::id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap_or_else(|e| panic!("the test rig could not run kill(1) to raise SIGTERM: {e}"));
    assert!(
        status.success(),
        "the test rig ran kill(1) and it refused: {status}"
    );
}

/// Wait until `port` accepts a TCP connection, rather than sleeping a guessed
/// interval.
async fn accepts(port: u16) -> bool {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn a_sigterm_drains_the_server_instead_of_killing_the_process() {
    let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("a free loopback port");
    let port = listener.local_addr().unwrap().port();

    // BEFORE the signal, and that ordering is the property under test as much
    // as the signal itself is. `serve::shutdown` installs both handlers when it
    // is CALLED; an `async fn` would install them on first poll instead, and a
    // SIGTERM arriving in that window would kill this process rather than
    // drain it. The `kill` below lands in exactly that window.
    let shutdown = serve::shutdown().expect("the signal handlers install");

    let serving = tokio::spawn(async move {
        axum::serve(listener, Router::new())
            .with_graceful_shutdown(shutdown)
            .await
    });

    assert!(
        accepts(port).await,
        "the rig never came up, so nothing below would mean anything"
    );

    sigterm_this_process();

    // A process that ignored SIGTERM never gets here, and one that took the
    // default disposition never gets here either — the second is the
    // regression.
    let served = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect(
            "SIGTERM did not end the serving future within 10s: the drain never started, so a \
             rolling update would sever every in-flight request when the SIGKILL lands",
        )
        .expect("the serving task panicked");
    served.expect("a graceful shutdown returns Ok, not an accept error");

    // RETURNED is not the same as CLOSED. `axum::serve` resolving while the
    // port still accepts would mean the listener outlived the server, and a
    // connection accepted after the drain is one nothing is left to answer.
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "the server returned but port {port} still accepts connections; the listener was never \
         released, so the drain did not finish"
    );
}
