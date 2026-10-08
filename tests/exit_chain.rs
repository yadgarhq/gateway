//! THE EXIT CHAIN, held at the binary (ledger 748): the two ways a running
//! `gateway` is asked to stop both reach `Drain::Finished(Ok(()))` and exit
//! code 0.
//!
//! **THIS PROVES THE TWO STOP PATHS EXIT 0, NOT THAT ANYTHING DRAINS.** Both
//! cases below send the signal, or rewrite the file, with no request in
//! flight — there is nothing here for a drain to wait out. The drain itself,
//! under load, with a real in-flight call, is `yadgar-lifecycle`'s own
//! `tests/shutdown.rs`: "a real server on a real port", a real SIGTERM sent
//! to that test's own process, asserting the serving future returned and the
//! port stopped accepting. That file's own header is explicit that it is the
//! one asserting the drain rather than only the registration. What is left
//! for THIS file to hold is the wiring one layer up, which is repo-specific
//! and which no library test can see.
//!
//! The library tests prove the parts — `yadgar-lifecycle` that a signal resolves
//! `shutdown()` and that a changed file resolves `rotate::watch`,
//! `tests/assembly.rs` that the watch set holds the right files. None of them
//! can see `boot::serve` wiring those futures into the `select!` that stops the
//! listener. Deleting either arm compiled and passed every suite here. Only
//! running the binary can tell.
//!
//! **What each case kills, measured by mutating `src/boot/wiring.rs`'s
//! `serve`:**
//!
//! - Delete the `shutdown()` binding AND its `select!` arm: no handler is ever
//!   installed, SIGTERM takes the kernel default, the status carries signal 15
//!   and no code, and [`sigterm_drains_and_exits_zero`]'s `Some(0)` is red.
//! - Delete the arm ONLY: the handler is installed when `shutdown()` is CALLED
//!   and tokio never removes it, so SIGTERM is swallowed and the listener keeps
//!   serving. The exit wait's deadline fires; the test kills the child and fails.
//! - Delete the rotation arm: nothing polls the watcher, so
//!   [`a_rewritten_shared_document_drains_and_exits_zero`] never sees the
//!   CHANGED line and fails on its deadline.
//!
//! A failing drain is NOT one of these cases. `Drain::Overran` exits 0 by
//! design and `Drain::Finished(Err)` exits 1 under either shape of `main`, so
//! nothing about the drain's own outcome moves the code this file asserts.
//!
//! See `tests/support/mod.rs` for why each run is in its own mount namespace,
//! and why this gateway needs TWO mounted documents where `task` needs one.

mod support;

use std::os::unix::process::ExitStatusExt;

use support::{cleartext_env, describe, Booted, MARGIN, POLL, SPLAY_MAX};
use yadgar_lifecycle::DRAIN_BUDGET;

/// Case (i): kubelet's SIGTERM ends the process with 0.
///
/// The deadline is the drain's whole budget plus a margin, not less: an
/// `Overran` drain is a legal exit 0 that arrives one budget after the signal.
#[test]
fn sigterm_drains_and_exits_zero() {
    let mut gateway = Booted::start(&cleartext_env());
    gateway.wait_until_listening();

    gateway.terminate();
    let status = gateway.wait_for_exit("after SIGTERM", DRAIN_BUDGET + MARGIN);

    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must drain and exit 0 ({}); signal 15 here means no handler was \
         installed",
        describe(Some(status))
    );
    assert_eq!(status.signal(), None);
    assert!(
        gateway
            .seen()
            .iter()
            .any(|l| l.contains("draining in-flight requests") && l.contains("SIGTERM")),
        "the drain must name the signal that started it"
    );
}

/// Case (ii): a rewritten watched file ends the process with 0.
///
/// `shared.yaml` is one of the two watched files a cleartext deployment has —
/// `gateway.yaml` joins the same watch set (ADR-0740), but `shared.yaml` is the
/// one `task` and `iam-db` watch too, so rewriting it is the case every exit
/// chain in the estate shares. The rewrite keeps the schedule valid and
/// changes the bytes, which is all the watcher compares.
#[test]
fn a_rewritten_shared_document_drains_and_exits_zero() {
    let mut gateway = Booted::start(&cleartext_env());
    gateway.wait_until_listening();

    gateway.rewrite_shared(
        "tlsRotation:\n  pollSeconds: 1\n  splayMaxSeconds: 0\n# rotated by tests/exit_chain.rs\n",
    );
    // One poll to notice, the splay, then the drain's whole budget.
    let deadline = POLL + SPLAY_MAX + DRAIN_BUDGET + MARGIN;
    let started = std::time::Instant::now();

    let changed = gateway.wait_for_line("the watcher's CHANGED line", deadline, |l| {
        l.contains("have CHANGED on disk")
    });
    assert!(
        changed.contains("shared.yaml"),
        "the CHANGED line must name the file that changed: {changed}"
    );
    // No TLS and no client identity are configured, so every fingerprint this
    // gateway could report is `none`.
    for field in [
        "\"serving_before\":\"none\"",
        "\"serving_after\":\"none\"",
        "\"client_before\":\"none\"",
        "\"client_after\":\"none\"",
    ] {
        assert!(
            changed.contains(field),
            "the CHANGED line must carry {field}: {changed}"
        );
    }

    let status = gateway.wait_for_exit(
        "after the watched file changed",
        deadline.saturating_sub(started.elapsed()),
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a rotation is not an error; it must drain and exit 0 ({})",
        describe(Some(status))
    );
}
