//! THE EDGE CLOSES A CLIENT THAT NEVER FINISHES ITS REQUEST HEAD, held at the
//! binary (yaadgaar #218, ADR-1006).
//!
//! `axum::serve` built hyper-util's `auto::Builder` and never gave it a timer.
//! hyper's `http1` builder defaults `header_read_timeout` to 30 s, but drops
//! that default with a warning when no timer is set. So the edge had NO bound
//! on a half-sent request head: one client per socket, sending a byte now and
//! then, or nothing at all, held a connection for ever (slowloris). An ingress
//! in front does not excuse it: D80 says this chart must not depend on one.
//!
//! `yadgar_gateway::edge::serve` sets the timer and the bound, and the bound is
//! the chart value `server.limits.headerReadTimeoutSeconds` (ADR-1006, default 10),
//! rendered as `LISTEN_HEADER_READ_TIMEOUT_SECS`. These cases boot the REAL
//! binary with that variable at 2 s, so they also prove `boot::serve` reads the
//! variable and hands it to the edge. A unit test of `edge::serve` alone cannot
//! see that wiring.
//!
//! **What each case kills, measured by mutating `src/edge.rs`:**
//!
//! - Delete `.timer(TokioTimer::new())`, the original defect's shape: with a
//!   bound configured and no timer, hyper 1.11 panics in the connection task,
//!   so the connection drops at once. Both cases are red on their LOWER bound.
//! - Delete `.header_read_timeout(..)` only: hyper falls back to its own 30 s,
//!   which is past the read deadline, and both cases are red.
//! - Serve through `serve_connection_with_upgrades`: hyper-util sniffs the
//!   protocol before the h1 connection exists, with no timer, so
//!   [`a_connection_that_sends_nothing_is_closed_within_the_bound`] is red.
//!
//! The lower bound matters as much as the upper one. A connection closed at
//! once, for any other reason, is not this bound at work, so each case also
//! asserts the close came no earlier than the bound less [`SLACK`].
//!
//! See `tests/support/mod.rs` for why each run is in its own mount namespace.

mod support;

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use support::{cleartext_env, Booted};

/// The bound these runs give the binary, as the chart would render it.
const BOUND_SECS: &str = "2";
const BOUND: Duration = Duration::from_secs(2);

/// How much earlier than [`BOUND`] a close may come. hyper's timer and the
/// first poll of the connection do not start at the same instant as the
/// client's clock.
const SLACK: Duration = Duration::from_millis(500);

/// How much later than [`BOUND`] a close may come on a slow runner.
const MARGIN: Duration = Duration::from_secs(3);

/// A loopback port nothing listens on at the moment of the call. The binary
/// binds it a moment later; the gap is the cost of naming the port before
/// boot, which the "gateway listening" line does not report.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free loopback port")
        .port()
}

/// Boot the binary on a known port with the edge bound at [`BOUND_SECS`].
fn booted() -> (Booted, String) {
    let addr = format!("127.0.0.1:{}", free_port());
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "LISTEN" && *k != "LISTEN_HEADER_READ_TIMEOUT_SECS");
    let mut vars: Vec<(&str, &str)> = vars;
    vars.push(("LISTEN", addr.as_str()));
    vars.push(("LISTEN_HEADER_READ_TIMEOUT_SECS", BOUND_SECS));
    let mut gateway = Booted::start(&vars);
    gateway.wait_until_listening();
    (gateway, addr)
}

/// Send `bytes`, then stall, and return how long the server took to close.
/// Fails if the connection is still open at `BOUND + MARGIN`.
fn closed_after(gateway: &mut Booted, addr: &str, bytes: &[u8]) -> Duration {
    let mut stream = TcpStream::connect(addr).expect("the edge must accept a connection");
    let started = Instant::now();
    stream
        .write_all(bytes)
        .expect("the partial head must be sent");
    stream
        .set_read_timeout(Some(BOUND + MARGIN))
        .expect("a read timeout");
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return started.elapsed(),
            // Whatever the server writes before it closes is not the point.
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return started.elapsed(),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => gateway
                .fail(&format!(
                    "the edge still held the connection {:?} after a stalled request head; \
                     LISTEN_HEADER_READ_TIMEOUT_SECS={BOUND_SECS} must close it",
                    started.elapsed()
                )),
            Err(e) => gateway.fail(&format!("the read failed unexpectedly: {e}")),
        }
    }
}

fn assert_within_bound(elapsed: Duration) {
    assert!(
        elapsed + SLACK >= BOUND,
        "closed after {elapsed:?}, before the {BOUND:?} bound: something other than the \
         header-read timeout closed it"
    );
    assert!(
        elapsed <= BOUND + MARGIN,
        "closed after {elapsed:?}, past the {BOUND:?} bound plus {MARGIN:?}"
    );
}

/// The slowloris shape: a request line and some headers, and never the blank
/// line that ends the head.
#[test]
fn a_stalled_request_head_is_closed_within_the_bound() {
    let (mut gateway, addr) = booted();
    let elapsed = closed_after(
        &mut gateway,
        &addr,
        b"GET /health HTTP/1.1\r\nHost: gateway\r\nX-Slow: 1\r\n",
    );
    assert_within_bound(elapsed);
}

/// Nothing at all. hyper-util's protocol sniff waits for bytes before any h1
/// connection exists, so only a builder that skips the sniff bounds this.
#[test]
fn a_connection_that_sends_nothing_is_closed_within_the_bound() {
    let (mut gateway, addr) = booted();
    let elapsed = closed_after(&mut gateway, &addr, b"");
    assert_within_bound(elapsed);
}
