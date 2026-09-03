//! The drain budget, and the defect it was introduced as elsewhere.
//!
//! **THE BUG THIS FILE EXISTS TO KEEP DEAD.** `iam`'s first attempt at bounding
//! the drain wrapped the SERVING FUTURE in `tokio::time::timeout`:
//!
//! ```ignore
//! tokio::time::timeout(DRAIN_BUDGET, axum::serve(listener, app).with_graceful_shutdown(stop)).await
//! ```
//!
//! `timeout` fixes its deadline when it is CALLED, and the serving future spans
//! the server's whole life — so that bounds the SERVER, not its drain. The
//! process logged "the drain did not finish within its budget" and exited 25
//! seconds after boot, on every boot, TLS on or off, with no rotation and no
//! signal, and kubelet restarted it to do it again — in exchange for a watcher
//! whose default poll interval of 60s meant it never completed one pass.
//!
//! It passed 123 tests in `iam`, because every one of them tested a piece and
//! none tested the composition. This file is a copy of `iam/tests/drain.rs`,
//! taken with the drain budget it covers: a copy of the code without a copy of
//! its regression test would leave the same defect available here and unwatched.
//! So the assertion below is about ELAPSED TIME rather than outcome: a server
//! asked to stop at 600ms under a 100ms budget must still be serving at 350ms,
//! and the call must return at 600ms and not at 100ms. The broken shape fails
//! both.
//!
//! `serve::drain_within` exists to make that shape unavailable: it takes the
//! server ALREADY SPAWNED and the sender that asks it to stop, so the budget
//! cannot be started before the request that it bounds.
//!
//! **The rig is `axum::serve` rather than tonic**, which is the one place this
//! copy differs from `iam`'s: what is under test is `drain_within`'s clock, and
//! the server it bounds has to be the server this binary actually runs.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use yadgar_gateway::serve::{self, Drain};

/// Far shorter than the real `DRAIN_BUDGET`, so a case finishes quickly. What is
/// under test is WHEN the clock starts, which is independent of its length.
const BUDGET: Duration = Duration::from_millis(100);

/// Long enough after the budget that a clock started at the wrong moment cannot
/// be mistaken for one started at the right moment.
const SERVE_FOR: Duration = Duration::from_millis(600);

/// Stand a real HTTP server on a real port, already spawned, with a oneshot as
/// its shutdown future — exactly the shape `main` uses.
async fn spawned() -> (
    u16,
    tokio::task::JoinHandle<std::io::Result<()>>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("a free loopback port");
    let port = listener.local_addr().unwrap().port();
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();

    // An EMPTY router. The LIFECYCLE is what is under test, not any handler.
    let serving = tokio::spawn(
        axum::serve(listener, axum::Router::new())
            .with_graceful_shutdown(async {
                let _ = stop_requested.await;
            })
            .into_future(),
    );
    (port, serving, ask_to_stop)
}

async fn accepts(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// THE REGRESSION. The budget must not run until something asks the server to
/// stop.
///
/// The broken shape ends the server at `BUDGET` — 100ms — while `stop` has not
/// resolved and nothing has asked for anything. Both assertions below catch it:
/// the port is closed at 350ms, and the call returns far too early.
#[tokio::test]
async fn the_budget_does_not_run_until_something_asks_the_server_to_stop() {
    let (port, serving, ask_to_stop) = spawned().await;
    assert!(accepts(port).await, "the rig never came up");

    let started = Instant::now();
    let stop = async {
        tokio::time::sleep(SERVE_FOR).await;
    };
    let still_serving = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(350)).await;
        accepts(port).await
    });

    let outcome = serve::drain_within(serving, ask_to_stop, stop, BUDGET).await;
    let elapsed = started.elapsed();

    assert!(
        still_serving.await.unwrap(),
        "the server stopped accepting {:?} in, long before anything asked it to. The budget's \
         clock started at the wrong moment, so it bounds the SERVER rather than its drain",
        Duration::from_millis(350)
    );
    assert!(
        elapsed >= SERVE_FOR,
        "the drain returned after {elapsed:?}, before the {SERVE_FOR:?} at which shutdown was \
         requested — so the budget was already running while the server was serving normally"
    );
    assert!(
        matches!(outcome, Drain::Finished(Ok(()))),
        "a server with nothing in flight drains at once"
    );
}

/// The ordinary path: asked to stop, finishes well inside its budget, and the
/// port it held is released.
#[tokio::test]
async fn a_drain_that_finishes_inside_its_budget_releases_the_port() {
    let (port, serving, ask_to_stop) = spawned().await;
    assert!(accepts(port).await, "the rig never came up");

    let outcome = serve::drain_within(serving, ask_to_stop, std::future::ready(()), BUDGET).await;

    assert!(matches!(outcome, Drain::Finished(Ok(()))));
    assert!(
        !accepts(port).await,
        "the drain returned but port {port} still accepts; the listener outlived the server"
    );
}

/// THE EXPIRY PATH. A server that will not finish is abandoned, and the caller
/// is told so rather than waiting for ever.
///
/// The stall is the server itself rather than a slow handler: what
/// `drain_within` promises is that a handle which does not complete cannot hold
/// the process open past the budget, and a task that never ends is the cleanest
/// statement of that. In production the same shape is one request blocked on a
/// responsive-but-slow upstream, with no deadline anywhere to end it.
#[tokio::test]
async fn a_drain_that_overruns_its_budget_ends_anyway() {
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel::<()>();
    let never_finishes = tokio::spawn(async move {
        let _ = stop_requested.await;
        std::future::pending::<()>().await
    });

    let started = Instant::now();
    let outcome =
        serve::drain_within(never_finishes, ask_to_stop, std::future::ready(()), BUDGET).await;

    assert!(
        matches!(outcome, Drain::Overran),
        "a server that never finishes must be abandoned, not waited on for ever"
    );
    assert!(
        started.elapsed() >= BUDGET,
        "it gave up before the budget had even elapsed"
    );
}
