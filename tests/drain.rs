//! RETURNED IS NOT THE SAME AS CLOSED — the one drain property that belongs to
//! axum rather than to `yadgar-lifecycle`.
//!
//! `yadgar-lifecycle` owns [`yadgar_lifecycle::drain_within`] and tests it
//! thoroughly, but it declares NO TRANSPORT — its own rig is a bare
//! `loop { listener.accept().await }`. Against a bare accept loop "the port
//! stopped accepting after the drain" is trivially true, because dropping the
//! listener binding releases the port. Against axum it is a property OF THE
//! DEPENDENCY: `with_graceful_shutdown` resolving while the port still accepts
//! would mean the listener outlived the server.
//!
//! **THE FAILURE THIS KEEPS VISIBLE.** Someone bumps `axum`, or the `hyper`
//! under it. The new version resolves its graceful-shutdown future but keeps
//! the listener alive until in-flight connections close, or leaks it outright.
//! Every other test in this repository stays green — nothing else here stands a
//! real server through a drain — and in production a rotation exit or a rollout
//! starts the drain, the port keeps accepting, new connections land on a process
//! that is going away, and they are severed by the SIGKILL at the end of
//! `terminationGracePeriodSeconds`. Silent in CI; visible only as 5xx during
//! rollouts. `hyper` 0.14 to 1.0, `tonic` 0.10 to 0.11 and `axum` 0.6 to 0.7 all
//! touched exactly this.
//!
//! **ONE RIG PER TRANSPORT, NOT ONE PER SERVICE.** This is the only axum server
//! in the estate, so this file stands alone for it; `iam/tests/drain.rs` is the
//! tonic half and stands for `iam` and `task` together.
//!
//! **THIS RIG IS WHAT `main.rs` RUNS.** `axum::serve(listener, ..)` takes an
//! already-bound listener there and here, so unlike the tonic half there is no
//! second binding path a release could break behind this file's back.
//!
//! **NO `AppState` IS INVOLVED.** An empty `axum::Router` — every request
//! answers 404 — needs no upstream channel, no cache and no attestation source,
//! and keeps the rig honest that the LIFECYCLE is what is under test.
//!
//! Recovered from the `tests/drain.rs` deleted when this repository adopted
//! `yadgar-lifecycle`, reduced to the half the crate cannot hold. The other half
//! — that the budget's clock starts when shutdown is REQUESTED rather than when
//! `drain_within` is called — is transport-independent and is the crate's own.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;

use yadgar_lifecycle::{drain_within, Drain};

/// Far shorter than the real `DRAIN_BUDGET`, so a case finishes quickly. A
/// server with nothing in flight drains at once, so the length is not what is
/// under test.
const BUDGET: Duration = Duration::from_millis(500);

async fn accepts(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// A real axum server, already spawned, with a oneshot as its shutdown future —
/// the shape `main` uses.
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

    let serving = tokio::spawn(
        axum::serve(listener, Router::new())
            .with_graceful_shutdown(async {
                let _ = stop_requested.await;
            })
            .into_future(),
    );
    (port, serving, ask_to_stop)
}

#[tokio::test]
async fn an_axum_drain_releases_the_port_and_not_merely_the_future() {
    let (port, serving, ask_to_stop) = spawned().await;
    assert!(accepts(port).await, "the rig never came up");

    let outcome = drain_within(serving, ask_to_stop, std::future::ready(()), BUDGET).await;

    assert!(
        matches!(outcome, Drain::Finished(Ok(()))),
        "a server with nothing in flight drains at once, well inside {BUDGET:?}"
    );
    assert!(
        !accepts(port).await,
        "the drain returned but port {port} still accepts connections. axum resolved its \
         graceful-shutdown future while its listener outlived the server, so a rollout would \
         keep landing new connections on a process that is going away until the SIGKILL"
    );
}
