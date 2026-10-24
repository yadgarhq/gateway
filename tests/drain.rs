//! RETURNED IS NOT THE SAME AS CLOSED — the one drain property that belongs to
//! the edge server rather than to `yadgar-lifecycle`.
//!
//! `yadgar-lifecycle` owns [`yadgar_lifecycle::drain_within`] and tests it
//! thoroughly, but it declares NO TRANSPORT — its own rig is a bare
//! `loop { listener.accept().await }`. Against a bare accept loop "the port
//! stopped accepting after the drain" is trivially true, because dropping the
//! listener binding releases the port. Against a real server it is a property
//! OF THE SERVE LOOP: its shutdown future resolving while the port still
//! accepts would mean the listener outlived the server.
//!
//! **THE FAILURE THIS KEEPS VISIBLE.** Someone edits `yadgar_gateway::edge`'s
//! accept loop, or bumps the `hyper` or `hyper-util` under it. The new code
//! resolves its shutdown but keeps the listener alive until in-flight
//! connections close, or leaks it outright. Every other test in this
//! repository stays green — nothing else here stands a real server through a
//! drain — and in production a rotation exit or a rollout starts the drain, the
//! port keeps accepting, new connections land on a process that is going away,
//! and they are severed by the SIGKILL at the end of
//! `terminationGracePeriodSeconds`. Silent in CI; visible only as 5xx during
//! rollouts. `hyper` 0.14 to 1.0, `tonic` 0.10 to 0.11 and `axum` 0.6 to 0.7 all
//! touched exactly this.
//!
//! **ONE RIG PER TRANSPORT, NOT ONE PER SERVICE.** This is the only HTTP edge
//! in the estate, so this file stands alone for it; `iam/tests/drain.rs` is the
//! tonic half and stands for `iam` and `task` together.
//!
//! **THIS RIG IS WHAT `main.rs` RUNS.** `boot::serve` calls
//! [`yadgar_gateway::edge::serve`] with an already-bound listener, and so does
//! this file. It used to be `axum::serve`; that call set no timer, so the edge
//! had no header-read bound (yaadgaar #218), and `edge::serve` replaced it.
//!
//! **NO `AppState` IS INVOLVED.** An empty `axum::Router` — every request
//! answers 404 — needs no upstream channel, no cache and no attestation source,
//! and keeps the rig honest that the LIFECYCLE is what is under test.
//!
//! Recovered from the `tests/drain.rs` deleted when this repository adopted
//! `yadgar-lifecycle`, reduced to the half the crate cannot hold. The other half
//! — that the budget's clock starts when shutdown is REQUESTED rather than when
//! `drain_within` is called — is transport-independent and is the crate's own.

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;

use yadgar_lifecycle::{drain_within, Drain};

/// Far shorter than the real `DRAIN_BUDGET`, so a case finishes quickly. A
/// server with nothing in flight drains at once, so the length is not what is
/// under test.
const BUDGET: Duration = Duration::from_millis(500);

/// Any bound inside the chart's range; nothing here sends a request head.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

async fn accepts(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// The real edge server, already spawned, with a oneshot as its shutdown
/// future — the shape `main` uses.
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

    let serving = tokio::spawn(yadgar_gateway::edge::serve(
        listener,
        Router::new(),
        HEADER_READ_TIMEOUT,
        async {
            let _ = stop_requested.await;
        },
    ));
    (port, serving, ask_to_stop)
}

#[tokio::test]
async fn an_edge_drain_releases_the_port_and_not_merely_the_future() {
    let (port, serving, ask_to_stop) = spawned().await;
    assert!(accepts(port).await, "the rig never came up");

    let outcome = drain_within(serving, ask_to_stop, std::future::ready(()), BUDGET).await;

    assert!(
        matches!(outcome, Drain::Finished(Ok(()))),
        "a server with nothing in flight drains at once, well inside {BUDGET:?}"
    );
    assert!(
        !accepts(port).await,
        "the drain returned but port {port} still accepts connections. The edge resolved \
         its shutdown while its listener outlived the server, so a rollout would \
         keep landing new connections on a process that is going away until the SIGKILL"
    );
}

/// A request in flight when the stop is asked for still gets its answer, and
/// only then does the serve future return. This is `edge::serve`'s own wait
/// on its connections: `axum::serve` did it inside the dependency, and the
/// loop that replaced it must do it itself. Dropping that wait returns the
/// future at once and severs the call, which reds both assertions below.
///
/// This holds the in-flight drain for the edge LOOP, in process. It does not
/// run the binary; `tests/exit_chain.rs` says what that leaves.
#[tokio::test]
async fn a_call_in_flight_at_the_stop_gets_its_answer_before_the_drain_ends() {
    use std::sync::Arc;

    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;

    let arrived = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let router = {
        let (arrived, release) = (arrived.clone(), release.clone());
        Router::new().route(
            "/slow",
            get(move || async move {
                arrived.notify_one();
                release.notified().await;
                "finished"
            }),
        )
    };

    let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("a free loopback port");
    let port = listener.local_addr().unwrap().port();
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(yadgar_gateway::edge::serve(
        listener,
        router,
        HEADER_READ_TIMEOUT,
        async {
            let _ = stop_requested.await;
        },
    ));

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    client
        .write_all(b"GET /slow HTTP/1.1\r\nHost: gateway\r\n\r\n")
        .await
        .expect("send");
    arrived.notified().await;

    let drain = tokio::spawn(drain_within(
        serving,
        ask_to_stop,
        std::future::ready(()),
        Duration::from_secs(5),
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !drain.is_finished(),
        "the drain ended while a call was still in flight"
    );
    release.notify_one();

    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
        .await
        .expect("the answer must arrive, and the connection then close")
        .expect("the read must not fail");
    assert!(
        response.starts_with("HTTP/1.1 200") && response.ends_with("finished"),
        "the call in flight at the stop must get its answer: {response:?}"
    );
    let outcome = drain.await.expect("the drain task");
    assert!(
        matches!(outcome, Drain::Finished(Ok(()))),
        "the drain must finish once the call does"
    );
}
