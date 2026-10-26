//! `yadgar_gateway::edge`, in process: the parts of the edge server that
//! `tests/edge_header_timeout.rs` cannot reach through the binary in a few
//! seconds (yaadgaar #218, ADR-1006).
//!
//! - The header-read bound applies to EVERY request head on a connection, not
//!   only the first. hyper re-arms its timer each time it starts reading a
//!   head, so a client that sends one good request and then stalls is closed
//!   too.
//! - A request still reaches the router with the peer address attached.
//!   `axum::serve` attached it through `into_make_service_with_connect_info`,
//!   and `src/boot/wiring.rs` explains why losing it makes every request
//!   `Source::Unknown`. `edge::serve` attaches it itself, and the
//!   [`a_whole_request_is_answered_with_its_peer_address`] case is what reds if
//!   that line goes.
//! - `edge::header_read_timeout` refuses an absent or invalid value, naming the
//!   variable and the chart key (ADR-0569: no compiled-in default).
//!
//! The drain half of `edge::serve` is `tests/drain.rs`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::routing::get;
use axum::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use yadgar_gateway::edge::{self, HEADER_READ_TIMEOUT_KEY, HEADER_READ_TIMEOUT_VAR};

const BOUND: Duration = Duration::from_secs(1);
const SLACK: Duration = Duration::from_millis(300);
const MARGIN: Duration = Duration::from_secs(3);

/// `edge::serve` on a free loopback port, with a stop channel that is never
/// fired: the case ends and the runtime takes the task with it.
async fn serving(router: Router) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free loopback port");
    let addr = listener.local_addr().expect("a local address");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(edge::serve(listener, router, BOUND, async {
        let _ = stopped.await;
    }));
    (addr, stop)
}

fn peer_router() -> Router {
    Router::new().route(
        "/peer",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
    )
}

/// Read one response whose body ends with `tail`.
async fn read_response(stream: &mut TcpStream, tail: &str) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + MARGIN;
    while !String::from_utf8_lossy(&got).ends_with(tail) {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = tokio::time::timeout(left, stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no whole response within {MARGIN:?}: {}",
                    String::from_utf8_lossy(&got)
                )
            })
            .expect("the read must not fail");
        assert!(
            n > 0,
            "the server closed before the response ended: {}",
            String::from_utf8_lossy(&got)
        );
        got.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

#[tokio::test]
async fn a_whole_request_is_answered_with_its_peer_address() {
    let (addr, _stop) = serving(peer_router()).await;
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let me = stream.local_addr().expect("a local address").to_string();
    stream
        .write_all(b"GET /peer HTTP/1.1\r\nHost: gateway\r\n\r\n")
        .await
        .expect("send");

    let response = read_response(&mut stream, &me).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the router must see ConnectInfo<SocketAddr>: {response}"
    );
}

#[tokio::test]
async fn a_stalled_second_head_on_a_kept_alive_connection_is_closed() {
    let (addr, _stop) = serving(peer_router()).await;
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let me = stream.local_addr().expect("a local address").to_string();
    stream
        .write_all(b"GET /peer HTTP/1.1\r\nHost: gateway\r\n\r\n")
        .await
        .expect("send the first request");
    read_response(&mut stream, &me).await;

    stream
        .write_all(b"GET /peer HTTP/1.1\r\nHost: gateway\r\n")
        .await
        .expect("send the stalled head");
    let started = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout(BOUND + MARGIN, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(_)) => {}
            Err(_) => panic!(
                "the second, stalled request head held the connection past {:?}",
                BOUND + MARGIN
            ),
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed + SLACK >= BOUND,
        "closed after {elapsed:?}, before the {BOUND:?} bound"
    );
}

#[test]
fn the_bound_is_read_from_its_variable() {
    let bound = edge::header_read_timeout(|n| (n == HEADER_READ_TIMEOUT_VAR).then(|| "10".into()))
        .expect("10 is the chart default and must be accepted");
    assert_eq!(bound, Duration::from_secs(10));
}

#[test]
fn an_absent_or_invalid_bound_is_refused_naming_the_variable_and_the_key() {
    let range = edge::HEADER_READ_TIMEOUT_RANGE;
    let below = (range.start() - 1).to_string();
    let above = (range.end() + 1).to_string();
    for value in [
        None,
        Some(""),
        Some("ten"),
        Some("-1"),
        Some("1.5"),
        Some(below.as_str()),
        Some(above.as_str()),
    ] {
        let refusal = edge::header_read_timeout(|n| {
            assert_eq!(n, HEADER_READ_TIMEOUT_VAR);
            value.map(str::to_string)
        })
        .expect_err("an absent or invalid bound must be refused");
        assert!(
            refusal.contains(HEADER_READ_TIMEOUT_VAR) && refusal.contains(HEADER_READ_TIMEOUT_KEY),
            "the refusal for {value:?} must name the variable and the chart key: {refusal}"
        );
    }
}

#[test]
fn both_ends_of_the_range_are_accepted() {
    let range = edge::HEADER_READ_TIMEOUT_RANGE;
    for secs in [*range.start(), *range.end()] {
        let value = secs.to_string();
        let bound = edge::header_read_timeout(|_| Some(value.clone()))
            .unwrap_or_else(|e| panic!("{secs} is inside the range: {e}"));
        assert_eq!(bound, Duration::from_secs(secs));
    }
}

#[test]
fn the_names_are_the_ones_the_chart_renders() {
    assert_eq!(HEADER_READ_TIMEOUT_VAR, "LISTEN_HEADER_READ_TIMEOUT_SECS");
    assert_eq!(
        HEADER_READ_TIMEOUT_KEY,
        "server.limits.headerReadTimeoutSeconds"
    );
}
