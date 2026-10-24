//! The HTTP edge: this gateway's own accept loop (yaadgaar #218, ADR-1006).
//!
//! **WHY NOT `axum::serve`.** axum 0.8's `serve` builds hyper-util's
//! `auto::Builder` and never gives it a timer, and it offers no hook to set one.
//! hyper's `http1` builder defaults `header_read_timeout` to 30 s, but without a
//! timer it drops that default with a warning. So the edge had NO bound on a
//! half-sent request head, and one slowloris client per socket could hold the
//! pod's connections for ever. D80 rules out leaning on an ingress for this, so
//! the edge bounds itself, and the bound is a chart value (ADR-1006).
//!
//! **HTTP/1 ONLY, AND WITHOUT THE PROTOCOL SNIFF.** `auto::Builder` normally
//! reads up to 24 bytes to tell HTTP/1 from an HTTP/2 preface BEFORE any h1
//! connection exists, and that read has no timer. A client that connects and
//! sends nothing, or a partial preface, stalls there with every bound unset.
//! `http1_only()` with `serve_connection` (never `_with_upgrades`, which always
//! sniffs) goes straight to the h1 connection, whose timer starts at accept.
//! No chart in gateway, platform or deploy sets an `appProtocol` or any h2c
//! setting, so the Envoy ingress forwards HTTP/1.1 here, and nothing in this
//! repository upgrades a connection. A client's own HTTP/2 ends at the ingress.
//!
//! **WHAT `axum::serve` DID THAT THIS LOOP DOES ITSELF**, each held by a test:
//! - `ConnectInfo<SocketAddr>` on every request. `src/boot/wiring.rs` explains
//!   why its absence makes every request `Source::Unknown`
//!   (`tests/edge_serve.rs`).
//! - On stop: no new connections, the listener dropped so the port closes, and
//!   then a wait for every open connection to finish its call
//!   (`tests/drain.rs`). `yadgar_lifecycle::drain_within` bounds that wait.
//! - An accept error never ends the server. A reset or aborted handshake is
//!   skipped; anything else, such as `EMFILE`, is logged and retried after one
//!   second, which is axum's own `handle_accept_error`. Returning it instead
//!   would end the process on a burst of connections.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::{TcpListener, TcpStream};
use tower_service::Service;

/// The variable the chart renders the bound as.
pub const HEADER_READ_TIMEOUT_VAR: &str = "LISTEN_HEADER_READ_TIMEOUT_SECS";

/// The chart key that sources [`HEADER_READ_TIMEOUT_VAR`].
pub const HEADER_READ_TIMEOUT_KEY: &str = "server.limits.headerReadTimeoutSeconds";

/// The seconds the binary accepts, and the schema's `minimum` and `maximum`
/// (`tests/chart_edge_timeout.rs` pins the two together). Zero would close
/// every connection at once. Above a minute the bound stops bounding anything
/// a client would notice.
pub const HEADER_READ_TIMEOUT_RANGE: RangeInclusive<u64> = 1..=60;

/// How long the loop waits after an accept error that is not a connection's
/// own fault: axum's and hyper 0.14's one second.
const ACCEPT_RETRY: Duration = Duration::from_secs(1);

/// The header-read bound, read through `lookup` (the environment in `boot`).
///
/// No fallback (ADR-0569): an absent, empty, non-numeric or out-of-range value
/// refuses, naming the variable and the chart key.
pub fn header_read_timeout(lookup: impl Fn(&str) -> Option<String>) -> Result<Duration, String> {
    let var = HEADER_READ_TIMEOUT_VAR;
    let key = HEADER_READ_TIMEOUT_KEY;
    let (low, high) = (
        HEADER_READ_TIMEOUT_RANGE.start(),
        HEADER_READ_TIMEOUT_RANGE.end(),
    );
    let raw = match lookup(var) {
        Some(raw) if !raw.is_empty() => raw,
        Some(_) => {
            return Err(format!(
                "{var} is set but EMPTY. It has no compiled-in default (ADR-0569); the chart \
                 renders it from `{key}`, and a values override that nulls it produces exactly \
                 this."
            ))
        }
        None => {
            return Err(format!(
                "{var} is NOT SET. It has no compiled-in default (ADR-0569); the chart renders \
                 it from `{key}`."
            ))
        }
    };
    let secs: u64 = raw.parse().map_err(|e| {
        format!(
            "{var}={raw:?} is not a whole number of seconds ({e}). Set `{key}` to {low}..={high}."
        )
    })?;
    if !HEADER_READ_TIMEOUT_RANGE.contains(&secs) {
        return Err(format!(
            "{var}={secs} is outside {low}..={high} seconds. Set `{key}` inside that range."
        ));
    }
    Ok(Duration::from_secs(secs))
}

/// Serve `router` on `listener` until `shutdown` resolves, then stop accepting,
/// close the port, and wait for every open connection to finish.
///
/// Every request head must arrive whole within `header_read_timeout`, or the
/// connection is closed. That includes the first head after accept and every
/// later head on a kept-alive connection.
///
/// It never returns an error. The `io::Result` keeps the shape `boot::serve`
/// already reports through, and leaves room for one.
pub async fn serve<F>(
    listener: TcpListener,
    router: Router,
    header_read_timeout: Duration,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut builder = Builder::new(TokioExecutor::new()).http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = accept(&listener) => accepted,
            () = &mut shutdown => break,
        };
        let service = hyper::service::service_fn({
            let router = router.clone();
            move |request: Request<Incoming>| {
                let mut router = router.clone();
                let mut request = request.map(Body::new);
                request.extensions_mut().insert(ConnectInfo(peer));
                async move {
                    Ok::<_, Infallible>(router.call(request).await.unwrap_or_else(|e| match e {}))
                }
            }
        });
        let connection = builder
            .serve_connection(TokioIo::new(stream), service)
            .into_owned();
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(%peer, error = %e, "an edge connection ended with an error");
            }
        });
    }

    // The port closes HERE, before the wait: a rollout must stop landing new
    // connections on a process that is going away (`tests/drain.rs`).
    drop(listener);
    graceful.shutdown().await;
    Ok(())
}

/// One accepted connection. Never fails: see the module comment.
async fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(accepted) => return accepted,
            Err(e) if is_connection_error(&e) => {}
            Err(e) => {
                tracing::error!(error = %e, "the edge could not accept a connection; retrying");
                tokio::time::sleep(ACCEPT_RETRY).await;
            }
        }
    }
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}
