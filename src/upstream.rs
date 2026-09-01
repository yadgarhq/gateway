//! The gRPC side: clients for the module services.
//!
//! The gateway is a client of every module and a gRPC server to none, which is
//! why `build.rs` generates the client half only.

use tonic::transport::Channel;

/// Connect to the `task` logic service, balancing across its replicas.
///
/// **This used to pin to a single pod, and fixing it took a change in two
/// repositories.** gRPC holds one long-lived HTTP/2 connection, so against a
/// Service with a virtual IP every request from this process reached the same
/// upstream pod while the others sat idle looking perfectly healthy — and D68's
/// autoscaler would have answered the resulting latency by adding replicas that
/// also received nothing.
///
/// `task`'s Service is headless now, so DNS returns every pod address, and
/// `yadgar-dial` balances across them and re-resolves as pods come and go.
///
/// The balancing code is a shared crate rather than a copy of
/// `task/src/balance.rs`. Two services needing the same logic is precisely the
/// case the invariant covers: a copy is how they come to disagree about how they
/// find their peers, and the disagreement is invisible until one of them is
/// wrong.
pub async fn connect_task(host: &str, port: u16) -> Result<Channel, yadgar_dial::BalanceError> {
    yadgar_dial::connect(host, port).await
}

/// Connect to the `iam` logic service, for `POST /auth/login` (D75).
///
/// **LAZY, and deliberately not `yadgar_dial::connect`.** `connect` resolves DNS eagerly
/// and returns `Err` when the name does not resolve, and `main` propagates that
/// with `?`, so an `iam` that is not deployed yet would crashloop the pod. The
/// endpoint at risk would not be `/auth/login`: it would be **all MCP traffic on
/// `/`**, taken down because a secondary upstream was missing. Rolling this
/// gateway out before `iam`'s Service exists is an ordinary ordering, not an
/// exotic one.
///
/// A lazy channel connects on first use instead, so an absent `iam` degrades to a
/// per-request failure that `http::login_answer` already collapses to an opaque
/// 503 — the same answer it gives for every other upstream problem, by
/// construction rather than by a second code path. `/` keeps serving throughout.
/// The only way THIS call can fail is a host string that cannot form a URI, which
/// is a configuration mistake rather than an outage, and D69's rule is the right
/// one for those.
///
/// **It pins ONE connection, and does not balance.** `iam`'s Service is a VIP
/// rather than headless, so there is one address to reach regardless; the
/// balancing `connect_task` exists for would have nothing to balance across. Fine
/// at the rate a person types a password. Written down because anyone reading
/// these two functions side by side would otherwise assume the gateway spreads
/// login across `iam` replicas, and would be wrong silently.
///
/// The timeouts match `yadgar_dial::endpoint`'s: a stalled pod must not hold a
/// request open, and HTTP/2 keepalive is what notices a pod that vanished without
/// closing its connection.
pub fn connect_iam(host: &str, port: u16) -> Result<Channel, tonic::transport::Error> {
    Ok(
        tonic::transport::Endpoint::from_shared(format!("http://{host}:{port}"))?
            .connect_timeout(std::time::Duration::from_secs(2))
            .http2_keep_alive_interval(std::time::Duration::from_secs(10))
            .keep_alive_timeout(std::time::Duration::from_secs(3))
            .connect_lazy(),
    )
}
