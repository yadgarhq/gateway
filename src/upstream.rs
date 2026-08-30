//! The gRPC side: clients for the module services.
//!
//! The gateway is a client of every module and a gRPC server to none, which is
//! why `build.rs` generates the client half only.

use tonic::transport::{Channel, Endpoint};

/// Connect to the `task` logic service.
///
/// **A single-endpoint channel, and that is a known limitation rather than a
/// choice.** gRPC holds one long-lived HTTP/2 connection, so a Service with a
/// virtual IP pins this process to ONE upstream pod and the other replicas take
/// no traffic — the problem D23 solved for `task -> task-db` with a headless
/// Service and client-side balancing.
///
/// `task`'s Service is not headless (`kubectl get svc task` returns a ClusterIP,
/// where `task-db` returns None), because until now nothing called `task` over
/// gRPC — the gateway is its first client. Fixing it properly means making that
/// Service headless AND moving the balancing helper out of `task/src/balance.rs`
/// into a shared crate, since two services now need it and the invariant is that
/// anything every service needs is implemented once. That is a change to another
/// repository and a decision about shared-crate layout, so it is filed rather
/// than smuggled in here.
///
/// The consequence today: correctness is unaffected, load distribution is not.
/// One `task` replica serves everything this gateway sends.
pub async fn connect_task(host: &str, port: u16) -> Result<Channel, tonic::transport::Error> {
    Endpoint::from_shared(format!("http://{host}:{port}"))?
        // A connect timeout, so a dead upstream fails the request rather than
        // hanging it. The gateway is the user-facing hop: a request that never
        // returns is worse here than anywhere else in the system.
        .connect_timeout(std::time::Duration::from_secs(5))
        .connect()
        .await
}
