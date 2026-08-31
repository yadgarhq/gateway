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
