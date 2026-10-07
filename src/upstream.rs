//! The gRPC side: clients for the module services.
//!
//! The gateway is a client of every module and a gRPC server to none, which is
//! why `build.rs` generates the client half only.
//!
//! # TLS and mutual TLS
//!
//! See [`tls`] for the full design reasoning (ADR-0845, ADR-0514, ADR-0516):
//! required, per upstream, with no compiled-in default; and the client
//! identity this gateway presents, a separate lever from the encrypted
//! transport. What stays here is the two things [`tls`] cannot see: the DIAL
//! itself, and the absence gauge that dialling through `yadgar_dial`
//! publishes.

use tonic::transport::Channel;

pub use tls::{TlsConfigError, UpstreamTls, IAM, PROJECT, TASK};

mod tls;

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
///
/// **`tls` decides the transport, and there is no third state.** `None` is the
/// cleartext path this gateway has always taken; `Some` is the same balancing
/// with the connection encrypted and `task` verified, and it returns an error
/// rather than a cleartext channel if the bundle is unusable.
///
/// **A `task` THAT IS NOT THERE YET IS NO LONGER AN ERROR HERE**, as of `dial`
/// v0.2.0 (ADR-0532). This used to resolve DNS before it built anything and
/// propagate the resolver's error, which `main` turned into a failed boot with
/// `?` — the behaviour that crash-looped this gateway six times on a rebuilt
/// cluster before `task`'s Service existed. The variant was
/// `BalanceError::Dns` rather than `NoEndpoints`: a Service that does not exist
/// answers NXDOMAIN, and the `?` on the resolution came before the
/// empty-answer branch that built `NoEndpoints`. The dial is lazy now: it
/// seeds the balancer with the name and returns a channel, so an absent `task`
/// costs a failed request rather than a pod that never starts, exactly as
/// [`connect_iam`] has always cost one. A CONFIGURATION mistake still fails
/// here — an unusable bundle, a missing client certificate, a host that is not a
/// URI authority.
pub async fn connect_task(
    host: &str,
    port: u16,
    tls: Option<&UpstreamTls>,
) -> Result<Channel, yadgar_dial::BalanceError> {
    match tls {
        None => yadgar_dial::connect(host, port).await,
        Some(tls) => yadgar_dial::connect_tls(host, port, &tls.options()).await,
    }
}

/// Connect to the `iam` logic service.
///
/// It carries the whole credential lifecycle: `POST /auth/login` and
/// `POST /auth/enrol` ISSUE a token over it (D75, D73), and `attest::attest`
/// RESOLVES one over it on every `tools/call` (ADR-0488).
///
/// **IT GOES THROUGH `yadgar_dial` NOW, and the paragraph that said it could
/// not is deleted rather than softened.** That paragraph gave two reasons and
/// neither survived. The first was ADR-0514: the scheme and the TLS
/// configuration must be decided in one expression, and a hand-rolled
/// `Endpoint` was how that was held here. `yadgar_dial::endpoint` IS that
/// expression — it is the implementation ADR-0514's own record points at — so
/// routing through it keeps the invariant in the one place that owns it
/// instead of holding it in two. The second was D23: `iam`'s Service WAS a
/// ClusterIP rather than headless, so "routing it through `yadgar_dial` would
/// change the balancing decision". It would not. A ClusterIP resolves to ONE
/// address, so the balancer holds one endpoint and every request rides one
/// HTTP/2 connection through kube-proxy — which is exactly what
/// `Endpoint::connect_lazy` did. Nothing about D23 moved.
///
/// **AND THE SERVICE DID BECOME HEADLESS, WITH NO SECOND CODE PATH** — ledger
/// 615 set `clusterIP: None` on `iam`'s chart. That sentence used to read "can
/// become headless later"; it has, and the prediction it made held: this
/// function is unchanged, because it names a host and a port and `yadgar_dial`
/// owns everything downstream of that.
///
/// **WHAT ROUTING IT HERE BUYS is the absence gauge.** `yadgar_dial` publishes
/// `yadgar_dial_upstream_never_resolved` for every upstream it dials, and
/// `deploy`'s `DialUpstreamNeverResolved` rule is the only thing that says a
/// lazy dial is pointed at nothing — ADR-0532 made an absent upstream cost a
/// failed request rather than a failed boot, so the pod is `1/1 Running` and
/// Argo-`Healthy` while it cannot log anybody in. The gauge is emitted from
/// INSIDE that crate, so the hop that bypassed the crate emitted nothing:
/// measured against the live store on 2026-09-05, series existed for `task`,
/// `task-db` and `iam-db`, and none for `iam`.
/// `tests/upstream_absence.rs` holds that, against string literals rather than
/// the crate's exported constant.
///
/// **STILL LAZY, and now lazy by the same mechanism as [`connect_task`].**
/// ADR-0532 seeds the balancer with the NAME — `Peer::Unresolved`, dialled the
/// way `connect_lazy` used to dial it — and withdraws it once an address
/// answers. An absent `iam` therefore degrades to a per-request failure that
/// `http::opaque_status` collapses to one opaque status, exactly as before.
///
/// **What that outage costs is larger than it was.** This comment used to say `/`
/// kept serving throughout, which was true while identity came from headers. It is
/// not true now: attestation goes through this channel, so an `iam` that cannot
/// answer stops MCP traffic too. The mitigation D72 names is a cache in front of
/// the lookup — "on a cache miss, never per request" — and it IS built:
/// [`crate::attest::Credentials`], cleared by the broker events
/// [`crate::invalidate`] consumes. So an `iam` outage costs a resolve per cache
/// miss rather than one per request, bounded by
/// `YADGAR_CREDENTIAL_TTL_SECONDS`.
///
/// **THE BUNDLE IS STILL READ EAGERLY, and that is not in tension with the
/// laziness above.** What stays lazy is the NAME RESOLUTION and the connection
/// — the parts that depend on `iam` existing. `yadgar_dial::connect_tls` calls
/// `TlsOptions::prepare` BEFORE it resolves anything, so a CA bundle that
/// cannot be used is still a refusal to boot rather than a per-request mystery
/// found under traffic.
///
/// The only ways THIS call can fail are a host string that cannot form a URI
/// authority and material that cannot be used — both configuration mistakes
/// rather than outages, and D69's rule is the right one for those.
pub async fn connect_iam(
    host: &str,
    port: u16,
    tls: Option<&UpstreamTls>,
) -> Result<Channel, yadgar_dial::BalanceError> {
    match tls {
        None => yadgar_dial::connect(host, port).await,
        Some(tls) => yadgar_dial::connect_tls(host, port, &tls.options()).await,
    }
}

/// Connect to `project`, the registry's logic tier (ledger 881).
///
/// **LAZY, LIKE THE OTHER TWO, AND HERE IT IS LOAD-BEARING RATHER THAN MERELY
/// CONSISTENT.** ADR-0674 rules that a gateway whose registry load fails still
/// boots and serves: unscoped surfaces — login, enrolment, health — need no
/// project at all, and crash-looping on an absent twin spends the restart budget
/// without changing anything. An eager dial with a `?` on it in `main` is exactly
/// the six-crash-loop shape ADR-0532 removed, and `project` is the newest service
/// in the estate — the one most likely not to be deployed yet on any given
/// cluster.
///
/// What still fails the boot is what fails it for the other two: a host that is
/// not a URI authority, and material that cannot be used.
///
/// **WHAT AN ABSENT `project` COSTS is one gauge at zero and a counter with a
/// reason of its own.** `crate::project::registry` publishes
/// `yadgar_gateway_project_registry_loaded` from boot, and in the shipped
/// `counting` mode every scoped call is served regardless — so the degraded
/// window is observable without being disruptive. Under `enforcing` it becomes a
/// 503 per scoped call, which is the ADR's intended behaviour and the reason the
/// flip is gated.
pub async fn connect_project(
    host: &str,
    port: u16,
    tls: Option<&UpstreamTls>,
) -> Result<Channel, yadgar_dial::BalanceError> {
    match tls {
        None => yadgar_dial::connect(host, port).await,
        Some(tls) => yadgar_dial::connect_tls(host, port, &tls.options()).await,
    }
}

/// D67's request id on every outbound request (ledger 1248).
pub mod request_id;

#[cfg(test)]
mod tests;
