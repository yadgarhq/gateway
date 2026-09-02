//! The gRPC side: clients for the module services.
//!
//! The gateway is a client of every module and a gRPC server to none, which is
//! why `build.rs` generates the client half only.
//!
//! # TLS
//!
//! **OPT-IN, OFF unless a deployment asks for it, and PER UPSTREAM.** With
//! nothing configured both channels dial exactly as they always have, in
//! cleartext. That is deliberate rather than timid: the code ships first and the
//! cut-over is a separate change that can be reverted on its own, and no server
//! in the estate serves TLS yet. Per upstream because `task` and `iam` are cut
//! over one at a time, and a single flag would make that all-or-nothing.
//!
//! **THE TRAP, and it is why this module has two implementations of the same
//! idea.** tonic decides TLS from `uri.scheme_str() == Some("https")`, NOT from
//! whether `Endpoint::tls_config` was set. An `http://` URI carrying a perfectly
//! valid `ClientTlsConfig` connects in cleartext, silently, with no error and no
//! log line — so a change that attaches a configuration and leaves the scheme
//! alone looks encrypted, passes any test that inspects configuration, and sends
//! the bearer token in the clear. `yadgar_dial::endpoint` couples the two
//! structurally; [`iam_endpoint`] below does the same thing for the one channel
//! that cannot go through `yadgar_dial` at all.
//!
//! **Why that channel cannot.** `iam`'s Service is a VIP rather than headless,
//! so it is dialled directly (see [`connect_iam`]); routing it through
//! `yadgar_dial` would change the balancing decision D23 made. The cost is that
//! the CA bundle checks exist twice — once inside `yadgar_dial`, once in
//! [`UpstreamTls::client_tls_config`] — and the two can drift. They are written
//! to the same list on purpose: read, decode, ASSERT NON-EMPTY, pin the
//! verification domain to the host, bound the handshake, and add no platform
//! trust store.
//!
//! **Configuration is file paths and a flag, never an issuer-specific resource**
//! (D80). A CA bundle on disk is written by cert-manager in the reference
//! deployment and by a hand-assembled Secret anywhere else, and nothing here can
//! tell the difference — which is the point.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

/// The environment variables one upstream's transport is configured from.
///
/// Built from a PREFIX rather than written out six times, so the naming stays
/// mechanical: `<PREFIX>_TLS_ENABLED`, `<PREFIX>_TLS_CA_FILE` and
/// `<PREFIX>_TLS_DOMAIN`. The two prefixes match the `TASK_HOST` / `IAM_HOST`
/// pair `main` already reads, and `task` and `iam` use the identical shape for
/// their own upstreams.
pub const TASK: &str = "TASK";

/// The other one. See [`TASK`].
pub const IAM: &str = "IAM";

/// How long one phase of establishing the `iam` connection may take.
///
/// Matches `yadgar_dial`'s, and bounds TWO phases once TLS is on for the reason
/// recorded there: tonic applies `connect_timeout` to the TCP connect alone,
/// while the handshake runs a layer above it, so the handshake is given the same
/// bound explicitly in [`UpstreamTls::client_tls_config`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// What a deployment got wrong about the transport, before anything is dialled.
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_CA_FILE names no CA bundle. TLS was asked \
         for, so this is a deployment mistake rather than a reason to connect in \
         cleartext — and it is NOT the same as leaving TLS off, which is the \
         supported way to run without one. Point {0}_TLS_CA_FILE at the PEM bundle \
         holding the authority that signed the upstream's certificate."
    )]
    NoCaFile(&'static str),
}

/// Why the `iam` channel could not be built.
///
/// The first three mirror `yadgar_dial::BalanceError`'s CA arms deliberately: an
/// operator who mounted the wrong bundle should get the same sentence whichever
/// upstream they got it wrong for.
#[derive(Debug, thiserror::Error)]
pub enum IamChannelError {
    #[error(
        "could not read the CA certificate bundle at {path}: {source}. TLS was \
         requested, so this is an error rather than a reason to connect in \
         cleartext."
    )]
    CaUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not decode the CA certificate bundle at {path}: {source}")]
    CaUnparsable {
        path: PathBuf,
        #[source]
        source: rustls_pki_types::pem::Error,
    },

    #[error(
        "the CA certificate bundle at {path} decoded without error but contains \
         no certificate. That is not the same as a missing file: the PEM reader \
         returns an empty list for input with no certificate section, so an \
         empty or truncated bundle would otherwise produce a trust store with \
         no roots — which trusts nobody and fails much later, at the handshake."
    )]
    CaEmpty { path: PathBuf },

    #[error("iam's address is not a usable URI: {source}")]
    Uri {
        #[source]
        source: tonic::transport::Error,
    },

    #[error("TLS could not be configured for iam: {source}")]
    Tls {
        #[source]
        source: tonic::transport::Error,
    },
}

/// Server TLS for one upstream: a CA bundle on disk, and optionally the name to
/// verify against.
///
/// **The verification domain defaults to the host being dialled**, and for
/// `task` that is what lets a certificate issued for the Service name work while
/// `yadgar_dial` talks to pod addresses. The override exists for a certificate
/// that names something else — a per-namespace FQDN, say — and is not needed
/// otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamTls {
    ca_file: PathBuf,
    domain: Option<String>,
}

impl UpstreamTls {
    /// Read one upstream's transport configuration from the environment.
    ///
    /// `Ok(None)` is the ordinary answer today: TLS is opt-in, so an
    /// unconfigured deployment dials in cleartext exactly as before.
    pub fn from_env(prefix: &'static str) -> Result<Option<Self>, TlsConfigError> {
        Self::from_lookup(prefix, |key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the
    /// decision that picks between an encrypted transport and a cleartext one
    /// could not be tested at all without this — the same reason
    /// `attest::Attestation::from_lookup` has one.
    pub fn from_lookup(
        prefix: &'static str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, TlsConfigError> {
        let get = |suffix: &str| {
            lookup(&format!("{prefix}_{suffix}"))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        // Exactly "1", the same rule `Attestation::from_lookup` applies to
        // YADGAR_TRUST_UNAUTHENTICATED_HEADERS. A permissive parse is how a
        // setting meant to be off ends up on, and the reverse mistake is worse
        // here: this flag is the revert lever for the cut-over, and a lever that
        // does not move is not one.
        if get("TLS_ENABLED").as_deref() != Some("1") {
            if get("TLS_CA_FILE").is_some() {
                // NOT an error. Leaving the bundle in place while the flag is
                // off is exactly how the cut-over gets reverted, so refusing it
                // would make the lever unusable. It is still worth a line: a
                // deployment that believes it is encrypted and is not should be
                // able to see that from the boot log.
                tracing::warn!(
                    prefix,
                    "a CA bundle is configured but {prefix}_TLS_ENABLED is not \"1\", so this \
                     upstream is dialled in CLEARTEXT"
                );
            }
            return Ok(None);
        }

        Ok(Some(Self {
            ca_file: PathBuf::from(get("TLS_CA_FILE").ok_or(TlsConfigError::NoCaFile(prefix))?),
            domain: get("TLS_DOMAIN"),
        }))
    }

    /// The PEM bundle holding the authorities this upstream is verified against.
    pub fn ca_file(&self) -> &Path {
        &self.ca_file
    }

    /// The name the peer's certificate is checked against, when it is not the
    /// host being dialled.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// The same settings as `yadgar_dial` takes them, for [`connect_task`].
    pub fn options(&self) -> yadgar_dial::TlsOptions {
        let options = yadgar_dial::TlsOptions::new(&self.ca_file);
        match &self.domain {
            None => options,
            Some(domain) => options.domain_name(domain),
        }
    }

    /// Read and CHECK the CA bundle, and settle the verification domain, for
    /// [`connect_iam`].
    ///
    /// **A second implementation of `yadgar_dial::TlsOptions::prepare`, and it
    /// is forced rather than chosen.** `iam` is dialled directly because its
    /// Service is a VIP (D23), so `yadgar_dial` never sees this configuration
    /// and its own preparation cannot be reached. The list is kept identical on
    /// purpose; every line below has a counterpart there.
    ///
    /// Everything that can be wrong about the configuration is wrong here, once,
    /// before a channel exists — so a bad path is a startup error rather than an
    /// unexplained handshake failure much later, and never a quiet downgrade.
    pub fn client_tls_config(&self, host: &str) -> Result<ClientTlsConfig, IamChannelError> {
        let pem = std::fs::read(&self.ca_file).map_err(|source| IamChannelError::CaUnreadable {
            path: self.ca_file.clone(),
            source,
        })?;

        // THE ASSERTION THIS FUNCTION EXISTS FOR. The PEM reader yields nothing
        // — rather than an error — for input that contains no certificate
        // section, so "parsed successfully" can mean "parsed nothing", and a
        // trust store with no roots trusts nobody. Left unchecked that surfaces
        // as a handshake failure against a hostname the operator has never seen,
        // which is among the hardest errors here to diagnose.
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| IamChannelError::CaUnparsable {
                path: self.ca_file.clone(),
                source,
            })?;
        if certificates.is_empty() {
            return Err(IamChannelError::CaEmpty {
                path: self.ca_file.clone(),
            });
        }

        Ok(ClientTlsConfig::new()
            // The host, NOT an address. `iam` is reached by its Service name so
            // the two coincide today; naming it anyway keeps this arm the same
            // shape as dial's, where they do not.
            .domain_name(self.domain.as_deref().unwrap_or(host))
            .ca_certificate(Certificate::from_pem(&pem))
            // The handshake needs its own bound: `connect_timeout` below covers
            // the TCP connect alone, so a peer that accepts the connection and
            // then stalls the handshake would otherwise be unbounded.
            .timeout(CONNECT_TIMEOUT))
        // NOTE the two methods NOT called here: `with_native_roots` and
        // `with_webpki_roots`. Either would add the platform's trust store
        // alongside the bundle, so a CA that failed to load would leave `iam`
        // verified against public roots instead — the silent downgrade this
        // change exists to remove, reintroduced one layer up.
    }
}

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

/// One endpoint for `iam`, with the scheme and the TLS configuration decided
/// TOGETHER.
///
/// **THE SCHEME IS WHAT SWITCHES TLS ON, not the presence of a configuration.**
/// tonic's connector tests `uri.scheme_str() == Some("https")` and, for an
/// `http://` URI, connects in cleartext while holding a perfectly good TLS
/// configuration it never consults. Nothing about the resulting channel says it
/// happened: no error, no log line, and a bearer token on the wire. So the two
/// are decided together, here, and cannot drift apart — which is exactly what
/// `yadgar_dial::endpoint` does for the upstreams that go through it.
fn iam_endpoint(
    host: &str,
    port: u16,
    tls: Option<&ClientTlsConfig>,
) -> Result<Endpoint, IamChannelError> {
    let scheme = if tls.is_some() { "https" } else { "http" };
    let endpoint = Endpoint::from_shared(format!("{scheme}://{host}:{port}"))
        .map_err(|source| IamChannelError::Uri { source })?
        // A stalled pod must not hold a request open until the caller's
        // deadline. tonic applies this to the TCP connect alone; the handshake
        // is bounded separately in `UpstreamTls::client_tls_config`.
        .connect_timeout(CONNECT_TIMEOUT)
        // HTTP/2 keepalive notices a pod that vanished without closing its
        // connection — the common case when a node goes away.
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(3));

    match tls {
        None => Ok(endpoint),
        Some(tls) => endpoint
            .tls_config(tls.clone())
            .map_err(|source| IamChannelError::Tls { source }),
    }
}

/// Connect to the `iam` logic service.
///
/// It carries the whole credential lifecycle: `POST /auth/login` and
/// `POST /auth/enrol` ISSUE a token over it (D75, D73), and `attest::attest`
/// RESOLVES one over it on every `tools/call` (ADR-0488).
///
/// **LAZY, and deliberately not `yadgar_dial::connect`.** `connect` resolves DNS eagerly
/// and returns `Err` when the name does not resolve, and `main` propagates that
/// with `?`, so an `iam` that is not deployed yet would crashloop the pod — and a
/// pod stuck in startup is one D68's autoscaler cannot help. Rolling this gateway
/// out before `iam`'s Service exists is an ordinary ordering, not an exotic one.
///
/// A lazy channel connects on first use instead, so an absent `iam` degrades to a
/// per-request failure that `http::opaque_status` collapses to one opaque status —
/// the same answer given for every other upstream problem, by construction rather
/// than by a second code path. The only way THIS call can fail is a host string
/// that cannot form a URI, or a CA bundle that cannot be used — both configuration
/// mistakes rather than outages, and D69's rule is the right one for those.
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
///
/// **THE BUNDLE IS READ HERE, EAGERLY, and that is not in tension with the
/// laziness above.** What stays lazy is the NAME RESOLUTION and the connection —
/// the parts that depend on `iam` existing. A CA bundle depends on nothing but
/// the deployment that wrote it, so deferring the read would turn an operator's
/// mistake into a per-request failure discovered under traffic instead of a
/// refusal to boot. `yadgar_dial::connect_tls` reads its bundle before the DNS
/// lookup for the same reason.
pub fn connect_iam(
    host: &str,
    port: u16,
    tls: Option<&UpstreamTls>,
) -> Result<Channel, IamChannelError> {
    let prepared = tls.map(|tls| tls.client_tls_config(host)).transpose()?;
    Ok(iam_endpoint(host, port, prepared.as_ref())?.connect_lazy())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values below are SENTINELS: nothing in `upstream.rs` could produce
    /// either of them, so a test that sees one saw it travel from the lookup.
    const SENTINEL_CA: &str = "/etc/yadgar/aardvark-9f3c/bundle.pem";
    const SENTINEL_DOMAIN: &str = "iam.verified-as-this.invalid";

    fn lookup<'a>(
        pairs: &'a [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// THE DEFAULT, and the property the whole change is built around: nothing
    /// configured means the cleartext path, unchanged, for BOTH upstreams.
    #[test]
    fn nothing_configured_means_no_tls() {
        assert_eq!(UpstreamTls::from_lookup(TASK, lookup(&[])).unwrap(), None);
        assert_eq!(UpstreamTls::from_lookup(IAM, lookup(&[])).unwrap(), None);
    }

    /// A bundle without the flag is the REVERTED state, not an error. The flag
    /// is the lever; leaving the path in place is how it gets pulled back.
    #[test]
    fn a_ca_bundle_alone_does_not_enable_tls() {
        let vars = [("IAM_TLS_CA_FILE", SENTINEL_CA)];
        assert_eq!(UpstreamTls::from_lookup(IAM, lookup(&vars)).unwrap(), None);
    }

    /// Anything but "1" is off, the same rule
    /// `YADGAR_TRUST_UNAUTHENTICATED_HEADERS` gets.
    #[test]
    fn only_exactly_one_enables_tls() {
        for value in ["0", "false", "no", "true", "yes", "", " "] {
            let vars = [("IAM_TLS_ENABLED", value), ("IAM_TLS_CA_FILE", SENTINEL_CA)];
            assert_eq!(
                UpstreamTls::from_lookup(IAM, lookup(&vars)).unwrap(),
                None,
                "{value:?} must not enable TLS"
            );
        }
    }

    /// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no bundle
    /// is a deployment mistake, and the answer to it is an error rather than a
    /// cleartext channel or the platform trust store.
    #[test]
    fn asking_for_tls_without_a_ca_bundle_is_an_error() {
        for vars in [
            vec![("IAM_TLS_ENABLED", "1")],
            vec![("IAM_TLS_ENABLED", "1"), ("IAM_TLS_CA_FILE", "")],
            vec![("IAM_TLS_ENABLED", "1"), ("IAM_TLS_CA_FILE", "   ")],
        ] {
            assert!(
                matches!(
                    UpstreamTls::from_lookup(IAM, lookup(&vars)),
                    Err(TlsConfigError::NoCaFile("IAM"))
                ),
                "{vars:?} must be refused, not silently downgraded"
            );
        }
    }

    /// Both values reach the settings, proved with names the module could not
    /// have chosen for itself.
    #[test]
    fn the_bundle_and_the_domain_both_arrive() {
        let vars = [
            ("IAM_TLS_ENABLED", "1"),
            ("IAM_TLS_CA_FILE", SENTINEL_CA),
            ("IAM_TLS_DOMAIN", SENTINEL_DOMAIN),
        ];
        let tls = UpstreamTls::from_lookup(IAM, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(tls.ca_file(), Path::new(SENTINEL_CA));
        assert_eq!(tls.domain(), Some(SENTINEL_DOMAIN));
    }

    /// TWO UPSTREAMS IN ONE PROCESS, cut over one at a time. `task` encrypted
    /// while `iam` is not is a state this deployment will actually pass
    /// through, so the prefixes have to keep the two apart.
    #[test]
    fn one_upstream_can_be_encrypted_while_the_other_is_not() {
        let vars = [("TASK_TLS_ENABLED", "1"), ("TASK_TLS_CA_FILE", SENTINEL_CA)];
        assert!(UpstreamTls::from_lookup(TASK, lookup(&vars))
            .unwrap()
            .is_some());
        assert_eq!(UpstreamTls::from_lookup(IAM, lookup(&vars)).unwrap(), None);
    }

    /// A REGRESSION GUARD on tonic's rule, not the proof that TLS works — the
    /// proof is `tests/iam_tls.rs`, which does real handshakes. It is here
    /// because the failure it catches is silent: tonic's connector switches on
    /// the URI SCHEME, so an `http://` endpoint carrying a TLS configuration
    /// connects in cleartext and reports nothing.
    #[test]
    fn the_scheme_follows_the_tls_configuration() {
        let cleartext = iam_endpoint("iam", 50052, None).unwrap();
        assert_eq!(cleartext.uri().scheme_str(), Some("http"));

        let secured = iam_endpoint(
            "iam",
            50052,
            Some(&ClientTlsConfig::new().domain_name("iam")),
        )
        .expect("a TLS endpoint with a valid domain builds");
        assert_eq!(secured.uri().scheme_str(), Some("https"));
    }

    /// A host that is not a name TLS can verify has to be refused. `ServerName`
    /// rejects it, and the only alternatives are to dial it unverified or to
    /// dial it in cleartext.
    #[test]
    fn a_host_that_is_not_a_valid_server_name_is_refused() {
        let tls = ClientTlsConfig::new().domain_name("not a server name");
        assert!(matches!(
            iam_endpoint("iam", 50052, Some(&tls)),
            Err(IamChannelError::Tls { .. })
        ));
    }
}
