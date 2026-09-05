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
//! to the same list on purpose: read, decode, ASSERT THE SECTIONS ARE NOT EMPTY,
//! ASSERT THE ROOT STORE IS NOT EMPTY, pin the verification domain to the host,
//! bound the handshake, and add no platform trust store.
//!
//! **THE TWO DID DRIFT, which is why the fourth item is spelled out.** A count of
//! PEM sections is not a count of trust anchors, and this copy made only the
//! first check for as long as the comment claimed the lists were identical. The
//! claim is a test now — `tests/iam_tls.rs::both_implementations_refuse_the_same_bundles`
//! — because a copy that only a paragraph holds together is a copy that drifts
//! again.
//!
//! # Mutual TLS
//!
//! **The CA bundles above are one direction; this is the other.** A bundle
//! authenticates the upstream to this gateway. A client certificate
//! authenticates THIS GATEWAY to the upstream — ADR-0516, which chose mutual TLS
//! over a NetworkPolicy because a control the CNI enforces protects an EKS
//! deployment and protects nothing on kind (D80).
//!
//! **ONE LEAF, TWO UPSTREAMS.** `gateway-client-tls` is this process's identity
//! rather than a property of a hop, so the chart mounts it once and points both
//! prefixes at the same two files. The prefixes still keep the hops apart: a
//! deployment can present an identity to `task` before it does to `iam`.
//!
//! **A SEPARATE LEVER FROM THE ENCRYPTED TRANSPORT, deliberately.**
//! `<PREFIX>_TLS_CLIENT_CERT_FILE` and `<PREFIX>_TLS_CLIENT_KEY_FILE` are unset
//! by default, so a deployment that turns TLS on verifies the upstream and
//! presents no identity — exactly as it did before.
//!
//! **THE CLIENT CERTIFICATE IS LOAD-BEARING FOR AVAILABILITY**, in a way the CA
//! bundles are not. ADR-0516 says it plainly: an expired client certificate
//! STOPS a hop rather than weakening it. That is why both files join
//! [`crate::rotate`]'s watch set in the same change that mounts them — and why,
//! in a process that serves no certificate of its own, they are the only
//! material whose expiry the gauge can report.
//!
//! **BOTH IMPLEMENTATIONS TAKE THEM, AND A TEST HOLDS THAT.** `options()` hands
//! them to `yadgar_dial` for the `task` hop; [`UpstreamTls::client_tls_config`]
//! reads them itself for the `iam` hop, which cannot go through `dial` at all.
//! `tests/iam_tls.rs::both_implementations_refuse_the_same_client_identity`
//! feeds one table of bad material to both and requires both to refuse.
//!
//! **NOTHING HERE CHECKS WHAT THE CERTIFICATE SAYS THE CALLER IS.** The upstream
//! learns that this deployment issued the leaf, not which service presented it.
//!
//! **Configuration is file paths and a flag, never an issuer-specific resource**
//! (D80). A CA bundle on disk is written by cert-manager in the reference
//! deployment and by a hand-assembled Secret anywhere else, and nothing here can
//! tell the difference — which is the point.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// The environment variables one upstream's transport is configured from.
///
/// Built from a PREFIX rather than written out ten times, so the naming stays
/// mechanical: `<PREFIX>_TLS_ENABLED`, `<PREFIX>_TLS_CA_FILE`,
/// `<PREFIX>_TLS_DOMAIN`, `<PREFIX>_TLS_CLIENT_CERT_FILE` and
/// `<PREFIX>_TLS_CLIENT_KEY_FILE`. The two prefixes match the `TASK_HOST` / `IAM_HOST`
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

    #[error(
        "{0}_TLS_CLIENT_CERT_FILE names a client certificate but {0}_TLS_CLIENT_KEY_FILE \
         names no private key. A certificate cannot be presented without the key that \
         proves it, so this is a deployment mistake rather than a reason to dial with no \
         identity at all — dialling without one is what leaving BOTH unset means, and it \
         is the default. Point {0}_TLS_CLIENT_KEY_FILE at the private key belonging to \
         that certificate."
    )]
    ClientCertificateWithoutKey(&'static str),

    #[error(
        "{0}_TLS_CLIENT_KEY_FILE names a private key but {0}_TLS_CLIENT_CERT_FILE names no \
         certificate. A key proves a certificate and is worth nothing on its own, so this \
         is a deployment mistake rather than a reason to dial with no identity at all — \
         dialling without one is what leaving BOTH unset means, and it is the default. \
         Point {0}_TLS_CLIENT_CERT_FILE at the certificate that key belongs to."
    )]
    ClientKeyWithoutCertificate(&'static str),
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

    #[error(
        "the CA certificate bundle at {path} holds {sections} PEM certificate \
         section(s) and NONE of them is a usable trust anchor. That is not the \
         same as an empty bundle: the sections are present and they decode as \
         PEM, so counting them says the file is fine. tonic builds its root \
         store with `add_parsable_certificates`, which reports how many it \
         accepted and how many it threw away, and discards that report — so a \
         bundle like this one produces a trust store with no roots and no error, \
         and fails much later, at the handshake."
    )]
    CaNoTrustAnchor { path: PathBuf, sections: usize },

    #[error(
        "could not read the client certificate at {path}: {source}. A client \
         certificate was configured, so this is an error rather than a reason \
         to connect without presenting one."
    )]
    ClientCertificateUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "could not read the client private key at {path}: {source}. A client \
         certificate without its key proves nothing, so this is an error rather \
         than a reason to connect without presenting one."
    )]
    ClientKeyUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

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
    client: Option<ClientIdentity>,
}

/// The certificate this gateway PRESENTS to an upstream, and the private key
/// that proves it — mutual TLS (ADR-0516).
///
/// **ONE LEAF, TWO UPSTREAMS.** `gateway-client-tls` is what this process shows
/// both `task` and `iam`; the chart mounts it once and points both prefixes at
/// the same two paths. That is why the watch set de-duplicates a path it already
/// holds — the same pair arrives twice.
///
/// **THIS GATEWAY SERVES NO CERTIFICATE OF ITS OWN**, so unlike `iam` and `task`
/// there is no serving leaf to confuse this with. `gateway-tls` is the EDGE
/// certificate, terminated by the ingress in front, and this process never reads
/// it. What it does read is this one, which makes the client leaf the only
/// certificate whose expiry this process can report.
///
/// **The two paths live together rather than as two `Option`s**, the same shape
/// `yadgar_dial::TlsOptions` uses: one without the other is not a configuration,
/// it is a mistake, and it is caught in [`UpstreamTls::from_lookup`] rather than
/// at the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClientIdentity {
    certificate: PathBuf,
    key: PathBuf,
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
            // THE CLIENT CERTIFICATE IS NAMED HERE TOO, and leaving it out was
            // the silent case: an operator who mounts a client leaf and forgets
            // the flag gets a cleartext hop presenting no identity, and nothing
            // says so. Mutual TLS is meaningless without the encrypted transport
            // it runs inside, so this one flag turns both off.
            if get("TLS_CA_FILE").is_some() || get("TLS_CLIENT_CERT_FILE").is_some() {
                // NOT an error. Leaving the bundle in place while the flag is
                // off is exactly how the cut-over gets reverted, so refusing it
                // would make the lever unusable. It is still worth a line: a
                // deployment that believes it is encrypted and is not should be
                // able to see that from the boot log.
                tracing::warn!(
                    prefix,
                    "a CA bundle or a client certificate is configured but \
                     {prefix}_TLS_ENABLED is not \"1\", so this upstream is dialled in \
                     CLEARTEXT and presents no identity"
                );
            }
            return Ok(None);
        }

        // BOTH, OR NEITHER. A certificate with no key cannot be presented and a
        // key with no certificate proves nothing, so each half alone is a
        // deployment mistake — and it is refused here rather than left to fail
        // at a handshake, where the message names neither variable.
        let client = match (get("TLS_CLIENT_CERT_FILE"), get("TLS_CLIENT_KEY_FILE")) {
            (None, None) => None,
            (Some(certificate), Some(key)) => Some(ClientIdentity {
                certificate: PathBuf::from(certificate),
                key: PathBuf::from(key),
            }),
            (Some(_), None) => return Err(TlsConfigError::ClientCertificateWithoutKey(prefix)),
            (None, Some(_)) => return Err(TlsConfigError::ClientKeyWithoutCertificate(prefix)),
        };

        Ok(Some(Self {
            ca_file: PathBuf::from(get("TLS_CA_FILE").ok_or(TlsConfigError::NoCaFile(prefix))?),
            domain: get("TLS_DOMAIN"),
            client,
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

    /// The certificate this gateway presents to this upstream, when it presents
    /// one.
    ///
    /// **`None` is the default and is not a degraded state**: mutual TLS is a
    /// separate lever from the encrypted transport, so a deployment can verify
    /// the upstream without identifying itself to it.
    pub fn client_certificate_file(&self) -> Option<&Path> {
        self.client.as_ref().map(|c| c.certificate.as_path())
    }

    /// The private key belonging to that certificate. Present exactly when
    /// [`Self::client_certificate_file`] is.
    pub fn client_key_file(&self) -> Option<&Path> {
        self.client.as_ref().map(|c| c.key.as_path())
    }

    /// The same settings as `yadgar_dial` takes them, for [`connect_task`].
    pub fn options(&self) -> yadgar_dial::TlsOptions {
        let options = yadgar_dial::TlsOptions::new(&self.ca_file);
        let options = match &self.domain {
            None => options,
            Some(domain) => options.domain_name(domain),
        };
        match &self.client {
            None => options,
            Some(client) => options.identity(&client.certificate, &client.key),
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
    /// **THAT SENTENCE WAS FALSE FOR AS LONG AS IT TOOK TO NOTICE, and saying so
    /// is the point.** `dial` grew the trust-anchor check first; this copy kept
    /// counting PEM sections, so the two disagreed about what "the bundle is
    /// usable" means while the comment went on asserting they agreed. A claim of
    /// sameness that nothing checks is how the copy drifts, so the claim is now
    /// backed by a TEST rather than by this paragraph:
    /// `tests/iam_tls.rs::both_implementations_refuse_the_same_bundles` feeds one
    /// table of bad bundles to BOTH paths and requires both to refuse. Delete a
    /// check on either side and it goes red.
    ///
    /// **What still differs, enumerated rather than waved at.** The CA list
    /// itself is identical: read, decode, non-empty sections, non-empty root
    /// store. The error TYPE differs — `IamChannelError` here,
    /// `yadgar_dial::BalanceError` there — because each names what its own
    /// caller can get wrong: this one adds `Uri`, and `dial`'s adds
    /// `InvalidHost`, which is the same mistake under the other name.
    ///
    /// **THAT SENTENCE USED TO NAME `Dns`, `DnsTimedOut` AND `NoEndpoints` as
    /// what `dial` adds, and v0.2.0 emptied the list.** `NoEndpoints` is
    /// DELETED — an empty resolution is no longer a failure — and `InvalidHost`
    /// replaces it. `Dns` and `DnsTimedOut` are still variants, and as far as
    /// this repository can tell no public entry point of that crate returns
    /// either one now: `resolve` is private, `connect_with` warns and continues
    /// with an empty set, and the refresh loop reports through `still_absent`
    /// and continues. That is a READING of another crate rather than a property
    /// anything here tests, and it is written as one. So the two error
    /// sets differ in naming alone, and what is CHECKED rather than asserted
    /// here is that neither implementation fails a dial because its upstream is
    /// absent —
    /// `tests/iam_tls.rs::both_implementations_survive_an_absent_upstream`.
    /// All four CA arms are one-for-one and their sentences are
    /// word-for-word — CHECKED against
    /// `yadgar_dial::BalanceError`, not assumed. Two wordings stay deliberately
    /// apart, and neither is a CA arm: the `Tls` arm names the upstream here
    /// ("for iam") because this module knows which one it is, and the comment on
    /// `.domain_name` differs because `dial` verifies a Service name against pod
    /// ADDRESSES while `iam` is reached by the name itself.
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

        // AND THE ASSERTION A SECTION COUNT CANNOT MAKE. The check above counts
        // PEM SECTIONS. What has to be non-empty is the ROOT STORE, and the two
        // part company for a bundle whose sections decode as PEM and then fail
        // to parse as a trust anchor — a key pasted under a CERTIFICATE header,
        // a truncated DER body. tonic hands exactly these DERs to
        // `add_parsable_certificates` and DISCARDS its `(accepted, rejected)`
        // return with no check after it
        // (`tonic-0.14.6/src/transport/channel/service/tls.rs:104`), so such a
        // bundle yields precisely the rootless trust store this function exists
        // to prevent, and the section count sees a healthy `1`.
        //
        // The store is built HERE, the way tonic will build it, and then
        // dropped: tonic accepts a PEM bundle rather than a store, so what this
        // buys is the answer to "how many roots will that produce", asked before
        // a channel exists instead of never.
        //
        // ORDER MATTERS. `CaEmpty` stays above: `accepted == 0` is also true of a
        // bundle with no sections at all, and that one has its own name and its
        // own sentence for the operator.
        let sections = certificates.len();
        let mut roots = rustls::RootCertStore::empty();
        let (accepted, _rejected) = roots.add_parsable_certificates(certificates);
        if accepted == 0 {
            return Err(IamChannelError::CaNoTrustAnchor {
                path: self.ca_file.clone(),
                sections,
            });
        }

        let mut configured = ClientTlsConfig::new()
            // The host, NOT an address. `iam` is reached by its Service name so
            // the two coincide today; naming it anyway keeps this arm the same
            // shape as dial's, where they do not.
            .domain_name(self.domain.as_deref().unwrap_or(host))
            .ca_certificate(Certificate::from_pem(&pem))
            // The handshake needs its own bound: `connect_timeout` below covers
            // the TCP connect alone, so a peer that accepts the connection and
            // then stalls the handshake would otherwise be unbounded.
            .timeout(CONNECT_TIMEOUT);

        // THE CLIENT IDENTITY, READ HERE AND EAGERLY, with the bundle and for
        // the same reason: a mount that did not happen is the operator's mistake
        // and is reported as itself, naming the file, rather than as a
        // connection the peer closed without saying why. `connect_iam` is lazy
        // about the NAME RESOLUTION, never about the material.
        //
        // THIS IS THE FIFTH ITEM ON THE LIST THIS FUNCTION'S DOC KEEPS, and it
        // is the one most likely to drift: `yadgar_dial::TlsOptions::prepare`
        // does exactly this, in the same order, with error sentences copied
        // word for word. `tests/iam_tls.rs::both_implementations_refuse_the_same_bundles`
        // feeds one table of bad material to BOTH paths and requires both to
        // refuse, so deleting either read goes red rather than quiet.
        //
        // THERE IS NO EMPTY-FILE CHECK TO MATCH `CaEmpty`, and the asymmetry is
        // deliberate rather than an omission — dial says the same. An empty CA
        // bundle parses to a trust store with no roots and fails much later; an
        // empty client chain is refused where rustls builds the configuration
        // and reaches the caller as `Tls` from `iam_endpoint`, before any
        // channel exists. Neither dials.
        if let Some(identity) = &self.client {
            let certificate = std::fs::read(&identity.certificate).map_err(|source| {
                IamChannelError::ClientCertificateUnreadable {
                    path: identity.certificate.clone(),
                    source,
                }
            })?;
            let key = std::fs::read(&identity.key).map_err(|source| {
                IamChannelError::ClientKeyUnreadable {
                    path: identity.key.clone(),
                    source,
                }
            })?;
            configured = configured.identity(Identity::from_pem(certificate, key));
        }

        Ok(configured)
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
/// **LAZY — and no longer the only lazy dial in this module.** `connect` used to
/// resolve DNS eagerly and return `Err` when the name did not resolve, and
/// `main` propagated that with `?`, so an `iam` that was not deployed yet would
/// have crashlooped the pod — and a pod stuck in startup is one D68's autoscaler
/// cannot help. Rolling this gateway out before `iam`'s Service exists is an
/// ordinary ordering, not an exotic one.
///
/// **`dial` v0.2.0 ADOPTED THIS SHAPE, which is why the paragraph above is in
/// the past tense.** ADR-0532 seeds `yadgar_dial`'s balancer with the NAME —
/// `Peer::Unresolved`, dialled the way `connect_lazy` dials it here — and
/// withdraws it once an address answers. So [`connect_task`] and this function
/// now AGREE about an absent upstream where they used to disagree: both hand
/// back a channel and defer the failure to the request.
/// `tests/iam_tls.rs::both_implementations_survive_an_absent_upstream` holds
/// that, because an agreement only a comment asserts is one that drifts — which
/// this module has already watched happen once, on the CA checks below.
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
    const SENTINEL_CLIENT_CERT: &str = "/etc/yadgar/aardvark-9f3c/gateway-caller.pem";
    const SENTINEL_CLIENT_KEY: &str = "/etc/yadgar/aardvark-9f3c/gateway-caller-key.pem";
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

    /// THE DEFAULT: no client certificate, so the dial presents no identity and
    /// behaves exactly as it did before ADR-0516.
    #[test]
    fn no_client_certificate_is_the_default() {
        let vars = [("IAM_TLS_ENABLED", "1"), ("IAM_TLS_CA_FILE", SENTINEL_CA)];
        let tls = UpstreamTls::from_lookup(IAM, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(tls.client_certificate_file(), None);
        assert_eq!(tls.client_key_file(), None);
    }

    /// BOTH PATHS ARRIVE, proved with names the module could not have chosen for
    /// itself. This is what `UpstreamTls`'s `Material` implementation reads to
    /// put them in the watch set, so a value that stopped travelling here would
    /// silently empty half the set.
    #[test]
    fn the_client_certificate_and_its_key_both_arrive() {
        let vars = [
            ("IAM_TLS_ENABLED", "1"),
            ("IAM_TLS_CA_FILE", SENTINEL_CA),
            ("IAM_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
            ("IAM_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
        ];
        let tls = UpstreamTls::from_lookup(IAM, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(
            tls.client_certificate_file(),
            Some(Path::new(SENTINEL_CLIENT_CERT))
        );
        assert_eq!(tls.client_key_file(), Some(Path::new(SENTINEL_CLIENT_KEY)));
    }

    /// HALF AN IDENTITY IS A DEPLOYMENT MISTAKE, refused at boot naming the
    /// variable rather than at a handshake naming neither.
    #[test]
    fn half_a_client_identity_is_refused() {
        let cert_only = [
            ("IAM_TLS_ENABLED", "1"),
            ("IAM_TLS_CA_FILE", SENTINEL_CA),
            ("IAM_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
        ];
        assert!(matches!(
            UpstreamTls::from_lookup(IAM, lookup(&cert_only)),
            Err(TlsConfigError::ClientCertificateWithoutKey("IAM"))
        ));

        let key_only = [
            ("IAM_TLS_ENABLED", "1"),
            ("IAM_TLS_CA_FILE", SENTINEL_CA),
            ("IAM_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
        ];
        assert!(matches!(
            UpstreamTls::from_lookup(IAM, lookup(&key_only)),
            Err(TlsConfigError::ClientKeyWithoutCertificate("IAM"))
        ));
    }

    /// AN EMPTY VALUE IS AN UNSET ONE, the same rule the CA bundle already gets.
    /// A values override that nulls the Secret name renders an empty string, and
    /// treating that as a configured path would fail the boot over a deployment
    /// that simply asked for no identity.
    #[test]
    fn an_empty_client_path_is_the_same_as_an_unset_one() {
        let vars = [
            ("IAM_TLS_ENABLED", "1"),
            ("IAM_TLS_CA_FILE", SENTINEL_CA),
            ("IAM_TLS_CLIENT_CERT_FILE", "  "),
            ("IAM_TLS_CLIENT_KEY_FILE", ""),
        ];
        let tls = UpstreamTls::from_lookup(IAM, lookup(&vars))
            .unwrap()
            .expect("a flag and a bundle enable TLS");
        assert_eq!(tls.client_certificate_file(), None);
    }

    /// A CLIENT CERTIFICATE WITHOUT THE FLAG IS THE REVERTED STATE, not an
    /// error. Mutual TLS runs inside the encrypted transport, so the one flag
    /// turns both off, and leaving the paths in place is how the cut-over gets
    /// pulled back.
    #[test]
    fn a_client_certificate_alone_does_not_enable_tls() {
        let vars = [
            ("IAM_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
            ("IAM_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
        ];
        assert_eq!(UpstreamTls::from_lookup(IAM, lookup(&vars)).unwrap(), None);
    }

    /// ONE LEAF, TWO UPSTREAMS, and the prefixes still have to keep them apart.
    /// The chart points both at the same mounted pair, but a deployment cutting
    /// one hop over before the other must be able to.
    #[test]
    fn one_upstream_can_present_an_identity_while_the_other_does_not() {
        let vars = [
            ("TASK_TLS_ENABLED", "1"),
            ("TASK_TLS_CA_FILE", SENTINEL_CA),
            ("TASK_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
            ("TASK_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
            ("IAM_TLS_ENABLED", "1"),
            ("IAM_TLS_CA_FILE", SENTINEL_CA),
        ];
        let task = UpstreamTls::from_lookup(TASK, lookup(&vars))
            .unwrap()
            .expect("task is configured");
        let iam = UpstreamTls::from_lookup(IAM, lookup(&vars))
            .unwrap()
            .expect("iam is configured");
        assert_eq!(
            task.client_certificate_file(),
            Some(Path::new(SENTINEL_CLIENT_CERT))
        );
        assert_eq!(iam.client_certificate_file(), None);
    }

    /// The gauge `dial` publishes for an upstream that never resolved reaches
    /// this binary's registry, under the name and the label an alert queries.
    ///
    /// **A METRIC A LIBRARY EMITS IS NOT AUTOMATICALLY A SERIES THIS SERVICE
    /// EXPORTS, and this case is what makes the difference visible.** On `dial`
    /// v0.2.0 the key does not exist at all, so this went RED before the pin
    /// moved. What it proves once green is the whole chain: the emission is on
    /// the boot path this service actually calls, it goes through the `metrics`
    /// facade this binary links rather than a second one, and
    /// `yadgar_telemetry::metrics::install_prometheus` builds a
    /// `PrometheusBuilder` with no allow-list, so a gauge in the registry is a
    /// gauge on `/metrics`.
    ///
    /// **THE NAME IS ASSERTED AS A STRING LITERAL, NOT AS
    /// `yadgar_dial::UPSTREAM_NEVER_RESOLVED`.** Comparing that constant with
    /// itself passes through a rename, and a rename is the one change to a
    /// metric that fails nowhere: every consumer compiles, a dashboard blanks
    /// and an alert stops. Spelling it out makes the next pin move that renames
    /// it fail HERE instead.
    ///
    /// **THERE IS NO `service` LABEL ON THIS SERIES.** `dial` is a library
    /// dialling outward with no service identity of its own and documents that
    /// it writes no second label, and `install_prometheus` adds no global one.
    /// `upstream` is the only dimension; the pod and the job come from the
    /// scrape. It differs from `yadgar_rotation_watched_files_unreadable` for
    /// that reason, not by oversight.
    ///
    /// **`task` IS THE ONLY UPSTREAM THIS BINARY COVERS, and that is a real gap
    /// rather than a gap in the test.** [`connect_iam`] builds its `Endpoint`
    /// here rather than through `yadgar_dial`, because the scheme and the TLS
    /// configuration are decided together in [`iam_endpoint`]. So no code path
    /// in this process publishes the series for `iam` — the upstream that
    /// carries every login, every enrolment and every attestation — and moving
    /// this pin does not change that. Closing it means routing `connect_iam`
    /// through the same crate, which is a change to how the gateway dials and
    /// not a change to what it observes.
    #[test]
    fn an_absent_task_is_published_as_a_gauge() {
        let (emitted, _channel) = dial_under_a_recorder(UNRESOLVABLE);
        assert!(
            gauge_for(&emitted, UNRESOLVABLE, 1.0),
            "a task that never resolved must be published as a gauge an alert \
             can read: {emitted:?}"
        );
    }

    /// The other direction, and it is not symmetry for its own sake.
    ///
    /// **A GAUGE WRITTEN ONLY ON THE UNHEALTHY PATH DOES NOT EXIST ON A HEALTHY
    /// POD**, and a series that does not exist cannot be compared against zero:
    /// `> 0` matches nothing, so "healthy" reads the same as "this crate was
    /// never linked" and the same as "the process died before its first tick".
    /// The boot dial publishing BOTH ways is what the alert `> 0` depends on,
    /// and it is a property of the pin rather than of this repository — so it is
    /// asserted here, where the pin is.
    #[test]
    fn a_task_that_resolves_publishes_the_same_gauge_at_zero() {
        let (emitted, _channel) = dial_under_a_recorder(RESOLVABLE);
        assert!(
            gauge_for(&emitted, RESOLVABLE, 0.0),
            "a resolvable task must still publish the series, at zero: \
             {emitted:?}"
        );
    }

    /// One row of a [`metrics_util::debugging::Snapshotter`] snapshot: the key
    /// with its kind, the unit and description a `describe_*` would have set,
    /// and the value.
    type Emitted = (
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        metrics_util::debugging::DebugValue,
    );

    /// A host that resolves to nothing, so the dial can only report absence.
    const UNRESOLVABLE: &str = "task-no-such-host-4b7e02.invalid";

    /// A name every host resolves without a network: `dial` only needs an
    /// address to build an endpoint, and nothing here connects.
    const RESOLVABLE: &str = "localhost";

    /// Dial `host` through [`connect_task`] with a LOCAL recorder and return
    /// everything it emitted.
    ///
    /// Local rather than `metrics::set_global_recorder`: a global one is
    /// process-wide and this binary runs its tests in parallel, so installing
    /// here would race every other case that emits a metric.
    ///
    /// The channel comes back with the snapshot and the caller HOLDS IT.
    /// `dial`'s refresh loop writes this same gauge back to 0 on the way out,
    /// and it leaves when the channel is dropped.
    fn dial_under_a_recorder(host: &str) -> (Vec<Emitted>, Channel) {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let channel = metrics::with_local_recorder(&recorder, || {
            rt.block_on(async { connect_task(host, 50051, None).await })
        })
        .expect("a cleartext dial is lazy and hands back a channel");

        // ONE SNAPSHOT. `Snapshotter::snapshot` DRAINS the registry, so a second
        // call sees nothing and its assertion fails while the gauge is being
        // emitted perfectly well.
        let emitted = snapshotter.snapshot().into_vec();
        // LENGTH FIRST, AND IT IS NOT A FORMALITY. A `metrics-util` resolving
        // against another `metrics` major links a SECOND facade; then this
        // snapshot is empty, and every assertion built on it passes vacuously.
        assert!(
            !emitted.is_empty(),
            "the recorder saw no metric at all, which is what a second metrics \
             facade in the tree looks like"
        );
        (emitted, channel)
    }

    /// Is the gauge present for `upstream`, holding `want`?
    fn gauge_for(emitted: &[Emitted], upstream: &str, want: f64) -> bool {
        emitted.iter().any(|(key, _, _, value)| {
            key.key().name() == "yadgar_dial_upstream_never_resolved"
                && key
                    .key()
                    .labels()
                    .any(|l| l.key() == "upstream" && l.value() == upstream)
                && matches!(value, metrics_util::debugging::DebugValue::Gauge(g) if g.0 == want)
        })
    }
}
