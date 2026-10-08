//! Each upstream's transport configuration — [`TASK`], [`IAM`] and
//! [`PROJECT`]'s TLS switch, CA bundle and optional client identity.
//!
//! Split out of [`super`] for the file-size ceiling: [`super::connect_task`],
//! [`super::connect_iam`] and [`super::connect_project`] are what USE this
//! configuration, and this module is what BUILDS it. The design reasoning
//! below is unchanged by the split.
//!
//! # TLS
//!
//! **REQUIRED, WITH NO COMPILED-IN DEFAULT (ADR-0845), AND PER UPSTREAM.** Each
//! upstream's `<PREFIX>_TLS_ENABLED` must be exactly `"1"` or `"0"`; an absent or
//! empty value refuses the boot naming the variable and the chart key, rather
//! than falling back to cleartext — a defaulted security switch decides the
//! transport's posture silently, which is the thing ADR-0569 forbids. `"0"` is
//! the explicit, supported way to dial in cleartext and the revert lever for the
//! cut-over. Per upstream because `task`, `iam` and `project` are cut over one at
//! a time, and a single flag would make that all-or-nothing.
//!
//! **THE TRAP, and it is why ADR-0514 exists.** tonic decides TLS from
//! `uri.scheme_str() == Some("https")`, NOT from whether `Endpoint::tls_config`
//! was set. An `http://` URI carrying a perfectly valid `ClientTlsConfig`
//! connects in cleartext, silently, with no error and no log line — so a change
//! that attaches a configuration and leaves the scheme alone looks encrypted,
//! passes any test that inspects configuration, and sends the bearer token in
//! the clear. `yadgar_dial::endpoint` couples the two structurally, in one
//! expression, and BOTH upstreams reach it: [`super::connect_task`] and
//! [`super::connect_iam`] hand their settings to that crate and build no
//! endpoint of their own.
//!
//! **THIS MODULE HELD A SECOND IMPLEMENTATION UNTIL IT DID NOT NEED TO.**
//! `connect_iam` used to build its own `Endpoint` and read its own CA bundle,
//! on the grounds that `iam`'s Service WAS a ClusterIP rather than headless and
//! that routing it through `yadgar_dial` would change the balancing decision
//! D23 made. It would not: a ClusterIP resolves to ONE address, so the balancer
//! holds one endpoint and every request rides one HTTP/2 connection through
//! kube-proxy — which is precisely what `Endpoint::connect_lazy` did. The
//! second implementation bought nothing and cost the thing a second
//! implementation always costs.
//!
//! **`iam`'s Service IS HEADLESS NOW** — `clusterIP: None`, ledger 615 — so the
//! premise that argument rested on is gone as well as the argument. Nothing
//! here changes with it, which was the prediction: this module names a host and
//! a port and hands both to `yadgar_dial`, so the Service type is not something
//! it can observe.
//!
//! **THE TWO DID DRIFT, and that is why the copy is gone rather than better
//! commented.** A count of PEM sections is not a count of trust anchors, and
//! this module's copy made only the first check for as long as its comment
//! claimed the lists were identical. A parity test caught it and then had to be
//! maintained forever. One implementation needs no parity test.
//!
//! **AND ROUTING BOTH HOPS THROUGH `yadgar_dial` IS WHAT PUBLISHES THE
//! ABSENCE GAUGE.** `yadgar_dial_upstream_never_resolved` is emitted from
//! inside that crate, so the hop that bypassed it emitted nothing and
//! `deploy`'s `DialUpstreamNeverResolved` rule could not fire for the upstream
//! carrying every login. See [`super::connect_iam`] and
//! `tests/upstream_absence.rs`.
//!
//! # Mutual TLS
//!
//! **The CA bundles above are one direction; this is the other.** A bundle
//! authenticates the upstream to this gateway. A client certificate
//! authenticates THIS GATEWAY to the upstream — ADR-0516, which chose mutual TLS
//! over a NetworkPolicy because a control the CNI enforces protects an EKS
//! deployment and protects nothing on kind (D80).
//!
//! **THAT PREMISE IS WITHDRAWN — ADR-0688 (2026-09-14).** `kindest/kindnetd:
//! v20260528-9350166c` runs the kube-network-policies controller and logs
//! `Policy engine is ready`; enforcement was measured live in the `yadgar`
//! namespace on 2026-09-12. A NetworkPolicy protects this hop on kind too.
//! ADR-0594, as amended by ADR-0686, ranks mutual TLS and an ingress
//! NetworkPolicy as EQUAL controls — but only on a hop where both sides hold a
//! leaf this deployment issued AND verifies. On this hop that is not yet true:
//! `iam` and `task`'s `serve.rs` present server TLS only and leave
//! `client_ca_root` unbuilt, so the certificate this module presents is not
//! checked by either upstream. Today the NetworkPolicy is the only BUILT
//! control on this hop; the certificate stays load-bearing for availability,
//! per the rest of this section, once the server side of mutual TLS lands.
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
//! **ONE READ SERVES BOTH HOPS.** [`UpstreamTls::options`] hands the pair to
//! `yadgar_dial`, which reads them before it resolves anything, for `task` and
//! for `iam` alike. This module used to read them a second time for `iam` and
//! a parity test held the two spellings together; the second spelling is gone.
//! `tests/iam_tls.rs::a_client_identity_that_cannot_be_read_is_an_error_before_any_channel_exists`
//! is what remains, and it asserts the WIRING — that the `IAM_TLS_CLIENT_*`
//! pair actually reaches that read — rather than a parity nothing can drift
//! from any more.
//!
//! **NOTHING HERE CHECKS WHAT THE CERTIFICATE SAYS THE CALLER IS.** The upstream
//! learns that this deployment issued the leaf, not which service presented it.
//!
//! **Configuration is file paths and a flag, never an issuer-specific resource**
//! (D80). A CA bundle on disk is written by cert-manager in the reference
//! deployment and by a hand-assembled Secret anywhere else, and nothing here can
//! tell the difference — which is the point.

use std::path::{Path, PathBuf};

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

/// The registry's logic tier (ledger 881). See [`TASK`].
///
/// A THIRD upstream and a third prefix, so the three can be cut over to TLS one
/// at a time exactly as the first two can.
pub const PROJECT: &str = "PROJECT";

/// What a deployment got wrong about the transport, before anything is dialled.
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error(
        "{0}_TLS_ENABLED is not set. It has no compiled-in default (ADR-0845, ADR-0569): \
         this flag is the one source for whether this hop dials in cleartext or over TLS, \
         and an absent or empty value refuses the boot rather than choosing cleartext \
         silently. Set {0}_TLS_ENABLED to \"1\" or \"0\", sourced from the chart's {1}."
    )]
    MissingEnabled(&'static str, String),

    #[error(
        "{0}_TLS_ENABLED is {1:?}, and only \"1\" or \"0\" are accepted. A permissive parse \
         is how a setting meant to be off ends up on, so this is refused rather than \
         treated as either value. Set {0}_TLS_ENABLED to \"1\" or \"0\", sourced from the \
         chart's {2}."
    )]
    InvalidEnabled(&'static str, String, String),

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
    /// `Ok(None)` is the explicit, supported answer for `<PREFIX>_TLS_ENABLED
    /// = "0"`: this upstream dials in cleartext. It is no longer what an
    /// unconfigured deployment gets — ADR-0845 requires the flag, and its
    /// absence refuses the boot. See [`Self::from_lookup`].
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

        // REQUIRED, WITH NO COMPILED-IN DEFAULT (ADR-0845, ADR-0569). Exactly
        // "1" or "0", the same rule `Attestation::from_lookup` applies to
        // YADGAR_TRUST_UNAUTHENTICATED_HEADERS — a permissive parse is how a
        // setting meant to be off ends up on — and an absent or empty value
        // is refused rather than treated as either one: a defaulted security
        // switch decides the hop's posture silently, which is the exact
        // thing ADR-0569 forbids. "0" is the explicit, supported way to dial
        // in cleartext and the revert lever for the cut-over.
        let chart_key = format!("{}.tls.enabled", prefix.to_lowercase());
        let enabled = match get("TLS_ENABLED").as_deref() {
            Some("1") => true,
            Some("0") => false,
            Some(other) => {
                return Err(TlsConfigError::InvalidEnabled(
                    prefix,
                    other.to_string(),
                    chart_key,
                ))
            }
            None => return Err(TlsConfigError::MissingEnabled(prefix, chart_key)),
        };

        if !enabled {
            // THE CLIENT CERTIFICATE IS NAMED HERE TOO, and leaving it out was
            // the silent case: an operator who mounts a client leaf and forgets
            // the flag gets a cleartext hop presenting no identity, and nothing
            // says so. Mutual TLS is meaningless without the encrypted transport
            // it runs inside, so this one flag turns both off.
            if get("TLS_CA_FILE").is_some() || get("TLS_CLIENT_CERT_FILE").is_some() {
                // NOT an error. Leaving the bundle in place while the flag is
                // explicitly off is exactly how the cut-over gets reverted, so
                // refusing it would make the lever unusable. It is still worth
                // a line: a deployment that believes it is encrypted and is
                // not should be able to see that from the boot log.
                tracing::warn!(
                    prefix,
                    "a CA bundle or a client certificate is configured but \
                     {prefix}_TLS_ENABLED is \"0\", so this upstream is dialled in \
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

    /// The same settings as `yadgar_dial` takes them, for
    /// [`super::connect_task`] and [`super::connect_iam`] alike — the one
    /// read the module header names.
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
}
