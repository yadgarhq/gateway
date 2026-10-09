//! How the broker hop is ENCRYPTED: the `NATS_TLS_*` contract, the boot-time
//! checks of its files, and the `async-nats` options that dial it (B-N3,
//! ADR-0852, ADR-0845).
//!
//! Split out of [`super::broker`] for the file-size ceiling, along the seam the
//! hop already has: that file is WHERE the broker is and what credential this
//! gateway presents; this one is how the connection to it is verified and who
//! this gateway says it is at the TLS layer.

use std::path::Path;

use async_nats::rustls::pki_types::pem::PemObject;
use async_nats::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::broker::{Broker, URL};
use crate::upstream::UpstreamTls;

/// The prefix of the broker hop's transport variables (B-N3, ADR-0852):
/// `NATS_TLS_ENABLED`, `NATS_TLS_CA_FILE`, `NATS_TLS_CLIENT_CERT_FILE` and
/// `NATS_TLS_CLIENT_KEY_FILE`.
///
/// **THE SAME PARSER THE THREE gRPC HOPS USE**, [`UpstreamTls::from_lookup`],
/// rather than a fourth copy of it. So the switch has the same contract as
/// theirs (ADR-0845: exactly `"1"` or `"0"`, absence refuses the boot naming
/// the variable and `nats.tls.enabled`), the identity is both-or-neither, and
/// `crate::rotate` watches the bundle and the pair through the same
/// `Material` impl — which is what folds the one client leaf this pod
/// presents everywhere into ONE watch-set member.
const TLS_PREFIX: &str = "NATS";
/// The one `UpstreamTls` variable the broker hop cannot honour.
const TLS_DOMAIN: &str = "NATS_TLS_DOMAIN";

impl Broker {
    /// The broker hop's CA bundle and client identity, or `None` when the hop
    /// is cleartext. `crate::rotate` builds the watch set from this — the
    /// resolved configuration, never a second read of the environment.
    pub fn tls(&self) -> Option<&UpstreamTls> {
        self.tls.as_ref()
    }

    /// What this gateway presents to the broker and how it verifies it: the
    /// credential and the transport, and nothing about what is done with the
    /// connection.
    ///
    /// **ONE FUNCTION, and `Broker::connect` builds on it.** `tests/nats_tls.rs`
    /// dials a real TLS nats-server with exactly these options, so what that
    /// suite proves is what production sends.
    ///
    /// **THE TRUST STORE IS THE CA FILE AND NOTHING ELSE, on the first dial and
    /// on every reconnect.** `async-nats` 0.50 builds its rustls config on EVERY
    /// connection attempt (`connector.rs:544`, `tls::config_tls`) and loads the
    /// platform store only when no root file was given (`tls.rs:59`). A root
    /// file is always given when TLS is on, so no platform or public root ever
    /// joins it — the "no public roots" rule the gRPC hops keep by enabling
    /// neither `tls-native-roots` nor `tls-webpki-roots`. `tls_client_config`
    /// is deliberately NOT used: on that path the library loads the platform
    /// store anyway, and a distroless image has none to load.
    ///
    /// **`require_tls` IS THE LOAD-BEARING OPTION.** `async-nats` upgrades
    /// whenever the SERVER asks for TLS, so against a TLS broker everything else
    /// here works without it. What it adds is the refusal of a broker that does
    /// NOT ask — a cleartext listener, or one serving `allow_non_tls` — so a
    /// configuration that says TLS never dials in the clear.
    pub fn connect_options(&self) -> async_nats::ConnectOptions {
        // BUILT FROM THE PAIR, never spliced into the URL. `nats://user:pass@host`
        // carries a password only URL-encoded, so one containing `@`, `/` or `#`
        // would be silently truncated and a DIFFERENT password sent than the one
        // in the Secret — a failure with no visible cause at any layer.
        let options = match &self.credentials {
            Some(c) => async_nats::ConnectOptions::with_user_and_password(
                c.user.clone(),
                c.password.clone(),
            ),
            None => async_nats::ConnectOptions::new(),
        };
        let Some(tls) = &self.tls else {
            return options.require_tls(false);
        };
        let options = options
            .require_tls(true)
            .add_root_certificates(tls.ca_file().to_path_buf());
        match (tls.client_certificate_file(), tls.client_key_file()) {
            (Some(certificate), Some(key)) => {
                options.add_client_certificate(certificate.to_path_buf(), key.to_path_buf())
            }
            // `UpstreamTls` holds both or neither, so this arm is "neither":
            // the hop is encrypted and presents no identity, which a broker
            // still at `clientAuth: off` accepts and one at `required` refuses.
            _ => options,
        }
    }
}

/// The broker hop's transport, resolved and CHECKED, or `None` for cleartext.
///
/// **REQUIRED ONCE A BROKER IS CONFIGURED (ADR-0845).** [`Broker::from_lookup`]
/// calls this only after `NATS_URL` is non-empty — with no URL there is no hop
/// to encrypt — and before the credential, so an absent or empty
/// `NATS_TLS_ENABLED` refuses the boot naming it and `nats.tls.enabled` rather
/// than dialling a password across the pod network in the clear.
///
/// **A REFUSED HANDSHAKE IS REPORTED AS I/O by `async-nats`, not as a TLS
/// kind**, so the redial lines in [`super::broker`] carry a `tls` field and say
/// "or the TLS handshake with it failed"; the alert is in their `error`.
///
/// **CHECKED HERE, AT BOOT, because `async-nats` does not check until the
/// dial.** It reads these files inside every connection attempt, and its
/// failures there are a connect error the redial loop retries for ever. Two of
/// them are worse than that:
///
/// - **A CA file holding no certificate is ZERO trust anchors and NO error**
///   (`tls.rs`: an empty iterator is not an error). Every handshake then fails
///   as an unknown issuer, which reads as a broker fault rather than a
///   deployment one.
/// - **The chart's CA and client-cert volumes are `optional: true`**, the same
///   as every other mount here, so a missing Secret is an EMPTY DIRECTORY. The
///   process must exit naming the path, as the gRPC hops do — not boot into a
///   retry loop that says "cannot reach the broker".
///
/// So each file is read once here and refused unless it holds what it must.
/// Each read is watched (ADR-0523): `Material for Broker` returns these same
/// paths from the resolved [`UpstreamTls`].
pub(super) fn broker_tls(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Option<UpstreamTls>, String> {
    let Some(tls) = UpstreamTls::from_lookup(TLS_PREFIX, lookup).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    if tls.domain().is_some() {
        return Err(format!(
            "{TLS_DOMAIN} is set, and the broker hop cannot honour it: async-nats verifies the \
             broker's certificate against the host in {URL} and has no override. Unset \
             {TLS_DOMAIN} and point {URL} at a name the broker's certificate carries."
        ));
    }
    let ca = tls.ca_file();
    if certificates_in(ca, "NATS_TLS_CA_FILE")? == 0 {
        return Err(format!(
            "NATS_TLS_CA_FILE names {}, which holds no PEM certificate. That is zero trust \
             anchors, so every handshake with the broker would fail as an unknown issuer. Point \
             it at the bundle holding the authority that signed the broker's certificate.",
            ca.display()
        ));
    }
    if let (Some(certificate), Some(key)) = (tls.client_certificate_file(), tls.client_key_file()) {
        if certificates_in(certificate, "NATS_TLS_CLIENT_CERT_FILE")? == 0 {
            return Err(format!(
                "NATS_TLS_CLIENT_CERT_FILE names {}, which holds no PEM certificate, so this \
                 gateway has no identity to present to the broker.",
                certificate.display()
            ));
        }
        private_key_in(key)?;
    }
    Ok(Some(tls))
}

/// How many PEM certificates `path` holds, refusing the boot naming `variable`
/// and the path when it cannot be read or parsed.
fn certificates_in(path: &Path, variable: &str) -> Result<usize, String> {
    // ADR-0523-WATCHED: Broker
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "{variable} names {}, which cannot be read: {e}. TLS to the broker was asked for, \
             so this refuses to start rather than dialling without it.",
            path.display()
        )
    })?;
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map(|certificates| certificates.len())
        .map_err(|e| {
            format!(
                "{variable} names {}, which is not valid PEM: {e}",
                path.display()
            )
        })
}

/// Refuse the boot unless `path` holds a PEM private key.
fn private_key_in(path: &Path) -> Result<(), String> {
    // ADR-0523-WATCHED: Broker
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "NATS_TLS_CLIENT_KEY_FILE names {}, which cannot be read: {e}. A client certificate \
             cannot be presented without its key.",
            path.display()
        )
    })?;
    PrivateKeyDer::from_pem_slice(&bytes)
        .map(drop)
        .map_err(|e| {
            format!(
                "NATS_TLS_CLIENT_KEY_FILE names {}, which holds no PEM private key: {e}",
                path.display()
            )
        })
}
