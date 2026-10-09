//! How the cache hop is ENCRYPTED: the `VALKEY_TLS_*` contract, and the
//! `redis` certificates built from it (B-V3, ADR-0852, ADR-0845).
//!
//! Split out of [`super::valkey`] for the file-size ceiling, along the same
//! seam [`crate::invalidate::transport`] uses for the broker hop.
//!
//! **A SECOND COPY OF A FEW SMALL CHECKS, DELIBERATELY.** `redis` wants the
//! CA bundle and the client identity as BYTES, not paths — `Client::
//! build_with_tls` bakes them into the `Client` once, where `async-nats`
//! re-reads a path on every reconnect — so this module cannot simply reuse
//! [`crate::invalidate::transport`]'s path-shaped helpers. `crate::rotate`'s
//! own history is this file's licence for the duplication rather than an
//! argument against it: that module held the THIRD near-byte-identical copy
//! of a watcher core before it was lifted into a shared crate, and the
//! ruling was to end the state before the third copy arrived, not before the
//! second. This is the second.

use std::path::Path;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::upstream::UpstreamTls;

/// The prefix of the cache hop's transport variables (B-V3, ADR-0852):
/// `VALKEY_TLS_ENABLED`, `VALKEY_TLS_CA_FILE`, `VALKEY_TLS_CLIENT_CERT_FILE`
/// and `VALKEY_TLS_CLIENT_KEY_FILE`.
///
/// **THE SAME PARSER THE OTHER FOUR HOPS USE**, [`UpstreamTls::from_lookup`],
/// rather than a fifth copy of it. So the switch has the same contract as
/// theirs (ADR-0845: exactly `"1"` or `"0"`, absence refuses the boot naming
/// the variable and `valkey.tls.enabled`), the identity is both-or-neither,
/// and `crate::rotate` watches the bundle and the pair through the same
/// `Material` impl — which is what folds the one client leaf this pod
/// presents everywhere into ONE watch-set member.
const TLS_PREFIX: &str = "VALKEY";
/// The one `UpstreamTls` variable the cache hop cannot honour.
const TLS_DOMAIN: &str = "VALKEY_TLS_DOMAIN";

/// The cache hop's transport, resolved and CHECKED, or `None` for cleartext.
///
/// **UNCONDITIONAL, unlike [`crate::invalidate::transport::broker_tls`].**
/// The broker hop is only required once `NATS_URL` is non-empty, because a
/// cleartext deployment may run no broker at all; `YADGAR_VALKEY_ADDR` is
/// ALWAYS required (`boot::rate_limiting`), so `VALKEY_TLS_ENABLED` is too,
/// with no condition in front of it.
///
/// **CHECKED HERE, AT BOOT, for the same reason the broker hop is: `redis`
/// does not check until the first dial, and one failure mode is worse than
/// that.** A CA file holding no certificate is ZERO TRUST ANCHORS AND NO
/// ERROR — measured against `redis` 1.6's `retrieve_tls_certificates`: an
/// empty PEM iterator runs the `RootCertStore::add` loop zero times and
/// returns `Ok` with an empty, but present, store. Every handshake then
/// fails as an unknown issuer, which reads as the cache being broken rather
/// than as a deployment mistake. The chart's CA volume is `optional: true`
/// like every other mount here, so a missing Secret is an EMPTY DIRECTORY —
/// this refuses it by name rather than letting that silence through.
pub fn valkey_tls(lookup: &impl Fn(&str) -> Option<String>) -> Result<Option<UpstreamTls>, String> {
    let Some(tls) = UpstreamTls::from_lookup(TLS_PREFIX, lookup).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    if tls.domain().is_some() {
        return Err(format!(
            "{TLS_DOMAIN} is set, and the cache hop cannot honour it: the `redis` crate \
             verifies the cache's certificate against the host it dials (`connection.rs`'s \
             `ServerName::try_from(host)`) and has no override. Unset {TLS_DOMAIN} and point \
             YADGAR_VALKEY_ADDR at a name the cache's certificate carries."
        ));
    }
    let ca = tls.ca_file();
    if certificates_in(ca, "VALKEY_TLS_CA_FILE")? == 0 {
        return Err(format!(
            "VALKEY_TLS_CA_FILE names {}, which holds no PEM certificate. That is zero trust \
             anchors, so every handshake with the cache would fail as an unknown issuer. Point \
             it at the bundle holding the authority that signed the cache's certificate.",
            ca.display()
        ));
    }
    if let (Some(certificate), Some(key)) = (tls.client_certificate_file(), tls.client_key_file()) {
        if certificates_in(certificate, "VALKEY_TLS_CLIENT_CERT_FILE")? == 0 {
            return Err(format!(
                "VALKEY_TLS_CLIENT_CERT_FILE names {}, which holds no PEM certificate, so this \
                 gateway has no identity to present to the cache.",
                certificate.display()
            ));
        }
        private_key_in(key, "VALKEY_TLS_CLIENT_KEY_FILE")?;
    }
    Ok(Some(tls))
}

/// How many PEM certificates `path` holds, refusing the boot naming
/// `variable` and the path when it cannot be read or parsed.
fn certificates_in(path: &Path, variable: &str) -> Result<usize, String> {
    // ADR-0523-WATCHED: UpstreamTls
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "{variable} names {}, which cannot be read: {e}. TLS to the cache was asked for, \
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

/// Refuse the boot unless `path` holds a PEM private key, naming `variable`.
fn private_key_in(path: &Path, variable: &str) -> Result<(), String> {
    // ADR-0523-WATCHED: UpstreamTls
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "{variable} names {}, which cannot be read: {e}. A client certificate cannot be \
             presented without its key.",
            path.display()
        )
    })?;
    PrivateKeyDer::from_pem_slice(&bytes)
        .map(drop)
        .map_err(|e| {
            format!(
                "{variable} names {}, which holds no PEM private key: {e}",
                path.display()
            )
        })
}

/// The CA bundle and, when presented, the client identity — read ONCE, as
/// BYTES, for `redis::Client::build_with_tls`.
///
/// **RE-READS FILES [`valkey_tls`] JUST VALIDATED, deliberately, rather than
/// threading the bytes through.** The two calls are microseconds apart in
/// [`super::valkey::Limiter::new`], both before this process accepts a
/// single connection, so there is no window for the files to change between
/// them that the rotation watcher does not also cover for every other leaf
/// this process reads once. Keeping the validation and the byte-read as two
/// functions is what lets [`valkey_tls`] report EACH mistake by the variable
/// that names it, rather than this one reporting a read failure with no
/// variable to blame.
///
/// **READ ONCE FOR THE LIFE OF THE PROCESS, UNLIKE THE BROKER HOP.**
/// `async-nats` re-reads `NATS_TLS_CA_FILE` on every reconnect; `redis`
/// bakes these bytes into the `Client` here and the `ConnectionManager`
/// reconnects through that SAME `Client` for ever. A renewed leaf is picked
/// up by the process restart the lifecycle watcher performs on a rotation
/// (`crate::rotate`), never by a second read of these files.
pub(super) fn certificates(tls: &UpstreamTls) -> std::io::Result<redis::TlsCertificates> {
    // ADR-0523-WATCHED: UpstreamTls
    let root_cert = std::fs::read(tls.ca_file())?;
    let client_tls = match (tls.client_certificate_file(), tls.client_key_file()) {
        (Some(certificate), Some(key)) => Some(redis::ClientTlsConfig {
            // ADR-0523-WATCHED: UpstreamTls
            client_cert: std::fs::read(certificate)?,
            // ADR-0523-WATCHED: UpstreamTls
            client_key: std::fs::read(key)?,
        }),
        // `UpstreamTls` holds both or neither, so this arm is "neither": the
        // hop is encrypted and presents no identity.
        _ => None,
    };
    Ok(redis::TlsCertificates {
        client_tls,
        root_cert: Some(root_cert),
    })
}
