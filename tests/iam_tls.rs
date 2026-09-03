//! `connect_iam`'s transport, proved by real handshakes.
//!
//! **A test that only shows "TLS was configured" passes against the broken
//! version of this change.** tonic decides TLS from `uri.scheme_str() ==
//! Some("https")`, not from whether `Endpoint::tls_config` was set — so an
//! `http://` URI carrying a perfectly valid `ClientTlsConfig` connects in
//! cleartext, silently, and sends the bearer token in the clear. Nothing here
//! inspects configuration for that reason: every case stands up a real gRPC
//! server and asserts on whether a request survived.
//!
//! THE MUTATION THESE ARE WRITTEN AGAINST is forcing the scheme to `http` in
//! `upstream::iam_endpoint` while leaving the TLS configuration attached. Two
//! shapes below catch it, and they catch it from opposite directions: a TLS
//! server stops answering, and a CLEARTEXT server starts.
//!
//! `iam` is dialled directly rather than through `yadgar_dial` because its
//! Service is a VIP rather than headless (D23). That is why these handshakes are
//! tested here as well as in `dial`: it is a second implementation, and a second
//! implementation is a second thing that can be wrong.
//!
//! CERTIFICATES ARE MINTED PER RUN. A fixture key committed to the repository is
//! a secret committed to the repository, and it expires on a date nobody is
//! watching.
//!
//! NOTE ON `localhost`: it is the one name that resolves without touching
//! `/etc/hosts`, and it may resolve to BOTH `::1` and `127.0.0.1`. `serve`
//! therefore binds every address the name resolves to, on one port, so a
//! connection to the name always lands on something listening.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::transport::{Channel, Identity, Server, ServerTlsConfig};

use yadgar_gateway::upstream::{self, IamChannelError, UpstreamTls, IAM};

/// The name the test certificates are issued for, and the name the test rig
/// listens on.
const SERVED_NAME: &str = "localhost";

/// A certificate authority and one certificate it issued.
struct Pki {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

/// Mint a CA and a server certificate whose ONLY subject alternative name is
/// `san` — a DNS name, with no IP SAN.
fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-gateway test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &ca).unwrap();

    Pki {
        ca_pem: ca.pem(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A file that deletes itself, so a CA bundle can be handed over as a PATH —
/// which is the only shape the configuration accepts, and the reason it accepts
/// it (D80: paths and a flag, never an issuer-specific resource).
struct TempPem(PathBuf);

impl TempPem {
    fn with(contents: &str) -> Self {
        let name = format!(
            "yadgar-gateway-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The configuration `main` would have built, assembled through the SAME public
/// entry point rather than by hand — so a test cannot succeed against wiring
/// that `main` does not use.
fn settings(ca: &TempPem, domain: Option<&str>) -> UpstreamTls {
    let ca_file = ca.path().display().to_string();
    let mut vars: Vec<(String, String)> = vec![
        ("IAM_TLS_ENABLED".to_string(), "1".to_string()),
        ("IAM_TLS_CA_FILE".to_string(), ca_file),
    ];
    if let Some(domain) = domain {
        vars.push(("IAM_TLS_DOMAIN".to_string(), domain.to_string()));
    }
    UpstreamTls::from_lookup(IAM, |key| {
        vars.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
    })
    .expect("a flag and a bundle are a valid configuration")
    .expect("the flag is set, so TLS is on")
}

/// Serve gRPC over TLS on every address `SERVED_NAME` resolves to, and return
/// the shared port. `Routes::default()` answers every method with
/// `Unimplemented`, which is all that is needed: the question each test asks is
/// whether a request reached the server at all.
async fn serve(p: &Pki) -> u16 {
    let addrs = resolve().await;
    let first = TcpListener::bind(addrs[0]).await.unwrap();
    let port = first.local_addr().unwrap().port();
    spawn_tls_server(first, p);

    for addr in &addrs[1..] {
        let listener = TcpListener::bind(SocketAddr::new(addr.ip(), port))
            .await
            .expect("the same free port on a second address of the same name");
        spawn_tls_server(listener, p);
    }

    ready(port).await;
    port
}

/// Serve gRPC in CLEARTEXT, for the case that has to keep working untouched —
/// and for the case that must STOP working once TLS is on.
async fn serve_cleartext() -> u16 {
    let addrs = resolve().await;
    let first = TcpListener::bind(addrs[0]).await.unwrap();
    let port = first.local_addr().unwrap().port();
    spawn_cleartext_server(first);
    for addr in &addrs[1..] {
        let listener = TcpListener::bind(SocketAddr::new(addr.ip(), port))
            .await
            .unwrap();
        spawn_cleartext_server(listener);
    }
    ready(port).await;
    port
}

async fn resolve() -> Vec<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((SERVED_NAME, 0))
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty(), "{SERVED_NAME} resolved to nothing");
    addrs
}

fn spawn_tls_server(listener: TcpListener, p: &Pki) {
    let identity = Identity::from_pem(&p.cert_pem, &p.key_pem);
    let mut builder = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))
        .unwrap();
    let router = builder.add_routes(tonic::service::Routes::default());
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

fn spawn_cleartext_server(listener: TcpListener) {
    let mut builder = Server::builder();
    let router = builder.add_routes(tonic::service::Routes::default());
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

/// Wait until the port accepts a TCP connection, rather than sleeping a guessed
/// interval.
async fn ready(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect((SERVED_NAME, port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test server never accepted a connection on port {port}");
}

/// Send one gRPC request down the channel and report whether it ARRIVED.
///
/// `Ok` means the transport carried it: the handshake completed and the server
/// answered — with `Unimplemented`, which is a perfectly good answer to this
/// question. `Err` means it never got there.
///
/// The request goes through `poll_ready` first, and that is not a formality —
/// nor is it the assertion. `connect_iam` returns a LAZY channel, so it reports
/// ready before it has connected to anything at all. Only a request proves a
/// transport.
async fn request(mut channel: Channel) -> Result<(), String> {
    let req = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!(
            "https://{SERVED_NAME}/yadgar.iam.v1.IamService/Probe"
        ))
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())
        .unwrap();

    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .map_err(|e| format!("{e}"))?;
    match tokio::time::timeout(Duration::from_secs(10), channel.call(req)).await {
        Err(_) => Err("the request timed out".to_string()),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{e}")),
    }
}

/// THE CASE THE WHOLE CHANGE IS FOR. A configured `connect_iam` must actually
/// complete a TLS handshake against a server presenting a certificate from the
/// configured authority.
///
/// **Force the scheme to `http` in `iam_endpoint` and this fails**: the client
/// speaks cleartext at a TLS listener and never gets an answer. That is the
/// mutation, and this is the first of the three tests it turns red.
#[tokio::test]
async fn a_configured_channel_reaches_a_tls_server() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let channel = upstream::connect_iam(SERVED_NAME, port, Some(&settings(&ca, None)))
        .expect("a valid CA bundle and a host that forms a URI");

    assert_eq!(request(channel).await, Ok(()));
}

/// THE OTHER DIRECTION, and the one that would have passed against the broken
/// version. A channel configured for TLS must NOT quietly succeed against a
/// server speaking cleartext — succeeding there is exactly what "attached a
/// configuration and left the scheme alone" looks like from the outside.
///
/// **Force the scheme to `http` and this fails**: the request goes through, the
/// bearer token crosses the network in the open, and the assertion catches it.
/// Second of the three.
#[tokio::test]
async fn a_configured_channel_refuses_to_talk_to_a_cleartext_server() {
    let port = serve_cleartext().await;
    // The bundle is valid; only the SERVER is wrong. So nothing here can pass
    // for a configuration error.
    let p = pki(SERVED_NAME);
    let ca = TempPem::with(&p.ca_pem);

    let channel = upstream::connect_iam(SERVED_NAME, port, Some(&settings(&ca, None)))
        .expect("a valid CA bundle and a host that forms a URI");

    let outcome = request(channel).await;
    assert!(
        outcome.is_err(),
        "TLS was configured, so a cleartext listener must not be reached: {outcome:?}"
    );
}

/// The verification domain, proved with a name the implementation could not
/// have chosen: the certificate is issued for a sentinel, the host dialled is
/// not that sentinel, and only the override can reconcile them. A `TLS_DOMAIN`
/// that is parsed and then never reaches `.domain_name()` fails here.
///
/// **Force the scheme to `http` and the first half fails**, because the
/// override cannot help a client that never handshakes. Third of the three.
#[tokio::test]
async fn the_verification_domain_can_be_overridden() {
    const SENTINEL: &str = "gateway-pins-this-name.invalid";

    let p = pki(SENTINEL);
    let port = serve(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let channel =
        upstream::connect_iam(SERVED_NAME, port, Some(&settings(&ca, Some(SENTINEL)))).unwrap();
    assert_eq!(request(channel).await, Ok(()));

    // And without the override the same server is correctly refused: the
    // certificate does not name the host.
    let channel = upstream::connect_iam(SERVED_NAME, port, Some(&settings(&ca, None))).unwrap();
    assert!(
        request(channel).await.is_err(),
        "a certificate for {SENTINEL} must not satisfy a connection to {SERVED_NAME}"
    );
}

/// Verification has to be REAL. A certificate from an authority the caller does
/// not trust is what an impostor presents, and the bearer token must not go to
/// it. Drop `ca_certificate` from `client_tls_config`, or add the platform trust
/// store beside it, and this is the test that notices.
#[tokio::test]
async fn a_certificate_from_an_untrusted_authority_is_refused() {
    let served = pki(SERVED_NAME);
    let port = serve(&served).await;

    // A second authority, which issued nothing the server holds.
    let stranger = pki(SERVED_NAME);
    let ca = TempPem::with(&stranger.ca_pem);

    let channel = upstream::connect_iam(SERVED_NAME, port, Some(&settings(&ca, None))).unwrap();
    assert!(
        request(channel).await.is_err(),
        "a certificate signed by an authority that is not trusted must be refused"
    );
}

/// THE SILENT-DOWNGRADE CASE, in the form it actually takes: the PEM reader
/// returns an EMPTY LIST rather than an error, so a bundle that decodes to
/// nothing looks like a bundle that decoded fine — and a trust store with no
/// roots trusts nobody.
///
/// Each of these must be an error from `connect_iam`, never a channel. Delete
/// the `is_empty` check and every one of them becomes a channel.
#[tokio::test]
async fn a_ca_bundle_with_no_certificate_in_it_is_an_error() {
    for contents in ["", "   ", "\n", "there is no certificate in this file\n"] {
        let ca = TempPem::with(contents);
        let outcome = upstream::connect_iam(SERVED_NAME, 50052, Some(&settings(&ca, None)));
        assert!(
            matches!(outcome, Err(IamChannelError::CaEmpty { .. })),
            "a bundle containing {contents:?} must be rejected, not connected"
        );
    }
}

/// A bundle whose framing and base64 are valid and whose DER is not a
/// certificate.
///
/// A real private key's body under CERTIFICATE headers. `CertificateDer`'s PEM
/// reader decodes bytes and does not look at them, so it hands this over without
/// complaint and a section count sees a healthy `1`.
fn one_section_that_is_not_a_certificate() -> TempPem {
    let body = pki(SERVED_NAME)
        .key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n");
    TempPem::with(&format!(
        "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"
    ))
}

/// THE CASE A SECTION COUNT CANNOT SEE: a bundle that decodes as PEM and yields
/// no trust anchor at all.
///
/// tonic feeds those DERs to `add_parsable_certificates`, which throws away what
/// it cannot parse and reports how much — and tonic discards the report with no
/// check after it. The result is the empty root store `CaEmpty` exists to
/// prevent, reached by a path `CaEmpty` never covered.
///
/// **THE MUTATION THIS IS WRITTEN AGAINST** is deleting the `accepted == 0` arm
/// in `UpstreamTls::client_tls_config` and leaving the section count alone.
/// Measured against that mutant, `connect_iam` returns `Ok(Channel)` — a channel
/// that trusts nobody while looking configured, on the hop that carries the
/// bearer token.
///
/// The section count is asserted too, not only the variant: `sections: 1` is what
/// makes it this case rather than the empty-file one.
#[tokio::test]
async fn a_ca_bundle_whose_sections_are_not_trust_anchors_is_an_error() {
    let ca = one_section_that_is_not_a_certificate();
    let outcome = upstream::connect_iam(SERVED_NAME, 50052, Some(&settings(&ca, None)));
    assert!(
        matches!(
            outcome,
            Err(IamChannelError::CaNoTrustAnchor { sections: 1, .. })
        ),
        "a bundle holding one PEM section and no trust anchor must be rejected, not connected: \
         {outcome:?}"
    );
}

/// THE DIVERGENCE DETECTOR, and the reason it is a test rather than a paragraph.
///
/// `client_tls_config` and `yadgar_dial::TlsOptions::prepare` are two spellings
/// of one list, kept in step by a doc comment asserting they were identical —
/// which stopped being true the moment one side grew a check the other lacked,
/// and nothing noticed because nothing was checking. This is what checks.
///
/// **A CROSS-CRATE test IS possible, and the reason is worth recording**: `dial`
/// is a DEPENDENCY of this crate, and `connect_tls` calls `TlsOptions::prepare`
/// BEFORE it resolves anything, so a bad bundle is refused with no server, no
/// port and no DNS. The two implementations can therefore be handed the same
/// file in the same process.
///
/// **WHAT IS MISSING FROM THIS TABLE AND WHY.**
/// [`one_section_that_is_not_a_certificate`] belongs here and cannot join yet:
/// `dial`'s half of the fix is `yadgarhq/dial` PR #9, still open, and `Cargo.toml`
/// pins `yadgar-dial` by `rev` to a commit before it. Against that pin `dial`
/// answers `Ok(Channel)` for that bundle, which is the defect, not a property to
/// assert. When the pin advances past #9, add the row:
///
/// ```text
/// (one_section_that_is_not_a_certificate(), "one PEM section, no trust anchor"),
/// ```
///
/// and widen both `matches!` arms to accept the `CaNoTrustAnchor` variants.
#[tokio::test]
async fn both_implementations_refuse_the_same_bundles() {
    for contents in ["", "   ", "\n", "there is no certificate in this file\n"] {
        let ca = TempPem::with(contents);

        // The gateway's own copy, reached the way `main` reaches it.
        let mine = upstream::connect_iam(SERVED_NAME, 50052, Some(&settings(&ca, None)));
        assert!(
            matches!(mine, Err(IamChannelError::CaEmpty { .. })),
            "the gateway must refuse {contents:?}: {mine:?}"
        );

        // And the crate this one is a copy of, given the identical file.
        let theirs =
            yadgar_dial::connect_tls(SERVED_NAME, 50052, &yadgar_dial::TlsOptions::new(ca.path()))
                .await;
        assert!(
            matches!(theirs, Err(yadgar_dial::BalanceError::CaEmpty { .. })),
            "yadgar_dial must refuse {contents:?} for the same reason: {theirs:?}"
        );
    }
}

/// A path that is not there at all. The mistake an operator actually makes is a
/// mount that did not happen, and the answer to it must not be a cleartext
/// channel.
///
/// It is also the case that proves the bundle is read EAGERLY. The channel is
/// lazy, so a `connect_iam` that deferred the read would hand back `Ok` here
/// and fail per request under traffic instead of at boot.
#[tokio::test]
async fn a_ca_bundle_that_cannot_be_read_is_an_error_before_any_channel_exists() {
    let missing = std::env::temp_dir().join("yadgar-gateway-no-such-bundle-9d3f1a.pem");
    let vars = [
        ("IAM_TLS_ENABLED", "1"),
        ("IAM_TLS_CA_FILE", missing.to_str().unwrap()),
    ];
    let tls = UpstreamTls::from_lookup(IAM, |key| {
        vars.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    })
    .unwrap()
    .unwrap();

    assert!(
        matches!(
            upstream::connect_iam(SERVED_NAME, 50052, Some(&tls)),
            Err(IamChannelError::CaUnreadable { .. })
        ),
        "a CA path that does not exist must be rejected"
    );
}

/// THE PATH THAT MUST NOT HAVE MOVED. Unconfigured, `connect_iam` still speaks
/// cleartext to a cleartext server — which is every deployment today, and the
/// case that fails if TLS ever becomes the default by accident.
#[tokio::test]
async fn the_cleartext_path_still_reaches_a_cleartext_server() {
    let port = serve_cleartext().await;
    let channel = upstream::connect_iam(SERVED_NAME, port, None).unwrap();
    assert_eq!(request(channel).await, Ok(()));
}

/// And it is still cleartext, which is the other half of "unchanged": an
/// unconfigured dial to a TLS server has to fail rather than quietly negotiate
/// something. Without this, the case above could start passing for the wrong
/// reason.
#[tokio::test]
async fn the_cleartext_path_cannot_reach_a_tls_server() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;
    let channel = upstream::connect_iam(SERVED_NAME, port, None).unwrap();
    assert!(
        request(channel).await.is_err(),
        "cleartext against a TLS listener must fail"
    );
}
