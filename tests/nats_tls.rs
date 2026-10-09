//! B-N3 (ledger 925, ADR-0852): the broker hop over TLS, against a REAL
//! nats-server rather than a configuration inspected in-process.
//!
//! **WHY A CONTAINER, AND WHY THIS TEST STARTS IT.** The property under test is
//! what a TLS verifier DOES with the material this gateway hands it, and only a
//! handshake shows that. A `services:` container cannot serve it: it starts
//! before the first step, so a certificate minted per run does not exist yet,
//! and nats-server reads its certificate once at startup. So each case mints its
//! own authority with rcgen, writes it to a fresh directory, and starts
//! `nats-server` with `docker run -d -v <dir>:/certs:ro` (the mechanism B-N0
//! measured). The image is the one the platform chart vendors, pinned by digest
//! (D61).
//!
//! **IT FAILS RATHER THAN SKIPS WITHOUT DOCKER.** A suite that turns green on a
//! machine that cannot run it is coverage that is not there. The shared CI's
//! `test` job runs on `ubuntu-latest`, which has docker.
//!
//! **EVERY CONTAINER IS REMOVED ON DROP**, including on a panic, and every name
//! is unique per run, because CI runs this suite twice (all features, then the
//! feature-off build) on one runner.
//!
//! **WHAT EACH CASE KILLS.** `require_tls` is killed only by the cleartext
//! broker case: against a TLS broker async-nats upgrades whenever the SERVER
//! asks, so every other case stays green without it. `add_root_certificates` is
//! killed by the accepting case (no root, no trust). `add_client_certificate` is
//! killed by the accepting case too, because the server runs `--tlsverify`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use yadgar_gateway::invalidate::{self, Broker};

/// The image `yadgarhq/platform` vendors (`nats-2.14.6.tgz`), by index digest.
const IMAGE: &str =
    "nats:2.14.6-alpine@sha256:ad7a43eb7e3337c3c38ce5d784d1461791f95f730f252d2b25eee699752a0ca3";

/// How long a container may take to print `Server is ready`.
const READY: Duration = Duration::from_secs(60);

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

fn unique(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_nanos();
    format!(
        "gateway-nats-tls-{label}-{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// An authority, and the PEM of what it signs.
struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Authority {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("a key"))
            .expect("a self-signed authority");
        Self { issuer }
    }

    fn pem(&self) -> String {
        self.issuer.pem()
    }

    /// The broker's serving leaf. `localhost` AND `127.0.0.1`, because the
    /// client dials `nats://localhost:<port>` and verifies that name.
    fn server_leaf(&self) -> (String, String) {
        let key = KeyPair::generate().expect("a key");
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params
            .subject_alt_names
            .push(SanType::IpAddress([127, 0, 0, 1].into()));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.distinguished_name.push(DnType::CommonName, "nats");
        let cert = params.signed_by(&key, &self.issuer).expect("a server leaf");
        (cert.pem(), key.serialize_pem())
    }

    /// A client leaf, as cert-manager issues `gateway-client-tls`.
    fn client_leaf(&self) -> (String, String) {
        let key = KeyPair::generate().expect("a key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params
            .distinguished_name
            .push(DnType::CommonName, "gateway");
        let cert = params.signed_by(&key, &self.issuer).expect("a client leaf");
        (cert.pem(), key.serialize_pem())
    }
}

/// A directory of PEM files, deleted on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(unique("certs"));
        std::fs::create_dir_all(&path).expect("the certificate directory");
        Self(path)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("a PEM file");
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One `nats-server` in a container, removed on drop.
struct Server {
    name: String,
    port: u16,
}

impl Server {
    /// `tls: None` serves cleartext. `Some(dir)` serves TLS from
    /// `dir/server.pem`, `dir/server-key.pem`, and VERIFIES clients against
    /// `dir/ca.pem` (`--tlsverify`, as B-N5 will run the platform broker).
    fn start(tls: Option<&Dir>) -> Self {
        let name = unique("server");
        let mut command = Command::new("docker");
        command.args(["run", "-d", "--name", &name, "-p", "127.0.0.1::4222"]);
        if let Some(dir) = tls {
            command.args(["-v", &format!("{}:/certs:ro", dir.0.display())]);
        }
        command.args([IMAGE, "-p", "4222"]);
        if tls.is_some() {
            command.args([
                "--tlsverify",
                "--tlscert=/certs/server.pem",
                "--tlskey=/certs/server-key.pem",
                "--tlscacert=/certs/ca.pem",
            ]);
        }
        let out = command.output().unwrap_or_else(|e| {
            panic!(
                "docker could not be run ({e}). This suite stands a real nats-server up and \
                 FAILS rather than skips without one; install docker or run it where docker is."
            )
        });
        // Constructed before the status check, so a container that started and
        // then failed to report is still removed.
        let mut server = Self { name, port: 0 };
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        server.port = server.published_port();
        server.wait_until_ready();
        server
    }

    fn published_port(&self) -> u16 {
        let out = Command::new("docker")
            .args(["port", &self.name, "4222/tcp"])
            .output()
            .expect("docker port");
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().next().unwrap_or_default();
        line.rsplit(':')
            .next()
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("no published port in {text:?}"))
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY;
        loop {
            let out = Command::new("docker")
                .args(["logs", &self.name])
                .output()
                .expect("docker logs");
            let log = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if log.contains("Server is ready") {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "nats-server never became ready:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn url(&self) -> String {
        format!("nats://localhost:{}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

/// The broker as `main` resolves it: through `Broker::from_lookup`, from the
/// same variables the chart renders.
fn broker(url: &str, ca: &Path, identity: Option<(&Path, &Path)>) -> Broker {
    let mut vars = vec![
        ("NATS_URL".to_string(), url.to_string()),
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        ("NATS_TLS_CA_FILE".to_string(), ca.display().to_string()),
    ];
    if let Some((cert, key)) = identity {
        vars.push((
            "NATS_TLS_CLIENT_CERT_FILE".to_string(),
            cert.display().to_string(),
        ));
        vars.push((
            "NATS_TLS_CLIENT_KEY_FILE".to_string(),
            key.display().to_string(),
        ));
    }
    Broker::from_lookup(move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
        .expect("a complete TLS configuration")
        .expect("a broker")
}

/// The platform's authority, the broker's leaf and the gateway's leaf, as
/// cert-manager issues all three from `yadgar-internal-ca`.
struct Estate {
    dir: Dir,
    ca: PathBuf,
    client: PathBuf,
    client_key: PathBuf,
}

fn estate() -> Estate {
    let authority = Authority::new("yadgar-gateway nats test authority");
    let dir = Dir::new();
    let ca = dir.write("ca.pem", &authority.pem());
    let (server, server_key) = authority.server_leaf();
    dir.write("server.pem", &server);
    dir.write("server-key.pem", &server_key);
    let (client, client_key) = authority.client_leaf();
    let client = dir.write("client.pem", &client);
    let client_key = dir.write("client-key.pem", &client_key);
    Estate {
        dir,
        ca,
        client,
        client_key,
    }
}

#[tokio::test]
async fn a_verifying_broker_accepts_the_gateways_leaf_and_the_gateway_consumes() {
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let broker = broker(
        &server.url(),
        &estate.ca,
        Some((&estate.client, &estate.client_key)),
    );

    broker
        .connect_options()
        .connect(server.url())
        .await
        .expect("the broker's own authority and an issued leaf connect");

    // THE SAME BROKER THROUGH THE PRODUCTION PATH: `start` dials, subscribes,
    // flushes and answers whether this replica consumes.
    assert!(
        invalidate::start(Some(broker), |_: &str| {}).await,
        "a TLS broker that verified this gateway's leaf is consumed from"
    );
}

#[tokio::test]
async fn a_verifying_broker_refuses_a_gateway_that_presents_no_leaf() {
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let broker = broker(&server.url(), &estate.ca, None);

    let error = broker
        .connect_options()
        .connect(server.url())
        .await
        .expect_err("--tlsverify refuses a client with no certificate");
    // THE BROKER's refusal, by its alert: this gateway verified the broker
    // and the broker then asked for a certificate it was not given.
    let printed = format!("{error:?}");
    assert!(printed.contains("CertificateRequired"), "{printed}");
    assert!(!invalidate::start(Some(broker), |_: &str| {}).await);
}

#[tokio::test]
async fn a_verifying_broker_refuses_a_leaf_from_a_foreign_authority() {
    // THE CI TWIN OF THE B-N5 PROBE: a leaf that is well-formed, unexpired and
    // carries ClientAuth, from an authority the broker does not trust.
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let (foreign, foreign_key) = Authority::new("a foreign authority").client_leaf();
    let foreign = estate.dir.write("foreign.pem", &foreign);
    let foreign_key = estate.dir.write("foreign-key.pem", &foreign_key);
    let broker = broker(&server.url(), &estate.ca, Some((&foreign, &foreign_key)));

    let error = broker
        .connect_options()
        .connect(server.url())
        .await
        .expect_err("a foreign leaf is refused by the broker");
    // THE BROKER's refusal, by its alert, so this cannot pass on a failure of
    // this gateway's own verification.
    let printed = format!("{error:?}");
    assert!(printed.contains("UnknownCA"), "{printed}");
}

#[tokio::test]
async fn a_broker_signed_by_another_authority_is_refused_by_this_gateway() {
    // CLIENT-SIDE VERIFICATION, with a trust store of ONE file: the broker's
    // leaf chains to `ca.pem`, and this gateway is handed a different
    // authority. No platform or public root may rescue the handshake.
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let wrong = estate
        .dir
        .write("wrong-ca.pem", &Authority::new("the wrong authority").pem());
    let broker = broker(
        &server.url(),
        &wrong,
        Some((&estate.client, &estate.client_key)),
    );

    let error = broker
        .connect_options()
        .connect(server.url())
        .await
        .expect_err("a broker this gateway cannot verify is refused");
    let printed = format!("{error} {error:?}");
    assert!(
        printed.contains("UnknownIssuer") || printed.contains("invalid peer certificate"),
        "the refusal is this gateway's verifier, not the broker's: {printed}"
    );
}

#[tokio::test]
async fn tls_on_against_a_cleartext_broker_is_refused_rather_than_downgraded() {
    // THE ONLY CASE THAT KILLS A DROPPED `require_tls`. A cleartext server
    // never asks for TLS, so without it async-nats would happily connect in
    // the clear while the configuration says otherwise.
    let estate = estate();
    let server = Server::start(None);
    let broker = broker(
        &server.url(),
        &estate.ca,
        Some((&estate.client, &estate.client_key)),
    );

    let refused = broker.connect_options().connect(server.url()).await;
    assert!(
        refused.is_err(),
        "NATS_TLS_ENABLED=1 never dials a broker in cleartext"
    );
}
