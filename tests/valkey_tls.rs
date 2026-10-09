//! B-V3 (ledger 925, ADR-0852): the cache hop over TLS, against a REAL
//! valkey rather than a configuration inspected in-process.
//!
//! **WHY A CONTAINER, AND WHY THIS TEST STARTS IT.** The property under test is
//! what a TLS verifier DOES with the material this gateway hands it, and only a
//! handshake shows that. A `services:` container cannot serve it: it starts
//! before the first step, so a certificate minted per run does not exist yet,
//! and valkey reads its certificate once at startup. So each case mints its own
//! authority with rcgen, writes it to a fresh directory, and starts
//! `valkey/valkey:9.1.1` with `docker run -d -v <dir>:/certs:ro` (the mechanism
//! B-V0 measured) — the image the platform chart vendors.
//!
//! **IT FAILS RATHER THAN SKIPS WITHOUT DOCKER.** A suite that turns green on a
//! machine that cannot run it is coverage that is not there. The shared CI's
//! `test` job runs on `ubuntu-latest`, which has docker.
//!
//! **ONE FIXED HOST PORT, SERIALISED, UNLIKE `tests/nats_tls.rs`'s RANDOM ONE.**
//! `limit::valkey::Limiter::new` dials the cache's fixed TLS port (6380)
//! rather than whatever port `addr` names — the production shape, where
//! `rateLimit.addr`'s port is the plaintext one and a TLS dial always reaches
//! 6380 instead. So this file cannot let docker publish a random host port
//! the way the broker hop's own test does; every case publishes CONTAINER
//! 6380 to HOST 6380 and [`PORT`] serialises the cases in this binary onto
//! that one port, the same way `tests/valkey_auth.rs` serialises onto the one
//! shared Valkey it mutates.
//!
//! **EVERY CONTAINER IS REMOVED ON DROP**, including on a panic, and every name
//! is unique per run, because CI runs this suite twice (all features, then the
//! feature-off build) on one runner.
//!
//! **WHAT EACH CASE KILLS.** The accepting case kills both `add_root_certificates`
//! (no root, no trust) and `build_with_tls`'s own `rediss://` scheme switch (a
//! `redis://` URL here would refuse to build at all — `InvalidClientConfig`).
//! The no-leaf case is the one `--tls-auth-clients yes` kills: a client that
//! connects without a certificate is accepted at the TCP and TLS-handshake
//! layer (TLS 1.3 defers the server's verdict to the first application
//! message) and refused on the FIRST command, which is why this is measured
//! through [`Limiter::check`] rather than at construction.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use yadgar_gateway::limit::{Decision, Limiter, Limits, Overrides};
use yadgar_gateway::upstream::UpstreamTls;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

/// The image `yadgarhq/platform` vendors, the same one `tests/valkey_auth.rs`
/// runs locally.
const IMAGE: &str = "docker.io/valkey/valkey:9.1.1";

/// The cache's fixed TLS listener (B-V2, ADR-0852) — see `limit::valkey`'s own
/// `TLS_PORT`. Duplicated here rather than imported: the constant is not
/// public, and this file is independent proof that the production code reaches
/// the SAME port a real server actually serves it on.
const TLS_PORT: u16 = 6380;

/// How long a container may take to print its ready line.
const READY: Duration = Duration::from_secs(60);

/// Serialises every case in this binary onto the one host port each
/// container publishes to. See the module comment.
static PORT: Mutex<()> = Mutex::new(());

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

fn unique(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_nanos();
    format!(
        "gateway-valkey-tls-{label}-{}-{nanos}-{}",
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

    /// The cache's serving leaf. `localhost` AND `127.0.0.1`, because the
    /// client dials `127.0.0.1:<TLS_PORT>` and verifies that address.
    fn server_leaf(&self) -> (String, String) {
        let key = KeyPair::generate().expect("a key");
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params
            .subject_alt_names
            .push(SanType::IpAddress([127, 0, 0, 1].into()));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.distinguished_name.push(DnType::CommonName, "valkey");
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

/// One `valkey` in a container, removed on drop, published at the host's
/// `127.0.0.1:TLS_PORT` — see the module comment for why this is fixed
/// rather than a random published port.
struct Server {
    name: String,
    /// Held for the server's whole life: the lock guards the host port, not
    /// just the `docker run`.
    _held: std::sync::MutexGuard<'static, ()>,
}

impl Server {
    /// Starts valkey serving ONLY TLS on [`TLS_PORT`] — `--port 0` drops the
    /// plaintext listener, so a dial that reaches the wrong port fails rather
    /// than quietly succeeding in the clear. `auth_clients` is valkey's own
    /// spelling (`no` / `optional` / `yes`).
    fn start(dir: &Dir, auth_clients: &str) -> Self {
        let held = PORT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let name = unique("server");
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &name,
                "-p",
                &format!("127.0.0.1:{TLS_PORT}:{TLS_PORT}"),
                "-v",
                &format!("{}:/certs:ro", dir.0.display()),
                IMAGE,
                "--port",
                "0",
                "--tls-port",
                &TLS_PORT.to_string(),
                "--tls-cert-file",
                "/certs/server.pem",
                "--tls-key-file",
                "/certs/server-key.pem",
                "--tls-ca-cert-file",
                "/certs/ca.pem",
                "--tls-auth-clients",
                auth_clients,
                "--save",
                "",
                "--appendonly",
                "no",
            ])
            .output()
            .unwrap_or_else(|e| {
                panic!(
                    "docker could not be run ({e}). This suite stands a real valkey up and \
                     FAILS rather than skips without one; install docker or run it where docker \
                     is."
                )
            });
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let server = Self { name, _held: held };
        server.wait_until_ready();
        server
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
            if log.contains("Ready to accept connections tls") {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "valkey never became ready:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// `host:port` as `rateLimit.addr` would name it — the plaintext port,
    /// unused here, exactly as it is unused in production once TLS is on.
    fn addr(&self) -> String {
        "127.0.0.1:6379".to_string()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

/// The platform's authority, the cache's leaf and the gateway's leaf, as
/// cert-manager issues all three from `yadgar-internal-ca`.
struct Estate {
    dir: Dir,
    ca: PathBuf,
    client: PathBuf,
    client_key: PathBuf,
}

fn estate() -> Estate {
    let authority = Authority::new("yadgar-gateway valkey test authority");
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

/// `tls` as `UpstreamTls::from_lookup("VALKEY", ...)` resolves it — the exact
/// parser `main` reaches through `limit::valkey_tls`.
fn tls(ca: &Path, identity: Option<(&Path, &Path)>) -> UpstreamTls {
    let mut vars = vec![
        ("VALKEY_TLS_ENABLED".to_string(), "1".to_string()),
        ("VALKEY_TLS_CA_FILE".to_string(), ca.display().to_string()),
    ];
    if let Some((cert, key)) = identity {
        vars.push((
            "VALKEY_TLS_CLIENT_CERT_FILE".to_string(),
            cert.display().to_string(),
        ));
        vars.push((
            "VALKEY_TLS_CLIENT_KEY_FILE".to_string(),
            key.display().to_string(),
        ));
    }
    UpstreamTls::from_lookup("VALKEY", move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete TLS configuration")
    .expect("the flag is set")
}

fn limiter(addr: &str, tls: UpstreamTls) -> Limiter {
    let limits = Limits::parse("auth.write=1000:1000", "1000:1000").expect("the limits parse");
    Limiter::new(addr, None, limits, Duration::from_secs(5), 6, Some(tls))
        .expect("the limiter opens")
}

async fn spend(limiter: &Limiter) -> Decision {
    limiter
        .check("someone", "auth", Kind::Write, &Overrides::default())
        .await
}

#[tokio::test]
async fn a_verifying_cache_accepts_the_gateways_leaf_and_the_call_is_allowed() {
    let estate = estate();
    let server = Server::start(&estate.dir, "yes");
    let limiter = limiter(
        &server.addr(),
        tls(&estate.ca, Some((&estate.client, &estate.client_key))),
    );
    assert_eq!(
        spend(&limiter).await,
        Decision::Allowed,
        "a verifying cache, given a leaf it trusts, must serve the call rather than degrade it"
    );
}

#[tokio::test]
async fn a_verifying_cache_refuses_a_gateway_that_presents_no_leaf() {
    let estate = estate();
    let server = Server::start(&estate.dir, "yes");
    let limiter = limiter(&server.addr(), tls(&estate.ca, None));
    assert_ne!(
        spend(&limiter).await,
        Decision::Allowed,
        "--tls-auth-clients yes must refuse a client with no certificate rather than serve it"
    );
}

#[tokio::test]
async fn a_cache_signed_by_another_authority_is_refused_by_this_gateway() {
    // CLIENT-SIDE VERIFICATION, with a trust store of ONE file: the cache's
    // leaf chains to its own authority, and this gateway is handed a
    // different one. No platform or public root may rescue the handshake.
    let estate = estate();
    let server = Server::start(&estate.dir, "no");
    let wrong = estate
        .dir
        .write("wrong-ca.pem", &Authority::new("the wrong authority").pem());
    let limiter = limiter(&server.addr(), tls(&wrong, None));
    assert_ne!(
        spend(&limiter).await,
        Decision::Allowed,
        "a cache this gateway cannot verify must be refused rather than served"
    );
}

#[test]
fn absent_valkey_tls_enabled_refuses_the_boot_naming_it() {
    let err = yadgar_gateway::limit::valkey_tls(&|_: &str| None)
        .expect_err("VALKEY_TLS_ENABLED absent must refuse rather than default to cleartext");
    assert!(err.contains("VALKEY_TLS_ENABLED"), "{err}");
    assert!(err.contains("valkey.tls.enabled"), "{err}");
}
