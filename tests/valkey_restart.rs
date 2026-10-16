//! The gap ledger 1430 measured: after a real Valkey restarts, the FIRST
//! rate-limit call on an already-warm gateway degraded exactly once, labelled
//! `Unreachable`, even though the restarted server was back up by the time
//! that call ran.
//!
//! **WHY, MEASURED AGAINST `redis` 1.7.1's OWN SOURCE
//! (`aio/connection_manager.rs`).** `ConnectionManager::send_packed_command`
//! awaits its CACHED, already-resolved connection future, tries to write the
//! command to the now-dead socket, fails, and only THEN kicks off a
//! reconnect — in the background, never awaited by that call. The call
//! reports the write failure it already has; the reconnect it just started is
//! for the NEXT caller's benefit, not this one's. `Limiter::spend`'s retry
//! (ledger 1430) is what gives THIS caller a chance to await that same
//! reconnect before giving up.
//!
//! **WHY A REAL, RESTARTABLE CONTAINER, NOT THE SHARED `YADGAR_TEST_VALKEY`
//! SERVICE.** The property under test is what happens to an
//! ALREADY-ESTABLISHED connection when the real process on the other end of
//! it dies and a new one takes the same port — a real TCP reset, which only a
//! real server breaking a real socket produces. Reusing the service
//! `tests/rate_limit.rs` and `tests/valkey_auth.rs` share would mean killing
//! the one Valkey every OTHER test binary in this job depends on; this file
//! starts and restarts its own, on its own dynamically-published port, the
//! same shape `tests/valkey_tls.rs` already uses for the same reason.
//!
//! **ALSO THE ABSENT-AT-BOOT CASE (ledger 1438).** A Valkey that is not up
//! when `Limiter::warm` first runs, and comes up later, needs the same
//! controllable real server on a port chosen in advance, so that case lives
//! here too: see `warm_retries_until_a_valkey_absent_at_boot_comes_up`.
//!
//! **IT FAILS RATHER THAN SKIPS WITHOUT DOCKER.** A suite that turns green on
//! a machine that cannot run it is coverage that is not there.

use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use yadgar_gateway::limit::{Decision, Degrade, Limiter, Limits, Overrides};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

const IMAGE: &str = "docker.io/valkey/valkey:9.1.1";

/// How long a container may take to print its ready line.
const READY: Duration = Duration::from_secs(60);

/// This case's own outer rate-limit timeout: generous, so the retry's
/// `response_timeout` fraction (two thirds, see
/// `limit::valkey::Limiter::connect_config`) comfortably covers however long
/// `docker run` takes to get a fresh container accepting connections —
/// typically under a second, bounded here at several.
///
/// **DELIBERATELY NOT PRODUCTION'S OWN NUMBER.** `chart/values.yaml`'s
/// `rateLimit.timeoutMs` is 20 — two thirds of that is ~13ms, which no real
/// container restart finishes inside. This case proves the MECHANISM: a
/// reconnect that lands within the budget it is given is not reported as
/// degraded. It does not claim that today's 20ms production value gives a
/// real restart that chance; under that number this retry mostly cannot
/// help, because the outer timeout `decide` already enforces (unchanged by
/// this PR) cuts the whole call off first regardless. See the PR body.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

fn unique(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_nanos();
    format!(
        "gateway-valkey-restart-{label}-{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// One `valkey` in a container, published on a host port Docker picks, so
/// this file needs no port of its own to serialise on the way
/// `tests/valkey_tls.rs` does — nothing else in this suite ever dials it.
struct Server {
    name: String,
    port: u16,
}

impl Server {
    /// Starts a fresh container and waits for it to accept connections.
    fn start() -> Self {
        Self::start_on("127.0.0.1::6379", &[])
    }

    /// Starts a fresh container on a host port the CALLER already chose, for
    /// a limiter that was built against that address before anything was
    /// listening on it (ledger 1438).
    fn start_at(port: u16) -> Self {
        Self::start_on(&format!("127.0.0.1:{port}:6379"), &[])
    }

    /// Starts a fresh container that demands `password` (`requirepass`).
    fn start_requiring(password: &str) -> Self {
        Self::start_on("127.0.0.1::6379", &["--requirepass", password])
    }

    fn start_on(publish: &str, extra: &[&str]) -> Self {
        let name = unique("server");
        let mut args = vec![
            "run",
            "-d",
            "--name",
            &name,
            "-p",
            publish,
            IMAGE,
            "--save",
            "",
            "--appendonly",
            "no",
        ];
        args.extend_from_slice(extra);
        let out = Command::new("docker")
            .args(&args)
            .output()
            .unwrap_or_else(|e| {
                panic!(
                    "docker could not be run ({e}). This suite stands a real valkey up and \
                     FAILS rather than skips without one; install docker or run it where \
                     docker is."
                )
            });
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let port = published_port(&name);
        let server = Self { name, port };
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
            if log.contains("Ready to accept connections tcp") {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "valkey never became ready:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// How many clients the server holds OTHER than the `valkey-cli` this
    /// asks with — read from the server, so it counts a connection the
    /// gateway really made rather than a flag the gateway sets about itself.
    fn foreign_clients(&self) -> usize {
        let out = Command::new("docker")
            .args(["exec", &self.name, "valkey-cli", "CLIENT", "LIST"])
            .output()
            .expect("docker exec valkey-cli");
        assert!(
            out.status.success(),
            "CLIENT LIST failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.is_empty() && !l.contains("cmd=client|list"))
            .count()
    }

    /// Kills THIS container outright (no graceful stop — the measured
    /// restart is an abrupt one) and starts a REPLACEMENT bound to the exact
    /// same host port, so `Limiter`'s `addr` never changes. The replacement
    /// is fully ready by the time this returns: the bug this file proves the
    /// fix for is not a race against container startup, it is what
    /// `ConnectionManager` does on the FIRST call after the swap regardless
    /// of how long that swap took.
    fn restart(&mut self) {
        let killed = Command::new("docker")
            .args(["kill", &self.name])
            .output()
            .expect("docker kill");
        assert!(
            killed.status.success(),
            "docker kill failed: {}",
            String::from_utf8_lossy(&killed.stderr)
        );
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();

        self.name = unique("server");
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &self.name,
                "-p",
                &format!("127.0.0.1:{}:6379", self.port),
                IMAGE,
                "--save",
                "",
                "--appendonly",
                "no",
            ])
            .output()
            .expect("docker run (restart)");
        assert!(
            out.status.success(),
            "docker run (restart) failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        self.wait_until_ready();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

fn published_port(name: &str) -> u16 {
    let out = Command::new("docker")
        .args(["port", name, "6379/tcp"])
        .output()
        .expect("docker port");
    assert!(
        out.status.success(),
        "docker port failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .rsplit(':')
        .next()
        .unwrap_or_else(|| panic!("`docker port` printed nothing usable: {text}"))
        .parse()
        .unwrap_or_else(|e| panic!("`docker port` printed a non-numeric port ({e}): {text}"))
}

fn limiter(addr: &str) -> Limiter {
    limiter_with(addr, None)
}

fn limiter_with(addr: &str, password: Option<&str>) -> Limiter {
    let limits = Limits::parse("auth.write=1000:1000", "1000:1000").expect("the limits parse");
    // Six, an arbitrary `max_replicas`: this case never takes the degraded
    // floor path, so the divisor is unexercised.
    Limiter::new(addr, password, limits, CALL_TIMEOUT, 6, None).expect("the limiter opens")
}

async fn spend(limiter: &Limiter) -> Decision {
    limiter
        .check("someone", "auth", Kind::Write, &Overrides::default())
        .await
}

#[tokio::test]
async fn the_first_call_after_a_restart_does_not_degrade_when_the_reconnect_lands_in_budget() {
    let mut server = Server::start();
    let limiter = limiter(&server.addr());

    assert_eq!(
        spend(&limiter).await,
        Decision::Allowed,
        "the warm connection must serve the call before any restart"
    );

    server.restart();

    assert_eq!(
        spend(&limiter).await,
        Decision::Allowed,
        "a restarted Valkey that is ready again must not be reported as a degrade on the \
         first call afterward (ledger 1430) — the retry in `Limiter::spend` exists to let \
         the manager's own already-started reconnect land within this call's budget"
    );
}

/// The CONTROL ARM: proves the harness actually reproduces the measured
/// defect rather than vacuously passing. Run against the pre-fix `spend`
/// (the single `invoke_async` call, no retry), the first case above fails
/// with exactly this `Decision`.
#[tokio::test]
async fn a_dropped_connection_that_never_comes_back_degrades_as_unreachable() {
    let server = Server::start();
    let limiter = limiter(&server.addr());
    assert_eq!(spend(&limiter).await, Decision::Allowed);

    // Killed and never replaced: nothing is listening on this port again, so
    // even WITH the retry, both attempts fail and the call must degrade —
    // the retry is bounded, not a guarantee.
    let killed = Command::new("docker")
        .args(["kill", &server.name])
        .output()
        .expect("docker kill");
    assert!(killed.status.success());
    let _ = Command::new("docker")
        .args(["rm", "-f", &server.name])
        .output();
    // Leave `server` in place for `Drop`; the name no longer names a running
    // container, so `Drop`'s own `rm -f` is a harmless no-op.

    assert_eq!(
        spend(&limiter).await,
        Decision::Degraded(Degrade::Unreachable),
        "a connection that drops and stays down must still degrade — the retry gives a \
         live reconnect a chance, not an unconditional pass"
    );
}

/// A port nothing is listening on, so a connect to it is REFUSED at once —
/// the shape of a Valkey that is simply not up yet when the gateway boots.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().expect("the bound address").port()
}

/// How long the warm-up may take to notice a Valkey that came up after it
/// first failed: one outage retry interval (5 s, `limit::valkey::warm`'s
/// `RETRY`) plus generous slack for a loaded runner.
const RECOVERY: Duration = Duration::from_secs(20);

/// Ledger 1438: a Valkey that is ABSENT when `warm` first runs and comes up
/// afterwards is connected by `warm` itself, in the background, with no
/// request ever having to pay for that connect.
///
/// **NO `check` IS EVER CALLED.** `spend` connects lazily on its own, so a
/// call here would make the connection appear whether or not `warm` retried —
/// the assertion would pass for the defect. The evidence is read from the
/// SERVER instead: a client connection that only `warm` could have opened.
///
/// Red before ledger 1438: `warm` made ONE attempt, which a closed port
/// refuses at once, and returned — so the task is already finished at the
/// first assertion, and no client ever appears at the second.
#[tokio::test]
async fn warm_retries_until_a_valkey_absent_at_boot_comes_up() {
    let port = closed_port();
    let limiter = Arc::new(limiter(&format!("127.0.0.1:{port}")));
    let warming = tokio::spawn({
        let limiter = Arc::clone(&limiter);
        async move { limiter.warm().await }
    });

    // Long enough for the first attempt against the closed port to be refused.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !warming.is_finished(),
        "`warm` gave up after a refused first attempt; a Valkey that comes up later would \
         then be connected only by a request paying for it on the hot path (ledger 1438)"
    );

    let server = Server::start_at(port);

    let deadline = Instant::now() + RECOVERY;
    while server.foreign_clients() == 0 {
        assert!(
            Instant::now() < deadline,
            "`warm` never connected to a Valkey that came up {RECOVERY:?} ago"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // AND IT STOPS once it has. A loop that kept dialling after success would
    // leak a connection per interval for the life of the pod.
    tokio::time::timeout(Duration::from_secs(5), warming)
        .await
        .expect("`warm` must end once it has connected")
        .expect("the warm task must not panic");
    assert_eq!(
        server.foreign_clients(),
        1,
        "exactly the one manager `warm` populated, and no second connection"
    );
}

/// A per-run credential with no string constant in its derivation: the
/// standard library's per-instance random hasher keys, hashed over nothing.
fn random_secret() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos(),
    );
    hasher.finish().to_string()
}

/// The server's own count of rejected AUTH attempts (`INFO stats`'
/// `acl_access_denied_auth`), asked with the RIGHT password so the asking is
/// not itself counted.
fn auth_denials(server: &Server, password: &str) -> u64 {
    let out = Command::new("docker")
        .args([
            "exec",
            &server.name,
            "valkey-cli",
            "-a",
            password,
            "--no-auth-warning",
            "INFO",
            "stats",
        ])
        .output()
        .expect("docker exec valkey-cli");
    assert!(
        out.status.success(),
        "INFO stats failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("acl_access_denied_auth:"))
        .unwrap_or_else(|| panic!("no acl_access_denied_auth in INFO stats:\n{text}"))
        .parse()
        .expect("acl_access_denied_auth is a number")
}

/// How long the refused-credential case watches `warm`: past two OUTAGE
/// intervals (5 s each, so attempts at 0, 5 and 10 s) with two seconds of
/// slack, and far inside one REFUSED interval (60 s).
const REFUSAL_WINDOW: Duration = Duration::from_secs(12);

/// Ledger 1438: a credential the cache REJECTED is retried at the refused
/// rate, not the outage rate (ADR-0893).
///
/// **A WRONG password, not a missing one.** Only a password that was sent and
/// rejected (`WRONGPASS`, which `redis` reports as `AuthenticationFailed`)
/// fails the connect. With no password `redis` sends no AUTH, the connect
/// succeeds, and `warm` ends — that case surfaces on calls as `NOAUTH`.
///
/// The evidence is the SERVER's count of denied AUTH attempts. At the refused
/// rate the window holds exactly the first attempt; misread as an outage it
/// would hold three.
#[tokio::test]
async fn warm_retries_a_rejected_credential_at_the_refused_rate() {
    // MINTED PER RUN, never from a literal: a throwaway credential for a
    // throwaway container. Code scanning traces a literal through `format!`,
    // so these carry no string constant at all.
    let password = random_secret();
    let wrong = random_secret();
    assert_ne!(password, wrong);
    let server = Server::start_requiring(&password);
    let limiter = Arc::new(limiter_with(&server.addr(), Some(&wrong)));
    let warming = tokio::spawn({
        let limiter = Arc::clone(&limiter);
        async move { limiter.warm().await }
    });

    tokio::time::sleep(REFUSAL_WINDOW).await;

    assert!(
        !warming.is_finished(),
        "a rejected credential must be retried, never treated as terminal (ADR-0893)"
    );
    assert_eq!(
        auth_denials(&server, &password),
        1,
        "a rejected credential must wait the refused interval (60 s), not the outage \
         interval (5 s), before it is tried again"
    );
    warming.abort();
}
