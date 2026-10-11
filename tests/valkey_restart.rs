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
//! **IT FAILS RATHER THAN SKIPS WITHOUT DOCKER.** A suite that turns green on
//! a machine that cannot run it is coverage that is not there.

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
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
        let name = unique("server");
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &name,
                "-p",
                "127.0.0.1::6379",
                IMAGE,
                "--save",
                "",
                "--appendonly",
                "no",
            ])
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
    let limits = Limits::parse("auth.write=1000:1000", "1000:1000").expect("the limits parse");
    // Six, an arbitrary `max_replicas`: this case never takes the degraded
    // floor path, so the divisor is unexercised.
    Limiter::new(addr, None, limits, CALL_TIMEOUT, 6, None).expect("the limiter opens")
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
