//! Running the REAL `yadgar-gateway` binary the way a pod runs it: with
//! `/etc/yadgar/config/shared/shared.yaml` AND `/etc/yadgar/config/gateway/gateway.yaml`
//! mounted, as the only two files it reads from a fixed path (ledger 748).
//!
//! **WHY A MOUNT NAMESPACE.** `yadgar_lifecycle::rotate::Configuration::mounted`
//! reads `/etc/yadgar/config/shared/shared.yaml` unconditionally and
//! `rotate::GatewayDocument::mounted` reads `/etc/yadgar/config/gateway/gateway.yaml`
//! unconditionally, and neither has an environment override, by design: both
//! paths are the chart's `mountPath`s. A test cannot write under the host's
//! `/etc`, so every run goes through `unshare -rm`, which gives the binary a
//! private mount table in which `/etc` is an overlay over the real one. Each
//! document's DIRECTORY is a bind mount of a per-test host directory, which is
//! the shape kubelet gives a ConfigMap volume — and it is what lets a test
//! rewrite a file from outside the namespace. Writing into an overlay's
//! upperdir while it is mounted is undefined behaviour; renaming inside a
//! bind-mounted directory is not.
//!
//! **TWO MOUNTED DOCUMENTS, NOT ONE.** `task` and `iam-db` read only
//! `shared.yaml`; this gateway also reads its own `gateway.yaml` for
//! `toolsPoll.intervalSeconds` (ADR-0740), and `wiring()` reads it before
//! either dial, so a run with only `shared/` mounted never reaches
//! `"gateway listening"`.
//!
//! `exec` at the end of the script replaces `sh`, and `unshare` without
//! `--fork` replaces itself, so the pid `Command` returns IS the binary's pid:
//! a SIGTERM sent to it reaches the process under test and nothing in between.
//!
//! **NO PROBE, NO SKIP.** If the runner forbids unprivileged user namespaces,
//! `mount` fails, the script exits non-zero before the binary starts, and every
//! wait below reports that with the captured stderr. `no-test-skips` forbids
//! probe-and-skip, and a harness that passed without running would certify
//! nothing.
//!
//! **EVERY WAIT FAILS ON ITS DEADLINE.** There is no wait here that returns
//! `None`: on its deadline it kills the child and panics, naming the wait and
//! printing every line the binary wrote.

// Each test target compiles its own copy of this module and uses a subset of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_yadgar-gateway");

/// The rotation schedule every run is given: poll each second, no splay. A
/// rewrite is therefore noticed within one second and acted on at once.
pub const SHARED_FIXTURE: &str = "tlsRotation:\n  pollSeconds: 1\n  splayMaxSeconds: 0\n";

/// This gateway's own document (ADR-0740): the one knob `wiring()` reads
/// before either dial.
pub const GATEWAY_FIXTURE: &str = "toolsPoll:\n  intervalSeconds: 30\n";

/// The poll and splay in [`SHARED_FIXTURE`], for deadlines derived from them.
pub const POLL: Duration = Duration::from_secs(1);
pub const SPLAY_MAX: Duration = Duration::from_secs(0);

/// What every deadline adds on top of the time the binary is allowed. Generous,
/// because a shared CI runner is slow; the waits it bounds are seconds long.
pub const MARGIN: Duration = Duration::from_secs(10);

/// How long a boot may take to reach its "listening" line.
pub const BOOT_DEADLINE: Duration = Duration::from_secs(20);

/// The script `unshare` runs. Paths arrive as positional arguments — `$1` the
/// per-test root, `$2` the binary — rather than interpolated into the text.
const SCRIPT: &str = r#"set -e
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$1/upper,workdir=$1/work" /etc
mkdir -p /etc/yadgar/config/shared /etc/yadgar/config/gateway
mount --bind "$1/shared" /etc/yadgar/config/shared
mount --bind "$1/gateway" /etc/yadgar/config/gateway
exec "$2""#;

/// A full, cleartext boot, down to the two upstream ports and the project
/// registry's own cadence. Port 0 on both listeners, because the cases in a
/// target run in parallel. Every `*_HOST` is an address rather than a name, so
/// no case depends on DNS: every dial is lazy (ADR-0532), so nothing needs to
/// answer on it. The three gRPC `*_TLS_ENABLED` are stated as `"0"` rather
/// than left absent. `VALKEY_TLS_ENABLED` joins them (B-V3, ADR-0852):
/// unlike `NATS_TLS_ENABLED`, which is only required once `NATS_URL` is set
/// (absent here, so it is never reached), `YADGAR_VALKEY_ADDR` above is
/// always required, so `VALKEY_TLS_ENABLED` is unconditionally required too.
pub fn cleartext_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("METRICS_LISTEN", "127.0.0.1:0"),
        ("YADGAR_CREDENTIAL_TTL_SECONDS", "0"),
        ("YADGAR_VALKEY_ADDR", "127.0.0.1:6379"),
        ("YADGAR_RATE_LIMITS", ""),
        ("YADGAR_RATE_LIMIT_DEFAULT", "100:10"),
        ("YADGAR_RATE_LIMIT_TIMEOUT_MS", "50"),
        ("YADGAR_MAX_REPLICAS", "1"),
        ("TASK_HOST", "127.0.0.1"),
        ("TASK_PORT", "50051"),
        ("IAM_HOST", "127.0.0.1"),
        ("IAM_PORT", "50052"),
        ("PROJECT_HOST", "127.0.0.1"),
        ("PROJECT_PORT", "50053"),
        ("YADGAR_ALLOWED_ORIGINS", ""),
        ("YADGAR_LOGIN_RATE_LIMIT", "100:10"),
        ("YADGAR_LOGIN_UNATTRIBUTED_RATE_LIMIT", "50:5"),
        ("YADGAR_ADMIN_RATE_LIMIT", "20:5"),
        ("YADGAR_ADMIN_UNATTRIBUTED_RATE_LIMIT", "10:2"),
        ("YADGAR_PROJECT_VALIDATION_MODE", "counting"),
        ("YADGAR_PROJECT_REGISTRY_POLL_SECONDS", "30"),
        ("LISTEN", "127.0.0.1:0"),
        ("TASK_TLS_ENABLED", "0"),
        ("IAM_TLS_ENABLED", "0"),
        ("PROJECT_TLS_ENABLED", "0"),
        ("VALKEY_TLS_ENABLED", "0"),
    ]
}

/// One line the binary wrote, and which stream it came from.
enum Line {
    Out(String),
    Err(String),
}

/// The binary, running in its own mount namespace, with its output pumped.
pub struct Booted {
    child: Child,
    lines: Receiver<Line>,
    seen: Vec<String>,
    root: PathBuf,
}

impl Booted {
    /// Start the binary with exactly `vars` (and `PATH`) in its environment.
    pub fn start(vars: &[(&str, &str)]) -> Self {
        let root = fresh_root();
        // `unshare`, `mount` and `sh` are found on the caller's PATH; on some
        // hosts none of them is under /usr/bin. A rig with no PATH fails here
        // rather than guessing one.
        let path = std::env::var_os("PATH").expect("the test runner must have a PATH");
        let mut child = Command::new("unshare")
            .args(["-rm", "sh", "-c", SCRIPT, "sh"])
            .arg(&root)
            .arg(BIN)
            .env_clear()
            .env("PATH", path)
            .envs(vars.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("`unshare` could not be started: {e}"));

        // ONE THREAD PER STREAM, pumping for the life of the child. Reading
        // only until the "listening" line would leave the pipe to fill and the
        // binary to block on its next log line.
        let (tx, lines) = mpsc::channel();
        let out = child.stdout.take().expect("stdout was piped");
        let err = child.stderr.take().expect("stderr was piped");
        let tx_err = tx.clone();
        std::thread::spawn(move || pump(out, move |l| tx.send(Line::Out(l)).is_ok()));
        std::thread::spawn(move || pump(err, move |l| tx_err.send(Line::Err(l)).is_ok()));

        Self {
            child,
            lines,
            seen: Vec::new(),
            root,
        }
    }

    /// The binary's pid. `exec` all the way down makes it the direct child.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for a line satisfying `matches`, or fail on `deadline`.
    ///
    /// A child whose output ends first — it exited, or the mount namespace was
    /// refused and it never started — fails at once with what it printed,
    /// rather than as a timeout.
    pub fn wait_for_line(
        &mut self,
        what: &str,
        deadline: Duration,
        matches: impl Fn(&str) -> bool,
    ) -> String {
        let until = Instant::now() + deadline;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(Line::Out(l) | Line::Err(l)) => {
                    self.seen.push(l.clone());
                    if matches(&l) {
                        return l;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.fail(&format!("waited {deadline:?} for {what}; it never came"))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.reap(Duration::from_secs(5));
                    self.fail(&format!(
                        "the binary's output ended before {what} ({})",
                        describe(status)
                    ))
                }
            }
        }
    }

    /// Wait for the boot to reach the line `boot::serve` logs once the signal
    /// handlers are armed and the listener is spawned.
    pub fn wait_until_listening(&mut self) {
        self.wait_for_line("the \"gateway listening\" line", BOOT_DEADLINE, |l| {
            l.contains("\"gateway listening\"")
        });
    }

    /// Send SIGTERM, the way kubelet ends a pod.
    pub fn terminate(&mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .unwrap_or_else(|e| panic!("`kill` could not be started: {e}"));
        if !status.success() {
            self.fail(&format!("`kill -TERM` failed: {status}"));
        }
    }

    /// Wait for the process to exit, or fail on `deadline`.
    pub fn wait_for_exit(&mut self, what: &str, deadline: Duration) -> ExitStatus {
        match self.reap(deadline) {
            Some(status) => {
                self.drain_lines();
                status
            }
            None => self.fail(&format!(
                "waited {deadline:?} for the process to exit {what}; it was still running"
            )),
        }
    }

    /// Replace the mounted `shared.yaml` the way kubelet replaces a projected
    /// file: write a sibling, then rename it over the original.
    pub fn rewrite_shared(&self, contents: &str) {
        let dir = self.root.join("shared");
        let staged = dir.join(".shared.yaml.next");
        std::fs::write(&staged, contents).expect("the staged document must be written");
        std::fs::rename(&staged, dir.join("shared.yaml"))
            .expect("the staged document must replace the mounted one");
    }

    /// Every line the binary has written so far.
    pub fn seen(&self) -> &[String] {
        &self.seen
    }

    /// Fail the test: kill the child, then panic with everything it printed.
    pub fn fail(&mut self, why: &str) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.drain_lines();
        panic!(
            "{why}\n--- everything the binary wrote ---\n{}",
            self.seen.join("\n")
        );
    }

    fn reap(&mut self, deadline: Duration) -> Option<ExitStatus> {
        let until = Instant::now() + deadline;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if Instant::now() >= until => return None,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("the child could not be waited on: {e}"),
            }
        }
    }

    fn drain_lines(&mut self) {
        // The pumps end at EOF, which follows the exit closely; a short bound
        // keeps a stray grandchild holding the pipe from hanging the test.
        while let Ok(Line::Out(l) | Line::Err(l)) =
            self.lines.recv_timeout(Duration::from_millis(500))
        {
            self.seen.push(l);
        }
    }
}

impl Drop for Booted {
    fn drop(&mut self) {
        // A panicking test must not leave a server running.
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_root(&self.root);
    }
}

/// Run the binary to completion under the same mounts, for a boot that is
/// expected to refuse. Returns the status and stderr.
pub fn run_to_exit(vars: &[(&str, &str)]) -> (ExitStatus, String) {
    let mut booted = Booted::start(vars);
    let status = booted.wait_for_exit("after refusing its boot", BOOT_DEADLINE);
    (status, booted.seen().join("\n"))
}

/// The exit status as a sentence that says whether a signal ended it.
pub fn describe(status: Option<ExitStatus>) -> String {
    match status {
        None => "still running".to_string(),
        Some(s) => format!("code {:?}, signal {:?}", s.code(), s.signal()),
    }
}

/// A per-test directory: the overlay's upper and work dirs, and the two
/// directories bind-mounted as `/etc/yadgar/config/shared` and
/// `/etc/yadgar/config/gateway`.
///
/// Under the system temp dir, which must not itself be an overlay: an overlay's
/// upperdir cannot sit on one. The name carries a counter as well as the pid,
/// because the cases of a target run on threads of one process (ledger 706).
fn fresh_root() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "yadgar-gateway-exit-chain-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    for dir in ["upper", "work", "shared", "gateway"] {
        std::fs::create_dir_all(root.join(dir)).expect("the test root must be created");
    }
    std::fs::write(root.join("shared").join("shared.yaml"), SHARED_FIXTURE)
        .expect("the shared fixture document must be written");
    std::fs::write(root.join("gateway").join("gateway.yaml"), GATEWAY_FIXTURE)
        .expect("the gateway fixture document must be written");
    root
}

/// Best effort. Overlayfs leaves `work/work` with mode 0, so it is opened up
/// before the tree is removed.
fn remove_root(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        root.join("work").join("work"),
        std::fs::Permissions::from_mode(0o700),
    );
    let _ = std::fs::remove_dir_all(root);
}

fn pump(stream: impl Read, mut send: impl FnMut(String) -> bool) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        if !send(line) {
            return;
        }
    }
}
