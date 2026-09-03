//! What this process does when the security material it read at boot is replaced
//! underneath it.
//!
//! **THIS GATEWAY SERVES NO CERTIFICATE, and that is the first thing to know
//! about this module.** TLS at the edge is terminated by the ingress in front
//! (D71, D80), so `gateway-tls` is never read by this process. What IS read once
//! and never again are the CA bundles `iam` and `task` are verified against, and
//! the client certificate and key this gateway presents to both of them
//! (ADR-0516). Those are the watch set, and there is no serving leaf beside
//! them.
//!
//! The chart mounts those Secrets as DIRECTORIES rather than with `subPath`,
//! deliberately, so kubelet does refresh the files inside the pod. Only the
//! process never re-reads them.
//!
//! # The ruling: exit on change
//!
//! This module polls a digest of every TLS input the process read at boot — one
//! per file, so a change can be reported by NAME. On a change it logs which
//! file, and the old and new leaf fingerprint, waits out a per-pod splay, and
//! ends — and the caller selects on that, drains, and returns. Kubelet restarts
//! the container and the new process reads the fresh file. **A change is not an
//! error, so the exit code is 0.**
//!
//! **THE CLIENT CERTIFICATE IS THE MEMBER WITH THE WORST FAILURE.** ADR-0516
//! records that an expired CLIENT leaf STOPS a hop rather than degrading it, so
//! a process that read it once and never again keeps answering `/` perfectly and
//! stops being able to reach `iam` or `task` — on a date, with nothing having
//! warned. It is also the ONLY certificate this process holds, so it is the only
//! one the expiry gauge can speak for.
//!
//! **ONE LEAF, TWO UPSTREAMS.** `gateway-client-tls` is presented to both `iam`
//! and `task`, so the same pair of paths arrives twice. [`Inputs::also`]
//! de-duplicates, which is what keeps the pair from being hashed twice, named
//! twice in the change log line, and counted twice by anything asserting
//! membership.
//!
//! In-process hot reload was rejected and is not available anyway: nothing
//! re-reads a dialled channel's material. A reloader operator was rejected
//! because it fails silent until the deadline and leaves off-reference adopters
//! broken (D80).
//!
//! # THIS IS A COPY, and saying so is the point
//!
//! **`iam/src/rotate.rs` is the original, `task` carries the second copy and
//! this is the third.** ADR-0523 says to lift the core into shared code before
//! the third, and this car defers that DELIBERATELY rather than by omission:
//! shared crates here are separate repositories consumed by git tag, so a lift
//! needs a fourth repository merged and tagged before any of these three changes
//! could compile, and this car has authority to do neither.
//!
//! **The core below is byte-identical to `iam`'s** — `Schedule`, `Watched`,
//! `Leaf`, `Presented`, `watch`, `watch_with_seed`, `splay`, `seed`, `never`,
//! `digest_of`, `hex`, and every method on `Inputs` except the builders. What
//! differs is enumerated rather than left to be discovered:
//!
//! 1. `SERVICE` is a module constant here; `iam` reads `crate::service::SERVICE`.
//! 2. There is no `listener` builder — this process serves no certificate.
//! 3. There is no `enrolment` builder — that CA is `iam`'s alone (D73).
//! 4. This process's watch set is EMPTY when both upstreams are cleartext, where
//!    `iam`'s is not.
//!
//! `serving_certificate` is kept and never called, so the core stays identical
//! and the lift is a move rather than a merge. The consequence is visible rather
//! than hidden: the change log line reports `serving_before = "none"`, which is a
//! different word from the `"unknown"` an unreadable certificate gets.
//!
//! A copy held together only by a paragraph is a copy that drifts. Keep this list
//! true, and lift the whole thing when the lift car runs.
//!
//! # THE PROPERTY THAT DECIDED IT, and the one every change here must keep
//!
//! **If the watcher dies you get today's behaviour, never worse.** A file that
//! cannot be read is not a changed one; an unparsable certificate is not a
//! changed one; no TLS at all means no watch. Nothing here may end the watch
//! over a state it is merely unsure about, because ending it exits the process.
//!
//! # A hash, never a modification time
//!
//! Kubelet rotates a mounted Secret by writing a whole new timestamped directory
//! and `rename`ing a replacement `..data` symlink over the old one. Every path
//! the process holds then resolves to a DIFFERENT inode with a fresh
//! modification time — on every resync, whether or not a single byte changed. An
//! mtime check restarts both replicas for nothing; a content hash does not.
//! `tests/tls_rotation.rs` performs that exact swap rather than overwriting a
//! file in place.
//!
//! # The splay, and why a PDB is not a substitute
//!
//! Both replicas see the refreshed file inside the same kubelet sync window, so
//! an unsplayed exit can drop both at once. **A PodDisruptionBudget does not
//! govern a self-exit** — it constrains eviction, and nothing is evicting
//! anything here. The splay is the only control. Renewal lands 30 days before
//! expiry, so the slack is enormous and minutes of waiting cost nothing.
//!
//! # The gauge is the half that makes a failure loud
//!
//! [`Inputs::export_not_after`] publishes the expiry of every certificate this
//! process ACTUALLY LOADED (D67), one series per certificate, told apart by a
//! `kind` label. Here that is one series, `kind = "client"`. If the watcher dies,
//! that gauge still shows the loaded leaf ageing out — which is what a watcher
//! whose own failure is silent would not give anybody.
//!
//! # "TLS is off" DOES mean "nothing is watched", here
//!
//! Unlike `iam`, this process reads no security material outside its two
//! upstream transports, so a deployment with both cleartext has an empty watch
//! set and this module idles. The schedule is still parsed at boot in that case:
//! a value an operator set and the binary cannot use is an error whether or not
//! the watcher would have run.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// The value of the `service` label on the gauge below.
///
/// A module constant here, where `iam` reads `crate::service::SERVICE`. That is
/// one of the four named differences from the original copy — see this module's
/// header.
const SERVICE: &str = "gateway";

/// When the certificate this process loaded stops being valid, in seconds since
/// the epoch.
///
/// **NO fingerprint label and no path label.** D67's boundary is that an
/// unbounded dimension goes on a wide event, never on a metric label — a
/// fingerprint label is one new time series per rotation, forever. The
/// fingerprints go in the log line, where the cardinality costs nothing.
pub const CERTIFICATE_NOT_AFTER: &str = "yadgar_tls_certificate_not_after_seconds";

/// How often the files are re-hashed.
const POLL_KEY: &str = "TLS_ROTATION_POLL_SECS";

/// The longest a pod waits before ending its watch.
const SPLAY_MAX_KEY: &str = "TLS_ROTATION_SPLAY_MAX_SECS";

/// Three small files a minute costs nothing, against a deadline 30 days wide.
const DEFAULT_POLL: Duration = Duration::from_secs(60);

/// Five minutes of spread between two replicas, against those same 30 days.
const DEFAULT_SPLAY_MAX: Duration = Duration::from_secs(300);

/// What a deployment got wrong about the rotation watcher.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error(
        "{key} is {value:?}, which is not a whole number of seconds ({source}). It is refused \
         rather than replaced with the default, because a deployment that believes it set this \
         and did not would run an interval nobody chose and see nothing wrong."
    )]
    Unparsable {
        key: &'static str,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "{POLL_KEY} is 0, which is not a poll interval. Sleeping for no time at all turns the \
         rotation watcher into a loop that re-reads and re-hashes the TLS files as fast as a \
         core allows, for the life of the pod. Set it to at least 1. Nothing is turned OFF by \
         setting it to 0 — leaving TLS off is what leaves the watcher idle. {SPLAY_MAX_KEY} is \
         different: 0 there means exit at once, which is a supported choice."
    )]
    ZeroPoll,
}

/// How often the watcher looks, and how long this pod waits once it has seen
/// something.
///
/// **A default nobody chose is fine here and would not be on a security
/// control**, which is why this has defaults at all while the response-time
/// floors do not. A value that was SET and cannot be used is still an error:
/// silently substituting one leaves an operator who believes they changed the
/// interval running the old one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    poll: Duration,
    splay_max: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Self::new(DEFAULT_POLL, DEFAULT_SPLAY_MAX)
    }
}

impl Schedule {
    pub fn new(poll: Duration, splay_max: Duration) -> Self {
        Self { poll, splay_max }
    }

    /// Read the schedule from the environment.
    pub fn from_env() -> Result<Self, ScheduleError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global** — the same
    /// reason [`crate::upstream::UpstreamTls::from_lookup`] takes one.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ScheduleError> {
        let seconds = |key: &'static str, default: Duration| match lookup(key) {
            None => Ok(default),
            Some(raw) => raw
                .trim()
                .parse()
                .map(Duration::from_secs)
                .map_err(|source| ScheduleError::Unparsable {
                    key,
                    value: raw,
                    source,
                }),
        };

        let poll = seconds(POLL_KEY, DEFAULT_POLL)?;
        if poll.is_zero() {
            return Err(ScheduleError::ZeroPoll);
        }
        Ok(Self::new(poll, seconds(SPLAY_MAX_KEY, DEFAULT_SPLAY_MAX)?))
    }

    /// How long between readings.
    pub fn poll(&self) -> Duration {
        self.poll
    }

    /// The top of the range this pod's wait is drawn from.
    pub fn splay_max(&self) -> Duration {
        self.splay_max
    }
}

/// Which direction a certificate this process loaded is presented in.
///
/// **Two certificates, two failure modes, and only one of them was ever
/// gauged.** The serving leaf is what callers verify when they connect here; the
/// client leaf (ADR-0516) is what this process shows the upstreams it connects
/// to. ADR-0516 records that the second is load-bearing for AVAILABILITY in a
/// way the first is not — an expired client leaf STOPS a hop rather than
/// weakening it — so a deployment that gauges only the serving one is blind to
/// the harder failure.
///
/// **The label is BOUNDED, which is what makes it allowed at all.** D67 forbids
/// an unbounded dimension on a metric label; this one has exactly two values and
/// always will, so it costs two series rather than one per rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presented {
    /// The leaf this process shows to its own callers.
    Serving,
    /// The leaf this process shows to the upstreams it dials (ADR-0516).
    Client,
}

impl Presented {
    /// The value of the `kind` label, and the word the log line uses.
    pub fn label(self) -> &'static str {
        match self {
            Self::Serving => "serving",
            Self::Client => "client",
        }
    }
}

/// One certificate this process loaded, AS IT WAS READ.
///
/// Kept rather than re-read, so the fingerprint and the gauge describe the
/// certificate actually loaded even after the file underneath has changed. The
/// path is kept beside it so the certificate ON DISK can be fingerprinted after
/// a rotation without re-deriving which file it was.
///
/// `der` is `None` for a file that was configured and could not be read or could
/// not be parsed. That is a deployment already broken in a way the boot log
/// carries, and it is DIFFERENT from the certificate not existing at all — which
/// is why the file is recorded either way.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Leaf {
    der: Option<Vec<u8>>,
    path: PathBuf,
}

/// One watched file, and what it held when this process read it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Watched {
    path: PathBuf,
    /// SHA-256 of the bytes AS LOADED. `None` when the file could not be read
    /// at that moment, which is a deployment already broken in a way the boot
    /// log carries.
    loaded: Option<[u8; 32]>,
}

/// The TLS files this process read at boot, and what they held when it read
/// them.
///
/// **Built from the configuration that was already resolved**, never by reading
/// the environment a second time: the point is to watch the files the process
/// actually opened, and a second reading could name different ones.
///
/// **THE BASELINE IS CAPTURED HERE, EAGERLY, AND THAT IS THE POINT.** Every
/// builder method below reads its file immediately, so each digest is taken
/// beside the code that loaded it rather than later. Deferring the first reading
/// to the watcher's first poll would put the whole of the rest of boot — the
/// `iam` and `task` dials, the broker connect — inside a window where a kubelet swap
/// makes the NEW file the baseline. The real rotation is then never noticed, and
/// the gauge describes a certificate the listener is not serving.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inputs {
    /// The leaf this service SERVES, when it serves one.
    serving: Option<Leaf>,
    /// The leaf this service PRESENTS TO ITS UPSTREAMS, when it presents one
    /// (ADR-0516). A different certificate from the one above, issued for a
    /// different purpose, and gauged separately because it fails differently.
    client: Option<Leaf>,
    /// Every watched file, both certificates included, in the order they were
    /// added and each appearing once.
    files: Vec<Watched>,
}

impl Inputs {
    /// The certificate this service presents to its callers.
    ///
    /// **NOTHING IN THIS REPOSITORY CALLS IT**, and it is kept anyway so the
    /// core stays byte-identical to `iam`'s and the lift ADR-0523 asks for is a
    /// move rather than a merge. This gateway terminates no TLS: the edge leaf
    /// belongs to the ingress in front of it (D71, D80).
    pub fn serving_certificate(self, path: &Path) -> Self {
        self.certificate(Presented::Serving, path)
    }

    /// The certificate this service presents to the upstreams it dials
    /// (ADR-0516).
    ///
    /// **The same mechanism, and a worse failure if it is left out.** An expired
    /// serving leaf degrades what callers see; an expired CLIENT leaf stops the
    /// hop outright, so this one being unwatched is the more expensive omission
    /// of the two.
    pub fn client_certificate(self, path: &Path) -> Self {
        self.certificate(Presented::Client, path)
    }

    /// Load one certificate and watch the file it came from, in ONE reading.
    ///
    /// One reading rather than two on purpose: reading the bytes for the digest
    /// separately from the bytes the leaf is parsed from opens a window in which
    /// a kubelet swap lands between them, and the process would then hold a
    /// fingerprint from one generation beside a baseline from the next.
    fn certificate(mut self, which: Presented, path: &Path) -> Self {
        let bytes = std::fs::read(path).ok();
        let leaf = Leaf {
            der: bytes
                .as_deref()
                .and_then(|b| CertificateDer::pem_slice_iter(b).next()?.ok())
                .map(|der| der.to_vec()),
            path: path.to_path_buf(),
        };
        match which {
            Presented::Serving => self.serving = Some(leaf),
            Presented::Client => self.client = Some(leaf),
        }
        self.watch(path, bytes.as_deref().map(digest_of))
    }

    /// The CA bundle an upstream's certificate is verified against, AND the
    /// client certificate this service presents to that upstream.
    ///
    /// **BOTH HALVES, and the second one is the reason this method changed.**
    /// The client certificate and its key are read once in
    /// `yadgar_dial::TlsOptions::prepare`, out of a directory mount that
    /// rotates — the watcher's exact shape. Left out of the set, this process
    /// works perfectly until the leaf expires and then fails hard, with no exit,
    /// no gauge movement and no log. ADR-0516 makes that failure a STOPPED hop
    /// rather than a degraded one, which is worse than the serving case this
    /// module was written for.
    ///
    /// The identity is `Some`/`Some` or `None`/`None` and cannot be half of one:
    /// `crate::upstream::UpstreamTls` refuses a certificate without its key at
    /// boot, so there is no half-configured arm to handle here.
    pub fn upstream(self, tls: Option<&crate::upstream::UpstreamTls>) -> Self {
        let Some(tls) = tls else {
            return self;
        };
        let watching = self.also(tls.ca_file());
        match (tls.client_certificate_file(), tls.client_key_file()) {
            (Some(certificate), Some(key)) => watching.client_certificate(certificate).also(key),
            _ => watching,
        }
    }

    /// A TLS file read at boot that is not a certificate this process presents:
    /// the private key belonging to one, and the CA bundle each upstream is
    /// verified against.
    pub fn also(self, path: &Path) -> Self {
        if self.is_watching(path) {
            return self;
        }
        let loaded = std::fs::read(path).ok().as_deref().map(digest_of);
        self.watch(path, loaded)
    }

    /// Add one file to the set, ONCE.
    ///
    /// **The de-duplication is load-bearing rather than tidy.** One process can
    /// present the SAME client leaf to two upstreams — the gateway does, to
    /// `iam` and to `task` — so the same two paths arrive twice. Without this
    /// they would be hashed twice, named twice in the line that reports a
    /// change, and counted twice by every assertion about membership.
    fn watch(mut self, path: &Path, loaded: Option<[u8; 32]>) -> Self {
        if self.is_watching(path) {
            return self;
        }
        self.files.push(Watched {
            path: path.to_path_buf(),
            loaded,
        });
        self
    }

    /// Whether this file is already in the set.
    fn is_watching(&self, path: &Path) -> bool {
        self.files.iter().any(|f| f.path == path)
    }

    /// Nothing was configured, so there is nothing to watch.
    ///
    /// **In THIS process that is the same as "both upstreams are cleartext"**,
    /// because the two upstream transports are the only security material it
    /// reads. `iam` differs: its enrolment CA (D73) is watched too, so a
    /// cleartext `iam` still has a non-empty set.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Every file being watched, in order. For tests that assert MEMBERSHIP,
    /// which is the half no rotation case can prove.
    pub fn watched(&self) -> Vec<&Path> {
        self.files.iter().map(|f| f.path.as_path()).collect()
    }

    /// What the files held when this process read them.
    ///
    /// `None` when any of them was unreadable then: there is no baseline to
    /// compare against, so every later reading would look like a change.
    fn baseline(&self) -> Option<Vec<[u8; 32]>> {
        self.files.iter().map(|f| f.loaded).collect()
    }

    /// What they hold now.
    ///
    /// **ONE DIGEST PER FILE, POSITIONALLY**, rather than one hash over all of
    /// them: it is what lets the change be reported by NAME, and it is why two
    /// files exchanging contents is a change rather than a wash.
    ///
    /// `None` when any of them cannot be read, which is a state to wait out
    /// rather than act on: kubelet is halfway through a swap, or a Secret has
    /// not been mounted yet.
    fn on_disk(&self) -> Option<Vec<[u8; 32]>> {
        self.files
            .iter()
            .map(|f| std::fs::read(&f.path).ok().as_deref().map(digest_of))
            .collect()
    }

    /// Which watched files differ from what this process read.
    fn differing(&self, current: &[[u8; 32]]) -> Vec<String> {
        self.files
            .iter()
            .zip(current)
            .filter(|(f, now)| f.loaded.as_ref() != Some(*now))
            .map(|(f, _)| f.path.display().to_string())
            .collect()
    }

    /// One of the two certificates this process holds, or nothing when this
    /// deployment has no such certificate at all.
    fn loaded(&self, which: Presented) -> Option<&Leaf> {
        match which {
            Presented::Serving => self.serving.as_ref(),
            Presented::Client => self.client.as_ref(),
        }
    }

    /// The leaf certificate this service presents, as it was loaded.
    ///
    /// **THE FIRST certificate in the file, and that is load-bearing.**
    /// cert-manager writes the leaf followed by the chain that issued it, so the
    /// LAST one is an authority whose expiry is years away — reporting it would
    /// keep the gauge green while the certificate actually on the wire ages out.
    fn leaf(&self, which: Presented) -> Option<CertificateDer<'static>> {
        Some(CertificateDer::from(self.loaded(which)?.der.clone()?))
    }

    /// The fingerprint of whatever that certificate's file holds RIGHT NOW,
    /// which is what a rotation replaced the loaded one with.
    ///
    /// The only reading in this module that deliberately goes back to disk: the
    /// "after" half of the log line has no other source.
    fn fingerprint_on_disk(&self, which: Presented) -> Option<String> {
        let bytes = std::fs::read(&self.loaded(which)?.path).ok()?;
        let der = CertificateDer::pem_slice_iter(&bytes).next()?.ok()?;
        Some(hex(&Sha256::digest(&der)))
    }

    /// A fingerprint for the log line, WITH THE TWO ABSENCES KEPT APART.
    ///
    /// `none` means this deployment holds no certificate of that kind — the
    /// gateway serves nothing, so its serving half is always `none` and that is
    /// correct rather than broken. `unknown` means one was configured and could
    /// not be parsed, which is a deployment to look at. Collapsing the two into
    /// one word is how a real fault reads as an ordinary shape.
    fn reported(&self, which: Presented, on_disk: bool) -> String {
        if self.loaded(which).is_none() {
            return absent();
        }
        let found = if on_disk {
            self.fingerprint_on_disk(which)
        } else {
            self.fingerprint(which)
        };
        found.unwrap_or_else(unknown)
    }

    /// SHA-256 over the leaf's DER, in hex.
    ///
    /// The same BYTES `openssl x509 -fingerprint -sha256` prints, in a different
    /// rendering: lowercase and unseparated, where openssl gives uppercase
    /// separated by colons. Comparable after case-folding and stripping the
    /// colons, and not by eye.
    ///
    /// **This is what answers "which certificate am I on".** It is the first
    /// question anybody asks when a rotation is suspected, and without it the
    /// log line saying one happened is unfalsifiable.
    pub fn fingerprint(&self, which: Presented) -> Option<String> {
        Some(hex(&Sha256::digest(self.leaf(which)?)))
    }

    /// When the loaded leaf stops being valid, in seconds since the epoch.
    pub fn not_after(&self, which: Presented) -> Option<i64> {
        let der = self.leaf(which)?;
        let (_, parsed) = X509Certificate::from_der(&der).ok()?;
        Some(parsed.validity().not_after.timestamp())
    }

    /// Publish that expiry as a gauge (D67).
    ///
    /// Called by the BINARY after the exporter is installed — a value recorded
    /// before there is a recorder is a value nobody ever sees. Absent or
    /// unparsable, nothing is published: an invented number is worse than a
    /// missing series, because a dashboard cannot tell it apart from a real one.
    pub fn export_not_after(&self) {
        for which in [Presented::Serving, Presented::Client] {
            let Some(seconds) = self.not_after(which) else {
                continue;
            };
            metrics::gauge!(
                CERTIFICATE_NOT_AFTER,
                "service" => SERVICE,
                "kind" => which.label(),
            )
            .set(seconds as f64);
            tracing::info!(
                kind = which.label(),
                not_after = seconds,
                fingerprint = self.fingerprint(which).unwrap_or_else(unknown),
                "certificate loaded; its expiry is exported as {CERTIFICATE_NOT_AFTER}"
            );
        }
    }
}

/// Wait until the TLS files this process read at boot have changed, then wait
/// out this pod's splay.
///
/// **The caller selects on this future and drains.** It resolves at most once,
/// and never for any reason but a change it could actually read.
pub async fn watch(inputs: Inputs, schedule: Schedule) {
    watch_with_seed(inputs, schedule, seed()).await
}

/// The same watch over an injected splay seed.
///
/// **A seam, because a splay drawn from the clock cannot be asserted.** The test
/// passes `u64::MAX` and gets the whole configured maximum, which turns "the
/// exit waits" into an equality rather than a coin toss.
pub async fn watch_with_seed(inputs: Inputs, schedule: Schedule, seed: u64) {
    if inputs.is_empty() {
        // BOTH UPSTREAMS ARE CLEARTEXT, which is the default. Nothing was read,
        // so nothing can rotate. The watch must NEVER end: the caller treats that as a
        // rotation and exits a process that has no certificate at all.
        tracing::debug!("no TLS inputs; this process will not exit on a rotation");
        never().await
    }
    let Some(booted) = inputs.baseline() else {
        // CONFIGURED AND UNREADABLE. There is no baseline to compare against, so
        // every later reading would look like a change. Today's behaviour —
        // serve what was loaded — is the safe answer, and the boot log already
        // carries whatever went wrong.
        tracing::warn!("the TLS inputs could not be read; rotation will not be noticed");
        never().await
    };
    let serving_before = inputs.reported(Presented::Serving, false);
    let client_before = inputs.reported(Presented::Client, false);

    loop {
        tokio::time::sleep(schedule.poll).await;
        let Some(current) = inputs.on_disk() else {
            // NOT A CHANGE. A file that cannot be read is a mount mid-swap or a
            // Secret not yet there, and restarting over it would make this
            // watcher's failure worse than not having one.
            tracing::warn!("a TLS input could not be read; keeping the certificate already loaded");
            continue;
        };
        if current == booted {
            continue;
        }

        let waited = splay(schedule.splay_max, seed);
        tracing::warn!(
            serving_before,
            serving_after = inputs.reported(Presented::Serving, true),
            client_before,
            client_after = inputs.reported(Presented::Client, true),
            changed = inputs.differing(&current).join(", "),
            splay_secs = waited.as_secs(),
            "the TLS files read at boot have CHANGED on disk. tonic cannot swap a running \
             listener's certificate, so this process drains and exits 0 to be restarted onto \
             the new one; the wait is this pod's splay, so both replicas do not go at once"
        );
        tokio::time::sleep(waited).await;
        tracing::warn!("splay elapsed; draining");
        return;
    }
}

/// How long THIS pod waits before ending its watch.
///
/// A pure function of the maximum and the seed, spread evenly over the range:
/// seed `0` waits not at all and `u64::MAX` waits the whole of it.
fn splay(max: Duration, seed: u64) -> Duration {
    // MILLISECONDS, not nanoseconds, and `saturating_mul` beside it. In
    // nanoseconds this product overflows `u128` once the configured maximum
    // passes roughly 1.85e10 seconds — measured, not reasoned about — and a
    // splay is a wait of minutes, so nanosecond resolution buys nothing to pay
    // for it with. `.min(max)` is the belt: whatever the arithmetic does at the
    // absurd end of the range, the wait never exceeds what was configured.
    let millis = u128::from(seed).saturating_mul(max.as_millis()) / u128::from(u64::MAX);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX)).min(max)
}

/// This pod's splay seed.
///
/// **The process start time, hashed.** Two replicas of the same rollout never
/// start in the same nanosecond, and hashing decorrelates the digits that are
/// close together — which is all the spread this needs. A restarted pod draws a
/// new one, which is correct: it is a new process, and the replica it must avoid
/// colliding with has moved on too.
///
/// Deliberately NOT a random-number generator: an estate with no `rand`
/// dependency does not grow one for a value that has to be assertable.
fn seed() -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes"))
}

/// A future that never resolves.
///
/// Spelled out rather than inlined because the mistake it prevents is
/// invisible: a `watch` that RETURNED when there was nothing to watch would look
/// to the caller exactly like a detected rotation, and exit the process.
async fn never() -> ! {
    let never: std::convert::Infallible = std::future::pending().await;
    match never {}
}

/// What a fingerprint reads as when the file holds no certificate this can
/// parse. Never an empty string: a log field that renders blank looks like a
/// bug in the logging rather than an answer.
fn unknown() -> String {
    "unknown".to_string()
}

/// What a fingerprint reads as when this deployment holds no certificate of that
/// kind at all. Deliberately a DIFFERENT word from [`unknown`]: the gateway
/// serves nothing and so has no serving leaf, which is a correct deployment, and
/// reading it as `unknown` would send somebody looking for a fault.
fn absent() -> String {
    "none".to_string()
}

/// SHA-256 of one file's contents.
fn digest_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: Duration = Duration::from_secs(300);

    /// The ends of the range, which is what makes the seam assertable at all:
    /// the test that proves the exit waits passes `u64::MAX` and expects the
    /// whole maximum back.
    #[test]
    fn the_splay_spans_the_whole_configured_range() {
        assert_eq!(splay(MAX, 0), Duration::ZERO);
        assert_eq!(splay(MAX, u64::MAX), MAX);
    }

    /// Never longer than what was configured. A splay that overshot would hold a
    /// pod on a certificate it has already been told to stop using.
    #[test]
    fn the_splay_never_exceeds_its_maximum() {
        for seed in [1, 7, 1_000, u64::MAX / 3, u64::MAX / 2, u64::MAX - 1] {
            assert!(splay(MAX, seed) <= MAX, "{seed} overshot");
        }
    }

    /// ZERO IS A USABLE SETTING, not a bug: it is how a single-replica or a
    /// development deployment says it wants the restart immediately.
    #[test]
    fn a_zero_maximum_waits_not_at_all() {
        assert_eq!(splay(Duration::ZERO, u64::MAX), Duration::ZERO);
    }

    /// THE POINT OF THE SPLAY. Different pods must draw different waits —
    /// a function that returned the same value for every seed would leave both
    /// replicas exiting together, which is the failure it exists to prevent.
    #[test]
    fn different_seeds_wait_for_different_times() {
        let waits: std::collections::BTreeSet<_> =
            (1..=8).map(|n| splay(MAX, u64::MAX / 9 * n)).collect();
        assert_eq!(waits.len(), 8, "seeds must spread across the range");
    }

    /// The seed is drawn from the clock, so two draws in one process differ —
    /// the property two pods rely on, tested where it can be observed.
    #[test]
    fn the_seed_moves() {
        assert_ne!(seed(), seed());
    }

    /// Nothing configured is the DEFAULT today, and it must not look like a
    /// deployment whose certificate has gone missing.
    #[test]
    fn nothing_configured_is_empty() {
        assert!(Inputs::default().is_empty());
        assert!(!Inputs::default()
            .serving_certificate(Path::new("/etc/yadgar/tls.pem"))
            .is_empty());
    }

    /// A file that does not exist yields no baseline — the state `watch` refuses
    /// to act on, because every later reading would look like a change.
    #[test]
    fn an_unreadable_input_has_no_baseline() {
        let inputs = Inputs::default().also(Path::new("/etc/yadgar/quokka-4d81/absent.pem"));
        assert_eq!(inputs.baseline(), None);
        assert_eq!(inputs.on_disk(), None);
        assert_eq!(inputs.fingerprint(Presented::Serving), None);
        assert_eq!(inputs.not_after(Presented::Serving), None);
        assert_eq!(inputs.fingerprint(Presented::Client), None);
        assert_eq!(inputs.not_after(Presented::Client), None);
    }

    /// ONE FILE, ONE ENTRY, however many times it is named.
    ///
    /// **The gateway presents ONE client leaf to TWO upstreams**, so `upstream`
    /// runs twice over the same two paths. Without this the pair is hashed
    /// twice, listed twice in the line that reports a change, and counted twice
    /// by anything asserting membership.
    #[test]
    fn a_file_named_twice_is_watched_once() {
        let path = Path::new("/etc/yadgar/quokka-4d81/client.pem");
        let inputs = Inputs::default().also(path).also(path);
        assert_eq!(inputs.watched(), vec![path]);

        let both = Inputs::default().client_certificate(path).also(path);
        assert_eq!(both.watched(), vec![path]);
    }

    /// A CERTIFICATE THAT DOES NOT EXIST AND ONE THAT CANNOT BE READ ARE
    /// DIFFERENT ANSWERS, and the log line has to say which.
    ///
    /// The gateway serves nothing at all, so its serving half is permanently
    /// absent — a correct deployment. Reporting that as `unknown` would send
    /// somebody looking for a fault that is not there.
    #[test]
    fn an_absent_certificate_reads_differently_from_an_unreadable_one() {
        assert_eq!(
            Inputs::default().reported(Presented::Serving, false),
            "none"
        );

        let configured =
            Inputs::default().serving_certificate(Path::new("/etc/yadgar/quokka-4d81/absent.pem"));
        assert_eq!(configured.reported(Presented::Serving, false), "unknown");
        assert_eq!(configured.reported(Presented::Serving, true), "unknown");
    }

    /// AN ABSURD MAXIMUM MUST NOT PANIC OR OVERSHOOT. In nanoseconds the product
    /// overflows here; the measured threshold is around 1.85e10 seconds.
    #[test]
    fn an_absurd_maximum_neither_panics_nor_overshoots() {
        for max in [
            Duration::from_secs(20_000_000_000),
            Duration::from_secs(u64::MAX / 1000),
        ] {
            for seed in [0, 1, u64::MAX / 2, u64::MAX] {
                assert!(splay(max, seed) <= max, "{max:?}/{seed} overshot");
            }
        }
    }

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

    /// Nothing configured is the ordinary case, and the defaults are the ones
    /// the chart also writes.
    #[test]
    fn an_unconfigured_schedule_is_the_default_one() {
        assert_eq!(
            Schedule::from_lookup(lookup(&[])).unwrap(),
            Schedule::default()
        );
        assert_eq!(Schedule::default().poll(), Duration::from_secs(60));
        assert_eq!(Schedule::default().splay_max(), Duration::from_secs(300));
    }

    /// Both values travel, proved with numbers no default could have produced.
    #[test]
    fn both_values_arrive() {
        let vars = [
            ("TLS_ROTATION_POLL_SECS", "17"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "941"),
        ];
        let schedule = Schedule::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(schedule.poll(), Duration::from_secs(17));
        assert_eq!(schedule.splay_max(), Duration::from_secs(941));
    }

    /// A ZERO POLL IS A HOT LOOP, not a way of turning the watcher off. Sleeping
    /// for no time at all re-reads and re-hashes the files as fast as a core
    /// allows, for the life of the pod — a setting nobody asked for, running
    /// quietly, which is the failure the strict parse exists to prevent.
    #[test]
    fn a_zero_poll_interval_is_refused() {
        let vars = [("TLS_ROTATION_POLL_SECS", "0")];
        assert!(matches!(
            Schedule::from_lookup(lookup(&vars)),
            Err(ScheduleError::ZeroPoll)
        ));
    }

    /// A zero SPLAY is the opposite: a supported choice, and what a
    /// single-replica or development deployment wants.
    #[test]
    fn a_zero_splay_is_allowed() {
        let vars = [("TLS_ROTATION_SPLAY_MAX_SECS", "0")];
        let schedule = Schedule::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(schedule.splay_max(), Duration::ZERO);
        assert_eq!(schedule.poll(), Duration::from_secs(60));
    }

    /// PARSED, NOT SALVAGED. A value that was set and cannot be used fails boot
    /// naming the variable, rather than leaving an operator who believes they
    /// changed the interval running the old one. An empty string is a SET value
    /// — that is what a values override nulling the block renders.
    #[test]
    fn a_value_that_cannot_be_parsed_is_refused() {
        for (key, value) in [
            ("TLS_ROTATION_POLL_SECS", ""),
            ("TLS_ROTATION_POLL_SECS", "60s"),
            ("TLS_ROTATION_POLL_SECS", "-1"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "five minutes"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "1.5"),
        ] {
            let vars = [(key, value)];
            assert!(
                matches!(
                    Schedule::from_lookup(lookup(&vars)),
                    Err(ScheduleError::Unparsable { key: named, .. }) if named == key
                ),
                "{key}={value:?} must be refused, naming the variable"
            );
        }
    }

    #[test]
    fn hex_renders_every_byte_as_two_digits() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
