//! What this process does when the security material it read at boot is replaced
//! underneath it — and, now, WHICH FILES this gateway puts in front of the
//! watcher that does it.
//!
//! **The watcher itself moved out.** `Schedule`, `Inputs`, `Presented`, `watch`
//! and the `yadgar_tls_certificate_not_after_seconds` gauge live in
//! [`yadgar_lifecycle::rotate`], pinned by tag per ADR-0526. This file was the
//! THIRD near-byte-identical copy of `iam/src/rotate.rs`, which is the state
//! ADR-0523 asked to be ended before it arrived — *"the watcher core is
//! repo-agnostic and is about to exist in four copies; lift it into a shared
//! crate before the third."* What is left here is the half that is genuinely
//! this service's.
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
//! [`yadgar_lifecycle::rotate::watch`] polls a digest of every file in
//! [`watch_set`] — one per file, so a change can be reported by NAME. On a
//! change it logs which file, and the old and new leaf fingerprint, waits out a
//! per-pod splay, and ends. The caller selects on that, drains, and returns.
//! Kubelet restarts the container and the new process reads the fresh file. **A
//! change is not an error, so the exit code is 0.**
//!
//! **THE CLIENT CERTIFICATE IS THE MEMBER WITH THE WORST FAILURE.** ADR-0516
//! records that an expired CLIENT leaf STOPS a hop rather than degrading it, so
//! a process that read it once and never again keeps answering `/` perfectly and
//! stops being able to reach `iam` or `task` — on a date, with nothing having
//! warned. It is also the ONLY certificate this process holds, so it is the only
//! one the expiry gauge can speak for.
//!
//! **ONE LEAF, TWO UPSTREAMS.** `gateway-client-tls` is presented to both `iam`
//! and `task`, so the same pair of paths arrives twice. The crate's fold
//! de-duplicates, which is what keeps the pair from being hashed twice, named
//! twice in the change log line, and counted twice by anything asserting
//! membership.
//!
//! In-process hot reload was rejected and is not available anyway: nothing
//! re-reads a dialled channel's material. A reloader operator was rejected
//! because it fails silent until the deadline and leaves off-reference adopters
//! broken (D80).
//!
//! # WHY THE SET IS A FUNCTION AND NOT A RUN OF STATEMENTS IN `main`
//!
//! It used to be two chained builder calls in `main.rs`. No test in this
//! repository spawns the binary, so deleting either compiled, passed the whole
//! suite, and shipped a process that would never notice that file rotating.
//! `tests/tls_rotation.rs` could not catch it either: it rebuilt the same
//! assembly by hand, so `main.rs` and the test could disagree while both stayed
//! green.
//!
//! [`watch_set`] is the one expression naming this gateway's material, and
//! `main.rs` calls it rather than repeating it. `tests/assembly.rs` calls the
//! SAME function, so dropping an upstream from the list below turns a test red.

pub use yadgar_lifecycle::rotate::{
    watch, Configuration, File, Inputs, Material, Presented, Schedule, ScheduleError,
    CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};

use crate::upstream::UpstreamTls;

/// The `service` label on [`CERTIFICATE_NOT_AFTER`], and the name in the
/// watcher's log lines.
///
/// A module constant here, where `iam` reads `crate::service::SERVICE`. That is
/// a difference of where the name is kept, never of what it is: a dashboard
/// selects on this string.
const SERVICE: &str = "gateway";

/// The CA bundle one upstream's certificate is verified against, AND the client
/// certificate this gateway presents to that upstream.
///
/// **BOTH HALVES, and the second one is the load-bearing member.** The client
/// certificate and its key are read once in `yadgar_dial::TlsOptions::prepare`,
/// out of a directory mount that rotates. Left out of the set, this process
/// answers `/` perfectly until that leaf expires and then stops being able to
/// reach the module behind it, with no exit, no gauge movement and no log.
///
/// The identity is `Some`/`Some` or `None`/`None` and cannot be half of one:
/// [`crate::upstream::UpstreamTls`] refuses a certificate without its key at
/// boot, so there is no half-configured arm to handle here.
impl Material for UpstreamTls {
    fn files(&self) -> Vec<File<'_>> {
        let mut files = vec![File::read(self.ca_file())];
        if let (Some(certificate), Some(key)) =
            (self.client_certificate_file(), self.client_key_file())
        {
            files.push(File::certificate(Presented::Client, certificate));
            files.push(File::read(key));
        }
        files
    }
}

/// Everything this deployment read at boot, hashed as it was read.
///
/// **THE LIST IS THE ASSERTION.** TLS is opt-in and read PER UPSTREAM so the two
/// can be cut over one at a time, and `Option<M>: Material` folds an absent one
/// to nothing — so neither argument needs a branch. A watch set that is empty
/// because both hops are cleartext is the ordinary deployment today, and
/// [`yadgar_lifecycle::rotate::watch`] never ends on one.
///
/// **THE SHARED CLIENT PAIR IS HASHED ONCE.** `gateway-client-tls` is presented
/// to both upstreams, so the same two paths arrive twice; the fold watches a
/// path once, in the position it first appeared.
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS THE FOURTH MEMBER (step 2a).**
/// `config` is `shared/shared.yaml`, mounted from `yadgarhq/config`'s `shared`
/// ConfigMap, and it is a [`Material`] like the other three: `Configuration`
/// implements the trait by returning the one file it read its schedule from
/// (`yadgar_lifecycle::rotate::Configuration::files`), so folding it in here
/// joins the document to the ADR-0523 watch set through the exact same
/// `Inputs::also` path the CA bundles and the client leaf already take. An
/// operator editing `shared.yaml` restarts this pod exactly as editing a CA
/// bundle would.
///
/// Called from `main.rs` INSIDE boot and BEFORE the dials: every entry is hashed
/// as it is added, so the baseline is the bytes the process actually loaded.
/// Collecting paths and reading them when the watcher first polls would put the
/// rest of boot inside a window where a kubelet swap quietly becomes the
/// baseline, and the real rotation would never be noticed.
pub fn watch_set(
    task: Option<&UpstreamTls>,
    iam: Option<&UpstreamTls>,
    config: &Configuration,
) -> Inputs {
    Inputs::of(SERVICE, &[&task, &iam, config])
}
