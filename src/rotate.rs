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
//! (ADR-0516). There is no serving leaf beside them.
//!
//! **AND TWO FILES THAT ARE NOT CERTIFICATES AT ALL.** The password this gateway
//! presents to the shared cache (D74) and the one it presents to the broker
//! (D72) are read once at boot and then held as VALUES for the life of the
//! process — the first baked into `crate::limit::Limiter`, the second into an
//! `async-nats` client. ADR-0523's rule is about PROVENANCE rather than payload:
//! a file this process read at boot is watched, whatever is in it. `iam` has
//! watched its broker password since its own set was lifted into a function;
//! this gateway watched neither of its own, which is the gap this module's
//! [`watch_set`] closes.
//!
//! **WHAT A ROTATION OF EITHER COSTS, and it is worse than a stale certificate.**
//! The cache password is on the hot path of every user-attributed call, and
//! `crate::limit::Decision::Unauthenticated` deliberately does NOT take the
//! fail-open floor an unreachable cache takes — so a rotated `requirepass`
//! turns every such call into a refusal, and it does not recover. The broker
//! password fails quieter and lasts longer: the broker answers
//! `AuthorizationViolation`, `crate::invalidate::run` redials at the refused
//! rate for ever, and NO invalidation is consumed, so a revoked credential goes
//! on working until its cached identity ages out. Neither ends the process, and
//! neither moves a gauge.
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
//! SAME function, so dropping ANY member from the list below turns a test red.

pub use yadgar_lifecycle::rotate::{
    watch, Configuration, File, Inputs, Material, Presented, Schedule, ScheduleError,
    CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};

use std::path::Path;

use crate::invalidate::Broker;
use crate::upstream::UpstreamTls;

/// The password this gateway presents to the broker that carries D72's cache
/// invalidation.
///
/// Not a certificate, and watched on exactly the same ground — see the module
/// documentation for what its rotation costs. The same shape `iam` already uses
/// for the same file.
///
/// **A BROKER THAT DEMANDS NO CREDENTIAL CONTRIBUTES NOTHING**, which is the
/// deployment running today rather than an edge case: the broker ships with no
/// authorization block at all. An empty list is the right answer for it — a path
/// invented here would be reported unreadable for ever by
/// [`WATCHED_FILES_UNREADABLE`] on a gateway with nothing wrong with it, and
/// that gauge is one an operator is meant to be able to read as a fault.
impl Material for Broker {
    fn files(&self) -> Vec<File<'_>> {
        self.password_file().map(File::read).into_iter().collect()
    }
}

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
/// **THE TWO PASSWORDS ARE MEMBERS THREE AND FOUR, and neither is transport.**
/// `broker` is `crate::invalidate::Broker`, which keeps the path beside the
/// value precisely so this set can be built from the RESOLVED credential rather
/// than by reading the environment a second time; a second reading could name a
/// different file from the one actually opened. `cache_password` is the plain
/// path `main.rs` read `YADGAR_VALKEY_PASSWORD_FILE` from, taken as `&Path`
/// exactly the way the three `*-db` services take their database password —
/// this gateway has no resolved cache-credential type to hang a [`Material`] on,
/// and inventing one to satisfy the shape would be a restructuring rather than
/// a fix.
///
/// **BOTH ARE `Option`, AND BOTH ARE `None` IN THE DEPLOYMENT RUNNING TODAY.**
/// The cache has no `requirepass` and the broker no authorization block, so this
/// change adds NOTHING to the watch set of a pod as currently deployed — which
/// is what makes it safe to roll ahead of either credential rather than in
/// lockstep with it. It also means neither can push
/// [`WATCHED_FILES_UNREADABLE`] off zero: an absent credential named no file,
/// and `Option<M>: Material` folds it to nothing.
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS THE LAST MEMBER (step 2a).**
/// `config` is `shared/shared.yaml`, mounted from `yadgarhq/config`'s `shared`
/// ConfigMap, and it is a [`Material`] like the other four: `Configuration`
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
    broker: Option<&Broker>,
    cache_password: Option<&Path>,
    config: &Configuration,
) -> Inputs {
    Inputs::of(SERVICE, &[&task, &iam, &broker, &cache_password, config])
}
