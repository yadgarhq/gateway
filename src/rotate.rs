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

use std::path::{Path, PathBuf};
use std::time::Duration;

use yadgar_lifecycle::rotate::CONFIG_DIR;

use crate::invalidate::Broker;
use crate::upstream::UpstreamTls;

/// The password this gateway presents to the broker that carries D72's cache
/// invalidation.
///
/// Not a certificate, and watched on exactly the same ground — see the module
/// documentation for what its rotation costs. The same shape `iam` already uses
/// for the same file.
///
/// **A BROKER THAT DEMANDS NO CREDENTIAL CONTRIBUTES NOTHING**, and that arm is
/// for an adopter rather than for the reference deployment. This chart points at
/// a broker whose authorization block declares a `gateway` user
/// (`chart/values.yaml`, `nats.url`), so the reference deployment resolves a
/// credential and this list is never empty there. An off-reference deployment
/// may still run an open broker, and an empty list is the right answer for it —
/// a path invented here would be reported unreadable for ever by
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

/// The document under [`CONFIG_DIR`] holding settings only THIS service reads.
const GATEWAY_DOCUMENT: &str = "gateway/gateway.yaml";

const TOOLS_POLL_LEAF: &str = "intervalSeconds";
const TOOLS_POLL_KNOB: &str = "toolsPoll.intervalSeconds";

/// This gateway's OWN configuration document — `chart/config/gateway.yaml` in
/// `yadgarhq/config`, mounted at `gateway/gateway.yaml` under [`CONFIG_DIR`].
///
/// **DISTINCT FROM [`Configuration`], which is `shared.yaml`.** `shared.yaml`'s
/// own header states the dividing line: a knob every service reads with the
/// same value goes there, and a knob only one service reads belongs in that
/// service's own file. `tools/list`'s poll interval is read by no other
/// service — `iam`, `task`, `iam-db` and `task-db` never build the response —
/// so it is the first knob in `gateway.yaml`, which existed, mounted and empty,
/// for exactly this day.
///
/// **`chart/config/gateway.yaml` DOES NOT ENFORCE `deny_unknown_fields`, on
/// purpose, for the same reason `yadgar-lifecycle`'s `Document` does not**:
/// this document will hold more than one section over time, and a parser that
/// refused an unrecognised key would make the second gateway-only knob a
/// breaking change for the first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayDocument {
    path: PathBuf,
}

impl GatewayDocument {
    /// The document where the chart mounts it.
    pub fn mounted() -> Self {
        Self::under(CONFIG_DIR)
    }

    /// The same, under any root — the seam that makes this testable without a
    /// cluster.
    pub fn under(root: impl AsRef<Path>) -> Self {
        Self {
            path: root.as_ref().join(GATEWAY_DOCUMENT),
        }
    }

    /// The file a refusal names.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How often a client should re-poll `tools/list` for a changed catalogue.
    ///
    /// # Errors
    ///
    /// Every way this file can fail to state the knob: absent, unreadable,
    /// unparsable as YAML, missing the knob, holding it empty, holding
    /// something that is not a whole number of seconds, or naming zero. None
    /// of them has a fallback (ADR-0569) — see [`ToolsPollError`].
    pub fn tools_poll_interval(&self) -> Result<Duration, ToolsPollError> {
        let where_ = || self.path.display().to_string();
        // ADR-0523-WATCHED: GatewayDocument
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(ToolsPollError::Absent { path: where_() })
            }
            Err(source) => {
                return Err(ToolsPollError::Unreadable {
                    path: where_(),
                    source,
                })
            }
        };

        // `Option<Mapping>` rather than a typed field, for the reason
        // `yadgar_lifecycle::rotate::Document` gives: an explicit YAML `null`
        // and an absent key both deserialise to `None` on a typed field, and
        // "present but empty" is a different, more useful fault to report than
        // "not there at all".
        #[derive(serde::Deserialize)]
        struct Document {
            #[serde(rename = "toolsPoll")]
            tools_poll: Option<serde_norway::Mapping>,
        }
        let document: Option<Document> =
            serde_norway::from_str(&text).map_err(|source| ToolsPollError::Malformed {
                path: where_(),
                source,
            })?;
        let section = document.and_then(|d| d.tools_poll).unwrap_or_default();
        let raw = match section.get(TOOLS_POLL_LEAF).cloned() {
            None => return Err(ToolsPollError::Missing { path: where_() }),
            Some(serde_norway::Value::Null) => {
                return Err(ToolsPollError::Empty { path: where_() })
            }
            Some(other) => match other.as_u64() {
                Some(n) => n,
                None => {
                    let raw = other
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| serde_norway::to_string(&other).unwrap_or_default());
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        return Err(ToolsPollError::Empty { path: where_() });
                    }
                    trimmed
                        .parse()
                        .map_err(|source| ToolsPollError::Unparsable {
                            path: where_(),
                            value: raw,
                            source,
                        })?
                }
            },
        };
        if raw == 0 {
            return Err(ToolsPollError::Zero { path: where_() });
        }
        Ok(Duration::from_secs(raw))
    }
}

impl Material for GatewayDocument {
    fn files(&self) -> Vec<File<'_>> {
        vec![File::read(&self.path)]
    }
}

/// A poll interval a deployment stated and this process cannot use, or did not
/// state at all.
///
/// **EVERY VARIANT REFUSES THE BOOT AND NAMES A FILE (ADR-0569).** There is no
/// compiled-in default behind any of them — an installation that never sets
/// [`TOOLS_POLL_KNOB`] does not silently ship a number nobody chose.
#[derive(Debug, thiserror::Error)]
pub enum ToolsPollError {
    #[error(
        "{path} does not exist, so no configuration was read. It is `gateway`'s own document \
         in the configuration chart in yadgarhq/config, mounted from the ConfigMap `gateway`. \
         There is no default to fall back to (ADR-0569)."
    )]
    Absent { path: String },

    #[error("reading {path} failed")]
    Unreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "{path} is not parseable as YAML, or `toolsPoll` within it is not a mapping of knobs."
    )]
    Malformed {
        path: String,
        #[source]
        source: serde_norway::Error,
    },

    #[error(
        "{TOOLS_POLL_KNOB} is not defined in {path}. There is no compiled-in default and no \
         fallback (ADR-0569) — add the line to the document."
    )]
    Missing { path: String },

    #[error(
        "{TOOLS_POLL_KNOB} is present in {path} and has no value. That is different from being \
         missing entirely, and is reported separately on purpose."
    )]
    Empty { path: String },

    #[error("{TOOLS_POLL_KNOB} in {path} is {value:?}, which is not a whole number of seconds.")]
    Unparsable {
        path: String,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "{TOOLS_POLL_KNOB} in {path} is 0. A client cannot poll at an interval of zero, so this \
         is refused rather than read as \"never\" or \"always\"."
    )]
    Zero { path: String },
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
/// **BOTH ARE `Option`, AND BOTH ARE `Some` IN THE DEPLOYMENT RUNNING TODAY.**
/// The chart sets `rateLimit.passwordSecret` by default and points `nats.url` at
/// a broker whose authorization block declares a `gateway` user, so a reference
/// pod resolves both credentials and this set is FIVE members rather than three.
/// Both files are read boot-fatally — an unreadable or empty one refuses the
/// start — so a pod that is up has read both, and a rotation of either now ends
/// it. The `Option` is for the off-reference deployment that runs an open cache
/// or an open broker (D80): there the credential names no file, `Option<M>:
/// Material` folds it to nothing, and it cannot push
/// [`WATCHED_FILES_UNREADABLE`] off zero by watching a path that never
/// existed.
///
/// **D73'S BOOTSTRAP TOKEN IS MEMBER FIVE, AND IT IS ABSENT ON THE DEPLOYMENT
/// RUNNING TODAY.** The chart mounts no `admin-bootstrap-token` Secret yet
/// (ledger 638's step 7), so this arm folds to nothing and the reference pod
/// watches what it always did. What it buys on the day the mount lands: the token
/// is held as a DIGEST for the life of the process, so a Secret rotated
/// underneath a running pod would otherwise leave the gateway comparing against
/// the value it booted with — the `present-and-wrong` shape ADR-0596 names, and
/// one no existence check discriminates. `Option<&Path>` rather than a resolved
/// type for `cache_password`'s reason: there is no credential object here to hang
/// a [`Material`] on, and inventing one to satisfy the shape would be a
/// restructuring rather than a fix.
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS MEMBER SIX (step 2a).**
/// `config` is `shared/shared.yaml`, mounted from `yadgarhq/config`'s `shared`
/// ConfigMap, and it is a [`Material`] like the others: `Configuration`
/// implements the trait by returning the one file it read its schedule from
/// (`yadgar_lifecycle::rotate::Configuration::files`), so folding it in here
/// joins the document to the ADR-0523 watch set through the exact same
/// `Inputs::also` path the CA bundles and the client leaf already take. An
/// operator editing `shared.yaml` restarts this pod exactly as editing a CA
/// bundle would.
///
/// **`gateway.yaml` IS MEMBER SEVEN, and the first one this service ever
/// watched.** Until the `tools/list` poll interval, `config-gateway` was
/// mounted and unread — see `chart/templates/deployment.yaml`'s volume-mount
/// comment, which named this exact gap and said the fix belongs in the same
/// pull request as the first gateway-only knob. This is that pull request:
/// [`GatewayDocument`] is a [`Material`] on the same terms as [`Configuration`],
/// so an operator editing `gateway.yaml` now restarts this pod too.
///
/// Called from `main.rs` INSIDE boot and BEFORE the dials: every entry is hashed
/// as it is added, so the baseline is the bytes the process actually loaded.
/// Collecting paths and reading them when the watcher first polls would put the
/// rest of boot inside a window where a kubelet swap quietly becomes the
/// baseline, and the real rotation would never be noticed.
/// **EIGHT ARGUMENTS, AND THE ALTERNATIVE IS WORSE THAN THE LINT.** Grouping
/// them into a struct is what clippy is asking for, and a struct that satisfied
/// the call sites would carry `Default` — at which point `tests/assembly.rs`'s
/// per-half cases could omit a member with `..Default::default()`, and a NEW
/// member added later would be silently absent from every one of them. That is
/// precisely the mutation this list exists to kill: the file's opening comment is
/// "an upstream deleted from that list turns this red". Positional arguments make
/// every call site name every member, so adding one is a visible edit everywhere
/// it matters.
#[allow(clippy::too_many_arguments)]
pub fn watch_set(
    task: Option<&UpstreamTls>,
    iam: Option<&UpstreamTls>,
    project: Option<&UpstreamTls>,
    broker: Option<&Broker>,
    cache_password: Option<&Path>,
    bootstrap_token: Option<&Path>,
    config: &Configuration,
    gateway_config: &GatewayDocument,
) -> Inputs {
    Inputs::of(
        SERVICE,
        &[
            &task,
            &iam,
            // THE THIRD UPSTREAM (ledger 881), IN THE SAME POSITION ITS DIAL
            // TAKES. It is `None` on every deployment today — no module serves
            // TLS yet, and TLS is opt-in per upstream so the three can be cut
            // over one at a time — and `Option<M>: Material` folds an absent one
            // to nothing. What it buys on the day the cut-over reaches
            // `project`: a rotated bundle for that hop ends this process exactly
            // as a rotated `task` bundle does, rather than being the one upstream
            // whose rotation is silent.
            &project,
            &broker,
            &cache_password,
            &bootstrap_token,
            config,
            gateway_config,
        ],
    )
}
