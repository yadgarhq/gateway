//! The loaded registry: what `ListProjects` answered, and the gauge that says
//! whether it ever answered at all.
//!
//! **THE SET IS LOADED, NOT ASKED PER REQUEST.**
//! `plans/project-registry-callers.md` §2 rules this and gives the argument:
//! resolve-upward's COMMON case is an unregistered child, a demand-filled row
//! cache cannot hold an absence, so a cache would cost a round trip on exactly
//! the case that happens most and would have nothing to invalidate when the
//! answer changed. `ListProjects` is therefore the hot-path verb and
//! `ResolveProject` is the fallback — the opposite of what their names suggest.
//!
//! **THE LOAD IS A LOOP UNTIL THE TOKEN IS EMPTY.** The store pages by BYTES
//! rather than by count (D56), and a caller that took the first page would hold
//! a registry silently truncated at one page — every project past the boundary
//! would then resolve to an ancestor instead of to itself, which is the soft
//! failure the taxonomy exists to make visible, arriving from the loader.
//!
//! **BOOT, SERVE, RETRY (ADR-0674).** A gateway whose load fails still boots and
//! still serves: login, enrolment and health need no project at all, and
//! crash-looping on an absent twin spends the restart budget without changing
//! anything — the six-crash-loop shape ADR-0532 measured and removed. So
//! [`Registry::start`] returns immediately and the load happens behind it.
//!
//! **THE GAUGE IS PUBLISHED FROM BOOT, NOT FROM THE LOOP.** Ledger 601 is the
//! precedent and `crate::invalidate::start` is the shipped form of the fix: a
//! gauge published only where it succeeds makes "never loaded" and "never
//! scraped" the same observation, and a gauge published only inside the poll
//! loop is ABSENT for the whole first interval — which is precisely the window
//! an operator is looking at it for.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tonic::transport::Channel;

use crate::pb::yadgar::project::v1::{
    project_service_client::ProjectServiceClient, ProjectServiceListProjectsRequest,
};

use super::classify::Registered;

/// Whether this replica has EVER loaded the registry: `1` after the first
/// successful load, `0` before it.
///
/// **"EVER", NOT "CURRENTLY", and the difference is what an operator needs.** A
/// reload that fails after a successful one leaves the previous set in place and
/// every claim still resolves against it, so the gateway is not degraded and
/// saying so would send somebody hunting an outage that is not happening. What
/// this series distinguishes is the ONE state in which no claim can be checked
/// at all.
pub const LOADED: &str = "yadgar_gateway_project_registry_loaded";

/// How long one `ListProjects` page may take before the load is abandoned and
/// retried.
///
/// A bound rather than a knob: it is the same 5 seconds `attest` allows one
/// credential lookup, sized for an upstream that is SLOW rather than one that is
/// expensive, and nothing about a deployment changes what a stalled page should
/// cost a background task.
const PAGE_DEADLINE: Duration = Duration::from_secs(5);

/// The environment variable naming the load cadence, in seconds.
pub const POLL: &str = "YADGAR_PROJECT_REGISTRY_POLL_SECONDS";

/// ONE cadence, serving two jobs, and ADR-0674 names only the first.
///
/// The ADR requires a retry cadence: a gateway whose load failed asks again.
/// The same interval is also what REFRESHES a set that loaded successfully, and
/// that second job is not a liberty taken with the ruling — it is forced by two
/// facts. `project` publishes no registry-change event yet
/// (`project.proto`: "Only the first of the three is in this release"), so a
/// load is the only way a newly registered project becomes resolvable. And the
/// refusal counter is what GATES the enforcement flip, so a counter computed
/// against the registry as it was at boot would go on counting every repository
/// seeded since — making the gate unreadable until somebody restarted every
/// pod, for a reason nothing would explain.
///
/// # Errors
///
/// Absent, empty, not a whole number of seconds, or zero. No compiled-in
/// default (ADR-0569).
/// The same cadence, from this process's environment.
///
/// # Errors
///
/// See [`poll_from_lookup`], which this is.
pub fn poll_from_env() -> Result<Duration, RetryError> {
    poll_from_lookup(|key| std::env::var(key).ok())
}

pub fn poll_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Duration, RetryError> {
    let raw = lookup(POLL).ok_or(RetryError::Absent)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RetryError::Empty);
    }
    let seconds: u64 = trimmed.parse().map_err(|source| RetryError::Unparsable {
        value: trimmed.to_string(),
        source,
    })?;
    if seconds == 0 {
        return Err(RetryError::Zero);
    }
    Ok(Duration::from_secs(seconds))
}

/// A cadence this deployment did not state, or stated unusably.
#[derive(Debug, thiserror::Error)]
pub enum RetryError {
    #[error(
        "{POLL} is not set. It is how often this gateway asks `project` for the registered set — \
         the retry after a failed load and the refresh after a successful one. There is no \
         compiled-in default (ADR-0569): an interval nobody chose decides how long a newly \
         registered project stays unresolvable, and how hard an unreachable `project` is \
         hammered."
    )]
    Absent,

    #[error("{POLL} is set and has no value. That is different from being absent and is reported separately.")]
    Empty,

    #[error("{POLL} is {value:?}, which is not a whole number of seconds.")]
    Unparsable {
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "{POLL} is 0. A load every zero seconds is a busy loop against `project`, so it is \
         refused rather than read as \"never\" or \"as fast as possible\"."
    )]
    Zero,
}

/// Every registered path and alias, folded for comparison.
///
/// **LIVE PATHS AND ALIASES IN ONE SET, and the contract requires it rather than
/// permitting it.** `RegisteredPath`'s own comment: a rename is an ALIAS and
/// never a rewrite (D53), so a walk over live paths alone would strand every
/// descendant of a renamed parent — the rewrite the alias exists to avoid,
/// arriving as a resolution failure. The store binds its chain against both, and
/// this is the same walk.
///
/// **STATUS IS NOT FILTERED, AND MUST NOT BE.** Same comment: the store's
/// resolution walks live paths and aliases without consulting status, so a
/// caller that dropped archived rows would resolve a candidate to a DIFFERENT
/// ancestor than the fallback rpc resolves it to — two answers for one path,
/// differing only in which route the caller took.
pub struct Loaded {
    /// Keyed on the LOWERCASED path, valued with the spelling the tier answered.
    ///
    /// Folded once here rather than on both sides of every comparison, because
    /// every comparison in the store's walk folds ASCII case and this one must
    /// stay the same comparison. The VALUE is kept because the resolved path a
    /// later release stamps is the row's spelling and not the caller's — the
    /// same answer `ProjectDbService.ResolveProject` gives.
    folded: BTreeMap<String, String>,
}

impl Loaded {
    /// The set, from whatever spellings the tier answered with.
    pub fn from_paths(paths: impl IntoIterator<Item = String>) -> Self {
        Self {
            folded: paths
                .into_iter()
                // THE BARE RESERVED SEGMENT IS DROPPED HERE TOO. The tier
                // already refuses to emit it, so this is the second half of a
                // guard neither half closes alone — and the walk in
                // `super::classify` drops it a third time, from the CANDIDATE's
                // chain. A row at `local` is the nearest registered ancestor of
                // every private path in the estate, so the cost of one
                // redundant check is nothing beside what it prevents.
                .filter(|p| !p.eq_ignore_ascii_case("local"))
                .map(|p| (p.to_ascii_lowercase(), p))
                .collect(),
        }
    }

    /// How many paths this replica resolved against, for the boot line.
    pub fn len(&self) -> usize {
        self.folded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.folded.is_empty()
    }
}

impl Registered for Loaded {
    fn registered_as(&self, path: &str) -> Option<String> {
        self.folded.get(&path.to_ascii_lowercase()).cloned()
    }
}

/// The loaded set as the request path sees it: present, or never loaded.
#[derive(Clone)]
pub struct Registry {
    current: Arc<RwLock<Option<Arc<Loaded>>>>,
}

impl Registry {
    /// A registry that has never loaded and never will.
    ///
    /// The state ADR-0674 describes, and the one every test that does not care
    /// about resolution should be in.
    ///
    /// **IT PUBLISHES NO GAUGE**, unlike [`Self::start`]: this constructs a
    /// value rather than beginning a load, and a test process that published
    /// `0` from a constructor would make the boot-publish assertion pass
    /// without a boot.
    pub fn never_loaded() -> Self {
        Self {
            current: Arc::new(RwLock::new(None)),
        }
    }

    /// A registry holding exactly these paths, loaded.
    ///
    /// For tests and for nothing else — the shipped binary reaches its set
    /// through [`Self::start`].
    pub fn loaded_with(paths: impl IntoIterator<Item = String>) -> Self {
        Self {
            current: Arc::new(RwLock::new(Some(Arc::new(Loaded::from_paths(paths))))),
        }
    }

    /// Publish the gauge, start loading behind this call, and return.
    ///
    /// **NOTHING IS AWAITED, AND THE BOOT IS NOT GATED (ADR-0674).** An
    /// unreachable `project` must not become a gateway that never listens:
    /// that converts one absent dependency into a total front-door outage — no
    /// login, no health — and a pod stuck in startup is one D68's autoscaler
    /// cannot help. The degraded window is observable instead, through [`LOADED`].
    pub fn start(project: Channel, poll: Duration) -> Self {
        // BEFORE THE FIRST DIAL AND BEFORE ANYTHING CAN FAIL. See [`LOADED`]: a
        // gauge that appeared only on success, or only on the loop's first
        // tick, would make a replica that has never loaded indistinguishable
        // from one nobody scraped.
        metrics::gauge!(LOADED).set(0.0);

        let registry = Self::never_loaded();
        tokio::spawn(run(project, poll, registry.clone()));
        registry
    }

    /// The set to resolve against, or `None` while none has ever loaded.
    pub fn loaded(&self) -> Option<Arc<Loaded>> {
        self.current
            .read()
            // A POISONED LOCK IS TREATED AS AN UNLOADED REGISTRY rather than
            // panicking the request that found it. Nothing between these two
            // guards can panic — the only writer replaces one `Arc` — so this
            // arm is unreachable by construction, and the honest unreachable
            // answer is the degraded one rather than a crash on the hot path.
            .ok()
            .and_then(|held| held.clone())
    }

    fn install(&self, loaded: Loaded) {
        if let Ok(mut held) = self.current.write() {
            *held = Some(Arc::new(loaded));
        }
    }
}

/// Load, then keep loading at the stated cadence.
///
/// Each arm is its own function, and not only for the complexity gate: what to do
/// with a set that loaded and what to say about one that did not are different
/// decisions, and the second one turns on a state the first one changes.
async fn run(project: Channel, poll: Duration, registry: Registry) {
    loop {
        match load(&project).await {
            Ok(paths) => install(&registry, paths),
            Err(e) => report(&registry, &e, poll),
        }
        tokio::time::sleep(poll).await;
    }
}

/// Install a freshly loaded set, and publish the gauge for it.
fn install(registry: &Registry, paths: Vec<String>) {
    let loaded = Loaded::from_paths(paths);
    let count = loaded.len();
    let first = registry.loaded().is_none();
    registry.install(loaded);
    // AFTER THE SET IS INSTALLED, never before: a gauge saying the registry is
    // loaded while the request path still answers `None` is a window in which the
    // instrument disagrees with the service.
    metrics::gauge!(LOADED).set(1.0);
    if first {
        tracing::info!(
            paths = count,
            "the project registry is loaded; claimed workspaces resolve against it"
        );
    } else {
        tracing::debug!(paths = count, "the project registry was refreshed");
    }
}

/// Say what a failed load means, which depends on whether a set is already held.
///
/// **TWO SEVERITIES FOR TWO CONDITIONS.** With no set, no scoped claim can be
/// checked at all on this replica. With a stale one, everything still resolves and
/// only a recent registration is missing — and reporting that as an error would
/// send somebody hunting an outage that is not happening.
fn report(registry: &Registry, e: &tonic::Status, poll: Duration) {
    if registry.loaded().is_none() {
        tracing::error!(
            error = %e,
            retry_secs = poll.as_secs(),
            "the project registry has NEVER loaded, so no claimed workspace can be checked on \
             this replica (ADR-0674). Unscoped surfaces — login, enrolment, health — are \
             unaffected."
        );
    } else {
        tracing::warn!(
            error = %e,
            retry_secs = poll.as_secs(),
            "the project registry could not be refreshed; the previously loaded set stays in \
             force"
        );
    }
}

/// One whole load: every page, until the token comes back empty.
async fn load(project: &Channel) -> Result<Vec<String>, tonic::Status> {
    let mut client = ProjectServiceClient::new(project.clone());
    let mut out = Vec::new();
    let mut token = String::new();
    loop {
        let request = ProjectServiceListProjectsRequest {
            // NO NUMBER, because this caller has none to state. The page a
            // caller can be given is derived from BYTES rather than declared as
            // a count (D56), and inventing a size here would be inventing a
            // configuration value nobody chose — see the field's own comment.
            page_size: 0,
            page_token: token.clone(),
        };
        let rpc = client.list_projects(request);
        let page = match tokio::time::timeout(PAGE_DEADLINE, rpc).await {
            Ok(answer) => answer?.into_inner(),
            Err(_elapsed) => {
                return Err(tonic::Status::deadline_exceeded(format!(
                    "ListProjects did not answer within {}s",
                    PAGE_DEADLINE.as_secs()
                )))
            }
        };
        for registered in page.paths {
            out.push(registered.path);
            out.extend(registered.aliases);
        }
        if page.next_page_token.is_empty() {
            return Ok(out);
        }
        // A TOKEN THAT DOES NOT MOVE ENDS THE LOAD, and it ends it as a
        // FAILURE. The loop's termination otherwise depends on the server's
        // good behaviour, and the failure mode is a background task allocating
        // for ever against one unchanging page — which reads as a memory leak
        // in this gateway rather than as a defect in the tier.
        if page.next_page_token == token {
            return Err(tonic::Status::internal(
                "ListProjects returned the same next_page_token twice, so the load would not \
                 terminate",
            ));
        }
        token = page.next_page_token;
    }
}
