//! ADR-1019 on the `project` path: both outbound calls state their deadline.
//!
//! `ListProjects` (the registry poll) is sent [`PAGE_DEADLINE`] per page and
//! `ResolveProject` (the refusal's fallback) [`FALLBACK_DEADLINE`], each as
//! `grpc-timeout` less [`DEADLINE_MARGIN`]. Without the header `project` is
//! bounded only by its own ceilings and keeps working on a load or a fallback
//! the gateway has already given up on.

use std::sync::Arc;
use std::time::{Duration, Instant};

use yadgar_dial::DEADLINE_MARGIN;

use super::super::registry::PAGE_DEADLINE;
use super::super::remediate::{self, FALLBACK_DEADLINE};
use super::super::{OrgGrants, Refusal, Registry};
use crate::upstream::hang::{self, Arrival, Seen};
use crate::upstream::Upstream;

/// How far below the stated value the header may read on arrival.
const SLACK: Duration = Duration::from_secs(1);

/// A `project` that never answers, and its arrival log. The ceiling is the
/// chart default, far above either deadline, so a pass cannot come from it.
async fn hanging_project() -> (Upstream, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let channel = hang::serve(hang::Project(Arc::clone(&seen))).await;
    (Upstream::new(channel, Duration::from_secs(30)), seen)
}

fn assert_stated(arrival: &Arrival, rpc: &str, deadline: Duration) {
    assert_eq!(arrival.path, rpc);
    let stated = arrival
        .timeout
        .unwrap_or_else(|| panic!("{rpc} must carry grpc-timeout (ADR-1019)"));
    assert!(
        stated <= deadline - DEADLINE_MARGIN,
        "{rpc} stated {stated:?}; the margin keeps it at or below {:?}",
        deadline - DEADLINE_MARGIN
    );
    assert!(
        stated >= deadline - SLACK,
        "{rpc} stated {stated:?}, far below its {deadline:?} deadline"
    );
}

#[tokio::test]
async fn the_registry_poll_states_its_page_deadline() {
    let (project, seen) = hanging_project().await;
    let _registry = Registry::start(project, Duration::from_secs(3600));
    for _ in 0..200 {
        if !seen.arrivals().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let arrivals = seen.arrivals();
    let first = arrivals.first().expect("the poll reaches project");
    assert_stated(
        first,
        "/yadgar.project.v1.ProjectService/ListProjects",
        PAGE_DEADLINE,
    );
}

/// And the refusal still degrades to the prose it used when the fallback
/// timed out: the caller's 400 does not wait past the deadline.
#[tokio::test]
async fn the_fallback_states_its_deadline_and_degrades_at_it() {
    let (project, seen) = hanging_project().await;
    let started = Instant::now();
    let denied = remediate::compose(
        &project,
        Refusal::under_anchor("yadgarhq"),
        "a-request-id",
        OrgGrants::Counting,
    )
    .await;
    let took = started.elapsed();
    assert!(
        took < FALLBACK_DEADLINE + SLACK,
        "the fallback took {took:?} against {FALLBACK_DEADLINE:?}"
    );
    assert!(
        denied
            .prose
            .contains("the registry could not be reached to name the repository"),
        "a stalled fallback is the degraded sentence: {}",
        denied.prose
    );
    let arrivals = seen.arrivals();
    assert_eq!(
        arrivals.len(),
        1,
        "exactly one ResolveProject reaches project"
    );
    assert_stated(
        &arrivals[0],
        "/yadgar.project.v1.ProjectService/ResolveProject",
        FALLBACK_DEADLINE,
    );
}
