//! Every gRPC upstream this chart dials serves the MODULE port, and no store's.
//!
//! **LEDGER 890: `project.port` SHIPPED AS `50051`, WHICH IS `project-db`'s.**
//! `svc/project` serves `50052`; `svc/project-db` serves `50051`. The dial is lazy
//! and `project` resolves, so nothing failed to boot and nothing was unhealthy:
//! the gateway logged `project channel ready`, every connection attempt against a
//! `project` pod was refused, and the registry never loaded. That made ledger
//! 881's whole chain inert on a cluster where `helm` and Argo both reported
//! everything fine, and the one instrument that would have said so —
//! `yadgar_gateway_project_registry_loaded` — was absent from the scrape for the
//! separate reason ADR-0677 rules on.
//!
//! **A TEST ALREADY PINNED THIS VALUE, AND PINNED IT WRONG.**
//! `tests/chart_project_validation.rs` asserted the bare literal `50051` with a
//! comment reading "`project`'s own chart serves 50051". It was green for as long
//! as the defect shipped. That is what a bare literal buys: it pins whatever the
//! author believed, and it restates the value it is meant to be checking, so the
//! copy-paste that produced the wrong number produces the wrong assertion too.
//!
//! **SO THIS FILE ENCODES THE CONVENTION INSTEAD, OVER EVERY UPSTREAM.** In this
//! estate a MODULE's gRPC service serves `50052` and only a `-db` store serves
//! `50051`. `task` and `iam` already embody it in this same file, and they are the
//! hops that work. Checking all of them, rather than the one that broke, is what
//! makes the next block copied from a store's values red here rather than in
//! production.
//!
//! **WHAT IT CANNOT DO, stated rather than left to be found.** Nothing in this
//! repository can read `project`'s own chart, so this asserts AGREEMENT WITH A
//! CONVENTION and not agreement with the server. A module that moved its own port
//! would leave this green. The cross-repository guard belongs where both halves are
//! in scope — `yadgarhq/config` — and is not this test.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// The port every module's gRPC service serves in this estate.
const MODULE_GRPC: &str = "50052";

/// The port every `-db` store serves. The value ledger 890 shipped.
const STORE_GRPC: &str = "50051";

/// Every top-level block carrying BOTH a `host:` and a `port:` — this chart's
/// spelling of "a service this gateway dials".
///
/// **DISCOVERED RATHER THAN ENUMERATED.** A list of three would be a list a fourth
/// upstream is added beside rather than into. `service:` carries a `port` and no
/// `host`, which is what keeps this gateway's OWN listener out of the set.
///
/// **DIRECT CHILDREN ONLY**, at exactly two spaces: `task.tls` and its twins are
/// nested maps, and one of them naming a `host` later must not be read as a fourth
/// upstream.
fn upstreams() -> BTreeMap<String, (String, String)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/values.yaml");
    let values = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));

    let mut blocks: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut block: Option<String> = None;

    for line in values.lines() {
        let unindented =
            !line.starts_with(' ') && !line.starts_with('#') && !line.trim().is_empty();
        if unindented {
            // `name:` and nothing else opens a block; any other unindented key —
            // `replicaCount: 2`, `preStopSleepSeconds: 5` — closes the previous one.
            block = line
                .strip_suffix(':')
                .filter(|name| !name.contains(' '))
                .map(str::to_string);
            continue;
        }
        let Some(name) = block.as_deref() else {
            continue;
        };
        // EXACTLY TWO SPACES. Deeper is a nested map; a comment at this depth is
        // prose that happens to contain a colon.
        let Some(child) = line.strip_prefix("  ") else {
            continue;
        };
        if child.starts_with(' ') || child.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, rest)) = child.split_once(':') else {
            continue;
        };
        let value = rest
            .split('#')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_string();
        blocks
            .entry(name.to_string())
            .or_default()
            .insert(key.trim().to_string(), value);
    }

    blocks
        .into_iter()
        .filter_map(|(name, children)| {
            let host = children.get("host")?.clone();
            let port = children.get("port")?.clone();
            Some((name, (host, port)))
        })
        .collect()
}

/// **THE THREE KNOWN UPSTREAMS ARE FOUND, so nothing below passes vacuously.**
///
/// A parser that matched no block would make every assertion in this file true of
/// an empty set — "passed, having checked nothing", which is the failure the
/// `actionlint` hook in `.pre-commit-config.yaml` already argues against at
/// length. If this reds because an upstream was RENAMED, rename it here; if it
/// reds because one was removed, delete it here in the same pull request.
#[test]
fn every_upstream_this_chart_dials_is_discovered() {
    let found = upstreams();
    for expected in ["task", "iam", "project"] {
        assert!(
            found.contains_key(expected),
            "`{expected}:` is no longer a top-level block with a `host:` and a `port:` in \
             chart/values.yaml — found {:?}. This file can only check upstreams it discovers",
            found.keys().collect::<Vec<_>>()
        );
    }
}

/// **EVERY UPSTREAM SERVES THE MODULE PORT, AND NONE SERVES A STORE'S.**
///
/// The gateway reaches no module's database (D4), so a `50051` in this file is
/// always a block copied from a store's values — which is what ledger 890 was. The
/// symptom is not a failed boot: the dial is lazy, the name resolves, the pod is
/// Ready, Argo is Healthy, and every connection to the port is refused.
///
/// If a module genuinely moves its gRPC port, this test reds and it should: change
/// `MODULE_GRPC` and that module's chart in the same release, never one of them.
#[test]
fn no_upstream_points_at_a_store_port() {
    let found = upstreams();
    assert!(!found.is_empty(), "no upstream was discovered at all");

    for (name, (host, port)) in found {
        assert!(
            !host.is_empty(),
            "`{name}.host` is empty, so `{name}.port` is a port on nothing"
        );
        assert_ne!(
            port, STORE_GRPC,
            "`{name}.port: {STORE_GRPC}` is `{name}-db`'s port, not `{name}`'s. Every module's \
             gRPC service in this estate serves {MODULE_GRPC} and only a `-db` store serves \
             {STORE_GRPC}; the gateway reaches no module's database (D4). The dial is lazy, so \
             this ships as a pod that is Ready with an upstream that refuses every connection \
             (ledger 890)"
        );
        assert_eq!(
            port, MODULE_GRPC,
            "`{name}.port: {port}` is not the port a module's gRPC service serves in this \
             estate. If `{name}` really moved, change MODULE_GRPC and that module's chart \
             together"
        );
    }
}
