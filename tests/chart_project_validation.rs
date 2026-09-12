//! The chart ships `counting`, and this is where that stops being a comment.
//!
//! **THE VALUE IN `chart/values.yaml` IS THE WHOLE OF WHAT PROTECTS THE ESTATE
//! IN THIS RELEASE.** `crate::project::Mode` has no compiled-in default
//! (ADR-0569), so the mode is whatever the chart renders — and ledger 829 records
//! 18 of 19 repositories unregistered, so a chart that rendered `enforcing`
//! refuses essentially every call in the estate. Nothing in the Rust tests can
//! see that edit: every one of them names its mode explicitly, which is correct
//! for what they assert and is exactly why the shipped VALUE needs its own
//! assertion.
//!
//! **THE FLIP IS MEANT TO BE A ONE-LINE CHANGE, and this test is the line that
//! argues with it.** Reddening here is the intended behaviour of a deliberate
//! flip: whoever performs it reads the gate in `plans/project-validation.md`,
//! changes the value, and changes this literal in the same pull request. What the
//! test prevents is the flip arriving as a side effect of something else — a
//! values reshuffle, a merge resolution, a copied block.
//!
//! **THE LITERAL IS SPELLED HERE (ADR-0599).** Comparing the chart against
//! `crate::project::Mode::Counting`'s own parse would pass through any rename of
//! the word, and the word is an interface: the deployment renders it and the
//! binary parses it.

use std::path::PathBuf;

/// The value of a scalar nested one level under a top-level key.
///
/// **ANCHORED, AND A MISSING KEY PANICS.** Both rules are
/// `tests/chart_grace_period.rs`'s and for its reasons: the keys below are also
/// NAMED in the prose above their own definitions, so a search that merely
/// contains the key reads a number out of English — and a parse that answered a
/// fallback when it found nothing would pass after somebody deleted the field,
/// which is the silence this file exists to break.
fn nested_scalar(parent: &str, key: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/values.yaml");
    let values = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));

    let mut inside = false;
    let mut found: Vec<String> = Vec::new();
    for line in values.lines() {
        if let Some(rest) = line.strip_prefix(parent) {
            // A TOP-LEVEL KEY ENDS THE PREVIOUS MAP. `parent:` with nothing after
            // it opens ours; any other unindented key closes it.
            inside = rest.starts_with(':');
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('#') && !line.trim().is_empty() {
            inside = false;
        }
        if !inside {
            continue;
        }
        if let Some(rest) = line
            .trim_start()
            .strip_prefix(key)
            .and_then(|r| r.strip_prefix(':'))
        {
            found.push(
                rest.split('#')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        }
    }

    assert_eq!(
        found.len(),
        1,
        "expected exactly one `{key}:` under `{parent}:` in {}, found {}: {found:?}",
        path.display(),
        found.len()
    );
    found.remove(0)
}

/// **THE SHIPPED MODE IS `counting`, WHICH REFUSES NOBODY.**
///
/// If this reds and you did not mean to flip enforcement, the chart has been
/// changed under you. If you DID mean to flip it: read
/// `plans/project-validation.md`'s three-legged gate first — one probe per reason
/// class observed to move its own counter before the window opens, then a window
/// over which `yadgar_gateway_project_refusal_total` increases by zero while
/// `yadgar_gateway_project_resolution_total` increases by more than zero — and
/// change this literal in the same pull request that changes the value.
#[test]
fn the_chart_ships_the_counting_mode_and_refuses_nobody() {
    assert_eq!(
        nested_scalar("projectValidation", "mode"),
        "counting",
        "the chart's project-validation mode moved. `counting` is the only value that refuses \
         nobody, and with the registry as seeded today `enforcing` refuses essentially every \
         call in the estate (ledger 829)"
    );
}

/// The cadence is a whole number of seconds greater than zero, which is what the
/// binary will accept.
///
/// A chart that rendered `0`, an empty value or a word would be refused at boot
/// by `crate::project::poll_from_lookup` — correctly, and after the rollout has
/// already started. This is the same check, before the image moves.
#[test]
fn the_chart_renders_a_load_cadence_this_binary_accepts() {
    let rendered = nested_scalar("projectValidation", "registryPollSeconds");
    let seconds: u64 = rendered.parse().unwrap_or_else(|why| {
        panic!("`projectValidation.registryPollSeconds: {rendered}` must be a number: {why}")
    });
    assert!(
        seconds > 0,
        "a load every zero seconds is a busy loop against `project`, and the binary refuses to \
         boot on it (ADR-0569)"
    );

    // THROUGH THE BINARY'S OWN PARSE, because agreeing with the number is not the
    // same as being accepted by the reader: the chart's value is an INPUT to
    // `poll_from_lookup`, and this is the one place both halves are in scope.
    assert_eq!(
        yadgar_gateway::project::poll_from_lookup(|_| Some(rendered.clone()))
            .expect("the chart's cadence must be one this binary accepts")
            .as_secs(),
        seconds
    );
}

/// The registry hop is configured, and its port is the one `project` serves.
///
/// A `PROJECT_PORT` naming a port nothing listens on is not a boot failure — the
/// dial is lazy — so the symptom would be a registry that never loads on a
/// cluster where everything is deployed and healthy.
#[test]
fn the_chart_points_at_the_port_project_serves() {
    assert_eq!(nested_scalar("project", "host"), "project");
    assert_eq!(
        nested_scalar("project", "port"),
        "50051",
        "`project`'s own chart serves 50051; a mismatch here is a registry that never loads on \
         a cluster with nothing wrong with it"
    );
}
