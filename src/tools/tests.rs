use super::*;

/// The tool set, WRITTEN OUT HERE and never derived from the code under
/// test. A test that read `SERVED` to check `SERVED` would agree with any
/// value it was given, including one an administrative verb had been added
/// to — which is the whole failure ADR-0492 is defended against.
const EXPECTED: [&str; 3] = ["create_task", "read_task", "find_tasks"];

fn sorted(names: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    out.sort_unstable();
    out
}

#[test]
fn the_served_set_is_exactly_the_three_task_tools() {
    // DIRECTION 1, AND THE GATE THE OTHER THREE REST ON. `label_for`,
    // `module_for`, `definitions` and `call` all consult `SERVED` before
    // they do anything else, so this is the one place a fourth tool can be
    // introduced — and ADR-0492 rules that an administrative verb is never
    // one of them.
    assert_eq!(
        sorted(&SERVED),
        sorted(&EXPECTED),
        "ADR-0492: the served tool set changed. An administrative verb is \
         NEVER an MCP tool — if this is a legitimate new tool, change the \
         literal in this test deliberately"
    );
}

#[test]
fn the_catalogue_advertises_exactly_the_served_set() {
    // DIRECTION 2 — ADVERTISEMENT. `definitions()` derives its name list
    // from `SERVED`, so this catches a catalogue that drifted from the
    // membership authority.
    let catalogue = definitions();
    let advertised: Vec<&str> = catalogue
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        sorted(&advertised),
        sorted(&EXPECTED),
        "ADR-0492: tools/list advertises a set other than the one this test \
         pins"
    );
}

#[tokio::test]
async fn call_refuses_a_name_outside_the_served_set() {
    // DIRECTION 4, AND ADR-0492'S ACTUAL PROPERTY: CALLABILITY. The
    // catalogue governs what `tools/list` advertises and nothing else, so a
    // verb wired into dispatch but left out of `definitions()` would be
    // callable and invisible. This asserts the refusal instead.
    //
    // `connect_lazy` never dials — the refusal must come before any upstream
    // is touched, and a test that needed a live task service could not prove
    // that.
    //
    // WHAT THIS DOES NOT DISTINGUISH: whether the `SERVED` guard refused or
    // the `other =>` arm at the bottom of the `match` did. Both satisfy
    // "never a dispatch", so the assertion is correct either way — but it is
    // not evidence that the guard is what fired. See the note at the guard
    // sites.
    let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
    // `match` rather than `expect_err`, because `Output` carries a
    // `serde_json::Value` and is not `Debug` — and adding a derive to
    // production code so a test can phrase itself more tidily is the wrong
    // trade.
    let err = match call(channel, Scope::default(), "admin_create_user", &json!({})).await {
        Ok(_) => panic!("ADR-0492: an administrative verb must never dispatch"),
        Err(err) => err,
    };
    assert!(
        matches!(&err, ToolError::Unknown(name) if name == "admin_create_user"),
        "ADR-0492: expected a refusal by name, got {err:?}"
    );
}

#[test]
fn every_advertised_tool_resolves_to_a_bounded_label() {
    // The list a client is told about and the set the metric layer accepts
    // must be the same set, or a tool works and reports under no label.
    for tool in definitions().as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        assert!(label_for(name).is_some(), "{name} has no bounded label");
    }
}

#[test]
fn an_unknown_tool_gets_no_label() {
    assert!(label_for("../../etc/passwd").is_none());
    assert!(label_for("").is_none());

    // DIRECTION 3. `admin_create_user` is the exact verb ADR-0492's
    // rationale names, and `module_for` is probed beside `label_for`
    // because `tools_call` gates on BOTH — a name that resolved on either
    // one alone would still be refused, but the pair is what the let-else
    // at `http.rs:1051` actually reads.
    for name in EXPECTED {
        assert!(
            label_for(name).is_some(),
            "{name} is served and must have a bounded label"
        );
        assert!(
            module_for(name).is_some(),
            "{name} is served and must have a bounded module"
        );
    }
    assert!(
        label_for("admin_create_user").is_none(),
        "ADR-0492: an administrative verb must never resolve to a tool label"
    );
    assert!(
        module_for("admin_create_user").is_none(),
        "ADR-0492: an administrative verb must never resolve to a tool module"
    );
}

#[test]
fn every_tool_declares_an_object_input_schema() {
    // Required by the spec, and clients drive argument collection from it.
    for tool in definitions().as_array().unwrap() {
        assert_eq!(tool["inputSchema"]["type"], "object", "{}", tool["name"]);
    }
}

#[test]
fn find_tasks_reports_how_many_tasks_it_returned() {
    // MUTATION THIS CATCHES: `Outcome { ..Default::default() }` at the call
    // site, or a `rows: 1` here. `rows_returned` was 0 on every gateway call
    // while the response knew its own length, so D67 could report what a call
    // cost and never how much it fetched.
    use crate::pb::yadgar::task::v1::Task;

    let empty = find_tasks_output(FindTasksResponse::default());
    assert_eq!(empty.rows, 0);

    let three = find_tasks_output(FindTasksResponse {
        tasks: vec![Task::default(), Task::default(), Task::default()],
        next_page_token: "next".into(),
    });
    assert_eq!(three.rows, 3, "the row count is the number of tasks");
    assert_eq!(
        three.content["tasks"].as_array().map(Vec::len),
        Some(3),
        "and it must agree with the payload the caller receives"
    );
}

#[test]
fn every_advertised_tool_belongs_to_a_bounded_module() {
    // The (user, module, kind) key D74 buckets on. A tool with no module
    // could not be limited at all, and the gateway must not serve a tool it
    // cannot key a bucket for.
    for tool in definitions().as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        assert!(module_for(name).is_some(), "{name} has no module");
    }
    assert!(module_for("../../etc/passwd").is_none());
    assert!(module_for("").is_none());
}

#[test]
fn no_module_contains_the_separator_the_bucket_key_is_built_from() {
    // LOAD-BEARING AND OTHERWISE UNASSERTED. `limit::Limiter::check` builds
    // `gw:rl:<user>:<module>:<kind>`, and the key is unambiguous only
    // because every component after the user is drawn from a closed,
    // colon-free set. A module named `a:b` would make
    // `gw:rl:u:a:b:write` and `gw:rl:u:a:b:write` reachable from two
    // different `(module, kind)` pairs, so one pair would spend the other's
    // tokens.
    //
    // The kinds are checked with it: `kind_str` is the other closed set on
    // the same key, and both are cheap to break by adding a variant.
    for tool in definitions().as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        let module = module_for(name).expect("a module");
        assert!(
            !module.contains(':'),
            "{module:?} would make the bucket key ambiguous"
        );
    }
    for kind in [
        yadgar_telemetry::pb::yadgar::telemetry::v1::Kind::Read,
        yadgar_telemetry::pb::yadgar::telemetry::v1::Kind::Write,
        yadgar_telemetry::pb::yadgar::telemetry::v1::Kind::Generate,
    ] {
        let name = crate::limit::kind_str(kind);
        assert!(
            !name.contains(':'),
            "{name:?} would make the bucket key ambiguous"
        );
    }
}

#[test]
fn only_create_is_a_write() {
    assert!(is_write(CREATE_TASK));
    assert!(!is_write(READ_TASK));
    assert!(!is_write(FIND_TASKS));
}
