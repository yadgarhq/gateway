use super::*;

/// The tool set, WRITTEN OUT HERE and never derived from the code under
/// test. A test that read `SERVED` to check `SERVED` would agree with any
/// value it was given, including one an administrative verb had been added
/// to — which is the whole failure ADR-0492 is defended against.
const EXPECTED: [&str; 5] = [
    "create_task",
    "read_task",
    "find_tasks",
    "edit_task",
    "transition_task",
];

fn sorted(names: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    out.sort_unstable();
    out
}

#[test]
fn the_served_set_is_exactly_the_five_task_tools() {
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

/// LEDGER 1281, ADR-0569: no second default. `task-db`'s `DEFAULT_PAGE` is the
/// one place an unspecified page size is decided; this gateway forwards `0`
/// rather than compiling in its own `20`.
#[test]
fn an_absent_page_size_forwards_zero_rather_than_a_compiled_in_default() {
    // MUTATION THIS CATCHES: `unwrap_or(20)` (or any other nonzero literal)
    // reappearing at the call site.
    assert_eq!(requested_page_size(&json!({})), 0);
    assert_eq!(requested_page_size(&json!({ "page_token": "next" })), 0);
}

/// An explicit `0` is indistinguishable from absence, which is the point: both
/// forward as `0` and `task-db` decides what that means.
#[test]
fn an_explicit_zero_page_size_forwards_as_zero() {
    assert_eq!(requested_page_size(&json!({ "page_size": 0 })), 0);
}

/// A caller-supplied page size still arrives unchanged.
#[test]
fn a_requested_page_size_forwards_unchanged() {
    assert_eq!(requested_page_size(&json!({ "page_size": 7 })), 7);
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
fn the_three_writes_are_writes_and_the_two_reads_are_not() {
    // `kind_of` feeds BOTH `CallRecord.kind` and D74's bucket key, so an edit
    // or a transition read as a READ would spend the read bucket and report
    // as read traffic. Literal names, not the constants, for the reason
    // `EXPECTED` gives.
    for name in ["create_task", "edit_task", "transition_task"] {
        assert!(is_write(name), "{name} writes");
    }
    for name in ["read_task", "find_tasks"] {
        assert!(!is_write(name), "{name} only reads");
    }
}

/// Call `name` against a channel that NEVER DIALS, and return the refusal.
///
/// A refusal of the caller's arguments must come before any upstream is
/// touched; `connect_lazy` to a closed port turns a dispatch into an
/// `Upstream` error, which the assertions below would reject.
async fn refusal(name: &str, args: Value) -> ToolError {
    let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
    match call(channel, Scope::default(), name, &args).await {
        Ok(_) => panic!("{name} with {args} must be refused"),
        Err(err) => err,
    }
}

#[tokio::test]
async fn edit_task_refuses_a_call_missing_what_it_requires() {
    // The same answer `create_task` gives for a missing `title`: a
    // `ToolError::Invalid`, which the HTTP layer renders as `isError: true`.
    for args in [
        // No id.
        json!({ "expect_version": 3, "title": "t" }),
        // No version. Upstream, 0 is a version no row holds, not a wildcard,
        // so defaulting it would turn a caller error into an opaque
        // FAILED_PRECONDITION.
        json!({ "id": "yadgar:task:x", "title": "t" }),
        // Neither field to write. An empty mask means "every editable field"
        // to `task`, so sending one would blank the body.
        json!({ "id": "yadgar:task:x", "expect_version": 3 }),
        // A field of the wrong type is not a field that was sent.
        json!({ "id": "yadgar:task:x", "expect_version": 3, "title": 7 }),
    ] {
        let err = refusal("edit_task", args.clone()).await;
        assert!(
            matches!(err, ToolError::Invalid(_)),
            "{args} must be refused as the caller's error, got {err:?}"
        );
    }
}

#[tokio::test]
async fn transition_task_refuses_a_call_missing_what_it_requires() {
    for args in [
        json!({ "expect_version": 3, "to": "done" }),
        json!({ "id": "yadgar:task:x", "to": "done" }),
        json!({ "id": "yadgar:task:x", "expect_version": 3 }),
        // Not a status at all.
        json!({ "id": "yadgar:task:x", "expect_version": 3, "to": "finished" }),
        // A status, but the proto's zero value, which is no target.
        json!({ "id": "yadgar:task:x", "expect_version": 3, "to": "unspecified" }),
        // The wire spelling is not the tool's spelling.
        json!({ "id": "yadgar:task:x", "expect_version": 3, "to": "TASK_STATUS_DONE" }),
    ] {
        let err = refusal("transition_task", args.clone()).await;
        assert!(
            matches!(err, ToolError::Invalid(_)),
            "{args} must be refused as the caller's error, got {err:?}"
        );
    }
}

#[test]
fn the_transition_schema_offers_exactly_the_statuses_a_task_can_move_to() {
    // The enum a client builds its picker from, WRITTEN OUT. `unspecified` is
    // the proto's zero value and is no target, so it must not be offered.
    let catalogue = definitions();
    let transition = catalogue
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "transition_task")
        .expect("transition_task is advertised");
    assert_eq!(
        transition["inputSchema"]["properties"]["to"]["enum"],
        json!(["open", "in_progress", "blocked", "done", "dropped"])
    );
    assert_eq!(
        transition["inputSchema"]["required"],
        json!(["id", "expect_version", "to"])
    );
}

#[test]
fn the_edit_schema_requires_the_id_and_the_version_it_compares_against() {
    let catalogue = definitions();
    let edit = catalogue
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "edit_task")
        .expect("edit_task is advertised");
    assert_eq!(
        edit["inputSchema"]["required"],
        json!(["id", "expect_version"])
    );
    for field in ["title", "body"] {
        assert_eq!(edit["inputSchema"]["properties"][field]["type"], "string");
    }
}

/// The refusal's MESSAGE, for the tests that pin which one a caller gets.
async fn refusal_message(name: &str, args: Value) -> String {
    match refusal(name, args.clone()).await {
        ToolError::Invalid(msg) => msg,
        other => panic!("{args} must be refused as the caller's error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_missing_field_and_a_mistyped_one_are_told_apart() {
    // "is required" for a field that is not there, a type complaint for one
    // that is. A caller told `id` is required when it sent `id: 7` looks for
    // a spelling mistake that is not there.
    for (tool, args, expected) in [
        (
            "edit_task",
            json!({ "expect_version": 3, "title": "t" }),
            "`id` is required",
        ),
        (
            "edit_task",
            json!({ "id": 7, "expect_version": 3, "title": "t" }),
            "`id` must be a string",
        ),
        (
            "edit_task",
            json!({ "id": "yadgar:task:x", "title": "t" }),
            "`expect_version` is required",
        ),
        (
            "edit_task",
            json!({ "id": "yadgar:task:x", "expect_version": "3", "title": "t" }),
            "`expect_version` must be a non-negative integer",
        ),
        (
            "transition_task",
            json!({ "id": "yadgar:task:x", "expect_version": -1, "to": "done" }),
            "`expect_version` must be a non-negative integer",
        ),
        (
            "transition_task",
            json!({ "id": "yadgar:task:x", "expect_version": 3 }),
            "`to` is required",
        ),
        (
            "transition_task",
            json!({ "id": "yadgar:task:x", "expect_version": 3, "to": 4 }),
            "`to` must be a string",
        ),
    ] {
        let msg = refusal_message(tool, args.clone()).await;
        assert_eq!(msg, expected, "{tool} {args}");
    }
}

#[tokio::test]
async fn edit_task_refuses_a_status_change_and_names_the_tool_that_makes_one() {
    // A caller who sends a status to `edit_task` must not get a title-only
    // SUCCESS and believe the status moved too.
    for key in ["status", "to"] {
        let mut args = json!({ "id": "yadgar:task:x", "expect_version": 3, "title": "t" });
        args[key] = json!("done");
        let msg = refusal_message("edit_task", args).await;
        assert!(
            msg.contains("transition_task"),
            "`{key}` must be refused with a pointer to transition_task, got {msg:?}"
        );
    }
}

#[tokio::test]
async fn an_edit_whose_fields_are_all_null_has_nothing_to_edit() {
    // Null is ABSENT, as `create_task` reads it. So an all-null edit is an
    // empty edit, and must hit the same refusal rather than clearing both.
    let msg = refusal_message(
        "edit_task",
        json!({ "id": "yadgar:task:x", "expect_version": 3, "title": null, "body": null }),
    )
    .await;
    assert!(msg.contains("nothing to edit"), "got {msg:?}");
}
