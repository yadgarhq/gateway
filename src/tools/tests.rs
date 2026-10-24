use super::*;
use crate::pb::yadgar::taskapi::v1::FindTasksResponse;

/// The tool set, WRITTEN OUT HERE and never derived from the code under
/// test. A test that read `SERVED` to check `SERVED` would agree with any
/// value it was given, including one an administrative verb had been added
/// to — which is the whole failure ADR-0492 is defended against.
///
/// `list_projects` is team access stage 8's deliberate addition (ADR-0963
/// (8)): a read of the caller's own reach, not an administrative verb.
const EXPECTED: [&str; 6] = [
    "create_task",
    "read_task",
    "find_tasks",
    "edit_task",
    "transition_task",
    "list_projects",
];

fn sorted(names: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    out.sort_unstable();
    out
}

#[test]
fn the_served_set_is_exactly_the_five_task_tools_and_list_projects() {
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
    let channel = TaskUpstream::new(
        tonic::transport::Channel::from_static("http://127.0.0.1:1").connect_lazy(),
        Duration::from_secs(16),
    );
    // `match` rather than `expect_err`, because `Output` carries a
    // `serde_json::Value` and is not `Debug` — and adding a derive to
    // production code so a test can phrase itself more tidily is the wrong
    // trade.
    let err = match call(&channel, Scope::default(), "admin_create_user", &json!({})).await {
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
    assert_eq!(find::requested_page_size(&json!({})), 0);
    assert_eq!(
        find::requested_page_size(&json!({ "page_token": "next" })),
        0
    );
}

/// An explicit `0` is indistinguishable from absence, which is the point: both
/// forward as `0` and `task-db` decides what that means.
#[test]
fn an_explicit_zero_page_size_forwards_as_zero() {
    assert_eq!(find::requested_page_size(&json!({ "page_size": 0 })), 0);
}

/// A caller-supplied page size still arrives unchanged.
#[test]
fn a_requested_page_size_forwards_unchanged() {
    assert_eq!(find::requested_page_size(&json!({ "page_size": 7 })), 7);
}

#[test]
fn find_tasks_reports_how_many_tasks_it_returned() {
    // MUTATION THIS CATCHES: `Outcome { ..Default::default() }` at the call
    // site, or a `rows: 1` here. `rows_returned` was 0 on every gateway call
    // while the response knew its own length, so D67 could report what a call
    // cost and never how much it fetched.
    use crate::pb::yadgar::task::v1::Task;

    let empty = find::output(FindTasksResponse::default(), find::Fields::Full, "");
    assert_eq!(empty.rows, 0);

    let three = find::output(
        FindTasksResponse {
            tasks: vec![Task::default(), Task::default(), Task::default()],
            next_page_token: "next".into(),
        },
        find::Fields::Full,
        "",
    );
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
    let channel = TaskUpstream::new(
        tonic::transport::Channel::from_static("http://127.0.0.1:1").connect_lazy(),
        Duration::from_secs(16),
    );
    match call(&channel, Scope::default(), name, &args).await {
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
        json!(["expect_version", "to"])
    );
}

/// The store refuses a title over 128 code points (task-db migration 7), so
/// both schemas that take a title advertise the same bound, in characters.
/// MUTATION THIS CATCHES: `maxLength` dropped from either schema.
#[test]
fn the_create_and_edit_schemas_bound_the_title_at_128_characters() {
    let catalogue = definitions();
    for name in ["create_task", "edit_task"] {
        let tool = catalogue
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} is advertised"));
        assert_eq!(
            tool["inputSchema"]["properties"]["title"]["maxLength"], 128,
            "{name} must bound `title` at 128"
        );
    }
}

/// ADR-0573: the description is literal text a caller reads, so assert it
/// verbatim. It states the 128 bound the schema enforces.
/// MUTATION THIS CATCHES: the description drifting from the `maxLength`.
#[test]
fn the_create_and_edit_schemas_describe_the_title_bound_in_words() {
    let catalogue = definitions();
    for name in ["create_task", "edit_task"] {
        let tool = catalogue
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} is advertised"));
        assert_eq!(
            tool["inputSchema"]["properties"]["title"]["description"],
            "Short summary of the task, at most 128 characters (Unicode code points); put detail in the body",
            "{name} must describe the `title` bound"
        );
    }
}

#[test]
fn the_edit_schema_requires_the_version_it_compares_against() {
    let catalogue = definitions();
    let edit = catalogue
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "edit_task")
        .expect("edit_task is advertised");
    assert_eq!(edit["inputSchema"]["required"], json!(["expect_version"]));
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
            "`id` or `number` is required",
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

// ---- ledger 1789: find_tasks status filter and summary shape -------------

/// The status filter REACHES the request. It used to be hard-coded to an empty
/// list, which `task-db` reads as every status, so a filter was impossible.
#[test]
fn find_tasks_forwards_the_statuses_the_caller_named() {
    // MUTATION THIS CATCHES: `statuses: Vec::new()` coming back.
    let (req, _) = find::request(
        Scope::default(),
        &json!({ "statuses": ["open", "blocked"] }),
    )
    .unwrap();
    assert_eq!(
        req.statuses,
        vec![TaskStatus::Open as i32, TaskStatus::Blocked as i32]
    );
}

/// Absent, null and `[]` all mean every status — `task-db`'s rule for an empty
/// filter, forwarded rather than re-decided here.
#[test]
fn find_tasks_without_a_filter_sends_an_empty_one() {
    for args in [
        json!({}),
        json!({ "statuses": null }),
        json!({ "statuses": [] }),
    ] {
        let (req, fields) = find::request(Scope::default(), &args).unwrap();
        assert!(req.statuses.is_empty(), "{args}");
        assert_eq!(fields, find::Fields::Full, "{args}");
    }
}

/// An unknown status is a refusal. Dropping it would turn `["opne"]` into an
/// empty filter, which answers with EVERY status and looks like success.
#[tokio::test]
async fn find_tasks_refuses_a_status_it_does_not_know() {
    for args in [
        json!({ "statuses": ["opne"] }),
        json!({ "statuses": ["open", "opne"] }),
        json!({ "statuses": ["unspecified"] }),
        json!({ "statuses": [1] }),
        json!({ "statuses": "open" }),
    ] {
        assert!(
            matches!(
                refusal(FIND_TASKS, args.clone()).await,
                ToolError::Invalid(_)
            ),
            "{args}"
        );
    }
}

#[test]
fn the_find_schema_offers_the_statuses_and_three_shapes() {
    let all = definitions();
    let find = &all[2];
    assert_eq!(find["name"], "find_tasks");
    let props = &find["inputSchema"]["properties"];
    assert_eq!(
        props["statuses"]["items"]["enum"],
        json!(["open", "in_progress", "blocked", "done", "dropped"])
    );
    assert_eq!(props["fields"]["enum"], json!(["full", "summary", "index"]));
    assert_eq!(props["fields"]["default"], "full");
    assert_eq!(props["statuses"]["maxItems"], 5);
}

/// A repeated status is sent ONCE, first occurrence first: `task-db` builds
/// one `?` per entry.
#[test]
fn find_tasks_sends_a_repeated_status_once() {
    // MUTATION THIS CATCHES: the `out.contains` de-duplication removed.
    let (req, _) = find::request(
        Scope::default(),
        &json!({ "statuses": ["blocked", "open", "blocked", "open"] }),
    )
    .unwrap();
    assert_eq!(
        req.statuses,
        vec![TaskStatus::Blocked as i32, TaskStatus::Open as i32]
    );
}

/// More entries than there are statuses is refused, even when every entry is
/// a valid name — the array is bounded before any name is read.
#[tokio::test]
async fn find_tasks_refuses_more_statuses_than_there_are() {
    // MUTATION THIS CATCHES: the `names.len() > TARGETS.len()` check removed
    // (de-duplication would otherwise accept six `open`s as one).
    let args = json!({ "statuses": vec!["open"; 6] });
    let msg = refusal_message(FIND_TASKS, args).await;
    assert!(msg.contains("at most 5"), "{msg}");
    let five = json!({ "statuses": ["open", "in_progress", "blocked", "done", "dropped"] });
    assert!(find::request(Scope::default(), &five).is_ok());
}

/// A refusal names the caller's value BOUNDED: a long string is cut, and a
/// non-string is named by its JSON type, never echoed.
#[tokio::test]
async fn a_status_refusal_does_not_echo_an_unbounded_value() {
    // MUTATION THIS CATCHES: the message formatting the raw `name` again.
    let long = "z".repeat(1000);
    let msg = refusal_message(FIND_TASKS, json!({ "statuses": [long] })).await;
    assert!(msg.len() < 200, "{} bytes: {msg}", msg.len());
    assert!(msg.contains(&"z".repeat(32)), "{msg}");

    let object = json!({ "statuses": [{ "secret": "x".repeat(1000) }] });
    let msg = refusal_message(FIND_TASKS, object).await;
    assert!(
        msg.contains("an object") && !msg.contains("secret"),
        "{msg}"
    );
}

/// LEDGER 1609: the description said "newest first" while `task-db` sorts
/// `ORDER BY id` over UUIDv7 ids — ascending, so oldest first.
#[test]
fn the_find_description_states_the_order_task_db_returns() {
    let all = definitions();
    let find = &all[2];
    let text = find["description"].as_str().unwrap();
    assert!(text.contains("oldest first"), "{text}");
    assert!(!text.contains("newest first"), "{text}");
}

fn a_full_task() -> crate::pb::yadgar::task::v1::Task {
    crate::pb::yadgar::task::v1::Task {
        meta: Some(crate::pb::yadgar::common::v1::Meta {
            id: "yadgar:task:1".into(),
            version: 4,
            ..Default::default()
        }),
        number: 7,
        title: "t".into(),
        body: "b".into(),
        status: TaskStatus::Open as i32,
        tags: vec!["ledger-1789".into()],
        links: vec!["L1789".into()],
    }
}

/// The summary is exactly the five fields a caller picks a task by.
#[test]
fn the_summary_shape_carries_no_body_tags_or_links() {
    let out = find::output(
        FindTasksResponse {
            tasks: vec![a_full_task()],
            next_page_token: String::new(),
        },
        find::Fields::Summary,
        "",
    );
    let row = out.content["tasks"][0].as_object().unwrap();
    let mut keys: Vec<&str> = row.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["id", "number", "status", "title", "version"]);
    assert_eq!(out.rows, 1, "a summary fetched the same rows");
}

/// The full shape returns what the response proto carries: tags and links
/// were in `Task` and dropped by the view.
#[test]
fn the_full_shape_returns_tags_and_links() {
    let view = serde_json::to_value(TaskView::full(Some(a_full_task()))).unwrap();
    assert_eq!(view["body"], "b");
    assert_eq!(view["tags"], json!(["ledger-1789"]));
    assert_eq!(view["links"], json!(["L1789"]));
}

#[tokio::test]
async fn find_tasks_refuses_a_shape_it_does_not_know() {
    for args in [json!({ "fields": "brief" }), json!({ "fields": false })] {
        assert!(
            matches!(
                refusal(FIND_TASKS, args.clone()).await,
                ToolError::Invalid(_)
            ),
            "{args}"
        );
    }
}

// ---- ledger 1789: create_task legacy_ref and caller idempotency key ------

fn minted() -> String {
    "minted".into()
}

#[test]
fn create_task_stores_the_legacy_ref_as_its_link() {
    // MUTATION THIS CATCHES: `links: Vec::new()` coming back.
    let req = create::request(
        Scope::default(),
        &json!({ "title": "t", "legacy_ref": "L1789" }),
        minted,
    )
    .unwrap();
    assert_eq!(req.links, vec!["L1789".to_string()]);

    let none = create::request(Scope::default(), &json!({ "title": "t" }), minted).unwrap();
    assert!(none.links.is_empty());
}

/// The caller's key is forwarded VERBATIM; replay and refusal are `task-db`'s
/// (D9), keyed on it. Absent, the gateway mints one as before.
#[test]
fn create_task_forwards_the_callers_idempotency_key() {
    let req = create::request(
        Scope::default(),
        &json!({ "title": "t", "idempotency_key": "copy-L1789" }),
        || panic!("a caller's key must not be replaced by a minted one"),
    )
    .unwrap();
    assert_eq!(req.idempotency.unwrap().key, "copy-L1789");

    let minted_req = create::request(Scope::default(), &json!({ "title": "t" }), minted).unwrap();
    assert_eq!(minted_req.idempotency.unwrap().key, "minted");

    let null_req = create::request(
        Scope::default(),
        &json!({ "title": "t", "idempotency_key": null }),
        minted,
    )
    .unwrap();
    assert_eq!(null_req.idempotency.unwrap().key, "minted");
}

/// An empty key would reach `task-db` as "does not participate" and dedupe
/// nothing; an over-long one would fail in the `VARCHAR(255)` column.
#[tokio::test]
async fn create_task_refuses_a_key_or_ref_it_cannot_honour() {
    for args in [
        json!({ "title": "t", "idempotency_key": "" }),
        json!({ "title": "t", "idempotency_key": "has space" }),
        // MUTATION THESE CATCH: the alphabet check narrowed to
        // `key.contains(' ')` — a tab, an accent and a NUL all pass it.
        json!({ "title": "t", "idempotency_key": "tab\tkey" }),
        json!({ "title": "t", "idempotency_key": "é" }),
        json!({ "title": "t", "idempotency_key": "\u{0}" }),
        json!({ "title": "t", "idempotency_key": "x".repeat(256) }),
        json!({ "title": "t", "idempotency_key": 7 }),
        json!({ "title": "t", "legacy_ref": "" }),
        json!({ "title": "t", "legacy_ref": "  " }),
        json!({ "title": "t", "legacy_ref": "\t\n" }),
        // MUTATION THIS CATCHES: the `LEGACY_REF_MAX` check removed.
        json!({ "title": "t", "legacy_ref": "é".repeat(256) }),
        json!({ "title": "t", "legacy_ref": 1789 }),
    ] {
        assert!(
            matches!(
                refusal(CREATE_TASK, args.clone()).await,
                ToolError::Invalid(_)
            ),
            "{args}"
        );
    }
    let longest = json!({ "title": "t", "idempotency_key": "x".repeat(255) });
    assert!(create::request(Scope::default(), &longest, minted).is_ok());
    // MUTATION THIS CATCHES: the bound counted in bytes (`.len()`), which
    // refuses 255 two-byte characters the schema's `maxLength` allows.
    let longest_ref = json!({ "title": "t", "legacy_ref": "é".repeat(255) });
    assert!(create::request(Scope::default(), &longest_ref, minted).is_ok());
    // VERBATIM: surrounding whitespace is kept, not trimmed.
    let padded = json!({ "title": "t", "legacy_ref": " urn:x " });
    let req = create::request(Scope::default(), &padded, minted).unwrap();
    assert_eq!(req.links, vec![" urn:x ".to_string()]);
}

#[test]
fn the_create_schema_offers_the_legacy_ref_and_the_key() {
    let all = definitions();
    let create = &all[0];
    assert_eq!(create["name"], "create_task");
    let props = &create["inputSchema"]["properties"];
    assert_eq!(props["legacy_ref"]["type"], "string");
    assert_eq!(props["legacy_ref"]["minLength"], 1);
    assert_eq!(props["legacy_ref"]["maxLength"], 255);
    assert_eq!(props["legacy_ref"]["pattern"], "\\S");
    assert_eq!(props["idempotency_key"]["minLength"], 1);
    assert_eq!(props["idempotency_key"]["maxLength"], 255);
    assert_eq!(props["idempotency_key"]["pattern"], "^[!-~]+$");
    assert_eq!(create["inputSchema"]["required"], json!(["title"]));
}

// ---- yaadgaar #397: the index shape and number addressing ---------------

/// The index is exactly number, status and title: no id, no version, no
/// body. A key set asserted whole, so an extra field fails as surely as a
/// missing one.
#[test]
fn the_index_shape_carries_only_number_status_and_title() {
    let out = find::output(
        FindTasksResponse {
            tasks: vec![a_full_task()],
            next_page_token: "page-2".into(),
        },
        find::Fields::Index,
        "",
    );
    let row = out.content["tasks"][0].as_object().unwrap();
    let mut keys: Vec<&str> = row.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["number", "status", "title"]);
    assert_eq!(row["number"], 7);
    assert_eq!(row["status"], "open");
    assert_eq!(row["title"], "t");
    assert_eq!(out.content["next_page_token"], "page-2");
    assert_eq!(out.rows, 1);
}

/// A listing reaches the scope's subtree, but `edit_task` and
/// `transition_task` resolve a number in the caller's EXACT project. So an
/// index row from a descendant project carries its `project_id`, and a row
/// from the scope's own project does not: a bare number in an index row
/// always means "this number, in the project you are working in".
#[test]
fn an_index_row_from_another_project_carries_its_project_id() {
    use crate::pb::yadgar::common::v1::Meta;
    use crate::pb::yadgar::task::v1::Task;

    let in_project = |project: &str, number| Task {
        meta: Some(Meta {
            id: format!("yadgar:task:{number}"),
            project_id: project.into(),
            ..Default::default()
        }),
        number,
        title: "t".into(),
        status: TaskStatus::Open as i32,
        ..Default::default()
    };
    let out = find::output(
        FindTasksResponse {
            tasks: vec![in_project("acme", 1), in_project("acme/a", 1)],
            next_page_token: String::new(),
        },
        find::Fields::Index,
        "acme",
    );
    let rows = out.content["tasks"].as_array().unwrap();

    let own = rows[0].as_object().unwrap();
    let mut keys: Vec<&str> = own.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["number", "status", "title"],
        "same project: no project_id"
    );

    let descendant = rows[1].as_object().unwrap();
    let mut keys: Vec<&str> = descendant.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["number", "project_id", "status", "title"]);
    assert_eq!(descendant["project_id"], "acme/a");
    assert_eq!(descendant["number"], 1);
}

#[test]
fn the_find_schema_offers_the_index_shape() {
    let all = definitions();
    let find = &all[2];
    assert_eq!(
        find["inputSchema"]["properties"]["fields"]["enum"],
        json!(["full", "summary", "index"])
    );
}

/// `id` is no longer required: `number` names a task as well. What stays
/// required is the version the compare-and-set checks.
#[test]
fn the_edit_and_transition_schemas_take_an_id_or_a_number() {
    let catalogue = definitions();
    let tool = |name: &str| {
        catalogue
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .cloned()
            .unwrap()
    };
    let edit = tool("edit_task");
    assert_eq!(edit["inputSchema"]["required"], json!(["expect_version"]));
    assert_eq!(
        edit["inputSchema"]["properties"]["number"]["type"],
        "integer"
    );
    assert_eq!(edit["inputSchema"]["properties"]["number"]["minimum"], 1);
    assert_eq!(
        edit["inputSchema"]["properties"]["expect_body_sha256"]["pattern"],
        "^[0-9a-f]{64}$"
    );
    let transition = tool("transition_task");
    assert_eq!(
        transition["inputSchema"]["required"],
        json!(["expect_version", "to"])
    );
    assert_eq!(
        transition["inputSchema"]["properties"]["number"]["minimum"],
        1
    );
}

/// Patch mode on the catalogue (ADR-1008): an object of three required
/// fields, and a description that says the match is literal and counted.
#[test]
fn the_edit_schema_offers_a_literal_patch() {
    let all = definitions();
    let edit = all
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "edit_task")
        .cloned()
        .unwrap();
    let patch = &edit["inputSchema"]["properties"]["patch"];
    assert_eq!(patch["type"], "object");
    assert_eq!(patch["required"], json!(["old", "new", "expect_count"]));
    assert_eq!(patch["properties"]["old"]["minLength"], 1);
    assert_eq!(patch["properties"]["expect_count"]["minimum"], 1);
    assert_eq!(patch["additionalProperties"], false);
    let digest = edit["inputSchema"]["properties"]["expect_body_sha256"]["description"]
        .as_str()
        .unwrap();
    assert!(
        digest.contains("pre-edit"),
        "patch mode missing from: {digest}"
    );
    let text = edit["description"].as_str().unwrap();
    for needle in ["patch", "literal", "expect_count", "pre-edit"] {
        assert!(text.contains(needle), "{needle:?} missing from: {text}");
    }
}

/// THE DESCRIPTION CAP, as a FLOOR for older clients. Claude Code 2.1.84
/// began cutting an MCP tool description at 2048 characters; 2.1.280 added
/// the `CLAUDE_CODE_MAX_MCP_DESCRIPTION_LENGTH` override; 2.1.295 allows 16384
/// for descriptions loaded through tool search; 2.1.296 raised the default to
/// 4096. A description within 2048 reaches every one of those clients whole.
/// Counted in UTF-16 code units, the unit a JavaScript client's length
/// measures. The cap is spelled as a literal here, not read from the code
/// under test.
#[test]
fn every_tool_description_fits_the_client_cap() {
    for tool in definitions().as_array().unwrap() {
        let text = tool["description"].as_str().unwrap();
        let n = text.encode_utf16().count();
        assert!(n <= 2048, "{}: {n} UTF-16 code units", tool["name"]);
    }
}
