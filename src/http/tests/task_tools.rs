//! `edit_task` and `transition_task`, served through the real router.
//!
//! **Against a FAKE `task` that records what arrived**, because what these tools
//! are for is the request they build: a field dropped, a mask left empty or a
//! scope taken from a header is invisible in the answer and only visible in the
//! request. The values below are sentinels no implementation could produce
//! without reading them from the call.
//!
//! **Under `Attestation::Iam`, and that is load-bearing.** Under
//! `TrustedHeaders` the `x-yadgar-user` header IS the identity, so the forged
//! header assertion would be backwards. Here `iam` resolves the token to
//! `u-that-iam-resolved`, and the header claims somebody else.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::{json, Value};
use tonic::transport::Channel;

use super::{a_live_credential, post, rpc, send, state_resolving_to_with_task};
use crate::http::AppState;
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::common::v1::Meta;
use crate::pb::yadgar::task::v1::{Task, TaskStatus};
use crate::pb::yadgar::taskapi::v1::{
    task_service_server::{TaskService, TaskServiceServer},
    CreateTaskRequest, CreateTaskResponse, EditTaskRequest, EditTaskResponse, FindTasksRequest,
    FindTasksResponse, ReadTaskRequest, ReadTaskResponse, RemoveTaskRequest, RemoveTaskResponse,
    TransitionTaskRequest, TransitionTaskResponse,
};

/// What the fake answers with, so the response shape is asserted against values
/// the gateway can only have read from `task`.
const RETURNED_ID: &str = "yadgar:task:returned-by-the-fake-c41d";
const RETURNED_VERSION: u64 = 9_173;

/// The version the fake refuses as stale, as `task-db`'s compare-and-set does.
/// Its message carries no reason token, as the store's refusal does not.
const STALE_VERSION: u64 = 13_131;

/// The version the fake refuses as stale WITH the reason token, as `task`
/// does once it ships ADR-1042 and has read the task itself.
const TOKENED_STALE_VERSION: u64 = 13_132;

/// `task`'s VERSION_MISMATCH refusal. A quote, a newline and a trailing space
/// and newline are in it on purpose: a gateway that re-renders the message
/// (Debug escaping, as tonic's `Display` for `Status` does) or trims it
/// changes those bytes.
const VERSION_MISMATCH_MESSAGE: &str =
    "VERSION_MISMATCH: the task is at version 7, not \"13132\"\nre-read it and retry \n";

/// The version at which the fake answers as a `task` whose own digest check
/// of `new` failed (ADR-1042 rule 11).
const NEW_DIGEST_REFUSED_VERSION: u64 = 13_133;

const PATCH_NEW_SHA256_MISMATCH_MESSAGE: &str =
    "PATCH_NEW_SHA256_MISMATCH: `new` does not match \"expect_new_sha256\"";

/// The version at which the fake answers UNAVAILABLE with a token-shaped
/// message. Only FAILED_PRECONDITION and INVALID_ARGUMENT carry reason tokens,
/// so this one must keep the gateway's usual rendering.
const UNAVAILABLE_TOKEN_SHAPED_VERSION: u64 = 13_134;

/// The versions at which the fake answers INTERNAL, PERMISSION_DENIED and
/// NOT_FOUND with a listed token. None of these codes carries reason tokens,
/// so each must keep the gateway's usual rendering.
const INTERNAL_TOKEN_SHAPED_VERSION: u64 = 13_135;
const PERMISSION_DENIED_TOKEN_SHAPED_VERSION: u64 = 13_136;
const NOT_FOUND_TOKEN_SHAPED_VERSION: u64 = 13_138;

/// The version at which the fake answers FAILED_PRECONDITION with a
/// token-SHAPED prefix that is not one of the proto's reason tokens.
const UNLISTED_TOKEN_VERSION: u64 = 13_137;

/// The identity the forged header claims. It must never reach `task`.
const FORGED_USER: &str = "mallory-forged-in-a-header";

#[derive(Default)]
struct Seen {
    edits: Mutex<Vec<EditTaskRequest>>,
    transitions: Mutex<Vec<TransitionTaskRequest>>,
    creates: Mutex<Vec<CreateTaskRequest>>,
    finds: Mutex<Vec<FindTasksRequest>>,
    /// Every RPC that arrived, of any kind.
    hits: AtomicUsize,
}

struct FakeTask(Arc<Seen>);

fn returned_meta() -> Option<Meta> {
    Some(Meta {
        id: RETURNED_ID.to_string(),
        version: RETURNED_VERSION,
        ..Default::default()
    })
}

#[tonic::async_trait]
impl TaskService for FakeTask {
    async fn edit_task(
        &self,
        request: tonic::Request<EditTaskRequest>,
    ) -> Result<tonic::Response<EditTaskResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        let req = request.into_inner();
        let version = req.expect_version;
        self.0.edits.lock().unwrap().push(req);
        match version {
            STALE_VERSION => return Err(tonic::Status::failed_precondition("version moved")),
            TOKENED_STALE_VERSION => {
                return Err(tonic::Status::failed_precondition(VERSION_MISMATCH_MESSAGE))
            }
            NEW_DIGEST_REFUSED_VERSION => {
                return Err(tonic::Status::invalid_argument(
                    PATCH_NEW_SHA256_MISMATCH_MESSAGE,
                ))
            }
            UNAVAILABLE_TOKEN_SHAPED_VERSION => {
                return Err(tonic::Status::unavailable(
                    "VERSION_MISMATCH: not a refusal",
                ))
            }
            INTERNAL_TOKEN_SHAPED_VERSION => {
                return Err(tonic::Status::internal("VERSION_MISMATCH: not a refusal"))
            }
            PERMISSION_DENIED_TOKEN_SHAPED_VERSION => {
                return Err(tonic::Status::permission_denied(
                    "VERSION_MISMATCH: not a refusal",
                ))
            }
            NOT_FOUND_TOKEN_SHAPED_VERSION => {
                return Err(tonic::Status::not_found("VERSION_MISMATCH: not a refusal"))
            }
            UNLISTED_TOKEN_VERSION => {
                return Err(tonic::Status::failed_precondition(
                    "SOMETHING_ELSE: not a listed token",
                ))
            }
            _ => {}
        }
        Ok(tonic::Response::new(EditTaskResponse {
            meta: returned_meta(),
        }))
    }

    async fn transition_task(
        &self,
        request: tonic::Request<TransitionTaskRequest>,
    ) -> Result<tonic::Response<TransitionTaskResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        let req = request.into_inner();
        let stale = req.expect_version == STALE_VERSION;
        self.0.transitions.lock().unwrap().push(req);
        if stale {
            return Err(tonic::Status::failed_precondition("version moved"));
        }
        Ok(tonic::Response::new(TransitionTaskResponse {
            meta: returned_meta(),
            // Not the target, so a gateway echoing `to` back as `from` fails.
            from: TaskStatus::InProgress as i32,
        }))
    }

    async fn create_task(
        &self,
        request: tonic::Request<CreateTaskRequest>,
    ) -> Result<tonic::Response<CreateTaskResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        self.0.creates.lock().unwrap().push(request.into_inner());
        Ok(tonic::Response::new(CreateTaskResponse {
            meta: returned_meta(),
            number: 4_242,
        }))
    }

    async fn read_task(
        &self,
        _: tonic::Request<ReadTaskRequest>,
    ) -> Result<tonic::Response<ReadTaskResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        Err(tonic::Status::unimplemented("not under test"))
    }

    async fn find_tasks(
        &self,
        request: tonic::Request<FindTasksRequest>,
    ) -> Result<tonic::Response<FindTasksResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        let request = request.into_inner();
        // The task lives in the project the caller is scoped to, so an index
        // row must carry no `project_id`.
        let project_id = request.scope.as_ref().map(|s| s.project_id.clone());
        self.0.finds.lock().unwrap().push(request);
        Ok(tonic::Response::new(FindTasksResponse {
            tasks: vec![Task {
                meta: returned_meta().map(|m| Meta {
                    project_id: project_id.unwrap_or_default(),
                    ..m
                }),
                number: 4_242,
                title: "returned title".into(),
                body: "a body the summary must not carry".into(),
                status: TaskStatus::Blocked as i32,
                tags: vec!["ledger-1789".into()],
                links: vec!["L1789".into()],
            }],
            next_page_token: String::new(),
        }))
    }

    async fn remove_task(
        &self,
        _: tonic::Request<RemoveTaskRequest>,
    ) -> Result<tonic::Response<RemoveTaskResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        Err(tonic::Status::unimplemented("not under test"))
    }
}

/// Serve the fake on an ephemeral port, bound before it is served.
async fn fake_task() -> (Channel, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the fake binds");
    let addr = incoming.local_addr().expect("a bound port");
    let served = Arc::clone(&seen);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(TaskServiceServer::new(FakeTask(served)))
            .serve_with_incoming(incoming)
            .await
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy();
    (channel, seen)
}

async fn gateway() -> (Arc<AppState>, Arc<Seen>) {
    let (task, seen) = fake_task().await;
    let (state, _) = state_resolving_to_with_task(
        a_live_credential(),
        std::time::Duration::from_secs(30),
        task,
    )
    .await;
    (state, seen)
}

/// One `tools/call`, with a good token AND a forged `x-yadgar-user`.
async fn call(state: Arc<AppState>, tool: &str, arguments: Value) -> (StatusCode, Value) {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: {},
            },
            "name": tool,
            "arguments": arguments,
        }
    });
    let req = post()
        .header(headers::METHOD, "tools/call")
        .header(headers::NAME, tool)
        .header("x-yadgar-project", "acme/sentinel-project")
        .header("x-yadgar-user", FORGED_USER)
        .header(
            axum::http::header::AUTHORIZATION,
            "Bearer a-token-iam-resolves",
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    send(state, req).await
}

fn sorted(paths: &[String]) -> Vec<String> {
    let mut out = paths.to_vec();
    out.sort_unstable();
    out
}

#[tokio::test]
async fn tools_list_advertises_the_five_task_tools_and_list_projects() {
    let (status, body) = rpc("tools/list", Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .expect("a tool array")
        .iter()
        .map(|t| t["name"].as_str().expect("a name"))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "create_task",
            "edit_task",
            "find_tasks",
            "list_projects",
            "read_task",
            "transition_task"
        ]
    );
}

#[tokio::test]
async fn edit_task_reaches_task_with_the_callers_fields_and_the_attested_user() {
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "edit_task",
        json!({
            "id": "yadgar:task:sentinel-edit-7f3a",
            "expect_version": 41,
            "title": "sentinel title q9",
            "body": "sentinel body z4",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    assert_eq!(edits.len(), 1, "exactly one EditTask must arrive");
    let req = &edits[0];
    assert_eq!(req.id, "yadgar:task:sentinel-edit-7f3a");
    assert_eq!(req.expect_version, 41);
    assert_eq!(req.title, "sentinel title q9");
    assert_eq!(req.body, "sentinel body z4");
    assert_eq!(
        sorted(&req.update_mask.as_ref().expect("a mask").paths),
        ["body", "title"],
        "the mask names what the caller sent"
    );
    assert!(
        !req.idempotency.as_ref().expect("a key").key.is_empty(),
        "a write carries a gateway-minted idempotency key (D9)"
    );
    let scope = req.scope.as_ref().expect("a scope");
    assert_eq!(
        scope.user_id, "u-that-iam-resolved",
        "ADR-0488: the user is the one `iam` resolved, never `x-yadgar-user`"
    );
    assert_ne!(scope.user_id, FORGED_USER);
    assert_eq!(scope.project_id, "acme/sentinel-project");

    assert_eq!(
        body["result"]["structuredContent"],
        json!({ "id": RETURNED_ID, "version": RETURNED_VERSION })
    );
}

#[tokio::test]
async fn a_body_only_edit_masks_the_title_out() {
    // THE TRAP THIS PINS. `task` reads an EMPTY mask as "every editable field",
    // so a gateway that sent none would write the empty title below — which
    // `task` refuses — or, on a title-only edit, blank the body.
    //
    // An EMPTY body is sent deliberately: key presence, not non-emptiness,
    // decides the mask, so clearing a body stays expressible.
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "edit_task",
        json!({ "id": "yadgar:task:sentinel-body-only", "expect_version": 5, "body": "" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    assert_eq!(edits.len(), 1);
    assert_eq!(
        edits[0].update_mask.as_ref().expect("a mask").paths,
        ["body"]
    );
    assert_eq!(edits[0].title, "");
}

#[tokio::test]
async fn transition_task_reaches_task_with_the_target_and_the_attested_user() {
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "transition_task",
        json!({
            "id": "yadgar:task:sentinel-transition-b8e2",
            "expect_version": 67,
            "to": "blocked",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let transitions = seen.transitions.lock().unwrap();
    assert_eq!(
        transitions.len(),
        1,
        "exactly one TransitionTask must arrive"
    );
    let req = &transitions[0];
    assert_eq!(req.id, "yadgar:task:sentinel-transition-b8e2");
    assert_eq!(req.expect_version, 67);
    assert_eq!(req.to, TaskStatus::Blocked as i32);
    assert!(!req.idempotency.as_ref().expect("a key").key.is_empty());
    let scope = req.scope.as_ref().expect("a scope");
    assert_eq!(scope.user_id, "u-that-iam-resolved", "ADR-0488");
    assert_eq!(scope.project_id, "acme/sentinel-project");

    assert_eq!(
        body["result"]["structuredContent"],
        json!({ "id": RETURNED_ID, "version": RETURNED_VERSION, "from": "in_progress" })
    );
}

#[tokio::test]
async fn a_call_missing_a_required_field_never_reaches_task() {
    // The answer `create_task` gives for a missing `title`: a tool-level
    // failure, `isError: true`, on a 200 — and no RPC at all.
    for (tool, args) in [
        (
            "edit_task",
            json!({ "id": "yadgar:task:x", "title": "no version" }),
        ),
        (
            "transition_task",
            json!({ "id": "yadgar:task:x", "expect_version": 2 }),
        ),
    ] {
        let (state, seen) = gateway().await;
        let (status, body) = call(state, tool, args).await;
        assert_eq!(status, StatusCode::OK, "{tool}: {body}");
        assert_eq!(body["result"]["isError"], true, "{tool}: {body}");
        assert_eq!(
            seen.hits.load(Ordering::SeqCst),
            0,
            "{tool}: a refused call must not reach `task`"
        );
    }
}

#[tokio::test]
async fn a_title_only_edit_leaves_the_body_out_of_the_mask() {
    // THE MIRROR OF THE BODY-ONLY CASE, and the one that loses data if wrong:
    // a mask naming `body` here would write the empty body below over the
    // task's real one.
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "edit_task",
        json!({ "id": "yadgar:task:sentinel-title-only", "expect_version": 8, "title": "sentinel only title k2" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    assert_eq!(edits.len(), 1);
    assert_eq!(
        edits[0].update_mask.as_ref().expect("a mask").paths,
        ["title"]
    );
    assert_eq!(edits[0].title, "sentinel only title k2");
    assert_eq!(edits[0].body, "", "no body was sent, so none is carried");
}

#[tokio::test]
async fn a_null_body_is_absent_and_does_not_clear_the_body() {
    // Null means "not sent", as on `create_task`. Clearing is `""`, and only
    // `""` — a client that fills omitted arguments with null must not wipe a
    // body it never meant to touch.
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "edit_task",
        json!({ "id": "yadgar:task:sentinel-null-body", "expect_version": 8, "title": "sentinel n7", "body": null }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    assert_eq!(edits.len(), 1);
    assert_eq!(
        edits[0].update_mask.as_ref().expect("a mask").paths,
        ["title"]
    );
}

#[tokio::test]
async fn a_stale_version_is_a_tool_failure_not_a_protocol_error() {
    // `task` answers a moved version with FAILED_PRECONDITION. Through the
    // router that must be a 200 carrying `isError: true` — the request was
    // well-formed MCP, and the caller's next step is to re-read, not to fix
    // its envelope.
    for (tool, args) in [
        (
            "edit_task",
            json!({ "id": "yadgar:task:x", "expect_version": STALE_VERSION, "title": "t" }),
        ),
        (
            "transition_task",
            json!({ "id": "yadgar:task:x", "expect_version": STALE_VERSION, "to": "done" }),
        ),
    ] {
        let (state, seen) = gateway().await;
        let (status, body) = call(state, tool, args).await;
        assert_eq!(seen.hits.load(Ordering::SeqCst), 1, "{tool} reached task");
        assert_eq!(status, StatusCode::OK, "{tool}: {body}");
        assert_eq!(body["result"]["isError"], true, "{tool}: {body}");
        assert!(
            body["error"].is_null(),
            "{tool}: not a JSON-RPC error: {body}"
        );
    }
}

/// LEDGER 1789: the filter and the shape, end to end. The filter must ARRIVE at
/// `task` — it was hard-coded empty — and the summary must leave the body out
/// of what the caller receives.
#[tokio::test]
async fn find_tasks_reaches_task_with_the_filter_and_answers_in_summary() {
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "find_tasks",
        json!({ "statuses": ["blocked", "in_progress"], "fields": "summary" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let finds = seen.finds.lock().unwrap();
    assert_eq!(finds.len(), 1, "exactly one FindTasks must arrive");
    assert_eq!(
        finds[0].statuses,
        vec![TaskStatus::Blocked as i32, TaskStatus::InProgress as i32]
    );
    assert_eq!(
        body["result"]["structuredContent"]["tasks"],
        json!([{
            "id": RETURNED_ID,
            "number": 4_242,
            "title": "returned title",
            "status": "blocked",
            "version": RETURNED_VERSION,
        }])
    );
}

/// yaadgaar #397: the index shape compares each row's project with the
/// ATTESTED scope's. A row from the caller's own project carries no
/// `project_id`; if the scope's project did not reach the comparison, this
/// same-project row would carry one.
#[tokio::test]
async fn find_tasks_in_index_shape_omits_the_callers_own_project() {
    let (state, _) = gateway().await;

    let (status, body) = call(state, "find_tasks", json!({ "fields": "index" })).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    assert_eq!(
        body["result"]["structuredContent"]["tasks"],
        json!([{ "number": 4_242, "title": "returned title", "status": "blocked" }])
    );
}

/// LEDGER 1789: the caller's key and the legacy reference reach `task` as sent.
/// Replay and refusal of a reused key are `task-db`'s (D9), keyed on this value.
#[tokio::test]
async fn create_task_reaches_task_with_the_callers_key_and_legacy_ref() {
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "create_task",
        json!({
            "title": "L1789: sentinel",
            "legacy_ref": "L1789",
            "idempotency_key": "copy-L1789-sentinel",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let creates = seen.creates.lock().unwrap();
    assert_eq!(creates.len(), 1, "exactly one CreateTask must arrive");
    let req = &creates[0];
    assert_eq!(req.links, vec!["L1789".to_string()]);
    assert_eq!(
        req.idempotency.as_ref().expect("a key").key,
        "copy-L1789-sentinel"
    );
    assert_eq!(
        req.scope.as_ref().expect("a scope").user_id,
        "u-that-iam-resolved"
    );
    assert_eq!(
        body["result"]["structuredContent"],
        json!({ "id": RETURNED_ID, "number": 4_242, "version": RETURNED_VERSION })
    );
}

// ---- yaadgaar #397: edit and transition by number -----------------------

/// A task named by its per-project number reaches `task` as a number with no
/// id. `task` resolves it in the caller's exact project; the gateway forwards
/// the attested scope unchanged, so it cannot widen that.
#[tokio::test]
async fn edit_and_transition_by_number_reach_task_as_a_number() {
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state.clone(),
        "edit_task",
        json!({ "number": 397, "expect_version": 41, "title": "sentinel by number e2" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");

    let (status, body) = call(
        state,
        "transition_task",
        json!({ "number": 397, "expect_version": 42, "to": "done" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");

    let edits = seen.edits.lock().unwrap();
    assert_eq!(edits[0].number, 397);
    assert_eq!(edits[0].id, "", "a call by number sends no id");
    assert_eq!(
        edits[0].scope.as_ref().expect("a scope").project_id,
        "acme/sentinel-project"
    );
    let transitions = seen.transitions.lock().unwrap();
    assert_eq!(transitions[0].number, 397);
    assert_eq!(transitions[0].id, "");
}

/// Both keys, neither key, and a number that is no task are the caller's
/// mistakes, answered before any RPC.
#[tokio::test]
async fn an_ambiguous_or_absent_key_never_reaches_task() {
    for (tool, args) in [
        (
            "edit_task",
            json!({ "id": "yadgar:task:x", "number": 3, "expect_version": 1, "title": "t" }),
        ),
        ("edit_task", json!({ "expect_version": 1, "title": "t" })),
        (
            "edit_task",
            json!({ "number": 0, "expect_version": 1, "title": "t" }),
        ),
        (
            "edit_task",
            json!({ "number": -4, "expect_version": 1, "title": "t" }),
        ),
        (
            "transition_task",
            json!({ "id": "yadgar:task:x", "number": 3, "expect_version": 1, "to": "done" }),
        ),
        (
            "transition_task",
            json!({ "expect_version": 1, "to": "done" }),
        ),
    ] {
        let (state, seen) = gateway().await;
        let (status, body) = call(state, tool, args.clone()).await;
        assert_eq!(status, StatusCode::OK, "{tool} {args}: {body}");
        assert_eq!(body["result"]["isError"], true, "{tool} {args}: {body}");
        assert_eq!(seen.hits.load(Ordering::SeqCst), 0, "{tool} {args}");
    }
}

// ---- yaadgaar #394: expect_body_sha256 ----------------------------------

/// `printf 'the whole body\n' | sha256sum`, spelled as a literal (ADR-0573).
const WHOLE_BODY: &str = "the whole body\n";
const WHOLE_BODY_SHA256: &str = "3dd6ee3056c3a5d527d642ff3d19900286ad919bfbdccc6acb083ffde283f726";

/// A matching digest is forwarded to `task` as its 32 raw bytes, so `task`
/// checks it again for every caller that does not come through here.
#[tokio::test]
async fn a_body_matching_its_digest_reaches_task_with_the_digest() {
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "edit_task",
        json!({
            "id": "yadgar:task:sentinel-sha",
            "expect_version": 5,
            "body": WHOLE_BODY,
            "expect_body_sha256": WHOLE_BODY_SHA256,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    assert_eq!(edits[0].body, WHOLE_BODY);
    assert_eq!(edits[0].expect_body_sha256.len(), 32);
    assert_eq!(edits[0].expect_body_sha256[0], 0x3d);
    assert_eq!(edits[0].expect_body_sha256[31], 0x26);
}

/// **THE CASE THE GUARD EXISTS FOR, CHECKED HERE AS WELL AS IN `task`.** A
/// `task` older than the field ignores it, so without this check the cut body
/// below would be stored during a rollout and reported as a success.
#[tokio::test]
async fn a_body_cut_off_before_its_digest_never_reaches_task() {
    const MISMATCH: &str = "the body does not match `expect_body_sha256`; it may have been \
                            cut off in transit, so nothing was written. Re-send the whole body";
    const NOT_HEX: &str = "`expect_body_sha256` must be 64 lowercase hex characters";
    const NO_BODY: &str = "`expect_body_sha256` was sent without a `body` to check";
    // SHA-256 of the empty string. Sent with NO body, it matches the body an
    // edit would get if a missing body were read as "", so only the
    // missing-body check can refuse it.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for (args, refusal) in [
        // Cut mid-word.
        (
            json!({ "id": "yadgar:task:x", "expect_version": 5, "body": "the whole bo",
                    "expect_body_sha256": WHOLE_BODY_SHA256 }),
            MISMATCH,
        ),
        // Lost only its trailing newline.
        (
            json!({ "id": "yadgar:task:x", "expect_version": 5, "body": "the whole body",
                    "expect_body_sha256": WHOLE_BODY_SHA256 }),
            MISMATCH,
        ),
        // Not 64 lowercase hex characters.
        (
            json!({ "id": "yadgar:task:x", "expect_version": 5, "body": WHOLE_BODY,
                    "expect_body_sha256": WHOLE_BODY_SHA256.to_uppercase() }),
            NOT_HEX,
        ),
        (
            json!({ "id": "yadgar:task:x", "expect_version": 5, "body": WHOLE_BODY,
                    "expect_body_sha256": &WHOLE_BODY_SHA256[..62] }),
            NOT_HEX,
        ),
        // A digest with no body to check.
        (
            json!({ "id": "yadgar:task:x", "expect_version": 5, "title": "t",
                    "expect_body_sha256": EMPTY_SHA256 }),
            NO_BODY,
        ),
    ] {
        let (state, seen) = gateway().await;
        let (status, body) = call(state, "edit_task", args.clone()).await;
        assert_eq!(status, StatusCode::OK, "{args}: {body}");
        assert_eq!(body["result"]["isError"], true, "{args}: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], refusal,
            "{args}: {body}"
        );
        assert_eq!(seen.hits.load(Ordering::SeqCst), 0, "{args}");
    }
}

// ---- yaadgaar #399: patch mode (ADR-1008) --------------------------------

/// A patch reaches `task` as the message, with `patch` named in the mask and
/// NO `body` path: `task` computes the result, and a `task` older than the
/// field refuses the `patch` path rather than writing a body.
///
/// The digest is FORWARDED UNCHECKED here: in patch mode it is over the
/// pre-edit body, which only `task` reads. So a digest of a body this gateway
/// never saw reaches `task` as its 32 bytes.
#[tokio::test]
async fn a_patch_reaches_task_as_a_patch_with_its_digest_unchecked() {
    let (state, seen) = gateway().await;

    let (status, body) = call(
        state,
        "edit_task",
        json!({
            "id": "yadgar:task:sentinel-patch",
            "expect_version": 5,
            "patch": { "old": "ledger", "new": "یادگار", "expect_count": 3 },
            "expect_body_sha256": WHOLE_BODY_SHA256,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    let patch = edits[0].patch.clone().expect("the patch is forwarded");
    assert_eq!(patch.old, "ledger");
    assert_eq!(patch.new, "یادگار");
    assert_eq!(patch.expect_count, 3);
    assert_eq!(edits[0].body, "");
    assert_eq!(
        edits[0].update_mask.clone().unwrap().paths,
        ["patch".to_string()]
    );
    // All 32 bytes, from the literal: a decoder that got any byte wrong fails.
    let expected: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&WHOLE_BODY_SHA256[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(edits[0].expect_body_sha256, expected);
}

/// A patch with a title names both, in the mask's usual order.
#[tokio::test]
async fn a_patch_with_a_title_names_both_in_the_mask() {
    let (state, seen) = gateway().await;
    let (_, body) = call(
        state,
        "edit_task",
        json!({
            "number": 7,
            "expect_version": 5,
            "title": "t",
            "patch": { "old": "a", "new": "", "expect_count": 1 },
        }),
    )
    .await;
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    assert_eq!(
        sorted(&edits[0].update_mask.clone().unwrap().paths),
        ["patch", "title"]
    );
}

/// Shapes the gateway can refuse without `task`: `patch` with `body`, a
/// patch missing a field or carrying the wrong type, and an `expect_count`
/// outside 1..=u32::MAX. Size, emptiness of `old` and the count itself are
/// `task`'s rules (ADR-1008: one place), so they are not checked here.
#[tokio::test]
async fn a_malformed_patch_never_reaches_task() {
    const EXCLUSIVE: &str = "send `body` or `patch`, not both";
    for (args, refusal) in [
        (
            json!({ "id": "x", "expect_version": 5, "body": "b",
                    "patch": { "old": "a", "new": "b", "expect_count": 1 } }),
            EXCLUSIVE,
        ),
        (
            json!({ "id": "x", "expect_version": 5, "patch": "a->b" }),
            "`patch` must be an object with `old`, `new` and `expect_count`",
        ),
        (
            json!({ "id": "x", "expect_version": 5,
                    "patch": { "new": "b", "expect_count": 1 } }),
            "`patch.old` is required",
        ),
        (
            json!({ "id": "x", "expect_version": 5,
                    "patch": { "old": "a", "expect_count": 1 } }),
            "`patch.new` is required",
        ),
        (
            json!({ "id": "x", "expect_version": 5,
                    "patch": { "old": 1, "new": "b", "expect_count": 1 } }),
            "`patch.old` must be a string",
        ),
        (
            json!({ "id": "x", "expect_version": 5,
                    "patch": { "old": "a", "new": "b" } }),
            "`patch.expect_count` must be an integer from 1 to 4294967295",
        ),
        (
            json!({ "id": "x", "expect_version": 5,
                    "patch": { "old": "a", "new": "b", "expect_count": 0 } }),
            "`patch.expect_count` must be an integer from 1 to 4294967295",
        ),
        (
            json!({ "id": "x", "expect_version": 5,
                    "patch": { "old": "a", "new": "b", "expect_count": 4294967296u64 } }),
            "`patch.expect_count` must be an integer from 1 to 4294967295",
        ),
        // A key the schema does not declare (`additionalProperties: false`):
        // a misspelt `expect_count` must not be read as absent and silently
        // replaced by another field's error, nor ignored.
        (
            json!({ "id": "x", "expect_version": 5,
                    "patch": { "old": "a", "new": "b", "expect_count": 1, "regex": true } }),
            "`patch` takes only `old`, `new`, `expect_count` and `expect_new_sha256`, \
             not `regex`",
        ),
    ] {
        let (state, seen) = gateway().await;
        let (status, body) = call(state, "edit_task", args.clone()).await;
        assert_eq!(status, StatusCode::OK, "{args}: {body}");
        assert_eq!(body["result"]["isError"], true, "{args}: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], refusal,
            "{args}: {body}"
        );
        assert_eq!(seen.hits.load(Ordering::SeqCst), 0, "{args}");
    }
}

// ---- yaadgaar #449: expect_new_sha256 and reason tokens (ADR-1042) -------

/// `printf 'یادگار\n' | sha256sum`, spelled as a literal (ADR-0573). The
/// digest of `new` only: `old` differs, so a digest over `old` fails.
const NEW_SIDE: &str = "یادگار\n";
const NEW_SIDE_SHA256: &str = "4b86b0e0f78bd0eb378f5a3ef9d277bc923462871b1a24b71b299927a04dede4";

fn patch_guarded(version: u64, new: &str, digest: Value) -> Value {
    json!({
        "id": "yadgar:task:sentinel-new-sha",
        "expect_version": version,
        "patch": { "old": "ledger", "new": new, "expect_count": 1,
                   "expect_new_sha256": digest },
    })
}

/// A `new` that matches its digest reaches `task` with the digest as all 32
/// raw bytes, so `task` checks it again for callers that do not come through
/// here.
#[tokio::test]
async fn a_new_matching_its_digest_reaches_task_with_the_digest() {
    let (state, seen) = gateway().await;
    let args = patch_guarded(5, NEW_SIDE, json!(NEW_SIDE_SHA256));
    let (status, body) = call(state, "edit_task", args).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let edits = seen.edits.lock().unwrap();
    let patch = edits[0].patch.clone().expect("the patch is forwarded");
    assert_eq!(patch.new, NEW_SIDE);
    let expected: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&NEW_SIDE_SHA256[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(patch.expect_new_sha256, expected);
    assert!(
        edits[0].expect_body_sha256.is_empty(),
        "no body digest was sent"
    );
}

/// Absent, or null (ADR-0819: null is absent): nothing is forwarded and no
/// check runs, so a `new` with no digest is never refused for one.
#[tokio::test]
async fn an_absent_new_digest_forwards_nothing_and_checks_nothing() {
    for digest in [None, Some(Value::Null)] {
        let (state, seen) = gateway().await;
        let mut args = json!({
            "id": "yadgar:task:x",
            "expect_version": 5,
            "patch": { "old": "ledger", "new": "cut off mid-wo", "expect_count": 1 },
        });
        if let Some(d) = digest.clone() {
            args["patch"]["expect_new_sha256"] = d;
        }
        let (status, body) = call(state, "edit_task", args).await;
        assert_eq!(status, StatusCode::OK, "{digest:?}: {body}");
        assert_ne!(body["result"]["isError"], true, "{digest:?}: {body}");
        let edits = seen.edits.lock().unwrap();
        let patch = edits[0].patch.clone().expect("the patch is forwarded");
        assert!(patch.expect_new_sha256.is_empty(), "{digest:?}");
    }
}

/// **THE CASE THE GUARD EXISTS FOR.** A `new` cut off in transit, or one that
/// lost only its trailing newline, is refused here with the reason token and
/// never reaches `task`: a `task` older than the field would apply it.
#[tokio::test]
async fn a_new_cut_off_before_its_digest_never_reaches_task() {
    const MISMATCH: &str = "PATCH_NEW_SHA256_MISMATCH: `patch.new` does not match \
                            `patch.expect_new_sha256`; it may have been cut off in transit, \
                            so nothing was written. Re-send the patch";
    for new in ["یاد", "یادگار"] {
        let (state, seen) = gateway().await;
        let args = patch_guarded(5, new, json!(NEW_SIDE_SHA256));
        let (status, body) = call(state, "edit_task", args).await;
        assert_eq!(status, StatusCode::OK, "{new}: {body}");
        assert_eq!(body["result"]["isError"], true, "{new}: {body}");
        let text = body["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("PATCH_NEW_SHA256_MISMATCH:"), "{text}");
        assert_eq!(text, MISMATCH, "{new}");
        assert_eq!(seen.hits.load(Ordering::SeqCst), 0, "{new}");
    }
}

/// A digest that is not 64 lowercase hex characters is refused before `task`,
/// as `expect_body_sha256` is: upper case, too short, too long, a non-hex
/// character, empty, and not a string.
#[tokio::test]
async fn a_malformed_new_digest_never_reaches_task() {
    const NOT_HEX: &str = "`patch.expect_new_sha256` must be 64 lowercase hex characters";
    let not_hex = format!("{}g", &NEW_SIDE_SHA256[..63]);
    for digest in [
        json!(NEW_SIDE_SHA256.to_uppercase()),
        json!(&NEW_SIDE_SHA256[..62]),
        json!(format!("{NEW_SIDE_SHA256}00")),
        json!(not_hex),
        json!(""),
        json!(42),
    ] {
        let (state, seen) = gateway().await;
        let args = patch_guarded(5, NEW_SIDE, digest.clone());
        let (status, body) = call(state, "edit_task", args).await;
        assert_eq!(status, StatusCode::OK, "{digest}: {body}");
        assert_eq!(body["result"]["isError"], true, "{digest}: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], NOT_HEX,
            "{digest}: {body}"
        );
        assert_eq!(seen.hits.load(Ordering::SeqCst), 0, "{digest}");
    }
}

/// `task`'s reason-token refusals reach the caller as `task` wrote them, byte
/// for byte, so a program can branch on the prefix before the first colon.
#[tokio::test]
async fn a_reason_token_from_task_reaches_the_caller_unchanged() {
    for (args, message) in [
        (
            json!({ "id": "yadgar:task:x", "expect_version": TOKENED_STALE_VERSION, "title": "t" }),
            VERSION_MISMATCH_MESSAGE,
        ),
        (
            patch_guarded(TOKENED_STALE_VERSION, NEW_SIDE, json!(NEW_SIDE_SHA256)),
            VERSION_MISMATCH_MESSAGE,
        ),
        (
            patch_guarded(NEW_DIGEST_REFUSED_VERSION, NEW_SIDE, json!(NEW_SIDE_SHA256)),
            PATCH_NEW_SHA256_MISMATCH_MESSAGE,
        ),
    ] {
        let (state, seen) = gateway().await;
        let (status, body) = call(state, "edit_task", args.clone()).await;
        assert_eq!(seen.hits.load(Ordering::SeqCst), 1, "{args} reached task");
        assert_eq!(status, StatusCode::OK, "{args}: {body}");
        assert_eq!(body["result"]["isError"], true, "{args}: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], message,
            "{args}: {body}"
        );
    }
}

/// A refusal with no reason token, and a token-shaped message on a code that
/// carries no tokens, keep the gateway's usual rendering, which names the
/// code. Only a listed refusal is passed through bare.
#[tokio::test]
async fn an_untokened_refusal_keeps_the_usual_rendering() {
    for (version, needle) in [
        (STALE_VERSION, "version moved"),
        (
            UNAVAILABLE_TOKEN_SHAPED_VERSION,
            "VERSION_MISMATCH: not a refusal",
        ),
        (
            INTERNAL_TOKEN_SHAPED_VERSION,
            "VERSION_MISMATCH: not a refusal",
        ),
        (
            PERMISSION_DENIED_TOKEN_SHAPED_VERSION,
            "VERSION_MISMATCH: not a refusal",
        ),
        (
            NOT_FOUND_TOKEN_SHAPED_VERSION,
            "VERSION_MISMATCH: not a refusal",
        ),
        (UNLISTED_TOKEN_VERSION, "SOMETHING_ELSE: not a listed token"),
    ] {
        let (state, _) = gateway().await;
        let (_, body) = call(
            state,
            "edit_task",
            json!({ "id": "yadgar:task:x", "expect_version": version, "title": "t" }),
        )
        .await;
        assert_eq!(body["result"]["isError"], true, "{body}");
        let text = body["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("code: "), "{version}: {text}");
        assert!(text.contains(needle), "{version}: {text}");
    }
}

/// An `expect_new_sha256` sent at the TOP LEVEL, beside an otherwise valid
/// patch, is refused before `task`. Ignoring it would apply the patch with no
/// guard while the caller believes one ran.
#[tokio::test]
async fn a_top_level_new_digest_is_refused_and_never_reaches_task() {
    let (state, seen) = gateway().await;
    let args = json!({
        "id": "yadgar:task:x",
        "expect_version": 5,
        "patch": { "old": "ledger", "new": NEW_SIDE, "expect_count": 1 },
        "expect_new_sha256": NEW_SIDE_SHA256,
    });
    let (status, body) = call(state, "edit_task", args).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(
        body["result"]["content"][0]["text"],
        "`expect_new_sha256` goes inside `patch`, beside the `new` it guards",
        "{body}"
    );
    assert_eq!(seen.hits.load(Ordering::SeqCst), 0);
}
