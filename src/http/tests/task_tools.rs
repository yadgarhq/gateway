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
use crate::pb::yadgar::task::v1::TaskStatus;
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

/// The identity the forged header claims. It must never reach `task`.
const FORGED_USER: &str = "mallory-forged-in-a-header";

#[derive(Default)]
struct Seen {
    edits: Mutex<Vec<EditTaskRequest>>,
    transitions: Mutex<Vec<TransitionTaskRequest>>,
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
        self.0.edits.lock().unwrap().push(request.into_inner());
        Ok(tonic::Response::new(EditTaskResponse {
            meta: returned_meta(),
        }))
    }

    async fn transition_task(
        &self,
        request: tonic::Request<TransitionTaskRequest>,
    ) -> Result<tonic::Response<TransitionTaskResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        self.0
            .transitions
            .lock()
            .unwrap()
            .push(request.into_inner());
        Ok(tonic::Response::new(TransitionTaskResponse {
            meta: returned_meta(),
            // Not the target, so a gateway echoing `to` back as `from` fails.
            from: TaskStatus::InProgress as i32,
        }))
    }

    async fn create_task(
        &self,
        _: tonic::Request<CreateTaskRequest>,
    ) -> Result<tonic::Response<CreateTaskResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        Err(tonic::Status::unimplemented("not under test"))
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
        _: tonic::Request<FindTasksRequest>,
    ) -> Result<tonic::Response<FindTasksResponse>, tonic::Status> {
        self.0.hits.fetch_add(1, Ordering::SeqCst);
        Err(tonic::Status::unimplemented("not under test"))
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
async fn tools_list_advertises_the_five_task_tools() {
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
