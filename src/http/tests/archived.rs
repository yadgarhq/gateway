//! ADR-0941 through the real router: an archived project refuses WRITES, and
//! its reads still answer.
//!
//! **WHY THIS IS NOT LEFT TO `crate::project::tests`.** Those tests hand
//! `Validator::check` its read/write flag directly, so they stay green for a
//! dispatch that passed the wrong flag — a hardcoded `Access::Read` would make
//! every archived write in the estate land, with the unit suite all green. Only
//! a request naming a real tool can see which flag dispatch derived.

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::{json, Value};

use super::{post, send, state_with};
use crate::attest::Attestation;
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::project::v1::{ProjectStatus, RegisteredPath};
use crate::project::{Mode, Registry, Validator};

/// The archived repository every call below names.
const ARCHIVED: &str = "yadgarhq/old";

/// A registry with one live and one archived project, under `mode`.
fn state_archiving(mode: Mode) -> std::sync::Arc<crate::http::AppState> {
    let rows = [
        ("yadgarhq", ProjectStatus::Active),
        ("yadgarhq/docs", ProjectStatus::Active),
        (ARCHIVED, ProjectStatus::Archived),
    ]
    .map(|(path, status)| RegisteredPath {
        path: path.to_string(),
        status: status as i32,
        aliases: Vec::new(),
        owner_user_id: String::new(),
        grants: Vec::new(),
    });
    let mut state = state_with(Attestation::TrustedHeaders, Vec::new());
    std::sync::Arc::get_mut(&mut state)
        .expect("the state is not shared yet")
        .projects = std::sync::Arc::new(Validator::new(
        Registry::loaded_from(rows.into_iter().collect()),
        mode,
        tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
    ));
    state
}

/// One `tools/call` of `tool`, claiming the archived project.
///
/// `create_task` carries a title so a refusal can only come from attestation;
/// the dead `task` channel behind `state_with` answers whatever reaches it.
async fn call(mode: Mode, tool: &str) -> (StatusCode, Value) {
    let arguments = if tool == "create_task" {
        json!({ "title": "t" })
    } else {
        json!({})
    };
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
        .header("x-yadgar-user", "max")
        .header("x-yadgar-project", ARCHIVED)
        .header("x-yadgar-instance", "i-1")
        .body(Body::from(body.to_string()))
        .expect("request");
    send(state_archiving(mode), req).await
}

/// Under enforcement every WRITE tool is refused: 400, the archived token.
///
/// MUTATION THIS CATCHES: pass `Access::Read` from dispatch, or derive it from
/// anything but the tool name — every row here reds.
#[tokio::test]
async fn under_enforcement_a_write_tool_to_an_archived_project_is_refused() {
    for tool in ["create_task", "edit_task", "transition_task"] {
        let (status, body) = call(Mode::Enforcing, tool).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{tool}: {body}");
        assert_eq!(
            body.pointer("/error/data/reason"),
            Some(&json!("PROJECT_ARCHIVED")),
            "{tool}: a client branches on the token: {body}"
        );
    }
}

/// Under enforcement a READ tool to the same project passes attestation.
///
/// MUTATION THIS CATCHES: pass `Access::Write` from dispatch — reads of every
/// archived project are then refused and its history is lost to callers.
#[tokio::test]
async fn under_enforcement_a_read_tool_to_an_archived_project_is_served() {
    for tool in ["find_tasks", "read_task"] {
        let (status, body) = call(Mode::Enforcing, tool).await;
        assert_ne!(status, StatusCode::BAD_REQUEST, "{tool}: {body}");
        assert_eq!(
            body.pointer("/error/data/reason"),
            None,
            "{tool}: nothing about the project reaches a reader: {body}"
        );
    }
}

/// Under counting the archived write is served, like every other would-be
/// refusal in this release.
#[tokio::test]
async fn under_counting_a_write_to_an_archived_project_is_served() {
    let (status, body) = call(Mode::Counting, "create_task").await;
    assert_ne!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body.pointer("/error/data/reason"), None, "{body}");
}
