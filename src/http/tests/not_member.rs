//! `PROJECT_NOT_MEMBER` through the real router (`plans/project-membership.md`
//! car P3): every tool, the 403, and one answer for every non-owner.
//!
//! **WHY THIS IS NOT LEFT TO `crate::project::tests`.** Those tests hand
//! `Validator::check` its user directly, so they stay green for an `attest`
//! that passed the request id, the project or `""` as the user. Each case here
//! pairs an owner who is SERVED with a non-owner who is REFUSED on the same
//! row, so a wrong argument reds one half or the other.

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{post, state_with};
use crate::attest::{AttestError, Attestation};
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::project::v1::{ProjectStatus, RegisteredPath};
use crate::project::{Denied, Mode, Reason, Registry, Validator};
use crate::test_accounts::{id, path};

const TOOLS: [&str; 5] = [
    "find_tasks",
    "read_task",
    "create_task",
    "edit_task",
    "transition_task",
];

/// Private rows with owners; `local/alice/notes/deep` is a foreign row beneath
/// alice's own (ledger 641).
fn state_owning(mode: Mode) -> std::sync::Arc<crate::http::AppState> {
    let rows = [
        ("local/alice/solo", "alice", ProjectStatus::Active),
        ("local/alice/notes", "alice", ProjectStatus::Active),
        ("local/alice/notes/deep", "mallory", ProjectStatus::Active),
        ("local/alice/attic", "alice", ProjectStatus::Archived),
    ]
    .map(|(p, owner, status)| RegisteredPath {
        path: path(p),
        status: status as i32,
        aliases: Vec::new(),
        owner_user_id: id(owner),
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

/// One `tools/call` of `tool` by `user` claiming `project`: status and the RAW
/// body bytes, so "byte-identical" means bytes.
async fn call(mode: Mode, user: &str, project: &str, tool: &str) -> (StatusCode, Vec<u8>) {
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
        .header("x-yadgar-user", id(user))
        .header("x-yadgar-project", path(project))
        .header("x-yadgar-instance", "i-1")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = crate::http::router(state_owning(mode))
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read the body")
        .to_vec();
    (status, bytes)
}

fn reason(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(bytes)
        .ok()?
        .pointer("/error/data/reason")
        .cloned()
}

/// THE SUBTREE RULE, one case per tool: alice owns `local/alice/notes`, but
/// mallory owns a row beneath it, so every tool is refused — `create_task`
/// too, deliberately (plan §3: `Access` cannot tell a create from an edit).
#[tokio::test]
async fn every_tool_under_a_foreign_private_row_is_refused_with_403() {
    for tool in TOOLS {
        let (status, body) = call(Mode::Enforcing, "alice", "local/alice/notes", tool).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{tool}");
        assert_eq!(reason(&body), Some(json!("PROJECT_NOT_MEMBER")), "{tool}");
    }
}

/// The owner of a row with nothing foreign beneath it passes attestation on
/// every tool; the non-owner is refused on every tool.
///
/// MUTATION THIS CATCHES: pass the request id, the project or `""` as the user
/// from `attest` — the owner half reds.
#[tokio::test]
async fn the_owner_is_served_and_a_non_owner_is_refused_on_every_tool() {
    for tool in TOOLS {
        let (status, body) = call(Mode::Enforcing, "alice", "local/alice/solo", tool).await;
        assert_ne!(status, StatusCode::FORBIDDEN, "{tool}: owner");
        assert_eq!(reason(&body), None, "{tool}: owner");

        let (status, body) = call(Mode::Enforcing, "bob", "local/alice/solo", tool).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{tool}: non-owner");
        assert_eq!(reason(&body), Some(json!("PROJECT_NOT_MEMBER")), "{tool}");
    }
}

/// ONE ANSWER FOR EVERY NON-OWNER: a read and a write, of an active row and
/// of an archived one, are the same bytes (ruling E).
#[tokio::test]
async fn a_non_owner_read_and_write_get_byte_identical_answers() {
    let (status, read) = call(Mode::Enforcing, "bob", "local/alice/solo", "find_tasks").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for (project, tool) in [
        ("local/alice/solo", "edit_task"),
        ("local/alice/attic", "find_tasks"),
        ("local/alice/attic", "create_task"),
    ] {
        let (status, other) = call(Mode::Enforcing, "bob", project, tool).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{project} {tool}");
        assert_eq!(
            other,
            read,
            "{project} {tool}: {} vs {}",
            String::from_utf8_lossy(&other),
            String::from_utf8_lossy(&read)
        );
    }
}

/// The OWNER of an archived private row learns it is archived on a write, and
/// reads it.
#[tokio::test]
async fn the_owner_of_an_archived_private_row_gets_the_archived_answer() {
    let (status, body) = call(Mode::Enforcing, "alice", "local/alice/attic", "edit_task").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason(&body), Some(json!("PROJECT_ARCHIVED")));

    let (status, body) = call(Mode::Enforcing, "alice", "local/alice/attic", "read_task").await;
    assert_ne!(status, StatusCode::FORBIDDEN);
    assert_eq!(reason(&body), None);
}

/// Under counting the non-owner is served, like every other would-be refusal.
#[tokio::test]
async fn under_counting_a_non_owner_is_served() {
    for tool in TOOLS {
        let (status, body) = call(Mode::Counting, "bob", "local/alice/solo", tool).await;
        assert_ne!(status, StatusCode::FORBIDDEN, "{tool}");
        assert_eq!(reason(&body), None, "{tool}");
    }
}

/// THE THREE FIELDS OF THE ANSWER: 403, JSON-RPC `INVALID_REQUEST`, and the
/// `PERMISSION_DENIED` label `http/gate.rs` already uses for its 403.
#[test]
fn the_not_member_answer_is_a_403_labelled_permission_denied() {
    let answer = super::super::answer::attest_answer(&AttestError::Project(Denied {
        reason: Reason::NotMember,
        prose: "p".to_string(),
    }));
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.code, -32600, "JSON-RPC INVALID_REQUEST");
    assert_eq!(answer.label, "PERMISSION_DENIED");
    assert_eq!(answer.data, Some(json!({ "reason": "PROJECT_NOT_MEMBER" })));

    let archived = super::super::answer::attest_answer(&AttestError::Project(Denied {
        reason: Reason::Archived,
        prose: "p".to_string(),
    }));
    assert_eq!(archived.status, StatusCode::BAD_REQUEST, "unchanged");
    assert_eq!(archived.label, "INVALID_ARGUMENT", "unchanged");
}
