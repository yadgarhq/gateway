//! ADR-0954 (ledger 1651) through the real router: a claim into another
//! account's `local/` segment answers the SAME BYTES whether the path is
//! registered, unregistered or soft-landed, and the caller's own unregistered
//! path keeps `PROJECT_UNREGISTERED_PERSONAL`.

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{post, state_with};
use crate::attest::Attestation;
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::project::v1::{ProjectStatus, RegisteredPath};
use crate::project::{Mode, Registry, Validator};

const ALICE: &str = "yadgar:user:0192f0a0-0000-7000-8000-00000000a11c";
const BOB: &str = "yadgar:user:0192f0a0-0000-7000-9000-000000000b0b";
const SEG_A: &str = "0192f0a0-0000-7000-8000-00000000a11c";

fn state() -> std::sync::Arc<crate::http::AppState> {
    let rows = vec![RegisteredPath {
        path: format!("local/{SEG_A}/reg"),
        status: ProjectStatus::Active as i32,
        aliases: Vec::new(),
        owner_user_id: ALICE.to_string(),
        grants: Vec::new(),
    }];
    let mut state = state_with(Attestation::TrustedHeaders, Vec::new());
    std::sync::Arc::get_mut(&mut state)
        .expect("the state is not shared yet")
        .projects = std::sync::Arc::new(Validator::new(
        Registry::loaded_from(rows),
        Mode::Enforcing,
        crate::upstream::Upstream::new(
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            std::time::Duration::from_secs(30),
        ),
    ));
    state
}

/// The whole response: status, every header (name and value, in order), and
/// the RAW body bytes — so "byte-identical" covers all of it.
#[derive(Debug, PartialEq, Eq)]
struct Whole {
    status: StatusCode,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

/// One `tools/call` by `user` claiming `project`.
async fn call(user: &str, project: &str, tool: &str) -> Whole {
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
        .header("x-yadgar-user", user)
        .header("x-yadgar-project", project)
        .header("x-yadgar-instance", "i-1")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = crate::http::router(state())
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read the body")
        .to_vec();
    Whole {
        status,
        headers,
        body,
    }
}

fn reason(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(bytes)
        .ok()?
        .pointer("/error/data/reason")
        .cloned()
}

/// BOB INTO ALICE'S SEGMENT: unregistered, registered and soft-landed claims,
/// read and write, are ONE 403 and the SAME BYTES — nothing tells Bob which of
/// Alice's paths exist.
#[tokio::test]
async fn another_accounts_paths_answer_byte_identically_registered_or_not() {
    let unregistered = call(BOB, &format!("local/{SEG_A}/nothere"), "find_tasks").await;
    assert_eq!(unregistered.status, StatusCode::FORBIDDEN);
    assert_eq!(
        reason(&unregistered.body),
        Some(json!("PROJECT_NOT_MEMBER"))
    );
    assert!(
        !unregistered.headers.is_empty(),
        "the response carries headers"
    );
    for (rest, tool) in [
        ("reg", "find_tasks"),
        ("reg/deeper", "find_tasks"),
        ("reg", "create_task"),
        ("nothere", "edit_task"),
    ] {
        let other = call(BOB, &format!("local/{SEG_A}/{rest}"), tool).await;
        assert_eq!(
            other,
            unregistered,
            "{rest} {tool}: the whole response must match — status, headers and body: {} vs {}",
            String::from_utf8_lossy(&other.body),
            String::from_utf8_lossy(&unregistered.body)
        );
    }
}

/// ALICE'S OWN unregistered path keeps its 400 and its remediation, and her
/// registered row is reached.
#[tokio::test]
async fn the_callers_own_unregistered_path_keeps_unregistered_personal() {
    let own = call(ALICE, &format!("local/{SEG_A}/nothere"), "create_task").await;
    assert_eq!(own.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reason(&own.body),
        Some(json!("PROJECT_UNREGISTERED_PERSONAL"))
    );

    let reg = call(ALICE, &format!("local/{SEG_A}/reg"), "find_tasks").await;
    assert_ne!(reg.status, StatusCode::FORBIDDEN);
    assert_eq!(reason(&reg.body), None);
}
