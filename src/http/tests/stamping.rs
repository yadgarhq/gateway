//! Stage 5's stamping through the real router: under enforcement the RESOLVED
//! path is what the call carries, and the tool result says whether the claim
//! had a row of its own (`plans/project-validation.md`, D52's soft landing).
//!
//! **WHY THIS IS NOT LEFT TO `crate::attest::tests`.** Those tests read the
//! `Scope` `attest` builds. Only a request through the router can see what the
//! CALLER is told, and the caller being told is the whole justification D52
//! gives for landing on an ancestor rather than refusing.
//!
//! **THE COUNTING CASE IS A BYTE COMPARISON AGAINST A GOLDEN.** The golden is
//! the body `origin/main` (b1ef90c) answered for the same request, captured
//! before this change. A "no `_meta` key" assertion alone would pass a
//! counting gateway that changed the body in any other way.

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{post, state_with};
use crate::attest::Attestation;
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::project::v1::{ProjectStatus, RegisteredPath};
use crate::project::{Mode, Registry, Validator};

/// A registered repository. Its anchor is `yadgarhq`.
const ROW: &str = "yadgarhq/docs";

/// A marker-file subpath beneath [`ROW`] (D53), with no row of its own.
const SUBPATH: &str = "yadgarhq/docs/services/api";

/// The `_meta` key the resolution rides under.
const KEY: &str = "io.yadgarhq/projectResolution";

/// What `origin/main` answered a COUNTING `find_tasks` claiming [`SUBPATH`],
/// byte for byte. The dead `task` channel makes it a tool-level failure, and
/// the text is the Linux refusal of a connect to port 1.
const GOLDEN_COUNTING: &str = r#"{"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"code: 'The service is currently unavailable', message: \"tcp connect error\", source: tonic::transport::Error(Transport, ConnectError(ConnectError(\"tcp connect error\", 127.0.0.1:1, Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" })))","type":"text"}],"isError":true,"resultType":"complete"}}"#;

/// What `origin/main` answered an ENFORCING `find_tasks` claiming
/// `nobody/x`, byte for byte: a refusal, which stamping must not touch.
const GOLDEN_REFUSED: &str = r#"{"error":{"code":-32600,"data":{"reason":"PROJECT_UNRESOLVABLE"},"message":"the workspace named in x-yadgar-project resolves to no registered project and to no registered namespace. Nothing is created automatically. Ask your operator which project this checkout should be registered as."},"id":1,"jsonrpc":"2.0"}"#;

/// A registry holding the anchor and [`ROW`], under `mode`.
fn state_stamping(mode: Mode) -> std::sync::Arc<crate::http::AppState> {
    let rows = ["yadgarhq", ROW].map(|path| RegisteredPath {
        path: path.to_string(),
        status: ProjectStatus::Active as i32,
        aliases: Vec::new(),
        owner_user_id: String::new(),
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

/// One `find_tasks` claiming `claimed`, answered as raw bytes.
async fn call(mode: Mode, claimed: &str) -> (StatusCode, String) {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: {},
            },
            "name": "find_tasks",
            "arguments": {},
        }
    });
    let req = post()
        .header(headers::METHOD, "tools/call")
        .header(headers::NAME, "find_tasks")
        .header("x-yadgar-user", "max")
        .header("x-yadgar-project", claimed)
        .header("x-yadgar-instance", "i-1")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = crate::http::router(state_stamping(mode))
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read the body");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("a JSON body is UTF-8"),
    )
}

fn parsed(body: &str) -> Value {
    serde_json::from_str(body).expect("the body is JSON")
}

/// MUTATION THIS CATCHES: stamping, or emitting the resolution, under
/// counting. The claim lands on an ancestor, so a stamping mutant has a
/// different path to write and the body moves.
#[tokio::test]
async fn under_counting_the_body_is_byte_identical_to_before() {
    let (status, body) = call(Mode::Counting, SUBPATH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body, GOLDEN_COUNTING,
        "counting changes no byte of the answer"
    );
}

/// D52's soft landing, made visible: the ancestor is named and `exact` is
/// false.
///
/// MUTATION THIS CATCHES: never stamping under enforcement — the key is
/// absent and the row reds.
#[tokio::test]
async fn under_enforcement_a_subpath_claim_lands_at_its_ancestor_with_exact_false() {
    let (status, body) = call(Mode::Enforcing, SUBPATH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        parsed(&body)
            .pointer("/result/_meta")
            .and_then(|m| m.get(KEY)),
        Some(&json!({ "resolvedPath": ROW, "exact": false })),
        "{body}"
    );
}

/// An exact claim keeps its own row, and says so. A case-folded spelling is
/// still exact, and the REGISTERED spelling is what is stamped.
#[tokio::test]
async fn under_enforcement_an_exact_claim_keeps_its_path_with_exact_true() {
    for claimed in [ROW, "YadgarHQ/Docs"] {
        let (status, body) = call(Mode::Enforcing, claimed).await;
        assert_eq!(status, StatusCode::OK, "{claimed}: {body}");
        assert_eq!(
            parsed(&body)
                .pointer("/result/_meta")
                .and_then(|m| m.get(KEY)),
            Some(&json!({ "resolvedPath": ROW, "exact": true })),
            "{claimed}: {body}"
        );
    }
}

/// A refusal under enforcement is the same bytes it was before stamping.
#[tokio::test]
async fn under_enforcement_a_refusal_is_byte_identical_to_before() {
    let (status, body) = call(Mode::Enforcing, "nobody/x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body, GOLDEN_REFUSED, "a refusal is unchanged by stamping");
}

/// The resolution MERGES into a result `_meta` that already holds keys, so a
/// key another layer set is never overwritten by stamping.
///
/// MUTATION THIS CATCHES: inserting a fresh `_meta` object over the old one.
#[test]
fn the_resolution_merges_into_an_existing_result_meta() {
    let payload = json!({ "jsonrpc": "2.0", "id": 1, "result": {
        "resultType": "complete",
        "_meta": { "io.yadgarhq/somethingElse": 7 },
    }});
    let merged = crate::http::call::with_resolution(payload, Some((ROW.to_string(), false)));
    assert_eq!(
        merged.pointer("/result/_meta"),
        Some(&json!({
            "io.yadgarhq/somethingElse": 7,
            KEY: { "resolvedPath": ROW, "exact": false },
        })),
        "{merged}"
    );
}
