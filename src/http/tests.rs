//! Tests for [`super`], driving the real [`router`] in process.
//!
//! **`http.rs` had no tests at all**, so every status code this file decides —
//! 405 on the wrong method, 202 on a notification, 400 on malformed JSON, 403 on
//! a bad Origin, 401 on a failed attestation — was asserted nowhere. `oneshot`
//! against `router()` exercises the routing, the body limit layer and the
//! handler together, which is the seam a caller actually meets.

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::*;
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};

/// State whose upstream is never reachable, and never reached.
///
/// `connect_lazy` builds a `Channel` without a server behind it: none of the
/// paths asserted here gets as far as an RPC, and one that did would fail loudly
/// rather than quietly passing.
///
/// **The limiter points at nothing either, and that is deliberate rather than
/// convenient.** Every `tools/call` in this file therefore takes D74's degraded
/// path, so these tests assert the property that path exists for: an unreachable
/// shared cache must not change any status code this file decides. A limiter that
/// failed closed would turn most of them into 429 and this suite would say so.
fn state(allowed_origins: Vec<String>) -> Arc<AppState> {
    Arc::new(AppState {
        attestation: Attestation::TrustedHeaders,
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        limiter: crate::limit::Limiter::new(
            // Nothing listens on port 1, and the refusal is immediate.
            "127.0.0.1:1",
            crate::limit::Limits::parse("task.write=1:1", "1:1").expect("the limits parse"),
            std::time::Duration::from_millis(200),
        )
        .expect("the limiter opens"),
        allowed_origins,
    })
}

fn envelope(method: &str, id: Option<i64>) -> Value {
    let mut v = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": {
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: {},
            }
        }
    });
    if let Some(id) = id {
        v["id"] = json!(id);
    }
    v
}

/// A POST carrying the protocol-version header the cross-check requires.
fn post() -> axum::http::request::Builder {
    HttpRequest::builder()
        .method(Method::POST)
        .uri("/")
        .header("content-type", "application/json")
        .header(headers::PROTOCOL_VERSION, PROTOCOL_VERSION)
}

async fn send(state: Arc<AppState>, req: HttpRequest<Body>) -> (StatusCode, Value) {
    let resp = router(state)
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read the body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// POST one MCP envelope and read the answer.
async fn rpc(method: &str, id: Option<i64>) -> (StatusCode, Value) {
    let req = post()
        .body(Body::from(envelope(method, id).to_string()))
        .expect("request");
    send(state(Vec::new()), req).await
}

// ---------------------------------------------------------------------------
// The method surface.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn only_post_is_answered() {
    // There is no GET stream in this revision, so there is nothing for a GET to
    // do. MUTATION THIS CATCHES: dropping `.fallback(method_not_allowed)`, which
    // turns these into 404 — a status that says the endpoint is not there, when
    // it is.
    for method in [Method::GET, Method::DELETE, Method::PUT] {
        let req = HttpRequest::builder()
            .method(method.clone())
            .uri("/")
            .body(Body::empty())
            .expect("request");
        let (status, _) = send(state(Vec::new()), req).await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} must be 405"
        );
    }
}

#[tokio::test]
async fn a_notification_is_accepted_with_no_body() {
    // A notification has no `id`, and JSON-RPC says it takes no response.
    // MUTATION THIS CATCHES: answering one with a result — a client that sent a
    // notification is not reading, so the reply is at best ignored and at worst
    // correlated against an id that was never issued.
    let req = post()
        .body(Body::from(envelope("tools/list", None).to_string()))
        .expect("request");
    let resp = router(state(Vec::new()))
        .oneshot(req)
        .await
        .expect("the router answers");
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    assert!(bytes.is_empty(), "a notification takes no response body");
}

#[tokio::test]
async fn an_unknown_method_is_a_json_rpc_error_and_not_an_http_one() {
    // 200 with `-32601` in the body, deliberately. The HTTP request succeeded;
    // it is the JSON-RPC method that does not exist, and returning 404 would tell
    // a client its transport was wrong.
    let (status, body) = rpc("tools/summon", Some(7)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], codes::METHOD_NOT_FOUND);
    assert_eq!(body["id"], 7);
}

#[tokio::test]
async fn malformed_json_is_a_parse_error_and_400() {
    // The other direction: the body never became a request, so there is no id to
    // answer under and the HTTP status must say the request was bad.
    let req = post()
        .body(Body::from("{not json at all"))
        .expect("request");
    let (status, body) = send(state(Vec::new()), req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], codes::PARSE_ERROR);
    assert_eq!(body["id"], Value::Null);
}

#[tokio::test]
async fn the_two_measured_methods_answer_two_hundred() {
    for method in ["tools/list", "server/discover"] {
        let (status, body) = rpc(method, Some(1)).await;
        assert_eq!(status, StatusCode::OK, "{method}");
        assert_eq!(body["result"]["resultType"], "complete", "{method}");
    }
}

// ---------------------------------------------------------------------------
// Attestation, at the HTTP boundary.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_call_without_an_identity_header_is_refused_with_401() {
    // Under TrustedHeaders the identity IS the header, so an absent one is a
    // missing credential rather than an empty user — the distinction
    // `AttestError::MissingIdentity` exists to keep.
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
        .body(Body::from(body.to_string()))
        .expect("request");

    let (status, answer) = send(state(Vec::new()), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer["error"]["code"], codes::INVALID_REQUEST);
}

// ---------------------------------------------------------------------------
// Origin (DNS rebinding).
// ---------------------------------------------------------------------------

async fn origin_status(allowed: Vec<String>, origin: Option<&[u8]>) -> StatusCode {
    let mut req = post();
    if let Some(bytes) = origin {
        req = req.header(
            axum::http::header::ORIGIN,
            axum::http::HeaderValue::from_bytes(bytes).expect("a header value"),
        );
    }
    let req = req
        .body(Body::from(envelope("tools/list", Some(1)).to_string()))
        .expect("request");
    send(state(allowed), req).await.0
}

#[tokio::test]
async fn an_origin_that_cannot_be_read_is_forbidden() {
    // MUTATION THIS CATCHES — and the bug this test was written for:
    // `.and_then(|v| v.to_str().ok())`, which turned a header of non-ASCII bytes
    // into `None` and took the ABSENT arm. So the one Origin the server could not
    // check was the one it waved through, while the spec says a present-and-
    // invalid Origin MUST get 403.
    let weird: &[u8] = &[b'h', b't', b't', b'p', b':', b'/', b'/', 0xC3, 0x28];
    assert_eq!(
        origin_status(vec!["http://localhost".into()], Some(weird)).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn an_absent_origin_is_allowed_and_a_listed_one_passes() {
    // Absence is allowed because a non-browser client sends none — which is
    // exactly why this check cannot substitute for attestation.
    assert_eq!(origin_status(Vec::new(), None).await, StatusCode::OK);
    assert_eq!(
        origin_status(
            vec!["http://localhost:3000".into()],
            Some(b"http://localhost:3000")
        )
        .await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn an_empty_allowlist_denies_every_origin() {
    // MUTATION THIS CATCHES: `allowed_origins.is_empty() || any(...)`, the
    // plausible-looking "fix" that accepts EVERY browser origin in the DEFAULT
    // configuration — and that passes a suite which only ever tests a populated
    // list. Empty means no browser origin is accepted at all, which is right for
    // a server whose clients are agents.
    assert_eq!(
        origin_status(Vec::new(), Some(b"http://evil.example")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        origin_status(
            vec!["http://localhost".into()],
            Some(b"http://evil.example")
        )
        .await,
        StatusCode::FORBIDDEN
    );
}
