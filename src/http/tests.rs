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
///
/// **A FRESH limiter per call, which the degraded floor makes load-bearing.**
/// While the cache is unreachable each replica holds callers to
/// `rate / maxReplicas` in process, so a shared limiter would let the second
/// `tools/call` in this file be refused by the first one's spending — and the
/// status codes asserted here would depend on test order. One limiter per state
/// is one floor per test.
fn state(allowed_origins: Vec<String>) -> Arc<AppState> {
    Arc::new(AppState {
        attestation: Attestation::TrustedHeaders,
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        iam: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        limiter: crate::limit::Limiter::new(
            // Nothing listens on port 1, and the refusal is immediate.
            "127.0.0.1:1",
            crate::limit::Limits::parse("task.write=1:1", "1:1").expect("the limits parse"),
            std::time::Duration::from_millis(200),
            6,
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

/// The five codes `iam.Login` can actually return, from `iam/src/service.rs`.
///
/// `UNAUTHENTICATED` is the refusal it raises itself. The other four arrive from
/// two places, and **that is the reason they are collapsed rather than mapped**:
/// `get_password_hash` runs BEFORE the password is checked and `create_credential`
/// runs after it, `upstream_failed` preserves the upstream code in both cases, and
/// `INTERNAL` comes from minting the token after verification. So the same
/// `UNAVAILABLE` can mean "the store is down and nothing was checked" or "your
/// password was right and then the store failed", and nothing in the code says
/// which.
const REACHABLE: [tonic::Code; 5] = [
    tonic::Code::Unauthenticated,
    tonic::Code::Internal,
    tonic::Code::Unavailable,
    tonic::Code::NotFound,
    tonic::Code::InvalidArgument,
];

/// EXACTLY ONE code says "wrong password", and the rest say nothing at all.
///
/// **This test is the security property, not a mapping table.** Some of the
/// non-`UNAUTHENTICATED` codes are raised only after the password has verified,
/// and a caller able to pick one out would learn from the status line alone that
/// its password was right. The gateway cannot tell those from the same codes
/// raised before the check (see `REACHABLE`), so any mapping that distinguishes
/// two of them risks handing out that oracle. Asserting that the four non-refusal
/// codes collapse to ONE value is what pins that; asserting each one individually
/// against a constant would pass for a mapping that leaked.
///
/// It also pins the rejected alternative shut. Mapping everything to 401 closes
/// the leak too, and would fail here — deliberately, because it lies to a
/// legitimate user whenever `iam-db` is down.
#[test]
fn login_status_leaks_nothing_beyond_the_refusal() {
    assert_eq!(
        login_status(&tonic::Status::new(tonic::Code::Unauthenticated, "no")),
        StatusCode::UNAUTHORIZED,
        "a refused password is the one thing the caller is told"
    );

    let others: std::collections::BTreeSet<u16> = REACHABLE
        .iter()
        .filter(|c| **c != tonic::Code::Unauthenticated)
        .map(|c| login_status(&tonic::Status::new(*c, "no")).as_u16())
        .collect();
    assert_eq!(
        others.len(),
        1,
        "every non-refusal code must be one indistinguishable status; got {others:?}"
    );
    let opaque = *others.iter().next().expect("one status");
    assert_ne!(
        opaque,
        StatusCode::UNAUTHORIZED.as_u16(),
        "collapsing everything onto 401 tells a user with the right password \
         that it is wrong whenever iam-db is down"
    );
    assert_eq!(opaque, StatusCode::SERVICE_UNAVAILABLE.as_u16());
}

/// The same property over EVERY `tonic::Code`, not just today's five.
///
/// `iam` gains RPCs and `iam-db` gains failure modes; a code that becomes
/// reachable later must not arrive with its own status code and reopen the
/// oracle. The five-code test above says what is true today, this says the rule
/// holds for whatever `iam` returns tomorrow.
#[test]
fn every_other_grpc_code_is_the_same_opaque_status() {
    let statuses: std::collections::BTreeSet<u16> = ALL_CODES
        .iter()
        .filter(|c| **c != tonic::Code::Unauthenticated)
        .map(|c| login_status(&tonic::Status::new(*c, "no")).as_u16())
        .collect();
    assert_eq!(
        statuses,
        std::collections::BTreeSet::from([StatusCode::SERVICE_UNAVAILABLE.as_u16()]),
        "no gRPC code other than UNAUTHENTICATED may get a status of its own"
    );
}

/// Every `tonic::Code` there is.
///
/// Written out rather than derived: `tonic::Code` implements no iterator, and a
/// list that silently lost an entry would narrow every test below it without
/// failing one.
const ALL_CODES: [tonic::Code; 17] = [
    tonic::Code::Ok,
    tonic::Code::Cancelled,
    tonic::Code::Unknown,
    tonic::Code::InvalidArgument,
    tonic::Code::DeadlineExceeded,
    tonic::Code::NotFound,
    tonic::Code::AlreadyExists,
    tonic::Code::PermissionDenied,
    tonic::Code::ResourceExhausted,
    tonic::Code::FailedPrecondition,
    tonic::Code::Aborted,
    tonic::Code::OutOfRange,
    tonic::Code::Unimplemented,
    tonic::Code::Internal,
    tonic::Code::Unavailable,
    tonic::Code::DataLoss,
    tonic::Code::Unauthenticated,
];

/// The whole failing response — status, body AND headers — over every code.
///
/// **This closes the gap the status-only tests above left open.** Every handler
/// test in this file points `iam` at `127.0.0.1:1`, so every one of them lands on
/// a transport `UNAVAILABLE` and the 401 branch was reached by nothing: adding
/// `WWW-Authenticate` to the refusal, or interpolating the upstream message into
/// its body, passed the entire suite. `login_failure` takes a bare `tonic::Code`,
/// so both branches are reachable here with no server stub and no `iam` at all.
///
/// Three properties, and each is a leak if it fails:
///
/// - exactly one code answers 401, and every other answers one identical
///   `(status, body)` pair — a body that varied would leak what the status line
///   was made opaque to hide, and the client never reads it, so nothing on the
///   client side could catch that;
/// - NO response carries `WWW-Authenticate`, which D72 forbids because it
///   advertises a discovery flow this deployment does not implement;
/// - every response is `application/json`, including the refusal.
#[tokio::test]
async fn every_login_failure_is_opaque_in_body_and_headers() {
    let mut answers = std::collections::BTreeSet::new();
    let mut refusals = 0;

    for code in ALL_CODES {
        let resp = login_failure(code);
        let status = resp.status();

        assert!(
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_none(),
            "D72: {code:?} must not advertise an authentication scheme"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "{code:?} must answer JSON"
        );

        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read the body");
        let body = String::from_utf8_lossy(&bytes).into_owned();

        // THE BODY MUST NOT CARRY THE UPSTREAM'S WORDS. `login_failure` takes a
        // `Code` and cannot see a message, so this asserts the signature is doing
        // its job rather than that the author was careful.
        assert!(
            !body.contains("no") || !body.contains(&format!("{code:?}")),
            "{code:?} leaked its own name into the body: {body}"
        );

        if code == tonic::Code::Unauthenticated {
            refusals += 1;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body, r#"{"error":"invalid username or password"}"#);
        } else {
            answers.insert((status.as_u16(), body));
        }
    }

    assert_eq!(refusals, 1, "exactly one code is a refusal");
    assert_eq!(
        answers.len(),
        1,
        "every non-refusal code must answer one identical status AND body; got {answers:?}"
    );
    assert_eq!(
        answers.into_iter().next().expect("one answer"),
        (
            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            r#"{"error":"login is unavailable"}"#.to_string()
        )
    );
}

// ---------------------------------------------------------------------------
// POST /auth/login (D75). The handler, through the real router.
// ---------------------------------------------------------------------------

/// POST a body to `/auth/login` and read the raw answer.
///
/// The body is returned as TEXT rather than parsed, because what these assert is
/// partly that it is a fixed string.
async fn login_post(body: &str) -> (StatusCode, String) {
    let req = HttpRequest::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router(state(Vec::new()))
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read the body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The route exists at all.
///
/// **This is the whole reason the endpoint was written.** `yaadgaar login` POSTs
/// here and measured a 404 from a VM: nothing in the tree served the path, so the
/// one command that makes the client's setup work could not work. A 404 here
/// again would mean the route was dropped or registered under another path, and
/// the failure would look exactly like the one this replaced.
#[tokio::test]
async fn the_login_route_is_served() {
    let (status, _) = login_post(r#"{"username":"u","password":"p","label":"l"}"#).await;
    assert_ne!(status, StatusCode::NOT_FOUND, "/auth/login must be routed");
}

/// An unreachable `iam` is an opaque 503 with a fixed body.
///
/// The state's `iam` channel is `connect_lazy` at `127.0.0.1:1`, so the RPC fails
/// in the transport and arrives as `UNAVAILABLE`. This is the END-TO-END half of
/// the property `every_login_failure_is_opaque_in_body_and_headers` pins over
/// every code: it proves the handler actually routes a failure through
/// `login_failure` rather than answering some other way, which a test on the pure
/// function alone cannot show. It reaches exactly ONE code, and that is why it is
/// not the test the security property rests on.
#[tokio::test]
async fn an_unreachable_iam_is_an_opaque_503() {
    let (status, body) = login_post(r#"{"username":"u","password":"p","label":"l"}"#).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body, r#"{"error":"login is unavailable"}"#,
        "the body is a constant: the client never reads it, so anything varying \
         in it is a channel its own tests cannot catch"
    );
}

/// Nothing in the ROUTER adds `WWW-Authenticate` on the way out.
///
/// `every_login_failure_is_opaque_in_body_and_headers` proves `login_failure`
/// sets no such header, over every code. It cannot prove a LAYER does not add one
/// afterwards, because it never goes through the router — so this drives the real
/// stack and checks what actually reaches the wire. One code is enough for that
/// question: layers do not vary by gRPC status.
#[tokio::test]
async fn no_layer_adds_an_authentication_challenge() {
    let req = HttpRequest::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"username":"u","password":"p"}"#.to_string()))
        .expect("request");
    let resp = router(state(Vec::new()))
        .oneshot(req)
        .await
        .expect("the router answers");
    assert!(
        resp.headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .is_none(),
        "D72: no WWW-Authenticate on this endpoint"
    );
}

/// Malformed JSON is the gateway's own 400, not the upstream's problem.
///
/// It is safe to describe, unlike the two constants: nothing has been sent to
/// `iam`, so no password has been checked and there is nothing to leak.
#[tokio::test]
async fn malformed_json_is_a_400() {
    let (status, body) = login_post("{not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid JSON"), "got {body}");
}

/// A missing field is refused HERE rather than sent on as an empty string.
///
/// `username: ""` would reach `iam`, fail its password check, and come back as a
/// 401 — telling the caller its credentials were wrong when what was wrong was
/// its request. It also spends an Argon2id verification on a request that could
/// not succeed.
#[tokio::test]
async fn a_missing_field_is_a_400() {
    for body in [
        r#"{"password":"p","label":"l"}"#,
        r#"{"username":"u","label":"l"}"#,
        r#"{}"#,
    ] {
        let (status, _) = login_post(body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} must be refused");
    }
    // `label` is NOT in that list on purpose: it only names the machine, and
    // requiring it would add a rule the proto does not have. Absent, the request
    // goes upstream — which here means the unreachable-iam path, not a 400.
    let (status, _) = login_post(r#"{"username":"u","password":"p"}"#).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// The wrong method on the login path is 405, not 404.
#[tokio::test]
async fn only_post_reaches_login() {
    for method in [Method::GET, Method::DELETE, Method::PUT] {
        let req = HttpRequest::builder()
            .method(method.clone())
            .uri("/auth/login")
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

/// The body limit covers the login route.
///
/// **`Router::layer` applies only to routes registered BEFORE it**, so a
/// `/auth/login` added below the `.layer(...)` call would be the one
/// unauthenticated endpoint on this server accepting a body of any size. The
/// route order in `router()` is load-bearing and nothing else would say so.
#[tokio::test]
async fn the_body_limit_covers_login() {
    let huge = format!(
        r#"{{"username":"{}","password":"p"}}"#,
        "u".repeat(2_000_000)
    );
    let (status, _) = login_post(&huge).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the 1MiB limit must apply to /auth/login"
    );
}
