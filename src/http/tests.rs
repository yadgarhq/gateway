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
    state_with(Attestation::TrustedHeaders, allowed_origins)
}

/// The same state, under a chosen identity source.
///
/// A SEAM, because the two sources answer the same request differently and the
/// difference is the property worth asserting. `state` is the development one and
/// every test above it uses that; the tests that compare the two reach for this.
fn state_with(attestation: Attestation, allowed_origins: Vec<String>) -> Arc<AppState> {
    Arc::new(AppState {
        attestation,
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        iam: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        // ONE CACHE PER STATE, for the same reason there is one limiter per state:
        // a shared one would make what a test observes depend on which test ran
        // first, which is the failure the comment above describes.
        credentials: crate::attest::Credentials::new(std::time::Duration::from_secs(30)),
        limiter: crate::limit::Limiter::new(
            // Nothing listens on port 1, and the refusal is immediate.
            "127.0.0.1:1",
            None,
            crate::limit::Limits::parse("task.write=1:1", "1:1").expect("the limits parse"),
            std::time::Duration::from_millis(200),
            6,
        )
        .expect("the limiter opens"),
        allowed_origins,
        // UNDECLARED, which is the shipped default and therefore the state these
        // tests should exercise. It refuses to attribute an address; combined
        // with `oneshot` supplying no `ConnectInfo` at all, every request here
        // resolves to `Source::Unknown` and spends no credential token — so the
        // status codes below stay the ones these tests were written to assert.
        // The throttle has its own state, in `credential_throttle.rs`.
        trust: crate::source::TrustBoundary::Undeclared,
        credential_limits: unlimited_credentials(),
    })
}

/// Credential buckets wide enough not to interfere.
///
/// Every test in this file drives `router` through `oneshot`, which supplies no
/// peer address, so the guard finds no key and spends nothing regardless. These
/// values exist so a future test that DOES supply one is not silently throttled
/// by a number nobody chose for it.
fn unlimited_credentials() -> CredentialLimits {
    CredentialLimits {
        attributed: crate::limit::Bucket {
            rate: 600.0,
            burst: 600.0,
        },
        unattributed: crate::limit::Bucket {
            rate: 600.0,
            burst: 600.0,
        },
    }
}

/// The shipped defaults must actually parse.
///
/// **`cargo test` NEVER CALLS `main`, which is where they are read.** So a
/// default that `Bucket::parse` refuses — a rate of zero, a refill window longer
/// than a key's life — would ship, and the first anyone knew of it would be every
/// gateway pod exiting at boot naming a variable nobody set. That is the failure
/// the whole refuse-a-bad-value story exists to prevent, arriving through the one
/// value the story cannot refuse safely: its own.
///
/// It asserts the CONSTANTS rather than two literals copied here, because two
/// literals that must agree is the shape this repository keeps refusing.
#[test]
fn the_shipped_credential_limit_defaults_parse() {
    let attributed = crate::limit::Bucket::parse(CredentialLimits::DEFAULT_ATTRIBUTED)
        .expect("the shipped attributed default parses");
    let unattributed = crate::limit::Bucket::parse(CredentialLimits::DEFAULT_UNATTRIBUTED)
        .expect("the shipped unattributed default parses");
    // AND THE RELATION BETWEEN THEM, which is the part a careless edit breaks
    // without breaking either parse: the shared-hop bucket must be the LOOSER of
    // the two. Swapping them would put a guess-prevention rate on a key every
    // caller behind an ingress shares, which is one attacker refusing every login
    // in the installation — the failure `CredentialLimits` is written to explain.
    assert!(
        unattributed.rate > attributed.rate,
        "the bucket shared by everybody behind a proxy must be looser than the per-client one"
    );
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

/// The `outcome` this route writes is a value the SHARED MAPPING can produce.
///
/// **`yadgar_calls_total` has ONE `outcome` label space, and this binary writes
/// into it from two seams.** `telemetry::grpc::status_name` exists to be the one
/// place a gRPC status becomes a label, and a literal written here bypasses it —
/// so the set an operator has to know is the mapping's range PLUS whatever any
/// handler happened to type. This route typed `FORBIDDEN`, which no arm of that
/// mapping produces, and it was the only such value in `gateway`, `iam` or
/// `task`: every other literal on either side (`INVALID_ARGUMENT`, `UNAVAILABLE`,
/// `RESOURCE_EXHAUSTED`, `INTERNAL`, `UNAUTHENTICATED`, `UNIMPLEMENTED`,
/// `FAILED_PRECONDITION`, `OK`) already spells a name `status_name` returns.
///
/// **IT MATTERS BEYOND TIDINESS.** ADR-0556 names the `outcome` label space open
/// and cites this exact value as the reason a KEDA query must count `OK` as a
/// closed POSITIVE set rather than exclude a list of failures. It is also the
/// label an alert on "Ready but failing everything" would key on.
///
/// **THE ASSERTION IS MEMBERSHIP IN THE MAPPING'S RANGE, computed from the
/// mapping**, not a second spelling of one name. A test that only compared the
/// label with `"PERMISSION_DENIED"` would go green for any invented value
/// somebody also typed into the test; this one cannot, because the set is
/// derived. The literal is asserted as well, so a change of WHICH status this
/// refusal reports is a decision somebody makes rather than a drift.
#[test]
fn the_outcome_of_an_origin_refusal_is_one_the_shared_mapping_produces() {
    // A LOCAL recorder rather than `metrics::set_global_recorder`: a global one
    // is process-wide and this binary runs its tests in parallel.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let req = HttpRequest::builder()
                .method(Method::POST)
                .uri("/auth/login")
                .header("content-type", "application/json")
                .header(axum::http::header::ORIGIN, "http://evil.example")
                .body(Body::from(r#"{"username":"u","password":"p"}"#.to_string()))
                .expect("request");
            let resp = router(state(vec!["http://localhost".into()]))
                .oneshot(req)
                .await
                .expect("the router answers");
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "the HTTP status is unchanged: this is about the metric label"
            );
        });
    });

    let emitted = snapshotter.snapshot().into_vec();
    // LENGTH FIRST. A `metrics-util` resolving against another `metrics` major
    // links a SECOND facade; then this snapshot is empty and every assertion
    // built on it passes vacuously.
    assert!(
        !emitted.is_empty(),
        "the recorder saw no metric at all, which is what a second metrics \
         facade in the tree looks like"
    );
    let outcomes: Vec<String> = emitted
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == yadgar_telemetry::metrics::CALLS)
        .flat_map(|(key, _, _, _)| {
            key.key()
                .labels()
                .filter(|l| l.key() == "outcome")
                .map(|l| l.value().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        outcomes.len(),
        1,
        "one refused call, one series: {emitted:?}"
    );

    // The mapping's whole range, derived rather than retyped. `Code::from_i32`
    // saturates to `Unknown` above the enum, so the sweep covers every code
    // tonic defines and the catch-all arm besides.
    let mapped: std::collections::BTreeSet<&'static str> = (0..32)
        .map(|i| {
            yadgar_telemetry::grpc::status_name(&tonic::Status::new(tonic::Code::from_i32(i), ""))
        })
        .collect();
    assert!(
        mapped.contains(outcomes[0].as_str()),
        "the outcome {:?} is not a value telemetry::grpc::status_name can \
         produce; its range is {mapped:?}",
        outcomes[0]
    );
    assert_eq!(
        outcomes[0], "PERMISSION_DENIED",
        "a refusal on identity is PermissionDenied, not a locally invented name"
    );
}

// ---------------------------------------------------------------------------
// The MCP header cross-check, when a header cannot be read.
// ---------------------------------------------------------------------------

/// Bytes that `HeaderValue` accepts and `to_str` refuses.
///
/// `HeaderValue::is_valid` is `b >= 32 && b != 127 || b == b'\t'`, so every byte
/// of a UTF-8 multibyte sequence is >= 0x80 and PASSES — the value travels as
/// obs-text and arrives intact. `\r`, `\n`, `\0` and `\x7F` are rejected
/// outright, so this is not request splitting; it is a header the server holds
/// and cannot decode.
///
/// **INVALID UTF-8 THAT SPELLS NOTHING, deliberately.** A fixture built out of
/// `tools/list` or a real tool name with a stray byte on the end would be a value
/// the implementation plausibly contains, and a test asserting on one would be
/// asserting the code's own output back at itself. Nothing in this repository
/// produces these four bytes.
const UNREADABLE: &[u8] = &[0xC3, 0x28, 0xA0, 0xA1];

/// POST `body`, with one extra header carrying raw bytes.
async fn with_raw_header(name: &str, value: &[u8], body: Value) -> (StatusCode, Value) {
    let req = post()
        .header(
            name,
            axum::http::HeaderValue::from_bytes(value).expect("a header value"),
        )
        .body(Body::from(body.to_string()))
        .expect("request");
    send(state(Vec::new()), req).await
}

#[tokio::test]
async fn an_mcp_method_header_that_cannot_be_read_is_refused() {
    // MUTATION THIS CATCHES — and the bug this test was written for:
    // `h.get(name).and_then(|v| v.to_str().ok())`, which collapses a header of
    // non-ASCII bytes into `None`. `None` at the cross-check means "the header is
    // absent, so there is nothing to compare" — so the ONE `Mcp-Method` the
    // server could not read was the one it never checked, and a validation that
    // does not validate answers 200. The same shape `origin_ok` carried until
    // `an_origin_that_cannot_be_read_is_forbidden` pinned it shut.
    let (status, answer) =
        with_raw_header(headers::METHOD, UNREADABLE, envelope("tools/list", Some(1))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unreadable Mcp-Method must be refused, not skipped"
    );
    // THE ASSERTION THAT CARRIES THIS TEST. A lossy implementation that decoded
    // the bytes rather than refusing them would ALSO answer 400 — via
    // HEADER_MISMATCH, because the mangled string cannot equal `tools/list`. Only
    // the code tells a refusal apart from a mismatch.
    assert_eq!(answer["error"]["code"], codes::INVALID_PARAMS);

    // THE CONTROL: the same header, readable and agreeing, still passes. Without
    // it this test would also pass for "refuse every request carrying an
    // Mcp-Method header at all".
    let (ok_status, _) = send(
        state(Vec::new()),
        post()
            .header(headers::METHOD, "tools/list")
            .body(Body::from(envelope("tools/list", Some(1)).to_string()))
            .expect("request"),
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK);
}

#[tokio::test]
async fn an_mcp_name_header_that_cannot_be_read_is_refused() {
    // The `Mcp-Name` arm is the one that was newly reachable: it is cross-checked
    // only when BOTH sides are present, so an undecodable header took the
    // absent arm and the check evaporated silently.
    //
    // MUTATION THIS CATCHES, beyond the skip itself: answering the 401 this
    // request would otherwise reach. The cross-check runs BEFORE attestation, so
    // a refusal here preempts the missing-credential answer — asserting
    // UNAUTHORIZED/INVALID_REQUEST is what an unfixed server does.
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
    let (status, answer) = with_raw_header(headers::NAME, UNREADABLE, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(answer["error"]["code"], codes::INVALID_PARAMS);
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

/// Nothing in the ROUTER adds `WWW-Authenticate` on the way out, on EITHER path.
///
/// `every_login_failure_is_opaque_in_body_and_headers` and its enrolment twin
/// prove the two builders set no such header, over every code. Neither can prove a
/// LAYER does not add one afterwards, because neither goes through the router — so
/// this drives the real stack and checks what actually reaches the wire. One code
/// is enough for that question: layers do not vary by gRPC status.
#[tokio::test]
async fn no_layer_adds_an_authentication_challenge() {
    for (path, body) in [
        ("/auth/login", r#"{"username":"u","password":"p"}"#),
        ("/auth/enrol", r#"{"secret":"s","password":"p"}"#),
    ] {
        let req = HttpRequest::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let resp = router(state(Vec::new()))
            .oneshot(req)
            .await
            .expect("the router answers");
        assert!(
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_none(),
            "D72: no WWW-Authenticate on {path}"
        );
    }
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

// ---------------------------------------------------------------------------
// POST /auth/enrol (D73). The second unauthenticated path.
// ---------------------------------------------------------------------------

/// POST a body to `/auth/enrol` and read the raw answer.
async fn enrol_post(body: &str) -> (StatusCode, String) {
    let req = HttpRequest::builder()
        .method(Method::POST)
        .uri("/auth/enrol")
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
/// The same test `/auth/login` has, for the same reason: `yaadgaar enrol` POSTs
/// here, and a 404 would look exactly like the endpoint never having been written.
#[tokio::test]
async fn the_enrol_route_is_served() {
    let (status, _) = enrol_post(r#"{"secret":"s","password":"p","label":"l"}"#).await;
    assert_ne!(status, StatusCode::NOT_FOUND, "/auth/enrol must be routed");
}

/// ONE FAILURE, NOT THREE — over every code, in body and headers.
///
/// The contract calls `RedeemEnrolment` "UNAUTHENTICATED BY CONSTRUCTION" and
/// requires that an unknown secret, a spent one and an expired one are one
/// indistinguishable answer. The gateway must not undo that, and the way it could
/// is by giving one gRPC code a status or a body of its own.
///
/// `InvalidArgument` is the code this walks over that looks safest to single out —
/// the contract runs VALIDATION BEFORE LOOKUP so a password-policy refusal arrives
/// without the secret having been checked. It is also what a replayed idempotency
/// key with a different password returns, and THAT check runs only once the store
/// has confirmed the secret was good. One code, both sides of the lookup.
#[tokio::test]
async fn every_enrol_failure_is_opaque_in_body_and_headers() {
    let mut answers = std::collections::BTreeSet::new();
    let mut refusals = 0;

    for code in ALL_CODES {
        let resp = enrol_failure(code);
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

        if code == tonic::Code::Unauthenticated {
            refusals += 1;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        } else {
            answers.insert((status.as_u16(), body.clone()));
        }
        // NOTHING IN THE REFUSAL NAMES ONE OF THE THREE. A sentence that fitted
        // only "already spent" or only "expired" would be the hint the contract's
        // one-failure rule exists to withhold, and it would sit inside a body no
        // client-side test ever reads.
        for word in [
            "spent",
            "expired",
            "unknown",
            "redeemed already",
            "not found",
        ] {
            assert!(
                !body.contains(word),
                "{code:?} named one of the three failures: {body}"
            );
        }
    }

    assert_eq!(refusals, 1, "exactly one code is a refusal");
    assert_eq!(
        answers.len(),
        1,
        "every non-refusal code must answer one identical status AND body; got {answers:?}"
    );
    // **PINNED TO THE ACTUAL PAIR, not merely to its uniqueness.** A mutation
    // returning 401 for all 17 codes passed everything above: `refusals` counts
    // only `Unauthenticated`, and one collapsed answer stays one collapsed answer
    // whatever its value. Only the cross-endpoint test caught it, so this test did
    // not stand on its own. `login`'s twin closes the same gap the same way.
    assert_eq!(
        answers.into_iter().next().expect("one answer"),
        (
            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            r#"{"error":"enrolment is unavailable"}"#.to_string()
        ),
        "collapsing onto 401 would tell a person with a good secret it is bad \
         whenever iam is down"
    );
    let (status, body) = enrol_answer(tonic::Code::Unauthenticated);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, r#"{"error":"this enrolment cannot be redeemed"}"#);
}

/// **The two credential endpoints share the STATUS RULE and not the WORDS.**
///
/// This is the assertion that says which of "reuse" and "duplicate" happened, and
/// it relates the two endpoints to each other rather than each to a constant. A
/// second copy of the rule that drifted — a 400 added to one of them for
/// `InvalidArgument`, say — fails the first half. A copy-paste of login's bodies
/// into `enrol_answer` fails the second: telling a person redeeming an enrolment
/// that their "username or password" was invalid sends them looking for an account
/// they do not have yet.
#[test]
fn the_two_credential_endpoints_share_the_status_rule_and_not_the_words() {
    for code in ALL_CODES {
        assert_eq!(
            login_answer(code).0,
            enrol_answer(code).0,
            "{code:?} must reach the same status on both paths"
        );
        assert_ne!(
            login_answer(code).1,
            enrol_answer(code).1,
            "{code:?} must not answer an enrolment in login's words"
        );
    }
}

/// The rule itself, over every code: 401 for exactly one, one status for the rest.
///
/// `login_status_leaks_nothing_beyond_the_refusal` and
/// `every_other_grpc_code_is_the_same_opaque_status` assert this THROUGH
/// `/auth/login`. This asserts it on the function all three paths now share, so a
/// fourth caller added later inherits a rule that is already pinned.
#[test]
fn the_opaque_rule_admits_exactly_one_distinguishable_code() {
    let statuses: std::collections::BTreeSet<u16> = ALL_CODES
        .iter()
        .filter(|c| **c != tonic::Code::Unauthenticated)
        .map(|c| opaque_status(*c).as_u16())
        .collect();
    assert_eq!(
        statuses.len(),
        1,
        "no gRPC code other than UNAUTHENTICATED may get a status of its own; got {statuses:?}"
    );
    let opaque = *statuses.iter().next().expect("one status");
    assert_ne!(
        opaque,
        StatusCode::UNAUTHORIZED.as_u16(),
        "collapsing everything onto 401 tells a caller whose credential is good \
         that it is not, every time iam is down"
    );
    assert_eq!(
        opaque_status(tonic::Code::Unauthenticated),
        StatusCode::UNAUTHORIZED
    );
}

/// An unreachable `iam` is an opaque 503 with a fixed body, here too.
#[tokio::test]
async fn an_unreachable_iam_is_an_opaque_503_on_enrol() {
    let (status, body) = enrol_post(r#"{"secret":"s","password":"p","label":"l"}"#).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, r#"{"error":"enrolment is unavailable"}"#);
}

/// Malformed JSON is the gateway's own 400, not the upstream's problem.
#[tokio::test]
async fn malformed_json_is_a_400_on_enrol() {
    let (status, body) = enrol_post("{not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid JSON"), "got {body}");
}

/// A missing field is refused HERE rather than sent on as an empty string.
///
/// An empty `secret` would reach `iam`, fail to resolve, and come back as a 401 —
/// telling the person their enrolment cannot be redeemed when what was wrong was
/// the request. It also spends the constant Argon2id work the contract requires on
/// an attempt that could not have succeeded.
#[tokio::test]
async fn a_missing_field_is_a_400_on_enrol() {
    for body in [
        r#"{"password":"p","label":"l"}"#,
        r#"{"secret":"s","label":"l"}"#,
        r#"{}"#,
    ] {
        let (status, _) = enrol_post(body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} must be refused");
    }
    // `label` is NOT in that list, for the reason it is not in `login`'s: it only
    // names the machine, and requiring it would add a rule the proto does not
    // have. Absent, the request goes upstream — the unreachable-iam path here.
    let (status, _) = enrol_post(r#"{"secret":"s","password":"p"}"#).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// The wrong method on the enrolment path is 405, not 404.
#[tokio::test]
async fn only_post_reaches_enrol() {
    for method in [Method::GET, Method::DELETE, Method::PUT] {
        let req = HttpRequest::builder()
            .method(method.clone())
            .uri("/auth/enrol")
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

/// The body limit covers the enrolment route.
///
/// **`Router::layer` applies only to routes registered BEFORE it**, so a
/// `/auth/enrol` added below the `.layer(...)` call would be an unauthenticated
/// endpoint accepting a body of any size. The route order in `router()` is
/// load-bearing and nothing else would say so.
#[tokio::test]
async fn the_body_limit_covers_enrol() {
    let huge = format!(r#"{{"secret":"{}","password":"p"}}"#, "s".repeat(2_000_000));
    let (status, _) = enrol_post(&huge).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the 1MiB limit must apply to /auth/enrol"
    );
}

// ---------------------------------------------------------------------------
// Attestation: which of the two sources a header can reach.
// ---------------------------------------------------------------------------

/// One `tools/call` carrying a FULL set of caller-supplied identity headers, and
/// optionally a bearer token.
async fn tools_call_under(attestation: Attestation, credential: Option<&str>) -> StatusCode {
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
    let mut req = post()
        .header(headers::METHOD, "tools/call")
        .header(headers::NAME, "find_tasks")
        // A name nothing in this process could have chosen for itself.
        .header("x-yadgar-user", "forged-by-the-caller")
        .header("x-yadgar-project", "acme/demo")
        .header("x-yadgar-instance", "i-1");
    if let Some(credential) = credential {
        req = req.header(axum::http::header::AUTHORIZATION, credential);
    }
    let req = req.body(Body::from(body.to_string())).expect("request");
    send(state_with(attestation, Vec::new()), req).await.0
}

/// A self-asserted username attests on the DEVELOPMENT path and nowhere else.
///
/// **The assertion that matters relates the two paths to each other**, not each to
/// a constant: the same bytes, sent twice, must not be attested the same way.
/// Under `TrustedHeaders` the header IS the identity and the call proceeds; under
/// `Iam` the identity comes from the bearer token, this request carries none, and
/// nothing it claims about itself can stand in for one.
///
/// MUTATION THIS CATCHES: reading `x-yadgar-user` on the `iam` path as a fallback
/// when no token is presented. Anyone who can reach the port is then anyone they
/// name, which is the defect this change exists to close — and every other test in
/// this file would still pass.
#[tokio::test]
async fn a_user_header_attests_only_on_the_development_path() {
    let dev = tools_call_under(Attestation::TrustedHeaders, None).await;
    let real = tools_call_under(Attestation::Iam, None).await;
    assert_ne!(
        dev, real,
        "a forged x-yadgar-user must not buy the same answer under both sources"
    );
    assert_eq!(
        dev,
        StatusCode::OK,
        "the development path trusts the header"
    );
    assert_eq!(
        real,
        StatusCode::UNAUTHORIZED,
        "a claim is not a credential, and iam is never asked about one"
    );
}

// ---------------------------------------------------------------------------
// A stub `iam`, so that a credential which RESOLVES is reachable at all.
// ---------------------------------------------------------------------------

/// An `iam` that answers `ResolveCredential` with one canned response.
///
/// **Every other test in this file points `iam` at a closed port**, which makes
/// exactly two outcomes reachable on the attested path: "no credential was
/// presented" and "the transport failed". A credential that RESOLVES was
/// unreachable, and so was the answer that matters most — the one `iam` returns as
/// `Ok` with an empty `user_id` when a token is unknown, revoked or expired. That
/// gap hid an authentication bypass: the gateway read the negative answer as a
/// success and attested `user_id: ""`, so `Bearer <anything>` was a 200 and
/// revocation was inert.
///
/// The other eleven RPCs are refused rather than implemented. A test that reached
/// one would be a test asserting something this stub was never built to say.
struct StubIam {
    answer: crate::pb::yadgar::iam::v1::ResolveCredentialResponse,
    /// **HOW MANY TIMES `ResolveCredential` WAS ACTUALLY CALLED.** Without it the
    /// credential cache (D72) has no test that can fail: every assertion about the
    /// answer passes identically whether the answer came from `iam` or from a
    /// cache, and a cache that never caches would look exactly like this one.
    resolves: Arc<std::sync::atomic::AtomicUsize>,
}

/// Write the stub's whole `IamService` impl: one real method and twelve refusals.
///
/// **THE MACRO EMITS THE `#[tonic::async_trait]` ATTRIBUTE TOO, and it has to.**
/// That attribute is a proc macro that rewrites every `async fn` in the block into
/// the boxed future the generated trait actually declares. An attribute applied
/// AROUND a `macro_rules!` call sees an unexpanded token tree where those methods
/// should be, leaves them alone, and every one of them then fails to match the
/// trait's lifetimes. Generating the attribute from inside the macro puts the
/// expansion in the right order.
macro_rules! stub_iam_service {
    ($($method:ident($req:ident) -> $resp:ident;)*) => {
        #[tonic::async_trait]
        impl crate::pb::yadgar::iam::v1::iam_service_server::IamService for StubIam {
            async fn resolve_credential(
                &self,
                _: tonic::Request<crate::pb::yadgar::iam::v1::ResolveCredentialRequest>,
            ) -> Result<
                tonic::Response<crate::pb::yadgar::iam::v1::ResolveCredentialResponse>,
                tonic::Status,
            > {
                self.resolves
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(tonic::Response::new(self.answer.clone()))
            }

            $(
                async fn $method(
                    &self,
                    _: tonic::Request<crate::pb::yadgar::iam::v1::$req>,
                ) -> Result<tonic::Response<crate::pb::yadgar::iam::v1::$resp>, tonic::Status> {
                    Err(tonic::Status::unimplemented(
                        "this stub answers ResolveCredential and nothing else",
                    ))
                }
            )*
        }
    };
}

stub_iam_service! {
    login(LoginRequest) -> LoginResponse;
    redeem_enrolment(RedeemEnrolmentRequest) -> RedeemEnrolmentResponse;
    issue_credential(IssueCredentialRequest) -> IssueCredentialResponse;
    revoke_credential(RevokeCredentialRequest) -> RevokeCredentialResponse;
    list_credentials(ListCredentialsRequest) -> ListCredentialsResponse;
    issue_enrolment(IssueEnrolmentRequest) -> IssueEnrolmentResponse;
    create_user(CreateUserRequest) -> CreateUserResponse;
    set_user_admin(SetUserAdminRequest) -> SetUserAdminResponse;
    set_rate_limit_override(SetRateLimitOverrideRequest) -> SetRateLimitOverrideResponse;
    add_team_member(AddTeamMemberRequest) -> AddTeamMemberResponse;
    remove_team_member(RemoveTeamMemberRequest) -> RemoveTeamMemberResponse;
    set_inherited_setting(SetInheritedSettingRequest) -> SetInheritedSettingResponse;
}

/// Serve `answer` as `iam`, and return a channel pointed at it plus the counter of
/// how many `ResolveCredential` calls actually arrived.
///
/// `TcpIncoming::bind` on port 0 takes an ephemeral port and keeps the listener,
/// so there is no window between discovering the port and serving on it.
async fn stub_iam(
    answer: crate::pb::yadgar::iam::v1::ResolveCredentialResponse,
) -> (Channel, Arc<std::sync::atomic::AtomicUsize>) {
    let resolves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the stub binds");
    let addr = incoming.local_addr().expect("a bound port");
    let counted = Arc::clone(&resolves);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                crate::pb::yadgar::iam::v1::iam_service_server::IamServiceServer::new(StubIam {
                    answer,
                    resolves: counted,
                }),
            )
            .serve_with_incoming(incoming)
            .await
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy();
    (channel, resolves)
}

/// A gateway attesting against a stub `iam`, and that stub's call counter.
async fn state_resolving_to(
    answer: crate::pb::yadgar::iam::v1::ResolveCredentialResponse,
    ttl: std::time::Duration,
) -> (Arc<AppState>, Arc<std::sync::atomic::AtomicUsize>) {
    let (iam, resolves) = stub_iam(answer).await;
    let state = Arc::new(AppState {
        attestation: Attestation::Iam,
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        iam,
        credentials: crate::attest::Credentials::new(ttl),
        // GENEROUS, unlike the shared `state_with` above, and it is load-bearing.
        // Valkey is unreachable here so D74 falls back to its local floor of
        // `rate / maxReplicas`; at `1:1` that floor is one token, and the SECOND
        // `tools/call` in a caching test would be a 429 rather than whatever the
        // credential bought. The limiter is not what these tests are measuring.
        limiter: crate::limit::Limiter::new(
            "127.0.0.1:1",
            None,
            crate::limit::Limits::parse("task.read=600:600", "600:600").expect("the limits parse"),
            std::time::Duration::from_millis(200),
            6,
        )
        .expect("the limiter opens"),
        allowed_origins: Vec::new(),
        trust: crate::source::TrustBoundary::Undeclared,
        credential_limits: unlimited_credentials(),
    });
    (state, resolves)
}

/// One `tools/call` carrying `token`, against `state`.
async fn tools_call_with(state: Arc<AppState>, token: &str) -> StatusCode {
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
        .header("x-yadgar-project", "acme/demo")
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .expect("request");
    send(state, req).await.0
}

/// One `tools/call` with a bearer token, against an `iam` that answers `answer`.
///
/// A FRESH state each time, so the credential cache built into it is cold — these
/// callers are asserting what `iam`'s answer buys, and a warm cache would make that
/// depend on which test ran first.
async fn tools_call_resolving_to(
    answer: crate::pb::yadgar::iam::v1::ResolveCredentialResponse,
) -> StatusCode {
    let (state, _) = state_resolving_to(answer, std::time::Duration::from_secs(30)).await;
    tools_call_with(state, "some-token").await
}

/// **A CREDENTIAL THAT DOES NOT RESOLVE IS A 401, AND `iam` REPORTS THAT AS `Ok`.**
///
/// This is the test for an authentication bypass that shipped in review: `iam-db`
/// answers an unknown, revoked, expired or soft-deleted credential with an EMPTY
/// response rather than an error — `iamdb.proto` says "Empty user_id means no live
/// credential matched. NOT an error… one is a 401, the other is a 503" — and the
/// gateway is the caller that owes the 401. Reading it as a success attested
/// `user_id: ""` for `Bearer <anything>`, made revocation and expiry inert, and
/// collapsed every bypasser into one D12 namespace.
///
/// **The two answers differ only in the response `iam` gives**, which is what makes
/// this an assertion about the rule rather than about a constant: identical request,
/// identical stub, one field changed.
#[tokio::test]
async fn a_credential_that_iam_does_not_recognise_is_refused() {
    let live = crate::pb::yadgar::iam::v1::ResolveCredentialResponse {
        user_id: "u-that-iam-resolved".to_string(),
        valid_for_seconds: 300,
        ..Default::default()
    };
    // The negative answer, exactly as `iam` builds it: empty user, zero lifetime.
    let dead = crate::pb::yadgar::iam::v1::ResolveCredentialResponse::default();

    let attested = tools_call_resolving_to(live).await;
    let refused = tools_call_resolving_to(dead).await;

    assert_ne!(
        attested, refused,
        "a credential iam did not recognise must not buy what a live one buys"
    );
    assert_eq!(
        refused,
        StatusCode::UNAUTHORIZED,
        "an empty user_id is the negative answer and owes a 401"
    );
    // The live one gets through attestation and on to `task`, which is unreachable
    // here — a tool-level failure, which this server reports as 200 with `isError`.
    // The point is that it passed the boundary the other did not.
    assert_eq!(attested, StatusCode::OK);
}

/// **THE SECOND `tools/call` WITH THE SAME TOKEN REACHES `iam` ZERO TIMES.**
///
/// The end-to-end form of D72's cache, through the real handler, the real
/// `attest`, a real gRPC channel and a real server — so it asserts that the
/// gateway USES the cache, not merely that a cache exists. The unit tests in
/// `attest` drive `resolve_through` directly and could all pass while nothing
/// called it.
///
/// The assertion is the stub's own call counter. Asserting the status code
/// instead would pass identically with no cache at all, which is the check that
/// cannot fail.
#[tokio::test]
async fn a_repeated_token_is_resolved_once_and_a_different_one_is_not() {
    let (state, resolves) = state_resolving_to(
        crate::pb::yadgar::iam::v1::ResolveCredentialResponse {
            user_id: "u-8823-only-iam-knows".to_string(),
            valid_for_seconds: 300,
            ..Default::default()
        },
        std::time::Duration::from_secs(30),
    )
    .await;
    let count = || resolves.load(std::sync::atomic::Ordering::SeqCst);

    assert_eq!(
        tools_call_with(Arc::clone(&state), "tok-repeated").await,
        StatusCode::OK
    );
    assert_eq!(count(), 1, "the first call resolves its credential");

    assert_eq!(
        tools_call_with(Arc::clone(&state), "tok-repeated").await,
        StatusCode::OK
    );
    assert_eq!(
        count(),
        1,
        "the second call must not reach iam — that hop is what this cache removes"
    );

    // AND THE CACHE IS NOT A BLANKET SKIP. A token this replica has not seen is
    // still resolved, which is what separates a cache from an authentication hole.
    assert_eq!(
        tools_call_with(Arc::clone(&state), "tok-never-seen").await,
        StatusCode::OK
    );
    assert_eq!(count(), 2, "an unseen token is resolved");
}

/// A junk token is refused ONCE and then refused from memory.
///
/// Attestation runs before D74's limiter — the bucket keys on the resolved user,
/// so there is nothing to spend until the credential resolves — which makes an
/// unauthenticated caller the only writer nothing throttles. Not caching the
/// refusal would leave a token-guessing run as an unthrottled amplifier onto
/// `iam`, which is the failure this cache exists to stop.
///
/// **AND THE REFUSAL MUST STAY A REFUSAL.** The second 401 is the assertion that a
/// remembered negative answer never becomes an attestation.
#[tokio::test]
async fn a_refused_token_is_refused_from_memory_and_not_from_iam() {
    let (state, resolves) = state_resolving_to(
        // Exactly what `iam` sends for a token it does not recognise.
        crate::pb::yadgar::iam::v1::ResolveCredentialResponse::default(),
        std::time::Duration::from_secs(30),
    )
    .await;
    let count = || resolves.load(std::sync::atomic::Ordering::SeqCst);

    for _ in 0..3 {
        assert_eq!(
            tools_call_with(Arc::clone(&state), "definitely-not-a-real-token").await,
            StatusCode::UNAUTHORIZED,
            "a cached refusal is still a refusal"
        );
    }
    assert_eq!(
        count(),
        1,
        "three attempts with one junk token cost iam one lookup"
    );
}

/// With the cache disabled, every call resolves again.
///
/// The revert path, asserted rather than assumed: `credentialCache.ttlSeconds: 0`
/// is the way back to the pre-cache behaviour without a new image, and a value
/// that quietly kept caching would be a revert that did not revert.
#[tokio::test]
async fn a_zero_ttl_puts_the_round_trip_back_on_every_call() {
    let (state, resolves) = state_resolving_to(
        crate::pb::yadgar::iam::v1::ResolveCredentialResponse {
            user_id: "u-4402-only-iam-knows".to_string(),
            valid_for_seconds: 300,
            ..Default::default()
        },
        std::time::Duration::ZERO,
    )
    .await;

    for _ in 0..3 {
        assert_eq!(
            tools_call_with(Arc::clone(&state), "tok-repeated").await,
            StatusCode::OK
        );
    }
    assert_eq!(
        resolves.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "a zero TTL means the cache is off, not that it never expires"
    );
}

/// A zero lifetime is the same negative answer, from the other direction.
///
/// `iam` sets `valid_for_seconds: if resolved { 300 } else { 0 }`, so the two
/// signals always agree today. Checking both is what keeps an `iam` that later
/// regresses on one of them from being believed.
#[tokio::test]
async fn a_credential_with_no_lifetime_is_refused_even_with_a_user() {
    let inconsistent = crate::pb::yadgar::iam::v1::ResolveCredentialResponse {
        user_id: "u-with-no-lifetime".to_string(),
        valid_for_seconds: 0,
        ..Default::default()
    };
    assert_eq!(
        tools_call_resolving_to(inconsistent).await,
        StatusCode::UNAUTHORIZED
    );
}

/// A credential that cannot be RESOLVED is an upstream failure, not a refusal.
///
/// **This is `login_status`'s argument on the attested path.** `iam` here is
/// `connect_lazy` at a closed port, so the lookup fails in the transport and
/// arrives as `UNAVAILABLE`. Answering 401 would tell a person holding a perfectly
/// good token that it is invalid every time `iam` is down — and `yaadgaar` would
/// then discard a working credential and prompt for a fresh login. That is the
/// same lie `login_answer` rejects mapping-everything-to-401 for.
///
/// It is also the END-TO-END half of the property `opaque_status` pins over every
/// code: it proves the handler routes an upstream failure through that rule rather
/// than answering some other way.
#[tokio::test]
async fn a_credential_that_cannot_be_resolved_is_an_outage_and_not_a_refusal() {
    assert_eq!(
        tools_call_under(
            Attestation::Iam,
            Some("Bearer a-token-iam-cannot-be-asked-about")
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
    );
}

// ---------------------------------------------------------------------------
// What the handshake says this server IS.
// ---------------------------------------------------------------------------

/// `server/discover` reports the version the BUILD was stamped with.
///
/// **This handshake is the only thing an MCP client reads to learn what it is
/// talking to**, so a wrong number here is a wrong answer in a protocol response.
/// It served `env!("CARGO_PKG_VERSION")` — the manifest — and nothing has ever
/// written a version into that manifest: it said `0.1.0` while the tags ran to
/// `v0.8.1`. Every client was told `0.1.0` by a `v0.8.0` binary.
///
/// **BOTH ASSERTIONS ARE MUTATIONS THIS CATCHES**, which is the point of writing
/// two:
///
/// * Reverting the call site to `CARGO_PKG_VERSION` makes the first fail — the
///   stamped value and the manifest placeholder are different strings by
///   construction, in a release build and in a local one alike.
/// * Deleting the `cargo:rustc-env` line from `build.rs` makes `crate::VERSION`
///   fail to compile, so this file goes red rather than quietly asserting a
///   tautology. Verified by doing exactly that, not by reasoning about it.
///
/// The second assertion names the placeholder as a LITERAL rather than reading
/// `CARGO_PKG_VERSION`, so it keeps biting if somebody later writes a
/// plausible-looking number back into the manifest.
///
/// **`YADGAR_GATEWAY_VERSION=9.9.9 cargo test` is the end-to-end proof** that the
/// number travels from the environment through `build.rs` into the JSON, and it
/// needs no image build to run.
#[tokio::test]
async fn discover_reports_the_stamped_version_rather_than_the_manifest() {
    let (status, body) = rpc(DISCOVER, Some(1)).await;
    assert_eq!(status, StatusCode::OK);

    let reported = body["result"]["_meta"][meta_keys::SERVER_INFO]["version"]
        .as_str()
        .expect("serverInfo carries a version");

    assert_eq!(
        reported,
        crate::VERSION,
        "the handshake must report the stamped version"
    );
    assert_ne!(
        reported, "0.0.0",
        "the manifest placeholder must never reach a client"
    );
}
