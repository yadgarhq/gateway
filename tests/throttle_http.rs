//! D74 at the HTTP seam: what a throttled caller actually receives.
//!
//! `rate_limit.rs` measures the bucket; this measures the wiring — the status
//! code, the `Retry-After` header, the JSON-RPC body, and the D67 record. All
//! four are things a client or an operator keys on, and all four were decided in
//! `http.rs` where a unit test of the limiter cannot reach them.
//!
//! **A SEPARATE TEST BINARY on purpose**, for the reason `telemetry.rs` already
//! gives: a global metrics recorder can be installed once per process, so it
//! cannot share one with the rest of the suite.
//!
//! Needs a real Valkey and therefore does not run in CI today — see the module
//! comment on `rate_limit.rs` for how to run it, and why an absent Valkey is a
//! skip locally and a failure on a runner.

use std::sync::Arc;
use std::time::Duration;

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use serde_json::{json, Value};
use tower::ServiceExt;
use yadgar_gateway::attest::{Attestation, Credentials};
use yadgar_gateway::http::{router, AppState};
use yadgar_gateway::limit::{Limiter, Limits};
use yadgar_gateway::mcp::{codes, headers, meta_keys, PROTOCOL_VERSION};

fn envelope(tool: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: {},
            },
            "name": tool,
            "arguments": { "title": "t" },
        }
    })
}

/// One `tools/call` as an attested caller, returning the status, the
/// `Retry-After` header if there is one, and the body.
async fn call(state: Arc<AppState>, user: &str) -> (StatusCode, Option<String>, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("content-type", "application/json")
        .header(headers::PROTOCOL_VERSION, PROTOCOL_VERSION)
        .header("x-yadgar-user", user)
        .header("x-yadgar-project", "acme/demo")
        .body(Body::from(envelope("create_task").to_string()))
        .expect("request");

    let resp = router(state)
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.expect("a body");
    (
        status,
        retry_after,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_bucket_is_429_with_an_exact_retry_after_and_a_record() {
    let Some(addr) = common::addr() else { return };

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("install the test recorder");

    // A bucket of exactly one, refilling once every ten seconds: the second call
    // in this test is throttled, and stays throttled for the whole run.
    //
    // THE USER is what is made unique, not the module. A bucket is keyed on
    // `(user, module, kind)` and the module is decided by `tools::module_for`,
    // which answers `task` for every tool this gateway serves — so the only axis
    // a test can vary to get a fresh key is the caller. Without this the second
    // run of this file starts against the bucket the first run emptied, ten
    // seconds from its next token.
    let user = format!("test-{}", uuid::Uuid::now_v7().simple());
    let limits = Limits::parse("task.write=0.1:1", "0.1:1").expect("limits");
    let state = Arc::new(AppState {
        attestation: Attestation::TrustedHeaders,
        // Unreachable, and never reached: `create_task` fails as a TOOL error
        // after the token is spent, which is all this test needs. What matters is
        // that the token WAS spent before the upstream was touched at all — D74
        // enforces at the gateway precisely so a refused call costs `task`
        // nothing.
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        // Never reached. /auth/login spends no token at all — D74's buckets key
        // on a user, and a login has none yet.
        iam: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        // Never reached either: the trusted-header path resolves no credential, so
        // there is nothing to cache. Present because AppState holds it, not because
        // this file exercises it.
        credentials: Credentials::new(Duration::from_secs(30)),
        limiter: Limiter::new(&addr, None, limits, Duration::from_millis(500), 6).expect("limiter"),
        allowed_origins: Vec::new(),
    });

    let (first, _, _) = call(Arc::clone(&state), &user).await;
    assert_eq!(
        first,
        StatusCode::OK,
        "the first call spends the only token and is served"
    );

    let (status, retry_after, body) = call(Arc::clone(&state), &user).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "an empty bucket is 429, not a tool-level error: the request was well formed and the \
         answer is transport-level backpressure a client must honour"
    );
    assert_eq!(
        retry_after.as_deref(),
        Some("10"),
        "Retry-After is whole seconds (RFC 9110) and never zero"
    );
    assert_eq!(
        body["error"]["code"],
        json!(codes::RATE_LIMITED),
        "and the JSON-RPC body says the same thing to a client that reads bodies"
    );
    // EXACT rather than shared: this is the caller's own wait, so a hundred
    // throttled callers are not all sent back at one instant.
    let precise = body["error"]["data"]["retryAfterMs"]
        .as_u64()
        .expect("retryAfterMs is a number");
    assert!(
        (9_000..=10_000).contains(&precise),
        "expected about 10s in milliseconds, got {precise}"
    );

    // A THROTTLED CALL IS A CALL. Without the record, a throttling storm looks
    // exactly like silence — the reading D15's retirement rule would act on, and
    // the failure shape D76 names.
    let recorded = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .any(|(key, _, _, value)| {
            let key = key.key();
            // BOTH labels, not just the outcome. The recorder is global to this
            // test binary, so a later test throttling a different tool would
            // otherwise satisfy this assertion and quietly make it vacuous —
            // which is why `telemetry.rs` matches on the pair too.
            let label = |want: &str| {
                key.labels()
                    .find(|l| l.key() == want)
                    .map(|l| l.value().to_string())
                    .unwrap_or_default()
            };
            key.name() == yadgar_telemetry::metrics::CALLS
                && label("outcome") == "RESOURCE_EXHAUSTED"
                && label("tool") == "create_task"
                && matches!(value, DebugValue::Counter(n) if n >= 1)
        });
    assert!(recorded, "a throttled call must emit a D67 record");
}
