//! D67 coverage: every method this gateway answers emits a record.
//!
//! **`Call::start` used to be reached only inside `tools_call`.** Two of the three
//! methods returned bytes nothing measured, and an authentication failure — the
//! outcome most worth seeing — emitted nothing at all, so a credential-stuffing
//! run looked exactly like silence.
//!
//! Asserted through the `metrics` facade rather than by reading stdout, because
//! the facade is where `Call::finish` actually lands: a `DebuggingRecorder`
//! installed for this test binary can be snapshotted in process. This is a
//! separate test BINARY on purpose — a global recorder can be installed once per
//! process, so it cannot share one with the rest of the suite.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use serde_json::{json, Value};
use tower::ServiceExt;
use yadgar_gateway::attest::Attestation;
use yadgar_gateway::http::{router, AppState};
use yadgar_gateway::mcp::{headers, meta_keys, PROTOCOL_VERSION};

fn state() -> Arc<AppState> {
    Arc::new(AppState {
        attestation: Attestation::TrustedHeaders,
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        // Never reached: nothing in this file posts to /auth/login.
        iam: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        // Never reached either: identity comes from a trusted header on this path,
        // so no credential is resolved and nothing is cached.
        credentials: yadgar_gateway::attest::Credentials::new(std::time::Duration::from_secs(30)),
        // Unreachable, so D74's limiter degrades and the call proceeds — which is
        // what keeps this file measuring instrumentation rather than rate limits.
        // A limiter that failed closed would turn the tools/call below into a 429
        // and the UNAUTHENTICATED record it asserts would never be emitted.
        limiter: yadgar_gateway::limit::Limiter::new(
            "127.0.0.1:1",
            None,
            yadgar_gateway::limit::Limits::parse("task.write=1:1", "1:1").expect("limits"),
            std::time::Duration::from_millis(200),
            6,
        )
        .expect("limiter"),
        allowed_origins: Vec::new(),
    })
}

fn envelope(method: &str, extra: Value) -> Value {
    let mut params = json!({
        "_meta": {
            meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
            meta_keys::CLIENT_CAPABILITIES: {},
        }
    });
    if let (Some(p), Some(e)) = (params.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            p.insert(k.clone(), v.clone());
        }
    }
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

async fn post(body: Value) -> StatusCode {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("content-type", "application/json")
        .header(headers::PROTOCOL_VERSION, PROTOCOL_VERSION)
        .body(Body::from(body.to_string()))
        .expect("request");
    router(state())
        .oneshot(req)
        .await
        .expect("the router answers")
        .status()
}

#[tokio::test]
async fn every_method_and_every_refusal_emits_a_call_record() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("install the test recorder");

    assert_eq!(
        post(envelope("tools/list", json!({}))).await,
        StatusCode::OK
    );
    assert_eq!(
        post(envelope("server/discover", json!({}))).await,
        StatusCode::OK
    );

    // No X-Yadgar-User header, so attestation refuses.
    assert_eq!(
        post(envelope(
            "tools/call",
            json!({ "name": "find_tasks", "arguments": {} })
        ))
        .await,
        StatusCode::UNAUTHORIZED
    );

    // An unknown METHOD, whose label would be a string the caller invented. It
    // must emit NOTHING: D67's cardinality rule means a caller cannot be allowed
    // to mint a time series.
    assert_eq!(
        post(envelope("tools/summon", json!({}))).await,
        StatusCode::OK
    );

    let calls: Vec<(String, String, u64)> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let key = key.key();
            if key.name() != yadgar_telemetry::metrics::CALLS {
                return None;
            }
            let label = |want: &str| {
                key.labels()
                    .find(|l| l.key() == want)
                    .map(|l| l.value().to_string())
                    .unwrap_or_default()
            };
            match value {
                DebugValue::Counter(n) => Some((label("tool"), label("outcome"), n)),
                _ => None,
            }
        })
        .collect();

    let recorded = |tool: &str, outcome: &str| {
        calls
            .iter()
            .any(|(t, o, n)| t == tool && o == outcome && *n >= 1)
    };

    assert!(
        recorded("tools/list", "OK"),
        "tools/list must emit a record; got {calls:?}"
    );
    assert!(
        recorded("server/discover", "OK"),
        "server/discover must emit a record; got {calls:?}"
    );
    assert!(
        recorded("find_tasks", "UNAUTHENTICATED"),
        "a refused call is still a call; got {calls:?}"
    );
    assert!(
        !calls.iter().any(|(t, _, _)| t == "tools/summon"),
        "an unknown method must mint no series; got {calls:?}"
    );
}
