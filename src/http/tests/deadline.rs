//! ADR-1019 on the `iam` paths: every outbound call STATES its deadline.
//!
//! The gateway has no caller deadline to inherit, so each `iam` call builds one
//! from the bound it already had — [`AUTH_DEADLINE`] on login, enrolment and
//! the administrative verbs, [`RESOLVE_DEADLINE`] on attestation — and sends it
//! as `grpc-timeout`, less [`DEADLINE_MARGIN`]. Without the header `iam` is
//! bounded only by its own ceilings and keeps working on a request the gateway
//! has already answered.
//!
//! Each case points `iam` at an upstream that never answers, then asserts what
//! that upstream was SENT and what the caller got back. The answer is the one
//! the gateway gave before the deadline was propagated: propagating it must not
//! change a user-visible error.
//!
//! REAL TIME, not a paused clock. `yadgar_dial::Deadline` measures with
//! `std::time::Instant`, which a paused tokio clock does not move, and the
//! hanging server's own tonic timer races the client's under auto-advance.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use tower::ServiceExt;
use yadgar_dial::DEADLINE_MARGIN;

use super::{
    admin_post, state_with_upstreams, tools_call_with, BOOTSTRAP_HEADER_NAME, BOOTSTRAP_SECRET,
};
use crate::attest::RESOLVE_DEADLINE;
use crate::http::{router, AppState, AUTH_DEADLINE};
use crate::upstream::hang::{self, Seen};

/// How far below the stated value the header may read on arrival: the time the
/// request spent between `Deadline::after` and the hanging upstream's read.
const SLACK: Duration = Duration::from_secs(1);

/// A gateway whose `iam` never answers, and that upstream's arrival log.
async fn hanging_iam() -> (Arc<AppState>, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let iam = hang::serve(hang::Iam(Arc::clone(&seen))).await;
    let task = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
    (
        state_with_upstreams(iam, task, Duration::from_secs(30)),
        seen,
    )
}

/// The same gateway, holding this file's bootstrap token.
async fn hanging_iam_bootstrapped() -> (Arc<AppState>, Arc<Seen>) {
    let (state, seen) = hanging_iam().await;
    let mut state = Arc::try_unwrap(state)
        .ok()
        .expect("the only handle on a fresh state");
    state.bootstrap = crate::admin::BootstrapToken::from_secret(BOOTSTRAP_SECRET);
    (Arc::new(state), seen)
}

/// POST `body` to `path` and read the answer as text.
async fn post_text(state: Arc<AppState>, path: &str, body: &str) -> (StatusCode, String) {
    let req = HttpRequest::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router(state)
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read the body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// ONE call reached `rpc`, stating at most `deadline - DEADLINE_MARGIN`.
fn assert_stated(seen: &Seen, rpc: &str, deadline: Duration) {
    let arrivals = seen.arrivals();
    assert_eq!(
        arrivals.iter().map(|a| a.path.as_str()).collect::<Vec<_>>(),
        [rpc],
        "exactly one {rpc} must reach iam"
    );
    let stated = arrivals[0]
        .timeout
        .unwrap_or_else(|| panic!("{rpc} must carry grpc-timeout (ADR-1019)"));
    assert!(
        stated <= deadline - DEADLINE_MARGIN,
        "{rpc} stated {stated:?}; the margin keeps it at or below {:?}",
        deadline - DEADLINE_MARGIN
    );
    assert!(
        stated >= deadline - SLACK,
        "{rpc} stated {stated:?}, far below its {deadline:?} deadline"
    );
}

/// The call ended at its deadline, not at the 30 s ceiling.
fn assert_ended_within(started: Instant, deadline: Duration) {
    let took = started.elapsed();
    assert!(
        took < deadline + SLACK,
        "the call took {took:?} against a {deadline:?} deadline"
    );
}

#[tokio::test]
async fn login_states_auth_deadline_and_answers_its_timeout() {
    let (state, seen) = hanging_iam().await;
    let started = Instant::now();
    let (status, body) = post_text(
        state,
        "/auth/login",
        r#"{"username":"u","password":"p","label":"l"}"#,
    )
    .await;
    assert_ended_within(started, AUTH_DEADLINE);
    assert_eq!(
        (status, body.as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"login is unavailable"}"#
        ),
        "a stalled iam is the same opaque 503 it always was"
    );
    assert_stated(&seen, "/yadgar.iam.v1.IamService/Login", AUTH_DEADLINE);
}

#[tokio::test]
async fn enrol_states_auth_deadline_and_answers_its_timeout() {
    let (state, seen) = hanging_iam().await;
    let started = Instant::now();
    let (status, body) = post_text(
        state,
        "/auth/enrol",
        r#"{"secret":"s","password":"p","label":"l"}"#,
    )
    .await;
    assert_ended_within(started, AUTH_DEADLINE);
    assert_eq!(
        (status, body.as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"enrolment is unavailable"}"#
        ),
        "a stalled iam is the same opaque 503 it always was"
    );
    assert_stated(
        &seen,
        "/yadgar.iam.v1.IamService/RedeemEnrolment",
        AUTH_DEADLINE,
    );
}

#[tokio::test]
async fn an_admin_verb_states_auth_deadline_and_answers_its_timeout() {
    let (state, seen) = hanging_iam_bootstrapped().await;
    let started = Instant::now();
    let (status, answer) = admin_post(
        state,
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada","is_admin":true}"#,
        &[(BOOTSTRAP_HEADER_NAME, BOOTSTRAP_SECRET)],
    )
    .await;
    assert_ended_within(started, AUTH_DEADLINE);
    assert_eq!(
        (status, answer.to_string().as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"the administrative service is unavailable"}"#
        ),
        "a stalled iam is admin_timeout's opaque 503"
    );
    assert_stated(&seen, "/yadgar.iam.v1.IamService/CreateUser", AUTH_DEADLINE);
}

/// The deadline is built BEFORE the credential cache is consulted, so the
/// wait on a cache miss counts against it.
#[tokio::test]
async fn attestation_states_resolve_deadline_and_answers_an_outage() {
    let (state, seen) = hanging_iam().await;
    let started = Instant::now();
    let status = tools_call_with(state, "a-token-iam-never-answers-for").await;
    assert_ended_within(started, RESOLVE_DEADLINE);
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a credential iam cannot resolve in time is an outage, not a refusal"
    );
    assert_stated(
        &seen,
        "/yadgar.iam.v1.IamService/ResolveCredential",
        RESOLVE_DEADLINE,
    );
}
