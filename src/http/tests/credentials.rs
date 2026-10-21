//! `/admin/list-credentials` and `/admin/revoke-credential` (ADR-0972 (2))
//! without an answering `iam`: the refusals every administrative route must
//! make before any upstream call. `tests/admin_credentials.rs` holds the
//! halves that need an `iam` that answers.

use axum::body::Body;
use axum::http::{Method, Request as HttpRequest, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::{
    admin_post, router, state, state_bootstrapped, BOOTSTRAP_HEADER_NAME, BOOTSTRAP_SECRET,
};

const ID: &str = "yadgar:user:0192f3c1-8a4e-7c2d-9b11-5f0e7a3d84c6";
const CREDENTIAL: &str = "yadgar:credential:0192f3c1-8a4e-7c2d-9b11-000000000010";

/// Each new path with a body it accepts.
fn paths() -> [(&'static str, String); 2] {
    [
        (
            "/admin/list-credentials",
            json!({ "user_id": ID }).to_string(),
        ),
        (
            "/admin/revoke-credential",
            json!({ "user_id": ID, "credential_id": CREDENTIAL }).to_string(),
        ),
    ]
}

#[tokio::test]
async fn the_body_limit_covers_the_credential_routes() {
    let huge = format!(r#"{{"user_id":"{}"}}"#, "u".repeat(2_000_000));
    for (path, _) in paths() {
        let (status, _) = admin_post(state(Vec::new()), path, &huge, &[]).await;
        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{path} must be registered above the body-limit layer"
        );
    }
}

#[tokio::test]
async fn the_credential_routes_are_post_only() {
    for (path, _) in paths() {
        let req = HttpRequest::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .expect("the request builds");
        let status = router(state(Vec::new()))
            .oneshot(req)
            .await
            .expect("the router answers")
            .status();
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "GET on {path} is 405"
        );
    }
}

#[tokio::test]
async fn a_trusted_header_caller_is_not_an_administrator_here() {
    for (path, body) in paths() {
        let (status, _) = admin_post(
            state(Vec::new()),
            path,
            &body,
            &[
                ("x-yadgar-user", "ada"),
                (axum::http::header::AUTHORIZATION.as_str(), "Bearer a-token"),
            ],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} refuses a non-administrator"
        );
    }
}

/// The bootstrap token is refused BEFORE it is compared: the right token and
/// a wrong one get the same answer, so neither verb is an oracle for it.
#[tokio::test]
async fn the_bootstrap_token_is_refused_before_it_is_compared() {
    for (path, body) in paths() {
        let right = admin_post(
            state_bootstrapped(BOOTSTRAP_SECRET),
            path,
            &body,
            &[(BOOTSTRAP_HEADER_NAME, BOOTSTRAP_SECRET)],
        )
        .await;
        let wrong = admin_post(
            state_bootstrapped(BOOTSTRAP_SECRET),
            path,
            &body,
            &[(BOOTSTRAP_HEADER_NAME, "not-the-token")],
        )
        .await;
        assert_eq!(
            right.0,
            StatusCode::FORBIDDEN,
            "the bootstrap token never reaches {path}"
        );
        assert_eq!(
            right, wrong,
            "{path}: one answer for the right and the wrong token"
        );
    }
}
