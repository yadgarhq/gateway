//! `/admin/revoke-credentials` (ADR-0945) without an answering `iam`: the
//! canonical id check as a function, and the refusals every administrative
//! route must make before any upstream call.

use axum::body::Body;
use axum::http::{Method, Request as HttpRequest, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::super::admin::revoke::is_canonical_user_id;
use super::{
    admin_post, router, state, state_bootstrapped, BOOTSTRAP_HEADER_NAME, BOOTSTRAP_SECRET,
};

const PATH: &str = "/admin/revoke-credentials";
const ID: &str = "yadgar:user:0192f3c1-8a4e-7c2d-9b11-5f0e7a3d84c6";

#[test]
fn an_id_iam_db_mints_is_canonical() {
    assert!(
        is_canonical_user_id(ID),
        "the form iam-db mints must be accepted"
    );
    let minted = format!("yadgar:user:{}", uuid::Uuid::now_v7());
    assert!(
        is_canonical_user_id(&minted),
        "a freshly minted uuidv7 id must be accepted"
    );
}

#[test]
fn every_other_spelling_of_the_same_id_is_refused() {
    let bare = ID.trim_start_matches("yadgar:user:");
    let refused = [
        ID.to_uppercase(),
        ID.replace("5f0e", "5F0E"),
        ID.replace("yadgar:user:", "Yadgar:user:"),
        format!("{ID} "),
        format!(" {ID}"),
        format!("{ID}\n"),
        bare.to_string(),
        format!("yadgar:user:{{{bare}}}"),
        format!("yadgar:user:urn:uuid:{bare}"),
        ID.replace('-', ""),
        ID.replace("-7c2d-", "-4c2d-"),
        ID.replace("-9b11-", "-cb11-"),
        format!("{ID}0"),
        ID[..ID.len() - 1].to_string(),
        ID.replace('c', "\u{0107}"),
        String::new(),
    ];
    for id in refused {
        assert!(
            !is_canonical_user_id(&id),
            "a non-canonical spelling must be refused"
        );
    }
}

#[tokio::test]
async fn the_body_limit_covers_revoke_credentials() {
    let huge = format!(r#"{{"user_id":"{}"}}"#, "u".repeat(2_000_000));
    let (status, _) = admin_post(state(Vec::new()), PATH, &huge, &[]).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the route must be registered above the body-limit layer"
    );
}

#[tokio::test]
async fn revoke_credentials_is_post_only() {
    let req = HttpRequest::builder()
        .method(Method::GET)
        .uri(PATH)
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
        "GET on revoke-credentials is 405"
    );
}

#[tokio::test]
async fn a_trusted_header_caller_is_not_an_administrator_here() {
    let (status, _) = admin_post(
        state(Vec::new()),
        PATH,
        &format!(r#"{{"user_id":"{ID}"}}"#),
        &[
            ("x-yadgar-user", "ada"),
            (axum::http::header::AUTHORIZATION.as_str(), "Bearer a-token"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a caller who is not an administrator must be refused"
    );
}

#[tokio::test]
async fn an_absent_bootstrap_secret_still_names_the_configuration() {
    let (status, answer) = admin_post(
        state(Vec::new()),
        PATH,
        &format!(r#"{{"user_id":"{ID}"}}"#),
        &[(BOOTSTRAP_HEADER_NAME, BOOTSTRAP_SECRET)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unmounted Secret disables the bootstrap path on every verb"
    );
    assert_eq!(
        answer["error"],
        json!("the bootstrap token is not configured"),
        "the refusal names the missing configuration"
    );
}

/// The bootstrap token is refused BEFORE it is compared: the right token and
/// a wrong one get the same answer, so this verb is no oracle for the secret.
#[tokio::test]
async fn the_bootstrap_token_is_refused_before_it_is_compared() {
    let body = format!(r#"{{"user_id":"{ID}"}}"#);
    let (right, right_answer) = admin_post(
        state_bootstrapped(BOOTSTRAP_SECRET),
        PATH,
        &body,
        &[(BOOTSTRAP_HEADER_NAME, BOOTSTRAP_SECRET)],
    )
    .await;
    let (wrong, wrong_answer) = admin_post(
        state_bootstrapped(BOOTSTRAP_SECRET),
        PATH,
        &body,
        &[(BOOTSTRAP_HEADER_NAME, "not-the-token")],
    )
    .await;
    assert_eq!(
        right,
        StatusCode::FORBIDDEN,
        "the bootstrap token never reaches revoke-credentials"
    );
    assert_eq!(
        (right, right_answer),
        (wrong, wrong_answer),
        "the right and the wrong token must get one answer"
    );
}
