//! ADR-0959 through the real router: `GET /auth/whoami` answers the caller's
//! OWN `user_id` and `account_segment`, takes nothing that names another user,
//! and refuses a missing, unknown, revoked or unverifiable credential with the
//! SAME BYTES an attested `/admin` route gives.

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{state_with, state_with_upstreams, stub_iam_refusing};
use crate::attest::Attestation;
use crate::http::{router, AppState};
use crate::pb::yadgar::iam::v1::ResolveCredentialResponse;
use crate::project::account_segment;

const PATH: &str = "/auth/whoami";
/// The caller, spelt exactly as `iam-db` mints an id.
const ALICE: &str = "yadgar:user:0192f0a0-0000-7000-8000-00000000a11c";
/// Somebody else, also canonical, so a forged claim is a WELL-FORMED one.
const BOB: &str = "yadgar:user:0192f0a0-0000-7000-9000-000000000b0b";

/// The whole response: status, every header in order, and the RAW body — so
/// "byte-identical" covers all three rather than a parsed reading of one.
#[derive(Debug, PartialEq, Eq)]
struct Whole {
    status: StatusCode,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

async fn whole(state: std::sync::Arc<AppState>, req: HttpRequest<Body>) -> Whole {
    let resp = router(state)
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
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

/// A live credential for `user_id`.
fn live(user_id: &str) -> ResolveCredentialResponse {
    ResolveCredentialResponse {
        user_id: user_id.to_string(),
        valid_for_seconds: 300,
        ..Default::default()
    }
}

/// A gateway attesting against a stub `iam` that answers `answer`, or refuses
/// with `refusal`. A FRESH state, so the credential cache is cold.
async fn resolving(
    answer: ResolveCredentialResponse,
    refusal: Option<tonic::Code>,
) -> std::sync::Arc<AppState> {
    let (iam, _) = stub_iam_refusing(answer, refusal).await;
    state_with_upstreams(
        iam,
        tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        std::time::Duration::from_secs(30),
    )
}

/// `GET /auth/whoami`, with `token` as the bearer when present.
fn whoami(token: Option<&str>) -> axum::http::request::Builder {
    let mut req = HttpRequest::builder().method(Method::GET).uri(PATH);
    if let Some(token) = token {
        req = req.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    req
}

/// The SIBLING: an attested `/admin` request that reaches `authorise`'s
/// attested branch. A valid body and no bootstrap header, so the only thing
/// that can refuse it is the credential.
fn sibling(token: Option<&str>) -> HttpRequest<Body> {
    let mut req = HttpRequest::builder()
        .method(Method::POST)
        .uri("/admin/create-user")
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    req.body(Body::from(
        json!({ "external_id": "e", "display_name": "d" }).to_string(),
    ))
    .expect("request")
}

fn parsed(w: &Whole) -> Value {
    serde_json::from_slice(&w.body).expect("a JSON body")
}

#[tokio::test]
async fn whoami_answers_the_callers_own_id_and_segment() {
    let state = resolving(live(ALICE), None).await;
    let got = whole(
        state,
        whoami(Some("alice-token")).body(Body::empty()).unwrap(),
    )
    .await;

    assert_eq!(got.status, StatusCode::OK, "{got:?}");
    let body = parsed(&got);
    assert_eq!(
        body,
        json!({
            "user_id": ALICE,
            "account_segment": "0192f0a0-0000-7000-8000-00000000a11c",
        }),
        "exactly the two keys ADR-0959 names, and nothing else"
    );
    assert!(got
        .headers
        .iter()
        .any(|(k, v)| k == "content-type" && v == b"application/json"));
}

/// The segment is `account_segment`'s answer and not a second derivation of it.
#[tokio::test]
async fn the_segment_is_account_segment_of_the_user_id() {
    let state = resolving(live(ALICE), None).await;
    let got = whole(state, whoami(Some("t")).body(Body::empty()).unwrap()).await;
    let body = parsed(&got);
    let user_id = body["user_id"].as_str().expect("a user_id");
    assert_eq!(
        body["account_segment"].as_str(),
        account_segment(user_id),
        "{body}"
    );
}

/// MUTATION THIS CATCHES: a handler that believes `x-yadgar-user`, or a
/// `user_id` query parameter, over the credential. Both claims name a real,
/// canonical account, and neither may move the answer.
#[tokio::test]
async fn no_claim_in_the_request_can_name_another_user() {
    let state = resolving(live(ALICE), None).await;
    let req = HttpRequest::builder()
        .method(Method::GET)
        .uri(format!("{PATH}?user_id={BOB}&account_segment=x"))
        .header(axum::http::header::AUTHORIZATION, "Bearer alice-token")
        .header("x-yadgar-user", BOB)
        .body(Body::empty())
        .unwrap();
    let got = whole(state, req).await;

    assert_eq!(got.status, StatusCode::OK, "{got:?}");
    assert_eq!(
        parsed(&got)["user_id"],
        ALICE,
        "the credential names the caller"
    );
}

/// One refusal case: its name, the bearer token, what `iam` answers (`None`
/// for an unreachable `iam`), and the status `iam` refuses with instead.
type Case = (
    &'static str,
    Option<&'static str>,
    Option<ResolveCredentialResponse>,
    Option<tonic::Code>,
);

/// THE REFUSAL PARITY ADR-0959 REQUIRES: every dead credential gets, byte for
/// byte, what `/admin/create-user` gives the same credential.
///
/// MUTATION THIS CATCHES: a handler that skips attestation and answers
/// anything — it is a 200 where the sibling is a 401.
#[tokio::test]
async fn every_dead_credential_is_refused_with_the_siblings_exact_bytes() {
    let iam_unreachable = || {
        state_with_upstreams(
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            std::time::Duration::from_secs(30),
        )
    };
    let cases: [Case; 4] = [
        // No `Authorization` at all: refused before `iam` is asked.
        ("no token", None, Some(live(ALICE)), None),
        // `iam`'s negative answer: an empty `Ok` (unknown, expired, revoked).
        (
            "bad token",
            Some("nobody"),
            Some(ResolveCredentialResponse::default()),
            None,
        ),
        // A revoked token answered as a status, as the invalidation fake does.
        (
            "revoked token",
            Some("revoked"),
            Some(live(ALICE)),
            Some(tonic::Code::Unauthenticated),
        ),
        // `iam` down: the opaque outage answer, which must match too.
        ("iam unreachable", Some("any"), None, None),
    ];
    for (name, token, answer, refusal) in cases {
        let (mine, theirs) = match answer {
            Some(answer) => (
                resolving(answer.clone(), refusal).await,
                resolving(answer, refusal).await,
            ),
            None => (iam_unreachable(), iam_unreachable()),
        };
        let got = whole(mine, whoami(token).body(Body::empty()).unwrap()).await;
        let want = whole(theirs, sibling(token)).await;
        assert_ne!(got.status, StatusCode::OK, "{name}: refused, not served");
        assert_eq!(
            got, want,
            "{name}: whoami must refuse with the sibling's bytes"
        );
    }
}

/// The three credential refusals are 401s and not merely equal to something.
#[tokio::test]
async fn a_dead_credential_is_a_401() {
    for (token, refusal) in [
        (None, None),
        (Some("nobody"), None),
        (Some("revoked"), Some(tonic::Code::Unauthenticated)),
    ] {
        let answer = if refusal.is_some() || token.is_none() {
            live(ALICE)
        } else {
            ResolveCredentialResponse::default()
        };
        let got = whole(
            resolving(answer, refusal).await,
            whoami(token).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(got.status, StatusCode::UNAUTHORIZED, "{token:?}: {got:?}");
    }
}

/// A non-canonical id names no account, so it has no segment: `null`, never
/// `""` (which would build `local//…`). Reachable only on the development
/// trusted-headers path, where the id is the header as sent.
#[tokio::test]
async fn a_non_canonical_id_has_a_null_segment() {
    let state = state_with(Attestation::TrustedHeaders, Vec::new());
    let req = whoami(None)
        .header("x-yadgar-user", "u-dev")
        .body(Body::empty())
        .unwrap();
    let got = whole(state, req).await;
    assert_eq!(got.status, StatusCode::OK, "{got:?}");
    assert_eq!(
        parsed(&got),
        json!({ "user_id": "u-dev", "account_segment": null })
    );
}

/// `guard` is wired: an unlisted browser `Origin` is refused before anything.
#[tokio::test]
async fn an_unlisted_origin_is_refused() {
    let state = resolving(live(ALICE), None).await;
    let req = whoami(Some("t"))
        .header(axum::http::header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(whole(state, req).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn whoami_is_get_only() {
    let state = resolving(live(ALICE), None).await;
    let req = HttpRequest::builder()
        .method(Method::POST)
        .uri(PATH)
        .header(axum::http::header::AUTHORIZATION, "Bearer t")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        whole(state, req).await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}
