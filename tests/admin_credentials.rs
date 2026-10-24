//! `/admin/list-credentials` and `/admin/revoke-credential` against an `iam`
//! that ANSWERS (ADR-0972 (2), ledger 1627).
//!
//! `src/http/tests/credentials.rs` holds the refusals that need no upstream.
//! This file holds the halves a refusal-only suite would pass without: what
//! reaches `iam` on the wire, what the 200 carries, and how each upstream
//! refusal is rendered.
//!
//! No Valkey: the limiter points at a closed port and every call takes D74's
//! degraded path, as in `admin_http.rs`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use tonic::transport::Channel;
use tower::ServiceExt;
use yadgar_gateway::admin::BootstrapToken;
use yadgar_gateway::attest::{Attestation, Credentials};
use yadgar_gateway::http::{router, AppState, CredentialLimits};
use yadgar_gateway::limit::{Bucket, Limiter, Limits};
use yadgar_gateway::pb::yadgar::common::v1::UnverifiedActor;
use yadgar_gateway::pb::yadgar::iam::v1::{
    iam_service_server::{IamService, IamServiceServer},
    Credential, ListCredentialsRequest, ListCredentialsResponse, ResolveCredentialResponse,
    RevokeCredentialRequest, RevokeCredentialResponse,
};
use yadgar_gateway::source::TrustBoundary;

/// The administrator every bearer resolves to.
const ADMIN_ID: &str = "yadgar:user:0192f3c1-8a4e-7c2d-9b11-5f0e7a3d84c6";
/// The user whose credentials are listed and revoked.
const OTHER_ID: &str = "yadgar:user:0192f3c1-8a4e-7c2d-9b11-000000000002";
const CREDENTIAL_ID: &str = "yadgar:credential:0192f3c1-8a4e-7c2d-9b11-000000000010";

const LIST: &str = "/admin/list-credentials";
const REVOKE: &str = "/admin/revoke-credential";

/// A bootstrap secret for this file only. Not a real credential.
const BOOTSTRAP_SECRET: &str = "a-bootstrap-token-for-this-file";
const BOOTSTRAP_HEADER: &str = "x-yadgar-bootstrap-token";

/// One RPC as it ARRIVED at the stub.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Received {
    List(ListCredentialsRequest),
    Revoke(RevokeCredentialRequest),
}

/// How the stub answers the two credential RPCs after recording the request.
#[derive(Clone, Default)]
enum Answer {
    #[default]
    Serve,
    Refuse(tonic::Status),
}

struct CredentialIam {
    is_admin: bool,
    answer: Answer,
    log: Arc<Mutex<Vec<Received>>>,
}

/// Two rows: one with an expiry and one without (a legacy row), so the
/// renderer's handling of both is visible.
fn rows() -> Vec<Credential> {
    vec![
        Credential {
            id: CREDENTIAL_ID.to_string(),
            label: "laptop".to_string(),
            created_at: Some(prost_types::Timestamp {
                seconds: 1_790_000_000,
                nanos: 0,
            }),
            expires_at: Some(prost_types::Timestamp {
                seconds: 1_797_776_000,
                nanos: 0,
            }),
        },
        Credential {
            id: "yadgar:credential:0192f3c1-8a4e-7c2d-9b11-000000000011".to_string(),
            label: "legacy".to_string(),
            created_at: Some(prost_types::Timestamp {
                seconds: 1_780_000_000,
                nanos: 0,
            }),
            expires_at: None,
        },
    ]
}

/// `admin_failure`'s body for every opaque upstream refusal.
const UNAVAILABLE: &str = r#"{"error":"the administrative service is unavailable"}"#;

const NEXT_PAGE: &str = "yadgar:credential:0192f3c1-8a4e-7c2d-9b11-000000000012";

macro_rules! credential_iam_service {
    ($($method:ident($req:ident) -> $resp:ident;)*) => {
        #[tonic::async_trait]
        impl IamService for CredentialIam {
            async fn resolve_credential(
                &self,
                _: tonic::Request<yadgar_gateway::pb::yadgar::iam::v1::ResolveCredentialRequest>,
            ) -> Result<tonic::Response<ResolveCredentialResponse>, tonic::Status> {
                Ok(tonic::Response::new(ResolveCredentialResponse {
                    user_id: ADMIN_ID.to_string(),
                    team_ids: Vec::new(),
                    valid_for_seconds: 300,
                    rate_limit_overrides: Vec::new(),
                    is_admin: self.is_admin,
                    owner_reads_own_record: None,
                }))
            }

            async fn list_credentials(
                &self,
                req: tonic::Request<ListCredentialsRequest>,
            ) -> Result<tonic::Response<ListCredentialsResponse>, tonic::Status> {
                self.log
                    .lock()
                    .expect("not poisoned")
                    .push(Received::List(req.into_inner()));
                match self.answer.clone() {
                    Answer::Serve => Ok(tonic::Response::new(ListCredentialsResponse {
                        credentials: rows(),
                        next_page_token: NEXT_PAGE.to_string(),
                    })),
                    Answer::Refuse(status) => Err(status),
                }
            }

            async fn revoke_credential(
                &self,
                req: tonic::Request<RevokeCredentialRequest>,
            ) -> Result<tonic::Response<RevokeCredentialResponse>, tonic::Status> {
                self.log
                    .lock()
                    .expect("not poisoned")
                    .push(Received::Revoke(req.into_inner()));
                match self.answer.clone() {
                    Answer::Serve => Ok(tonic::Response::new(RevokeCredentialResponse {})),
                    Answer::Refuse(status) => Err(status),
                }
            }

            $(
                async fn $method(
                    &self,
                    _: tonic::Request<yadgar_gateway::pb::yadgar::iam::v1::$req>,
                ) -> Result<
                    tonic::Response<yadgar_gateway::pb::yadgar::iam::v1::$resp>,
                    tonic::Status,
                > {
                    Err(tonic::Status::unimplemented("not served by this stub"))
                }
            )*
        }
    };
}

credential_iam_service! {
    login(LoginRequest) -> LoginResponse;
    redeem_enrolment(RedeemEnrolmentRequest) -> RedeemEnrolmentResponse;
    issue_credential(IssueCredentialRequest) -> IssueCredentialResponse;
    revoke_all_credentials(RevokeAllCredentialsRequest) -> RevokeAllCredentialsResponse;
    create_user(CreateUserRequest) -> CreateUserResponse;
    issue_enrolment(IssueEnrolmentRequest) -> IssueEnrolmentResponse;
    set_user_admin(SetUserAdminRequest) -> SetUserAdminResponse;
    set_rate_limit_override(SetRateLimitOverrideRequest) -> SetRateLimitOverrideResponse;
    add_team_member(AddTeamMemberRequest) -> AddTeamMemberResponse;
    sync_teams(SyncTeamsRequest) -> SyncTeamsResponse;
    remove_team_member(RemoveTeamMemberRequest) -> RemoveTeamMemberResponse;
    set_inherited_setting(SetInheritedSettingRequest) -> SetInheritedSettingResponse;
}

type Log = Arc<Mutex<Vec<Received>>>;

/// A gateway attesting against the stub, plus the log of what reached it.
async fn gateway(is_admin: bool, answer: Answer) -> (Arc<AppState>, Log) {
    let log: Log = Arc::default();
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the stub binds");
    let addr = incoming.local_addr().expect("a bound port");
    let served = Arc::clone(&log);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(IamServiceServer::new(CredentialIam {
                is_admin,
                answer,
                log: served,
            }))
            .serve_with_incoming(incoming)
            .await
    });
    let iam: Channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy();
    let wide = || CredentialLimits {
        attributed: Bucket {
            rate: 600.0,
            burst: 600.0,
        },
        unattributed: Bucket {
            rate: 600.0,
            burst: 600.0,
        },
    };
    let state = Arc::new(AppState {
        attestation: Attestation::Iam,
        task: yadgar_gateway::upstream::TaskUpstream::new(
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            std::time::Duration::from_secs(1),
        ),
        iam,
        credentials: Credentials::new(Duration::from_secs(30)),
        limiter: Limiter::new(
            "127.0.0.1:1",
            None,
            Limits::parse("task.write=600:600", "600:600").expect("the limits parse"),
            Duration::from_millis(200),
            1,
            None,
        )
        .expect("the limiter opens"),
        allowed_origins: Vec::new(),
        trust: TrustBoundary::Undeclared,
        credential_limits: wide(),
        admin_limits: wide(),
        bootstrap: BootstrapToken::from_secret(BOOTSTRAP_SECRET),
        tools_poll_interval: Duration::from_secs(600),
        projects: Arc::new(yadgar_gateway::project::Validator::new(
            yadgar_gateway::project::Registry::never_loaded(),
            yadgar_gateway::project::Mode::Counting,
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        )),
    });
    (state, log)
}

/// POST and return the status and the raw body text.
async fn post(
    state: Arc<AppState>,
    path: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json");
    for (name, value) in extra {
        req = req.header(*name, *value);
    }
    let req = req
        .body(Body::from(body.to_string()))
        .expect("the request builds");
    let resp = router(state)
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.expect("a body");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("a UTF-8 body"),
    )
}

/// The headers an attested administrator sends. The bearer is a fixture the
/// stub resolves whatever it says.
fn as_admin() -> Vec<(&'static str, &'static str)> {
    vec![("authorization", "Bearer a-real-token")]
}

fn list_body(user_id: &str) -> String {
    json!({ "user_id": user_id }).to_string()
}

fn revoke_body(user_id: &str, credential_id: &str) -> String {
    json!({ "user_id": user_id, "credential_id": credential_id }).to_string()
}

fn drained(log: &Log) -> Vec<Received> {
    std::mem::take(&mut *log.lock().expect("not poisoned"))
}

fn admin_actor() -> Option<UnverifiedActor> {
    Some(UnverifiedActor {
        user_id: ADMIN_ID.to_string(),
    })
}

// ---------------------------------------------------------------------------
// /admin/list-credentials
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_credentials_relays_the_user_the_page_and_the_actor() {
    let (state, log) = gateway(true, Answer::Serve).await;
    let body = json!({ "user_id": OTHER_ID, "page_token": NEXT_PAGE }).to_string();
    let (status, answer) = post(state, LIST, &body, &as_admin()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an administrator is served: {answer}"
    );
    assert_eq!(
        drained(&log),
        vec![Received::List(ListCredentialsRequest {
            user_id: OTHER_ID.to_string(),
            page_size: 0,
            page_token: NEXT_PAGE.to_string(),
            unverified_actor: admin_actor(),
        })],
        "the target, the page token and the resolved actor arrive at iam"
    );
}

#[tokio::test]
async fn list_credentials_answers_rows_in_rfc_3339_and_the_next_page() {
    let (state, _log) = gateway(true, Answer::Serve).await;
    let (status, answer) = post(state, LIST, &list_body(OTHER_ID), &as_admin()).await;
    assert_eq!(status, StatusCode::OK);
    let answer: Value = serde_json::from_str(&answer).expect("a JSON body");
    assert_eq!(
        answer,
        json!({
            "credentials": [
                {
                    "id": CREDENTIAL_ID,
                    "label": "laptop",
                    "created_at": "2026-09-21T14:13:20Z",
                    "expires_at": "2026-12-20T14:13:20Z",
                },
                {
                    "id": "yadgar:credential:0192f3c1-8a4e-7c2d-9b11-000000000011",
                    "label": "legacy",
                    "created_at": "2026-05-28T20:26:40Z",
                },
            ],
            "next_page_token": NEXT_PAGE,
        }),
        "an absent expiry is an absent key, never null and never a sentinel"
    );
}

#[tokio::test]
async fn a_listed_row_never_carries_a_token() {
    let (state, _log) = gateway(true, Answer::Serve).await;
    let (_, answer) = post(state, LIST, &list_body(OTHER_ID), &as_admin()).await;
    let answer: Value = serde_json::from_str(&answer).expect("a JSON body");
    for row in answer["credentials"].as_array().expect("an array") {
        for key in row.as_object().expect("an object").keys() {
            assert!(
                ["id", "label", "created_at", "expires_at"].contains(&key.as_str()),
                "a listed row carries only the four projected fields, got `{key}`"
            );
        }
    }
}

#[tokio::test]
async fn list_credentials_refuses_the_bootstrap_token_before_iam() {
    let (state, log) = gateway(true, Answer::Serve).await;
    let (status, _) = post(
        state,
        LIST,
        &list_body(OTHER_ID),
        &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the bootstrap token never lists"
    );
    assert!(drained(&log).is_empty(), "nothing reaches iam");
}

#[tokio::test]
async fn list_credentials_refuses_a_non_admin_bearer_before_iam() {
    let (state, log) = gateway(false, Answer::Serve).await;
    let (status, _) = post(state, LIST, &list_body(OTHER_ID), &as_admin()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no owner self-service (ADR-0972 (2))"
    );
    assert!(drained(&log).is_empty(), "nothing reaches iam");
}

#[tokio::test]
async fn list_credentials_refuses_a_bad_body_before_iam() {
    let bodies = [
        json!({ "user_id": OTHER_ID, "page_size": 5 }).to_string(),
        json!({ "user_id": OTHER_ID, "page_token": 7 }).to_string(),
        json!({ "user_id": OTHER_ID.to_uppercase() }).to_string(),
        json!({}).to_string(),
        "[]".to_string(),
    ];
    for body in bodies {
        let (state, log) = gateway(true, Answer::Serve).await;
        let (status, _) = post(state, LIST, &body, &as_admin()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} is a 400");
        assert!(drained(&log).is_empty(), "{body} reaches no iam");
    }
}

#[tokio::test]
async fn every_list_refusal_from_iam_is_opaque() {
    for refusal in [
        tonic::Status::not_found("no iam_user row"),
        tonic::Status::invalid_argument("`page_token` is malformed"),
    ] {
        let (state, _log) = gateway(true, Answer::Refuse(refusal)).await;
        let (status, body) = post(state, LIST, &list_body(OTHER_ID), &as_admin()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "ADR-0927");
        assert_eq!(body, UNAVAILABLE, "a fixed body, never iam's own words");
    }
}

// ---------------------------------------------------------------------------
// /admin/revoke-credential
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_credential_relays_the_owner_the_credential_and_the_actor() {
    let (state, log) = gateway(true, Answer::Serve).await;
    let (status, body) = post(
        state,
        REVOKE,
        &revoke_body(OTHER_ID, CREDENTIAL_ID),
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an administrator is served: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("a JSON body"),
        json!({ "user_id": OTHER_ID, "credential_id": CREDENTIAL_ID }),
    );
    let received = drained(&log);
    let [Received::Revoke(r)] = received.as_slice() else {
        panic!("exactly one RevokeCredential arrives, got {received:?}");
    };
    assert_eq!(r.user_id, OTHER_ID, "the owner is relayed (ADR-0972 (2))");
    assert_eq!(r.credential_id, CREDENTIAL_ID);
    assert_eq!(r.unverified_actor, admin_actor());
    assert!(
        r.idempotency.as_ref().is_some_and(|i| !i.key.is_empty()),
        "D9's key travels"
    );
}

#[tokio::test]
async fn an_admin_may_revoke_their_own_credential() {
    let (state, log) = gateway(true, Answer::Serve).await;
    let (status, body) = post(
        state,
        REVOKE,
        &revoke_body(ADMIN_ID, CREDENTIAL_ID),
        &as_admin(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "no self-target refusal on revoke-credential (ADR-0972 (2)): {body}"
    );
    assert_eq!(drained(&log).len(), 1, "the revoke reached iam");
}

#[tokio::test]
async fn a_credential_of_another_user_is_a_404() {
    let (state, _log) = gateway(
        true,
        Answer::Refuse(tonic::Status::not_found("no row carries that pair")),
    )
    .await;
    let (status, body) = post(
        state,
        REVOKE,
        &revoke_body(OTHER_ID, CREDENTIAL_ID),
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body, r#"{"error":"no such credential for this user"}"#,
        "one body for an unknown id and another user's id"
    );
}

#[tokio::test]
async fn revoke_credential_keeps_invalid_argument_opaque() {
    let (state, _log) = gateway(
        true,
        Answer::Refuse(tonic::Status::invalid_argument("bad id")),
    )
    .await;
    let (status, body) = post(
        state,
        REVOKE,
        &revoke_body(OTHER_ID, "not-an-id"),
        &as_admin(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "only NOT_FOUND has a ruling past ADR-0927 on this route"
    );
    assert_eq!(body, UNAVAILABLE);
}

#[tokio::test]
async fn an_unknown_key_is_a_400() {
    let cases = [
        (LIST, json!({ "user_id": OTHER_ID, "userid": OTHER_ID })),
        (
            REVOKE,
            json!({ "user_id": OTHER_ID, "credential_id": CREDENTIAL_ID, "all": true }),
        ),
    ];
    for (path, body) in cases {
        let (state, log) = gateway(true, Answer::Serve).await;
        let (status, _) = post(state, path, &body.to_string(), &as_admin()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{path}: an unknown key is a 400"
        );
        assert!(drained(&log).is_empty(), "{path}: nothing reaches iam");
    }
}

#[tokio::test]
async fn revoke_credential_refuses_a_bad_body_before_iam() {
    let bodies = [
        json!({ "user_id": OTHER_ID }).to_string(),
        json!({ "credential_id": CREDENTIAL_ID }).to_string(),
        json!({ "user_id": OTHER_ID, "credential_id": "" }).to_string(),
        json!({ "user_id": OTHER_ID, "credential_id": 1 }).to_string(),
        revoke_body(&OTHER_ID.to_uppercase(), CREDENTIAL_ID),
    ];
    for body in bodies {
        let (state, log) = gateway(true, Answer::Serve).await;
        let (status, _) = post(state, REVOKE, &body, &as_admin()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} is a 400");
        assert!(drained(&log).is_empty(), "{body} reaches no iam");
    }
}

#[tokio::test]
async fn revoke_credential_refuses_the_bootstrap_token_and_a_non_admin() {
    let (state, log) = gateway(true, Answer::Serve).await;
    let (status, _) = post(
        state,
        REVOKE,
        &revoke_body(OTHER_ID, CREDENTIAL_ID),
        &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the bootstrap token never revokes"
    );
    assert!(drained(&log).is_empty());

    let (state, log) = gateway(false, Answer::Serve).await;
    let (status, _) = post(
        state,
        REVOKE,
        &revoke_body(OTHER_ID, CREDENTIAL_ID),
        &as_admin(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-administrator never revokes"
    );
    assert!(drained(&log).is_empty());
}

/// An invariant guard: neither verb is an MCP tool (ADR-0492).
#[test]
fn the_credential_verbs_are_not_mcp_tools() {
    assert!(
        !yadgar_gateway::tools::SERVED
            .iter()
            .any(|name| name.contains("credential")),
        "an administrative verb is never an MCP tool (ADR-0492)"
    );
}
