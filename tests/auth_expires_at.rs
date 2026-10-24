//! `/auth/login` and `/auth/enrol` against an `iam` that ANSWERS (ADR-0972
//! (3) and (4), ledger 1628 and 1734).
//!
//! `src/http/tests.rs` points `iam` at a closed port, so no success and no
//! upstream refusal body is reachable there. This file holds the three halves
//! that need a reply: `expires_at` is echoed in RFC 3339, an absent one is an
//! absent key, and a redemption whose mint lost the epoch race answers 409
//! with the fixed "password is set" sentence.
//!
//! No Valkey: the limiter points at a closed port and every call takes D74's
//! degraded path, as in `admin_http.rs`.

use std::sync::Arc;
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
use yadgar_gateway::pb::yadgar::iam::v1::{
    iam_service_server::{IamService, IamServiceServer},
    LoginRequest, LoginResponse, RedeemEnrolmentRequest, RedeemEnrolmentResponse,
};
use yadgar_gateway::source::TrustBoundary;

/// The token the stub mints. Not base64-shaped, so gitleaks does not read it
/// as a real credential.
const STUB_TOKEN: &str = "the-stub-bearer";
const USERNAME: &str = "ada";

/// 2026-12-20T14:13:20Z.
const EXPIRY_SECONDS: i64 = 1_797_776_000;
const EXPIRY_RFC_3339: &str = "2026-12-20T14:13:20Z";

/// What the stub answers both RPCs with.
#[derive(Clone)]
enum Answer {
    /// Mint, carrying this expiry or none.
    Mint(Option<i64>),
    /// Refuse with this status.
    Refuse(tonic::Status),
}

struct AuthIam(Answer);

impl AuthIam {
    fn expiry(at: Option<i64>) -> Option<prost_types::Timestamp> {
        at.map(|seconds| prost_types::Timestamp { seconds, nanos: 0 })
    }
}

macro_rules! auth_iam_service {
    ($($method:ident($req:ident) -> $resp:ident;)*) => {
        #[tonic::async_trait]
        impl IamService for AuthIam {
            async fn login(
                &self,
                _: tonic::Request<LoginRequest>,
            ) -> Result<tonic::Response<LoginResponse>, tonic::Status> {
                match self.0.clone() {
                    Answer::Mint(at) => Ok(tonic::Response::new(LoginResponse {
                        token: STUB_TOKEN.to_string(),
                        credential_id: "yadgar:credential:1".to_string(),
                        expires_at: Self::expiry(at),
                    })),
                    Answer::Refuse(status) => Err(status),
                }
            }

            async fn redeem_enrolment(
                &self,
                _: tonic::Request<RedeemEnrolmentRequest>,
            ) -> Result<tonic::Response<RedeemEnrolmentResponse>, tonic::Status> {
                match self.0.clone() {
                    Answer::Mint(at) => Ok(tonic::Response::new(RedeemEnrolmentResponse {
                        token: STUB_TOKEN.to_string(),
                        credential_id: "yadgar:credential:1".to_string(),
                        username: USERNAME.to_string(),
                        expires_at: Self::expiry(at),
                    })),
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

auth_iam_service! {
    resolve_credential(ResolveCredentialRequest) -> ResolveCredentialResponse;
    issue_credential(IssueCredentialRequest) -> IssueCredentialResponse;
    revoke_credential(RevokeCredentialRequest) -> RevokeCredentialResponse;
    revoke_all_credentials(RevokeAllCredentialsRequest) -> RevokeAllCredentialsResponse;
    list_credentials(ListCredentialsRequest) -> ListCredentialsResponse;
    create_user(CreateUserRequest) -> CreateUserResponse;
    issue_enrolment(IssueEnrolmentRequest) -> IssueEnrolmentResponse;
    set_user_admin(SetUserAdminRequest) -> SetUserAdminResponse;
    set_rate_limit_override(SetRateLimitOverrideRequest) -> SetRateLimitOverrideResponse;
    add_team_member(AddTeamMemberRequest) -> AddTeamMemberResponse;
    sync_teams(SyncTeamsRequest) -> SyncTeamsResponse;
    remove_team_member(RemoveTeamMemberRequest) -> RemoveTeamMemberResponse;
    set_inherited_setting(SetInheritedSettingRequest) -> SetInheritedSettingResponse;
}

/// A gateway whose `iam` answers both credential RPCs with `answer`.
async fn gateway(answer: Answer) -> Arc<AppState> {
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the stub binds");
    let addr = incoming.local_addr().expect("a bound port");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(IamServiceServer::new(AuthIam(answer)))
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
    Arc::new(AppState {
        attestation: Attestation::Iam,
        task: yadgar_gateway::upstream::TaskUpstream::new(
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            std::time::Duration::from_secs(1),
        ),
        iam: yadgar_gateway::upstream::Upstream::new(iam, std::time::Duration::from_secs(30)),
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
        bootstrap: BootstrapToken::disabled(),
        tools_poll_interval: Duration::from_secs(600),
        projects: Arc::new(yadgar_gateway::project::Validator::new(
            yadgar_gateway::project::Registry::never_loaded(),
            yadgar_gateway::project::Mode::Counting,
            yadgar_gateway::upstream::Upstream::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
                std::time::Duration::from_secs(30),
            ),
        )),
    })
}

/// POST and return the status and the raw body text.
async fn post(state: Arc<AppState>, path: &str, body: Value) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
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

/// A login body. The password is a fixture the stub never checks.
fn login_body() -> Value {
    json!({ "username": USERNAME, "password": "p", "label": "laptop" })
}

/// An enrol body. The secret and password are fixtures the stub never checks.
fn enrol_body() -> Value {
    json!({ "secret": "s", "password": "p", "label": "laptop" })
}

#[tokio::test]
async fn login_echoes_expires_at() {
    let state = gateway(Answer::Mint(Some(EXPIRY_SECONDS))).await;
    let (status, body) = post(state, "/auth/login", login_body()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("a JSON body"),
        json!({ "token": STUB_TOKEN, "expires_at": EXPIRY_RFC_3339 }),
        "the expiry iam minted is echoed in RFC 3339 (ADR-0972 (3))"
    );
}

#[tokio::test]
async fn enrol_echoes_expires_at() {
    let state = gateway(Answer::Mint(Some(EXPIRY_SECONDS))).await;
    let (status, body) = post(state, "/auth/enrol", enrol_body()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("a JSON body"),
        json!({ "token": STUB_TOKEN, "username": USERNAME, "expires_at": EXPIRY_RFC_3339 }),
        "the expiry iam minted is echoed in RFC 3339 (ADR-0972 (3))"
    );
}

/// ABSENT MEANS AN `iam` TOO OLD TO SET IT (iam.proto), never "no expiry".
/// So the key is left out rather than sent as `null` or a sentinel.
#[tokio::test]
async fn an_absent_expiry_is_an_absent_key_on_both_routes() {
    let (status, body) = post(
        gateway(Answer::Mint(None)).await,
        "/auth/login",
        login_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("a JSON body"),
        json!({ "token": STUB_TOKEN }),
    );
    let (status, body) = post(
        gateway(Answer::Mint(None)).await,
        "/auth/enrol",
        enrol_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("a JSON body"),
        json!({ "token": STUB_TOKEN, "username": USERNAME }),
    );
}

/// ADR-0972 (4), plan §5.1: the redemption committed, the password is set,
/// and only the mint lost the epoch race. The answer must not send the person
/// for a new enrolment, so it is not the single refusal, and it is not the
/// opaque 503 that invites a retry with a now-spent secret.
#[tokio::test]
async fn enrol_maps_failed_precondition_to_password_set_run_login() {
    let state = gateway(Answer::Refuse(tonic::Status::failed_precondition(
        "iam's own words, which must not reach the caller",
    )))
    .await;
    let (status, body) = post(state, "/auth/enrol", enrol_body()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        r#"{"error":"your password is set, but the account changed before a credential could be issued; run `yaadgaar login`"}"#,
        "a fixed body, never iam's message"
    );
}

/// The carve-out is enrol's only. A FAILED_PRECONDITION on login stays the
/// opaque 503: `iam` already maps a login that lost the race to the
/// wrong-password refusal, so this code reaching the gateway is an outage.
#[tokio::test]
async fn login_keeps_failed_precondition_opaque() {
    let state = gateway(Answer::Refuse(tonic::Status::failed_precondition("x"))).await;
    let (status, body) = post(state, "/auth/login", login_body()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, r#"{"error":"login is unavailable"}"#);
}
