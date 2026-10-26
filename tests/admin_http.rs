//! The administrative surface against an `iam` that ANSWERS (ADR-0492, D73,
//! ledger 638).
//!
//! # What is here and what deliberately is not
//!
//! `src/http/tests.rs` points `iam` at a closed port, which makes every
//! administrative REFUSAL reachable — a non-administrator, an excluded verb, an
//! unmounted Secret — and nothing else. Three properties need an upstream that
//! replies, and each of the three is the half a refusal-only suite would pass
//! without:
//!
//! 1. **`is_admin: true` is actually read from `iam`'s answer.** Plan §9's step-3
//!    row: "The field is carried into `Attested` and no handler reads it. Every
//!    test passes; every admin route is open." The 403 tests next door go green
//!    against a `from_resolved` that writes `false` unconditionally — the flag
//!    would be plumbed, unread and unreadable, and nothing would say so. **Only
//!    the positive reds on that mutation**, and it is why the two live in one
//!    pull request.
//! 2. **What ADR-0534's relay carries, ON THE WIRE.** §9's actor row is about a
//!    message that is SENT, and the only way to assert a message is absent is to
//!    look at the one that arrived. A stub that records `unverified_actor` is
//!    what tells `None` apart from `Some(UnverifiedActor { user_id: "" })` —
//!    which `iam-db` renders identically as `<unattributed>`, so downstream
//!    output cannot discriminate them.
//! 3. **Team access stage 10's retirement**: `set-user-admin` is no route, and
//!    a `create-user` body carrying `is_admin` is refused before `iam` is
//!    called, whoever sends it.
//!
//! # No Valkey
//!
//! The limiter points at a closed port, so every call takes D74's degraded path
//! and this file runs in CI. The buckets are wide; what is measured here is
//! authority, and `credential_throttle.rs` measures the throttle.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde_json::Value;
use tonic::transport::Channel;
use tower::ServiceExt;
use yadgar_gateway::admin::BootstrapToken;
use yadgar_gateway::attest::{Attestation, Credentials};
use yadgar_gateway::http::{router, AppState, CredentialLimits};
use yadgar_gateway::limit::{Bucket, Limiter, Limits};
use yadgar_gateway::pb::yadgar::common::v1::{Meta, UnverifiedActor};
use yadgar_gateway::pb::yadgar::iam::v1::{
    iam_service_server::{IamService, IamServiceServer},
    CreateUserRequest, CreateUserResponse, IssueEnrolmentRequest, IssueEnrolmentResponse,
    ResolveCredentialResponse, RevokeAllCredentialsRequest, RevokeAllCredentialsResponse,
    SetUserAdminRequest, SetUserAdminResponse,
};
use yadgar_gateway::source::TrustBoundary;

/// The user id the stub resolves every credential to.
const ADMIN_ID: &str = "yadgar:user:0192f3c1-8a4e-7c2d-9b11-5f0e7a3d84c6";
/// A different user, so a demotion has somebody to be about.
const OTHER_ID: &str = "yadgar:user:0192f3c1-8a4e-7c2d-9b11-000000000002";
/// The id `create_user` answers with.
const CREATED_ID: &str = "yadgar:user:0192f3c1-8a4e-7c2d-9b11-000000000003";

const BOOTSTRAP_SECRET: &str = "a-bootstrap-token-for-this-file";
const BOOTSTRAP_HEADER: &str = "x-yadgar-bootstrap-token";

/// One administrative RPC as it ARRIVED at `iam`.
///
/// **`actor` IS AN `Option` AND NOT A `String`, which is the whole point.** The
/// property §6 asks for is that the bootstrap path sends NO actor message —
/// absence, not an empty one. A recorder that flattened this to a string would
/// pass against exactly the bug §9's row names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Received {
    verb: &'static str,
    actor: Option<UnverifiedActor>,
    /// Whether D9's key travelled. `iam-db` discards it today (ledger 668) and
    /// step 1's sensor exists to say so; suppressing it here to keep that sensor
    /// quiet would be this gateway asserting an exception to D9 it cannot make.
    has_idempotency_key: bool,
    /// ADR-0655's demand, AS IT ARRIVED, and `None` means something different
    /// here than it does on `actor`.
    ///
    /// **`None` = THE REQUEST SHAPE HAS NO SUCH FIELD**, which is true of
    /// `CreateUserRequest` and `SetUserAdminRequest`. `actor`'s `None` is an
    /// absent message on a shape that HAS the field; this one is the field not
    /// existing. Flattening the two into one `bool` would record `false` for
    /// two verbs that can never carry a demand, which reads as "the demand was
    /// not set" and is a claim this stub has no business making.
    ///
    /// **AND THIS IS THE ONLY THING THAT CATCHES THE HEADLINE FALSE GREEN.**
    /// `require_zero_credential_admin` is a proto3 `bool`, so an arm that
    /// flipped `Verb::accepts_bootstrap` while the handler never set the field
    /// puts the bootstrap token on `IssueEnrolment` carrying NO demand — a
    /// deployed `iam-db` reads the proto3 default, takes the ORDINARY path, and
    /// the unrestricted grant is live with every status-code test in this
    /// repository green. The only way to assert a message is absent is to look
    /// at the one that arrived.
    demands_zero_credential_admin: Option<bool>,
    /// ADR-0943's revoke instruction, AS IT ARRIVED. `None` means what it means
    /// on `demands_zero_credential_admin`: the request shape has no such field.
    revokes_existing_credentials: Option<bool>,
    /// The `user_id` the request TARGETED, recorded for `RevokeAllCredentials`
    /// only (ADR-0945): that verb's wire assertion is about whose credentials
    /// are revoked. `None` on the other verbs means "not recorded here", not
    /// "absent on the wire".
    target_user_id: Option<String>,
    /// `CreateUserRequest.user_id` AS IT ARRIVED (team access stage 3b).
    /// `None` = the request shape has no such field; `Some("")` = iam-db mints.
    created_user_id: Option<String>,
    /// `CreateUserRequest.is_admin` AS IT ARRIVED. `None` as above.
    creates_admin: Option<bool>,
}

#[derive(Default)]
struct Log(Mutex<Vec<Received>>);

impl Log {
    fn push(&self, received: Received) {
        self.0
            .lock()
            .expect("the log is not poisoned")
            .push(received);
    }
    fn drain(&self) -> Vec<Received> {
        std::mem::take(&mut *self.0.lock().expect("the log is not poisoned"))
    }
}

/// An `iam` that resolves one canned identity and records the four
/// administrative RPCs it is asked for.
struct AdminIam {
    answer: ResolveCredentialResponse,
    log: Arc<Log>,
    resolves: Arc<AtomicUsize>,
    /// A `tonic::Status` this stub answers `IssueEnrolment` with instead of a
    /// token, so the gateway's rendering of an upstream REFUSAL is reachable.
    refuse_issue_enrolment: Option<tonic::Status>,
    /// The same for `CreateUser`, and it exists for the SECOND DIRECTION of the
    /// endpoint-scoping property: the enrolment refusal's body must be
    /// unreachable from a verb that is not an enrolment.
    refuse_create_user: Option<tonic::Status>,
    /// How this stub answers `RevokeAllCredentials` (ADR-0945).
    revoke: RevokeAnswer,
    /// Which id this stub's `CreateUser` answers with (team access stage 3b).
    create_answer: CreateAnswer,
}

/// Which id the stub's `CreateUser` answers with.
#[derive(Clone, Copy, Default)]
enum CreateAnswer {
    /// The `user_id` it was sent, or [`CREATED_ID`] when that is empty: an iam
    /// and iam-db that carry the field.
    #[default]
    Honour,
    /// [`CREATED_ID`] always: the old-store shape, which drops `user_id`
    /// (proto3 drops an unknown field) and mints an id of its own.
    Minted,
}

/// What the stub's `RevokeAllCredentials` does after recording the request.
#[derive(Clone, Default)]
enum RevokeAnswer {
    /// Answer `{revoked: REVOKED_COUNT}`.
    #[default]
    Count,
    /// Refuse with this status.
    Refuse(tonic::Status),
    /// Never answer, so the gateway's own deadline is what ends the call.
    Hang,
}

/// The count the stub's `RevokeAllCredentials` answers. Not 0 and not 1, so an
/// echo that hardcoded either is visible.
const REVOKED_COUNT: u32 = 3;

/// The void count the stub's `RevokeAllCredentials` answers (ADR-0972 (5)).
/// Different from [`REVOKED_COUNT`], so an echo that swapped the two is visible.
const VOIDED_COUNT: u32 = 2;

/// Write the stub's whole `IamService` impl: five real methods and nine refusals.
///
/// **THE MACRO EMITS `#[tonic::async_trait]` ITSELF, and it has to.** That
/// attribute rewrites every `async fn` in the block into the boxed future the
/// generated trait declares; applied AROUND a `macro_rules!` call it sees an
/// unexpanded token tree where those methods should be, leaves them alone, and
/// every one of them then fails to match the trait's lifetimes. The two stubs
/// already in this repository carry the same comment, and writing this file
/// without it reproduced the error verbatim.
macro_rules! admin_iam_service {
    ($($method:ident($req:ident) -> $resp:ident;)*) => {
        #[tonic::async_trait]
        impl IamService for AdminIam {
            async fn resolve_credential(
                &self,
                _: tonic::Request<yadgar_gateway::pb::yadgar::iam::v1::ResolveCredentialRequest>,
            ) -> Result<tonic::Response<ResolveCredentialResponse>, tonic::Status> {
                self.resolves.fetch_add(1, Ordering::SeqCst);
                Ok(tonic::Response::new(self.answer.clone()))
            }

            async fn create_user(
                &self,
                req: tonic::Request<CreateUserRequest>,
            ) -> Result<tonic::Response<CreateUserResponse>, tonic::Status> {
                let r = req.into_inner();
                // AN IAM THAT KNOWS `user_id` creates the user under it; an
                // empty one (and an old store, which drops the field) mints.
                let id = match self.create_answer {
                    CreateAnswer::Honour if !r.user_id.is_empty() => r.user_id.clone(),
                    _ => CREATED_ID.to_string(),
                };
                self.log.push(Received {
                    verb: "CreateUser",
                    actor: r.unverified_actor,
                    has_idempotency_key: r.idempotency.is_some_and(|i| !i.key.is_empty()),
                    demands_zero_credential_admin: None,
                    revokes_existing_credentials: None,
                    target_user_id: None,
                    created_user_id: Some(r.user_id),
                    creates_admin: Some(r.is_admin),
                });
                if let Some(refusal) = self.refuse_create_user.clone() {
                    return Err(refusal);
                }
                Ok(tonic::Response::new(CreateUserResponse {
                    meta: Some(Meta {
                        id,
                        version: 1,
                        ..Default::default()
                    }),
                }))
            }

            async fn issue_enrolment(
                &self,
                req: tonic::Request<IssueEnrolmentRequest>,
            ) -> Result<tonic::Response<IssueEnrolmentResponse>, tonic::Status> {
                let r = req.into_inner();
                self.log.push(Received {
                    verb: "IssueEnrolment",
                    actor: r.unverified_actor,
                    has_idempotency_key: r.idempotency.is_some_and(|i| !i.key.is_empty()),
                    demands_zero_credential_admin: Some(r.require_zero_credential_admin),
                    revokes_existing_credentials: Some(r.revoke_existing_credentials),
                    target_user_id: None,
                    created_user_id: None,
                    creates_admin: None,
                });
                // RECORDED BEFORE THE REFUSAL, deliberately: a refusing stub
                // must still let a test read what arrived, or the refusal path
                // could never be checked for the demand as well as the body.
                if let Some(refusal) = self.refuse_issue_enrolment.clone() {
                    return Err(refusal);
                }
                Ok(tonic::Response::new(IssueEnrolmentResponse {
                    // NOT BASE64-SHAPED, deliberately. The real blob is
                    // base64(EnrolmentToken) and a fixture that looked like one
                    // trips this repository's gitleaks hook as a generic API
                    // key — which is the hook working: a high-entropy literal in
                    // a test file is indistinguishable from a real credential
                    // checked in. Nothing here asserts the ENCODING; the gateway
                    // forwards `iam`'s string untouched.
                    token: "the-stub-enrolment-blob".to_string(),
                    enrolment_id: "yadgar:enrolment:1".to_string(),
                    expires_at: None,
                }))
            }

            async fn set_user_admin(
                &self,
                req: tonic::Request<SetUserAdminRequest>,
            ) -> Result<tonic::Response<SetUserAdminResponse>, tonic::Status> {
                let r = req.into_inner();
                self.log.push(Received {
                    verb: "SetUserAdmin",
                    actor: r.unverified_actor,
                    has_idempotency_key: r.idempotency.is_some_and(|i| !i.key.is_empty()),
                    demands_zero_credential_admin: None,
                    revokes_existing_credentials: None,
                    target_user_id: None,
                    created_user_id: None,
                    creates_admin: None,
                });
                Ok(tonic::Response::new(SetUserAdminResponse {}))
            }

            async fn revoke_all_credentials(
                &self,
                req: tonic::Request<RevokeAllCredentialsRequest>,
            ) -> Result<tonic::Response<RevokeAllCredentialsResponse>, tonic::Status> {
                let r = req.into_inner();
                self.log.push(Received {
                    verb: "RevokeAllCredentials",
                    actor: r.unverified_actor,
                    has_idempotency_key: r.idempotency.is_some_and(|i| !i.key.is_empty()),
                    demands_zero_credential_admin: None,
                    revokes_existing_credentials: None,
                    target_user_id: Some(r.user_id),
                    created_user_id: None,
                    creates_admin: None,
                });
                // RECORDED BEFORE THE ANSWER, for `issue_enrolment`'s reason: a
                // refusal or a stall must still let a test read what arrived.
                match self.revoke.clone() {
                    RevokeAnswer::Count => Ok(tonic::Response::new(RevokeAllCredentialsResponse {
                        revoked: REVOKED_COUNT,
                        voided_enrolments: VOIDED_COUNT,
                    })),
                    RevokeAnswer::Refuse(status) => Err(status),
                    RevokeAnswer::Hang => std::future::pending().await,
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
                    Err(tonic::Status::unimplemented(
                        "this stub answers ResolveCredential and the four administrative verbs",
                    ))
                }
            )*
        }
    };
}

admin_iam_service! {
    login(LoginRequest) -> LoginResponse;
    redeem_enrolment(RedeemEnrolmentRequest) -> RedeemEnrolmentResponse;
    issue_credential(IssueCredentialRequest) -> IssueCredentialResponse;
    revoke_credential(RevokeCredentialRequest) -> RevokeCredentialResponse;
    list_credentials(ListCredentialsRequest) -> ListCredentialsResponse;
    set_rate_limit_override(SetRateLimitOverrideRequest) -> SetRateLimitOverrideResponse;
    add_team_member(AddTeamMemberRequest) -> AddTeamMemberResponse;
    sync_teams(SyncTeamsRequest) -> SyncTeamsResponse;
    remove_team_member(RemoveTeamMemberRequest) -> RemoveTeamMemberResponse;
    set_inherited_setting(SetInheritedSettingRequest) -> SetInheritedSettingResponse;
}

/// What `iam` answers `ResolveCredential` with, for a caller whose administrative
/// flag is `is_admin`.
fn resolved(is_admin: bool) -> ResolveCredentialResponse {
    ResolveCredentialResponse {
        user_id: ADMIN_ID.to_string(),
        team_ids: Vec::new(),
        valid_for_seconds: 300,
        rate_limit_overrides: Vec::new(),
        is_admin,
        owner_reads_own_record: None,
    }
}

/// A gateway attesting against a stub `iam` that answers every administrative
/// verb, plus the log of what reached it.
async fn gateway(answer: ResolveCredentialResponse) -> (Arc<AppState>, Arc<Log>) {
    gateway_with(answer, Refusals::default()).await
}

/// Which administrative verbs the stub `iam` refuses, and with what status.
///
/// **PER VERB AND NOT ONE SHARED STATUS**, because the property under test is
/// that the gateway's new enrolment refusal body is scoped BY ENDPOINT: a single
/// knob could not express "refuse create-user and not issue-enrolment", which is
/// the direction that catches a code-only match.
#[derive(Default, Clone)]
struct Refusals {
    issue_enrolment: Option<tonic::Status>,
    create_user: Option<tonic::Status>,
    revoke: RevokeAnswer,
    create_answer: CreateAnswer,
    /// NOT A REFUSAL OF THE STUB: the GATEWAY's own switch,
    /// `adminBootstrap.refusePreMintedUserId`. `false` is the shipped value.
    refuse_pre_minted: bool,
}

/// [`gateway`], with a stub `iam` that REFUSES the named verbs.
async fn gateway_with(
    answer: ResolveCredentialResponse,
    refusals: Refusals,
) -> (Arc<AppState>, Arc<Log>) {
    let log = Arc::new(Log::default());
    let refuse_pre_minted = refusals.refuse_pre_minted;
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the stub binds");
    let addr = incoming.local_addr().expect("a bound port");
    let served = Arc::clone(&log);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(IamServiceServer::new(AdminIam {
                answer,
                log: served,
                resolves: Arc::new(AtomicUsize::new(0)),
                refuse_issue_enrolment: refusals.issue_enrolment,
                refuse_create_user: refusals.create_user,
                revoke: refusals.revoke,
                create_answer: refusals.create_answer,
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
        iam: yadgar_gateway::upstream::Upstream::new(iam, std::time::Duration::from_secs(30)),
        // SHORT, AND NOT ZERO. Each test builds its own gateway, so nothing here
        // depends on a cached answer — but a zero would disable the cache and
        // make this suite exercise a path the deployment does not run.
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
        pre_minted_ids: if refuse_pre_minted {
            yadgar_gateway::admin::PreMintedIds::Refused
        } else {
            yadgar_gateway::admin::PreMintedIds::Admitted
        },
        // NOT WHAT THIS FILE MEASURES — the shipped value, unused by any assertion here.
        tools_poll_interval: std::time::Duration::from_secs(600),
        // LEDGER 881'S VALIDATOR, in the SHIPPED configuration: `Mode::Counting`
        // counts which terminal state a claim reached and serves the call anyway,
        // and the registry has never loaded — the deployed state until `project`
        // answers (ADR-0674). So every assertion in this file holds WITH project
        // validation in the path, which is how the claim that counting mode
        // changes no existing answer is asserted rather than stated.
        projects: std::sync::Arc::new(yadgar_gateway::project::Validator::new(
            yadgar_gateway::project::Registry::never_loaded(),
            yadgar_gateway::project::Mode::Counting,
            yadgar_gateway::upstream::Upstream::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
                std::time::Duration::from_secs(30),
            ),
        )),
    });
    (state, log)
}

/// POST to an administrative path with the given headers.
async fn post(
    state: Arc<AppState>,
    path: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
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
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The headers an attested administrator sends.
fn as_admin() -> Vec<(&'static str, &'static str)> {
    vec![
        ("authorization", "Bearer a-real-token"),
        // SENT BY MANY CLIENTS AND NOT REQUIRED: `/admin` is not project-scoped
        // (ledger 1545), so the header is ignored here. Tests below send none.
        ("x-yadgar-project", "acme/demo"),
    ]
}

/// The write verbs, with a body each, as an ADMINISTRATOR would send them.
/// `set-user-admin` is not one: team access stage 10 retired it.
fn admin_verbs() -> Vec<(&'static str, String)> {
    vec![
        (
            "/admin/create-user",
            r#"{"external_id":"ada","display_name":"Ada"}"#.to_string(),
        ),
        (
            "/admin/issue-enrolment",
            format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        ),
        (
            "/admin/revoke-credentials",
            format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The pair that makes step 3 load-bearing
// ---------------------------------------------------------------------------

/// **THE POSITIVE HALF, and the only test in this repository that reds when
/// `from_resolved` stops reading `resolved.is_admin`.**
///
/// Every refusal test passes against a gateway that hardcodes `false`: the flag
/// would be plumbed, unread, and every administrator locked out — a failure that
/// reports as a working authorisation check. This is what says the value came
/// from `iam`'s answer.
#[tokio::test]
async fn an_administrator_reaches_every_administrative_verb() {
    for (path, body) in admin_verbs() {
        let (state, _log) = gateway(resolved(true)).await;
        let (status, answer) = post(state, path, &body, &as_admin()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{path} must admit a caller iam resolved as an administrator; got {answer}"
        );
    }
}

/// The negative half, through a credential `iam` actually resolved.
///
/// Stronger than the trusted-header version next door: here `iam` answered, the
/// credential is live, the user id is real, and the ONLY thing separating this
/// caller from the test above is the flag.
#[tokio::test]
async fn a_resolved_non_administrator_is_refused_every_administrative_verb() {
    for (path, body) in admin_verbs() {
        let (state, log) = gateway(resolved(false)).await;
        let (status, answer) = post(state, path, &body, &as_admin()).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} must refuse a resolved caller whose is_admin is false; got {answer}"
        );
        assert!(
            log.drain().is_empty(),
            "{path} must refuse BEFORE it reaches iam: a refusal that still performed the write \
             is not a refusal"
        );
    }
}

/// Headers of an administrator who names NO workspace (ledger 1545).
fn as_admin_without_project() -> Vec<(&'static str, &'static str)> {
    vec![("authorization", "Bearer a-real-token")]
}

/// **`/admin` IS NOT PROJECT-SCOPED (ledger 1545).** A bearer administrator
/// with no `x-yadgar-project` is admitted, as the bootstrap path always was.
/// The credential is still resolved through `iam`, so attestation is not skipped.
#[tokio::test]
async fn an_administrator_with_no_project_header_reaches_every_administrative_verb() {
    for (path, body) in admin_verbs() {
        let (state, _log) = gateway(resolved(true)).await;
        let (status, answer) = post(state, path, &body, &as_admin_without_project()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{path} must not demand a workspace; got {answer}"
        );
    }
}

/// Dropping the header must not drop the admin check: a resolved
/// non-administrator with no project header is 403, before `iam` is written to.
#[tokio::test]
async fn a_non_administrator_with_no_project_header_is_still_403() {
    for (path, body) in admin_verbs() {
        let (state, log) = gateway(resolved(false)).await;
        let (status, answer) = post(state, path, &body, &as_admin_without_project()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {answer}");
        assert!(log.drain().is_empty(), "{path} must refuse before iam");
    }
}

/// Dropping the header must not drop attestation: no credential is still 401.
#[tokio::test]
async fn no_credential_and_no_project_header_is_still_401() {
    let (state, _log) = gateway(resolved(true)).await;
    let (status, _) = post(
        state,
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada"}"#,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A caller presenting no credential at all is 401, not 403.
///
/// The two refusals are different facts and a client branches on the difference:
/// 401 says "say who you are", 403 says "you may not do this". Collapsing them
/// would send an administrator's colleague to re-authenticate against a condition
/// re-authenticating cannot fix.
#[tokio::test]
async fn a_caller_with_no_credential_is_401_and_not_403() {
    let (state, _log) = gateway(resolved(true)).await;
    let (status, _) = post(
        state,
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada"}"#,
        &[("x-yadgar-project", "acme/demo")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// ADR-0534's relay, measured on the wire (§6)
// ---------------------------------------------------------------------------

/// An administrator's resolved id is stamped as the actor on all three verbs.
///
/// This is ledger 612's missing SOURCE, arriving. What it buys is bounded and
/// stated rather than assumed: ADR-0534 rules that a recorded actor "is asserted
/// by the caller and verified by nothing on the wire, so it MUST NOT be read as
/// an authorisation input". It happens to be an id `iam` itself resolved; `iam`
/// cannot know that and must not start believing it.
#[tokio::test]
async fn an_administrator_stamps_their_resolved_id_as_the_actor() {
    for (path, body) in admin_verbs() {
        let (state, log) = gateway(resolved(true)).await;
        let (status, _) = post(state, path, &body, &as_admin()).await;
        assert_eq!(status, StatusCode::OK);

        let received = log.drain();
        assert_eq!(received.len(), 1, "{path} reached iam exactly once");
        assert_eq!(
            received[0].actor,
            Some(UnverifiedActor {
                user_id: ADMIN_ID.to_string(),
            }),
            "{path} must relay the RESOLVED id, never a header the caller wrote"
        );
        assert!(
            received[0].has_idempotency_key,
            "{path} must send D9's key. Suppressing it would keep ledger 668's sensor quiet by \
             asserting a per-RPC exception this gateway has no authority to make"
        );
    }
}

/// **§9's actor row: assert ABSENCE, not an empty string.**
///
/// "`UnverifiedActor` is stamped with an empty `user_id` on the bootstrap path
/// rather than omitted, and `iam-db`'s reader — which filters empty ids — logs
/// `<unattributed>`. That is the right OUTPUT reached by the wrong route, and it
/// hides a bug where a real id was dropped."
///
/// So the assertion is on the MESSAGE, and `Option::None` is what it must be.
/// There is no actor on this path by construction — D73 calls a shared secret
/// "unattributable by construction" — and a fabricated empty one is a false
/// record rather than a null one.
#[tokio::test]
async fn the_bootstrap_path_sends_no_actor_message_at_all() {
    for (path, body) in [
        ("/admin/create-user", create_body(PRE_MINTED)),
        (
            "/admin/issue-enrolment",
            format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        ),
    ] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, answer) =
            post(state, path, &body, &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)]).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{path} is one of the bootstrap token's two grants; got {answer}"
        );

        let received = log.drain();
        assert_eq!(received.len(), 1, "{path} reached iam exactly once");
        assert_eq!(
            received[0].actor, None,
            "{path}: the bootstrap path must send NO actor message. `Some(user_id: \"\")` renders \
             identically downstream and would hide a dropped id"
        );
    }
}

// ---------------------------------------------------------------------------
// The ceremony joins up
// ---------------------------------------------------------------------------

/// `create-user` answers with an id the other two verbs accept.
///
/// §9's step-7 shape is an administrator who can create users and not enrol them,
/// with every status green. The id `CreateUserResponse.meta.id` carries is
/// `iam-db`'s `iam_user.id` — the same column `iam_credential.user_id` points at,
/// and therefore the same identifier space `ResolveCredential` answers with — so
/// what this returns is what `issue-enrolment` and the credential verbs take. Handing
/// back anything else would look identical until an administrator tried the next
/// step.
#[tokio::test]
async fn create_user_answers_with_the_id_the_other_verbs_take() {
    let (state, _log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        Arc::clone(&state),
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada"}"#,
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let created = answer["user_id"].as_str().expect("a user_id comes back");
    assert_eq!(created, CREATED_ID);

    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{created}"}}"#),
        &as_admin(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the id create-user returned must be the id issue-enrolment takes; got {answer}"
    );
    assert!(
        answer["token"].as_str().is_some_and(|t| !t.is_empty()),
        "and the enrolment blob comes back for the administrator to hand over"
    );
}

// ---------------------------------------------------------------------------
// ADR-0655's grant, measured on the wire, and its refusal rendered (§4 step 4,
// §7.2 of `plans/the-bootstrap-enrolment-predicate.md`)
// ---------------------------------------------------------------------------

/// The ONE body the gateway answers for EITHER failed conjunct (ADR-0657).
///
/// **A LITERAL, never `super`'s constant.** A test that read the constant it is
/// pinning passes under any rewording of it (ADR-0599), which is the whole class
/// this repository keeps out — and this string is a contract two other repos'
/// probes are written against.
///
/// Reworded by team access stage 3b: "never held a credential" is false once
/// ADR-0966's break-glass arm applies, so the body names the predicate instead
/// and is true in both modes.
const ENROLMENT_REFUSAL_BODY: &str = r#"{"error":"the bootstrap token may only enrol an administrator the enrolment predicate admits"}"#;

/// A message the implementation could not plausibly contain, so if it appears in
/// a response body the only way it got there is interpolation of `e.message()`.
const UPSTREAM_SENTINEL: &str = "sentinel-upstream-text-that-must-not-appear";

/// **THE HEADLINE ASSERTION OF STEP 4, and the only thing in this repository
/// that reds on the false green the whole design exists to refuse.**
///
/// `require_zero_credential_admin` is a proto3 `bool`. Flip
/// `Verb::accepts_bootstrap`'s `IssueEnrolment` arm and forget the handler, and
/// the bootstrap token reaches the verb carrying NO demand: a deployed `iam-db`
/// reads the proto3 default, takes the ORDINARY unrestricted path, and the grant
/// ADR-0655's own rationale refuses is live while every status-code test in this
/// repository stays green. Asserting a 200 does not catch it. Asserting the
/// handler's intention does not catch it. This asserts the message that ARRIVED.
#[tokio::test]
async fn the_bootstrap_path_demands_a_zero_credential_admin_on_the_wire() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ADR-0655 admits the bootstrap token to this verb; got {answer}"
    );

    let received = log.drain();
    assert_eq!(
        received.len(),
        1,
        "issue-enrolment reached iam exactly once"
    );
    assert_eq!(
        received[0].demands_zero_credential_admin,
        Some(true),
        "the bootstrap path must SEND the demand. A request that arrives without it is enforced \
         by nobody: `iam-db` reads proto3's `false` and takes the ordinary path, which is the \
         unrestricted grant"
    );
    assert_eq!(
        received[0].actor, None,
        "and the bootstrap path still stamps no actor — this change touches the demand and \
         nothing else about the message"
    );
}

/// **THE MIRROR, AND IT IS NOT OPTIONAL.** One arm alone proves only that the
/// test is connected to something.
///
/// An attested administrator's re-enrolment is the FORGOTTEN-PASSWORD RECOVERY
/// path (`iam.proto` states it; §8.1 names it). It targets a user who ALREADY
/// HOLDS a credential by definition, so a handler that set the demand
/// unconditionally would refuse every recovery — and no other gateway test
/// notices, because none of them enrols a credentialed user.
#[tokio::test]
async fn an_attested_administrator_demands_nothing_on_the_wire() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");

    let received = log.drain();
    assert_eq!(
        received.len(),
        1,
        "issue-enrolment reached iam exactly once"
    );
    assert_eq!(
        received[0].demands_zero_credential_admin,
        Some(false),
        "an ATTESTED administrator must demand nothing: the demand only narrows, and narrowing \
         this path breaks re-enrolment as forgotten-password recovery"
    );
    assert_eq!(
        received[0].revokes_existing_credentials,
        Some(false),
        "an absent `revoke_existing_credentials` must arrive false, or every recovery signs the \
         person out everywhere (ADR-0943)"
    );
    assert_eq!(
        answer["revoke_existing_credentials"], false,
        "the 200 echoes the instruction AS APPLIED, so an absent one reads back false"
    );
}

/// ADR-0943: an ATTESTED administrator may ask a re-enrolment to revoke every
/// credential its target holds, and the instruction must ARRIVE at `iam` — a
/// proto3 `bool` the handler forgot to copy reads as `false` and the containing
/// reset silently becomes a plain one.
#[tokio::test]
async fn an_attested_administrator_can_ask_to_revoke_existing_credentials() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}","revoke_existing_credentials":true}}"#),
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");

    let received = log.drain();
    assert_eq!(
        received.len(),
        1,
        "issue-enrolment reached iam exactly once"
    );
    assert_eq!(received[0].revokes_existing_credentials, Some(true));
    assert_eq!(
        received[0].demands_zero_credential_admin,
        Some(false),
        "the instruction changes nothing about the demand"
    );
    assert_eq!(
        answer["revoke_existing_credentials"], true,
        "the 200 echoes the instruction AS APPLIED (ledger 1579)"
    );
}

/// LEDGER 1579: THE TYPO FALSE GREEN, and the echo is what exposes it. Unknown
/// JSON keys are ignored, so a client that misspells the field gets a 200 and a
/// plain reset — the old tokens keep working and nothing said so. The 200 now
/// states what was applied, so a client that asked for a revoke can see it did
/// not get one.
#[tokio::test]
async fn a_misspelt_revoke_instruction_reads_back_as_not_applied() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}","revoke_existing_credential":true}}"#),
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");
    assert_eq!(log.drain()[0].revokes_existing_credentials, Some(false));
    assert_eq!(
        answer["revoke_existing_credentials"], false,
        "a misspelt key is not the instruction, and the answer must say none was applied"
    );
}

/// A `revoke_existing_credentials` that is not a JSON boolean is a 400, before
/// any authorisation and before `iam`: `"true"` or `1` is not an instruction to
/// sign somebody out everywhere, and guessing what was meant is not a kindness.
///
/// THREE SHAPES, ONE RULE (ledger 1579): a string, a number and `null`. `1` is
/// the truthy reading a lenient parser would take, and `null` the one a client
/// serialising an unset optional would send; neither is a boolean, so neither
/// is guessed at.
#[tokio::test]
async fn a_non_boolean_revoke_instruction_is_refused() {
    for value in [r#""true""#, "1", "null"] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, answer) = post(
            state,
            "/admin/issue-enrolment",
            &format!(r#"{{"user_id":"{OTHER_ID}","revoke_existing_credentials":{value}}}"#),
            &as_admin(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{value} must be refused; got {answer}"
        );
        assert!(
            log.drain().is_empty(),
            "a malformed request ({value}) must not reach iam"
        );
    }
}

/// An upstream `PERMISSION_DENIED` on enrolment renders as ONE 403 with ONE
/// constant body (ADR-0657, §5.1).
///
/// Two properties, and the second is the one a body-equality assertion alone
/// would certify green:
///
/// 1. The status is 403 and the body is §5.1's sentence byte-for-byte. Without
///    the arm this is `opaque_status`'s catch-all 503 "the administrative service
///    is unavailable" — which tells an operator the service is down when it
///    refused correctly.
/// 2. **The UPSTREAM's words are nowhere in the body.** The stub refuses with a
///    sentinel rather than with §5.1's sentence on purpose: a stub that spoke the
///    expected sentence would let a handler which interpolated `e.message()` pass
///    the equality assertion — and that handler is the ADR-0657 disclosure
///    channel, certified green by the test written to refuse it.
///
/// There is deliberately NO message-dependent branch and no second body per
/// conjunct: ADR-0657 rules that distinct refusals per conjunct are an
/// administrator-set enumeration oracle naming exactly the administrators who
/// have never logged in, which is the set this grant can still take over.
#[tokio::test]
async fn an_upstream_permission_denied_on_enrolment_is_one_403_with_one_body() {
    let (state, log) = gateway_with(
        resolved(true),
        Refusals {
            issue_enrolment: Some(tonic::Status::permission_denied(UPSTREAM_SENTINEL)),
            ..Default::default()
        },
    )
    .await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a refusal is 403, not the 503 every other upstream code collapses into; got {answer}"
    );
    let body = answer.to_string();
    assert_eq!(
        body, ENROLMENT_REFUSAL_BODY,
        "the refusal answers §5.1's single sentence, byte for byte"
    );
    assert!(
        !body.contains(UPSTREAM_SENTINEL),
        "the upstream's own message must not reach the caller: naming the failed conjunct is the \
         oracle ADR-0657 exists to refuse. Got {body}"
    );

    // AND THE DEMAND STILL TRAVELLED. A refusal reached by never sending the
    // demand would satisfy the two assertions above and prove nothing.
    let received = log.drain();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].demands_zero_credential_admin, Some(true));
}

/// **THE ENDPOINT SCOPE, IN THE DIRECTION THAT CATCHES A CODE-ONLY MATCH.**
///
/// `admin_failure` renders every administrative endpoint. An arm keyed on
/// `Code::PermissionDenied` ALONE would answer the enrolment refusal to a
/// caller who was creating a USER — a message about a verb the call was not.
///
/// Since Max's ruling (a) of 2026-10-24, `create-user`'s `PERMISSION_DENIED`
/// (the bootstrap create-user predicate, §6) is the opaque 503 again, with no
/// upstream text.
#[tokio::test]
async fn the_enrolment_refusal_body_is_unreachable_from_create_user() {
    let (state, _log) = gateway_with(
        resolved(true),
        Refusals {
            create_user: Some(tonic::Status::permission_denied(UPSTREAM_SENTINEL)),
            ..Default::default()
        },
    )
    .await;
    let (status, answer) = post(
        state,
        "/admin/create-user",
        &format!(r#"{{"external_id":"ada","display_name":"Ada","user_id":"{PRE_MINTED}"}}"#),
        &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)],
    )
    .await;

    let body = answer.to_string();
    assert_ne!(
        body, ENROLMENT_REFUSAL_BODY,
        "create-user must never be told about enrolment: the body names a verb this call was not"
    );
    assert!(!body.contains(UPSTREAM_SENTINEL), "got {body}");
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY),
        "create-user's PERMISSION_DENIED is the opaque 503 (ruling (a))"
    );
}

// ---------------------------------------------------------------------------
// `/admin/revoke-credentials` (ADR-0945, ledger 1626)
// ---------------------------------------------------------------------------

const REVOKE: &str = "/admin/revoke-credentials";

/// The 404 body for a user `iam` does not hold. Asserted byte for byte, so an
/// unregistered route's 404 (axum's empty body) cannot pass for it.
const REVOKE_NOT_FOUND_BODY: &str = r#"{"error":"no such user"}"#;

/// `admin_timeout`'s body, which every upstream stall answers with.
const UNAVAILABLE_BODY: &str = r#"{"error":"the administrative service is unavailable"}"#;

/// POST to [`REVOKE`] and return the raw body text, so a test can compare it
/// byte for byte.
async fn revoke_raw(
    state: Arc<AppState>,
    body: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(REVOKE)
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

fn revoke_body(user_id: &str) -> String {
    format!(r#"{{"user_id":"{user_id}"}}"#)
}

#[tokio::test]
async fn revoke_refuses_a_non_administrator_before_iam() {
    let (state, log) = gateway(resolved(false)).await;
    let (status, _) = revoke_raw(state, &revoke_body(OTHER_ID), &as_admin()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a resolved caller whose is_admin is false must be refused"
    );
    assert!(
        log.drain().is_empty(),
        "the refusal must come before RevokeAllCredentials is sent"
    );
}

/// THE BOOTSTRAP TOKEN NEVER REACHES THIS VERB (ADR-0945): 403, no RPC, and
/// the ACCEPTED counter does not move. The control in the same recorder is a
/// bootstrap create-user that DOES move it, so an absent counter cannot pass
/// for an unchanged one.
#[tokio::test]
async fn revoke_refuses_the_bootstrap_token_without_counting_an_acceptance() {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let local = metrics::set_default_local_recorder(&recorder);

    let (state, log) = gateway(resolved(true)).await;
    let (control, _) = post(
        Arc::clone(&state),
        "/admin/create-user",
        &create_body(PRE_MINTED),
        &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)],
    )
    .await;
    assert_eq!(
        control,
        StatusCode::OK,
        "the control: the bootstrap token creates an administrator"
    );
    log.drain();

    let (status, _) = revoke_raw(
        state,
        &revoke_body(OTHER_ID),
        &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)],
    )
    .await;
    drop(local);

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the bootstrap token must be refused on revoke-credentials"
    );
    assert!(
        log.drain().is_empty(),
        "the bootstrap refusal must come before RevokeAllCredentials is sent"
    );
    let accepted: Vec<u64> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| key.key().name() == "yadgar_gateway_bootstrap_accepted_total")
        .filter_map(|(_, _, _, value)| match value {
            metrics_util::debugging::DebugValue::Counter(n) => Some(n),
            _ => None,
        })
        .collect();
    assert_eq!(
        accepted,
        vec![1],
        "ACCEPTED must count the control's acceptance and nothing for the revoke attempt"
    );
}

#[tokio::test]
async fn revoke_refuses_an_administrator_targeting_themselves() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, _) = revoke_raw(state, &revoke_body(ADMIN_ID), &as_admin()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an administrator may not revoke their own credentials"
    );
    assert!(
        log.drain().is_empty(),
        "the self-target refusal must come before RevokeAllCredentials is sent"
    );
}

/// THE CANONICAL CHECK RUNS BEFORE THE SELF-TARGET CHECK. `iam-db`'s id column
/// compares case-insensitively and the cache eviction compares bytes, so the
/// caller's own id in upper case is the case that must be a 400: a 403 would
/// mean the self check judged a non-canonical id, and an RPC would mean the
/// rows were revoked while the cache kept answering for the TTL.
#[tokio::test]
async fn revoke_refuses_a_non_canonical_id_before_the_self_target_check() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, _) = revoke_raw(state, &revoke_body(&ADMIN_ID.to_uppercase()), &as_admin()).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the caller's own id in upper case must be a 400, not a 403 and not an RPC"
    );
    assert!(
        log.drain().is_empty(),
        "a non-canonical id must never reach RevokeAllCredentials"
    );
}

#[tokio::test]
async fn revoke_refuses_every_non_canonical_shape() {
    let bare = OTHER_ID.trim_start_matches("yadgar:user:");
    let mixed_case = OTHER_ID.replace("8a4e", "8A4E");
    let padded = format!("{OTHER_ID} ");
    let braced = format!("yadgar:user:{{{bare}}}");
    let simple = OTHER_ID.replace('-', "");
    let upper_prefix = OTHER_ID.replace("yadgar:user:", "YADGAR:USER:");
    for id in [
        mixed_case.as_str(),
        padded.as_str(),
        bare,
        braced.as_str(),
        simple.as_str(),
        upper_prefix.as_str(),
        "",
    ] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, _) = revoke_raw(state, &revoke_body(id), &as_admin()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a user_id outside iam-db's canonical form must be a 400"
        );
        assert!(
            log.drain().is_empty(),
            "a non-canonical id must never reach RevokeAllCredentials"
        );
    }
}

#[tokio::test]
async fn revoke_refuses_a_malformed_body() {
    let unknown = format!(r#"{{"user_id":"{OTHER_ID}","everywhere":true}}"#);
    for body in [
        "{}",
        r#"{"user_id":7}"#,
        r#"{"user_id":null}"#,
        r#"{"user_id":["a"]}"#,
        unknown.as_str(),
        "[]",
        "not json",
    ] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, _) = revoke_raw(state, body, &as_admin()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a missing, non-string or unknown key must be a 400"
        );
        assert!(
            log.drain().is_empty(),
            "a malformed body must never reach RevokeAllCredentials"
        );
    }
}

/// The guard runs: a cross-origin browser request is refused with the guard's
/// own body and reaches nothing, while the same request with no Origin goes
/// through. An attested administrator is used so that the refusal cannot be
/// the bootstrap exclusion's 403.
#[tokio::test]
async fn revoke_refuses_a_cross_origin_request() {
    let (state, log) = gateway(resolved(true)).await;
    let mut headers = as_admin();
    headers.push(("origin", "https://attacker.example"));
    let (status, body) = revoke_raw(Arc::clone(&state), &revoke_body(OTHER_ID), &headers).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::FORBIDDEN, r#"{"error":"origin not allowed"}"#),
        "an unknown browser origin must be refused by the guard"
    );
    assert!(
        log.drain().is_empty(),
        "a cross-origin request must never reach RevokeAllCredentials"
    );

    let (control, _) = revoke_raw(state, &revoke_body(OTHER_ID), &as_admin()).await;
    assert_eq!(
        control,
        StatusCode::OK,
        "the control: the same request with no Origin is served"
    );
}

/// What ARRIVED at `iam`: the target, the attested actor and D9's key.
#[tokio::test]
async fn revoke_sends_the_target_and_the_actor_on_the_wire() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, _) = revoke_raw(state, &revoke_body(OTHER_ID), &as_admin()).await;
    assert_eq!(status, StatusCode::OK, "an administrator is served");
    assert_eq!(
        log.drain(),
        vec![Received {
            verb: "RevokeAllCredentials",
            actor: Some(UnverifiedActor {
                user_id: ADMIN_ID.to_string(),
            }),
            has_idempotency_key: true,
            demands_zero_credential_admin: None,
            revokes_existing_credentials: None,
            target_user_id: Some(OTHER_ID.to_string()),
            created_user_id: None,
            creates_admin: None,
        }],
        "exactly one RevokeAllCredentials carrying the target, the resolved actor and a key"
    );
}

#[tokio::test]
async fn revoke_answers_the_user_id_and_the_count() {
    let (state, _log) = gateway(resolved(true)).await;
    let (status, body) = revoke_raw(state, &revoke_body(OTHER_ID), &as_admin()).await;
    assert_eq!(status, StatusCode::OK, "an administrator is served");
    let answer: Value = serde_json::from_str(&body).expect("a JSON body");
    assert_eq!(
        answer,
        serde_json::json!({
            "user_id": OTHER_ID,
            "revoked": REVOKED_COUNT,
            "voided_enrolments": VOIDED_COUNT,
        }),
        "the 200 echoes user_id, the revoked count and the void count iam answered"
    );
}

/// NOT_FOUND IS 404 HERE AND NOWHERE ELSE. The arrival assertion is what
/// stops axum's own 404 for an unregistered route passing for this one.
#[tokio::test]
async fn revoke_answers_404_for_a_user_iam_does_not_hold() {
    let (state, log) = gateway_with(
        resolved(true),
        Refusals {
            revoke: RevokeAnswer::Refuse(tonic::Status::not_found("no iam_user row")),
            ..Default::default()
        },
    )
    .await;
    let (status, body) = revoke_raw(state, &revoke_body(OTHER_ID), &as_admin()).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::NOT_FOUND, REVOKE_NOT_FOUND_BODY),
        "an upstream NOT_FOUND is a 404 with the constant body"
    );
    assert_eq!(
        log.drain().len(),
        1,
        "the 404 must come from iam's answer, not from a missing route"
    );
}

/// The mirror: create-user meeting NOT_FOUND keeps the opaque 503, so the 404
/// mapping is scoped to revoke-credentials.
#[tokio::test]
async fn not_found_stays_opaque_on_create_user() {
    let (state, _log) = gateway_with(
        resolved(true),
        Refusals {
            create_user: Some(tonic::Status::not_found("not found")),
            ..Default::default()
        },
    )
    .await;
    let (status, answer) = post(
        state,
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada"}"#,
        &as_admin(),
    )
    .await;
    assert_eq!(
        (status, answer.to_string().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY),
        "NOT_FOUND on create-user stays the opaque 503"
    );
}

/// AN `iam` THAT STALLS: the gateway's own deadline ends the call with the
/// opaque 503. The clock is paused, so the deadline elapses without the test
/// waiting for it; the arrival assertion shows the stall was in the RPC and
/// not in the attestation.
#[tokio::test(start_paused = true)]
async fn revoke_answers_503_when_iam_stalls() {
    let (state, log) = gateway_with(
        resolved(true),
        Refusals {
            revoke: RevokeAnswer::Hang,
            ..Default::default()
        },
    )
    .await;
    let (status, body) = revoke_raw(state, &revoke_body(OTHER_ID), &as_admin()).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY),
        "a stalled RevokeAllCredentials is the opaque 503"
    );
    assert_eq!(
        log.drain().len(),
        1,
        "the stall must be in RevokeAllCredentials itself"
    );
}

/// An invariant guard rather than a red-first test: no administrative verb is
/// an MCP tool (ADR-0492), and this one is no exception.
#[test]
fn revoke_credentials_is_not_an_mcp_tool() {
    assert!(
        !yadgar_gateway::tools::SERVED
            .iter()
            .any(|name| name.contains("revoke")),
        "an administrative verb is never an MCP tool (ADR-0492)"
    );
}

// ---------------------------------------------------------------------------
// Team access stage 3b: the bootstrap `create-user` arm (plans/team-access.md
// §6, stage 3b; ADR-0963 (5), ADR-0966, ADR-0927, ADR-1011)
// ---------------------------------------------------------------------------

/// A well-formed lowercase uuidv7, bare, as the operator declares it.
const PRE_MINTED: &str = "0192f3c1-8a4e-7c2d-9b11-5f0e7a3d8400";

/// The verb-rule 403, rewritten by stage 3b and again by stage 10, when
/// `set-user-admin` is retired and "promote one" stops being true. A literal,
/// for `ENROLMENT_REFUSAL_BODY`'s reason.
const VERB_RULE_BODY: &str = r#"{"error":"the bootstrap token may only create the declared first administrator or issue an enrolment the enrolment predicate admits"}"#;

/// The 400 for a `create-user` body that carries the retired `is_admin` field
/// (team access stage 10). A literal, for `ENROLMENT_REFUSAL_BODY`'s reason.
const IS_ADMIN_RETIRED_BODY: &str = r#"{"error":"`is_admin` is retired: admin is membership of the declared administrators team (ADR-0962), so send create-user without it"}"#;

/// What `iam`'s `refusal_for` sends for `PERMISSION_DENIED`: iam replaces every
/// iam-db message with a fixed sentence per code (`iam/src/service.rs`).
const IAM_PERMISSION_DENIED_SENTENCE: &str = "the iam-db call failed";

/// The echo check's 502 names this (red 3).
const ECHO_MISMATCH: &str = "iam predates pre-minted user ids";

/// What one request did, observed from outside: the answer, what reached
/// `iam`, the D67 `outcome` label of the call, and every log line.
struct Seen {
    status: StatusCode,
    body: String,
    received: Vec<Received>,
    outcomes: Vec<String>,
    /// Whether `yadgar_gateway_bootstrap_accepted_total` was registered at all:
    /// it registers on the first acceptance only (see `admin::ACCEPTED`).
    accepted: bool,
    logs: String,
}

/// A `MakeWriter` that keeps every formatted log line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Drive one administrative request under a LOCAL metrics recorder and a LOCAL
/// log subscriber. Both are thread-local, so this runs its own current-thread
/// runtime: the stub `iam` and the router are polled on this thread.
fn seen(
    answer: ResolveCredentialResponse,
    refusals: Refusals,
    path: &'static str,
    body: &str,
    headers: &[(&str, &str)],
) -> Seen {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let (status, value, received) = metrics::with_local_recorder(&recorder, || {
        let _guard = tracing::subscriber::set_default(subscriber);
        rt.block_on(async {
            let (state, log) = gateway_with(answer, refusals).await;
            let (status, value) = post(state, path, body, headers).await;
            (status, value, log.drain())
        })
    });
    let tool = path.trim_start_matches('/');
    let snapshot = snapshotter.snapshot().into_vec();
    let accepted = snapshot
        .iter()
        .any(|(key, _, _, _)| key.key().name() == yadgar_gateway::admin::ACCEPTED);
    let outcomes = snapshot
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == yadgar_telemetry::metrics::CALLS)
        .filter(|(key, _, _, _)| {
            key.key()
                .labels()
                .any(|l| l.key() == "tool" && l.value() == tool)
        })
        .flat_map(|(key, _, _, _)| {
            key.key()
                .labels()
                .filter(|l| l.key() == "outcome")
                .map(|l| l.value().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    let logs = String::from_utf8_lossy(&captured.0.lock().expect("log buffer")).into_owned();
    Seen {
        status,
        body: value.to_string(),
        received,
        outcomes,
        accepted,
        logs,
    }
}

fn bootstrap() -> Vec<(&'static str, &'static str)> {
    vec![(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)]
}

fn create_body(user_id: &str) -> String {
    format!(r#"{{"external_id":"ada","display_name":"Ada","user_id":"{user_id}"}}"#)
}

/// Red 1. Each malformed class of stage 2 red 13, in BARE form, from the
/// bootstrap token. The gateway judges no format (ADR-0927: a format answer
/// before authorization would be an oracle to an unauthenticated caller), so
/// iam receives `yadgar:user:<value>` byte for byte, refuses
/// `INVALID_ARGUMENT`, and the caller gets the opaque 503, the same bytes as
/// `UNAVAILABLE`.
///
/// Stage 2's "missing `yadgar:user:` prefix" class has no bare form, because
/// the gateway always adds the prefix. Its bare analogue is a value that
/// already carries it, which arrives doubled.
#[tokio::test]
async fn red_01_malformed_user_ids_reach_iam_verbatim_and_answer_the_opaque_503() {
    let classes = [
        ("uppercase hex", "0192F3C1-8A4E-7C2D-9B11-5F0E7A3D8400"),
        ("uuidv4", "0192f3c1-8a4e-4c2d-9b11-5f0e7a3d8400"),
        ("variant c", "0192f3c1-8a4e-7c2d-cb11-5f0e7a3d8400"),
        (
            "prefix already present",
            "yadgar:user:0192f3c1-8a4e-7c2d-9b11-5f0e7a3d8400",
        ),
        ("nil uuid", "00000000-0000-0000-0000-000000000000"),
        ("35 characters", "0192f3c1-8a4e-7c2d-9b11-5f0e7a3d840"),
    ];
    let unavailable = {
        let (state, _log) = gateway_with(
            resolved(true),
            Refusals {
                create_user: Some(tonic::Status::unavailable("storage unavailable")),
                ..Default::default()
            },
        )
        .await;
        let (status, answer) = post(
            state,
            "/admin/create-user",
            &create_body(PRE_MINTED),
            &bootstrap(),
        )
        .await;
        (status, answer.to_string())
    };
    assert_eq!(
        unavailable,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            UNAVAILABLE_BODY.to_string()
        )
    );

    for (class, value) in classes {
        let (state, log) = gateway_with(
            resolved(true),
            Refusals {
                create_user: Some(tonic::Status::invalid_argument(
                    "the store refused the request",
                )),
                ..Default::default()
            },
        )
        .await;
        let (status, answer) = post(
            state,
            "/admin/create-user",
            &create_body(value),
            &bootstrap(),
        )
        .await;
        let received = log.drain();
        assert_eq!(
            received.len(),
            1,
            "{class}: the gateway must not judge the format"
        );
        assert_eq!(
            received[0].created_user_id.as_deref(),
            Some(format!("yadgar:user:{value}").as_str()),
            "{class}: iam receives the prefixed value byte for byte"
        );
        assert_eq!(
            (status, answer.to_string()),
            unavailable,
            "{class}: INVALID_ARGUMENT is the opaque 503, byte-identical to UNAVAILABLE"
        );

        // THE SAME BODY WITH NO TOKEN AT ALL: 401, and nothing reaches iam, so
        // there is no pre-auth answer about the format.
        let (state, log) = gateway(resolved(true)).await;
        let (status, _) = post(state, "/admin/create-user", &create_body(value), &[]).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{class}: no credential is 401"
        );
        assert!(
            log.drain().is_empty(),
            "{class}: zero calls before authorization"
        );
    }

    // A NON-STRING `user_id` is a SHAPE error: 400, before authorization.
    for value in ["1", "null", "true", "{}", r#"["x"]"#] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, answer) = post(
            state,
            "/admin/create-user",
            &format!(r#"{{"external_id":"ada","display_name":"Ada","user_id":{value}}}"#),
            &bootstrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}: got {answer}");
        assert!(log.drain().is_empty(), "{value}: zero calls");
    }
}

/// Red 2. The F2 arm: bootstrap token, well-formed `user_id`, `is_admin`
/// absent. iam receives the prefixed id and `is_admin: false`, and the gateway
/// answers the id iam echoed.
#[tokio::test]
async fn red_02_the_bootstrap_token_creates_the_pre_minted_administrator() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/create-user",
        &create_body(PRE_MINTED),
        &bootstrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");
    assert_eq!(
        answer.to_string(),
        format!(r#"{{"user_id":"yadgar:user:{PRE_MINTED}"}}"#)
    );
    let received = log.drain();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].created_user_id.as_deref(),
        Some(format!("yadgar:user:{PRE_MINTED}").as_str())
    );
    assert_eq!(
        received[0].creates_admin,
        Some(false),
        "the F2 arm sets no column: admin is membership (ADR-0962)"
    );
    assert_eq!(
        received[0].actor, None,
        "the bootstrap path stamps no actor"
    );
}

/// Red 3. The echo check: an iam that predates the field drops it and mints an
/// id of its own. The gateway answers 502 naming that, logs a warning, and
/// records the call as failed.
#[test]
fn red_03_an_echo_mismatch_is_a_loud_502() {
    let seen = seen(
        resolved(true),
        Refusals {
            create_answer: CreateAnswer::Minted,
            ..Default::default()
        },
        "/admin/create-user",
        &create_body(PRE_MINTED),
        &bootstrap(),
    );
    assert_eq!(seen.status, StatusCode::BAD_GATEWAY, "got {}", seen.body);
    assert!(seen.body.contains(ECHO_MISMATCH), "got {}", seen.body);
    assert!(
        !seen.body.contains(CREATED_ID),
        "the minted id goes to the log, not to the caller"
    );
    assert!(
        seen.logs.contains("WARN") && seen.logs.contains(ECHO_MISMATCH),
        "a warning names the mismatch; logs: {}",
        seen.logs
    );
    assert_eq!(
        seen.outcomes.len(),
        1,
        "one call, one series: {:?}",
        seen.outcomes
    );
    assert_ne!(seen.outcomes[0], "OK", "the call is recorded as failed");
    // A VALUE THE SHARED MAPPING PRODUCES (ADR-0558), derived over every code.
    let mapped: std::collections::BTreeSet<&'static str> = (0..32)
        .map(|i| {
            yadgar_telemetry::grpc::status_name(&tonic::Status::new(tonic::Code::from_i32(i), ""))
        })
        .collect();
    assert!(
        mapped.contains(seen.outcomes[0].as_str()),
        "{:?} is not a value telemetry::grpc::status_name produces",
        seen.outcomes[0]
    );
}

/// Red 4, as Max's ruling (a) of 2026-10-24 changes it. iam's
/// `PERMISSION_DENIED` on `create-user` (the bootstrap create-user predicate
/// refused) is the opaque 503, byte-identical to `UNAVAILABLE`, whichever
/// message iam sent. The D67 label still says `PERMISSION_DENIED`, for the
/// operator: it is not visible to the caller.
#[test]
fn red_04_the_create_user_predicate_refusal_is_the_opaque_503() {
    for message in [IAM_PERMISSION_DENIED_SENTENCE, UPSTREAM_SENTINEL] {
        let seen = seen(
            resolved(true),
            Refusals {
                create_user: Some(tonic::Status::permission_denied(message)),
                ..Default::default()
            },
            "/admin/create-user",
            &create_body(PRE_MINTED),
            &bootstrap(),
        );
        assert_eq!(
            (seen.status, seen.body.as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY),
            "{message}: the predicate refusal is the opaque 503"
        );
        assert_eq!(seen.outcomes, vec!["PERMISSION_DENIED".to_string()]);
    }
}

/// Red 5, on the wire. `ALREADY_EXISTS` and `INVALID_ARGUMENT` keep the opaque
/// 503 (ADR-0927: a 409 would say an id or a name is taken), and so does
/// `FAILED_PRECONDITION` (yaadgaar #202: the enrolment sentence was false
/// here). No upstream text in any body. The unit-level loop is
/// `admin_failure_failed_precondition_gets_a_distinct_body` in
/// `src/http/tests.rs`.
#[tokio::test]
async fn red_05_upstream_codes_on_create_user_stay_opaque() {
    for (code, expected) in [
        (tonic::Code::AlreadyExists, UNAVAILABLE_BODY),
        (tonic::Code::InvalidArgument, UNAVAILABLE_BODY),
        (tonic::Code::FailedPrecondition, UNAVAILABLE_BODY),
    ] {
        let (state, _log) = gateway_with(
            resolved(true),
            Refusals {
                create_user: Some(tonic::Status::new(code, UPSTREAM_SENTINEL)),
                ..Default::default()
            },
        )
        .await;
        let (status, answer) = post(
            state,
            "/admin/create-user",
            &create_body(PRE_MINTED),
            &bootstrap(),
        )
        .await;
        assert_eq!(
            (status, answer.to_string().as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, expected),
            "{code:?}"
        );
    }
}

/// Red 6. The `user_id` parameter is bootstrap-path-only: an attested
/// administrator's body with it is the opaque 503 after authorization, with a
/// warning naming the rule, and nothing reaches iam.
#[test]
fn red_06_an_attested_administrator_may_not_pre_mint_an_id() {
    let seen = seen(
        resolved(true),
        Refusals::default(),
        "/admin/create-user",
        &create_body(PRE_MINTED),
        &as_admin(),
    );
    assert_eq!(
        (seen.status, seen.body.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY)
    );
    assert!(seen.received.is_empty(), "zero calls: {:?}", seen.received);
    assert!(
        seen.logs.contains("WARN") && seen.logs.contains("bootstrap-only"),
        "a warning names the bootstrap-only rule; logs: {}",
        seen.logs
    );
}

/// Red 7. Bootstrap token, `user_id` WITH `is_admin: true`: refused, zero
/// calls. Stage 10 makes the refusal the retired-field 400, before the verb
/// rule is reached.
#[tokio::test]
async fn red_07_a_pre_minted_id_with_the_flag_is_refused() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/create-user",
        &format!(
            r#"{{"external_id":"ada","display_name":"Ada","user_id":"{PRE_MINTED}","is_admin":true}}"#
        ),
        &bootstrap(),
    )
    .await;
    assert_eq!(
        (status, answer.to_string().as_str()),
        (StatusCode::BAD_REQUEST, IS_ADMIN_RETIRED_BODY)
    );
    assert!(log.drain().is_empty());
}

/// Red 8. Bootstrap token, no `user_id`: refused by the verb rule, with the
/// rewritten body. Since stage 10 the body carries no `is_admin` (one that
/// does is the retired-field 400).
#[tokio::test]
async fn red_08_an_ordinary_account_is_still_refused() {
    for body in [r#"{"external_id":"ada","display_name":"Ada"}"#] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, answer) = post(state, "/admin/create-user", body, &bootstrap()).await;
        assert_eq!(
            (status, answer.to_string().as_str()),
            (StatusCode::FORBIDDEN, VERB_RULE_BODY),
            "{body}"
        );
        assert!(log.drain().is_empty());
    }
}

/// Red 9. An attested administrator's body without `user_id`: the upstream
/// `user_id` is empty, so iam-db mints, as today.
#[tokio::test]
async fn red_09_an_attested_create_user_sends_an_empty_user_id() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada"}"#,
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");
    assert_eq!(answer["user_id"], CREATED_ID);
    let received = log.drain();
    assert_eq!(received[0].created_user_id.as_deref(), Some(""));
    assert_eq!(received[0].creates_admin, Some(false));
}

/// Red 10. Bootstrap token, every other verb outside the existing arms: refused
/// as today, zero calls. The verb-rule body is asserted on the verb that
/// renders it.
#[tokio::test]
async fn red_10_other_verbs_stay_refused_to_the_bootstrap_token() {
    for (path, body) in [
        (
            "/admin/revoke-credentials",
            format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        ),
        (
            "/admin/list-credentials",
            format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        ),
        (
            "/admin/revoke-credential",
            format!(r#"{{"user_id":"{OTHER_ID}","credential_id":"yadgar:credential:1"}}"#),
        ),
    ] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, answer) = post(state, path, &body, &bootstrap()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: got {answer}");
        if path == "/admin/revoke-credentials" {
            assert_eq!(answer.to_string(), VERB_RULE_BODY);
        }
        assert!(log.drain().is_empty(), "{path}: zero calls");
    }
}

/// Red 11. ADR-0966 with ADR-1014: the bootstrap caller decides the revoke
/// instruction at issue time. No gateway refusal; iam receives the demand AND
/// the instruction; the 200 echoes it as applied.
#[tokio::test]
async fn red_11_the_bootstrap_path_carries_the_revoke_instruction() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}","revoke_existing_credentials":true}}"#),
        &bootstrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");
    let received = log.drain();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].demands_zero_credential_admin, Some(true));
    assert_eq!(received[0].revokes_existing_credentials, Some(true));
    assert_eq!(answer["revoke_existing_credentials"], true);
}

/// Red 12. Bootstrap `issue-enrolment`, iam answering `PERMISSION_DENIED` with
/// its fixed sentence and with an arbitrary message: one 403, the new
/// enrolment-refusal text, neither "never held a credential" nor the upstream
/// message; label `PERMISSION_DENIED`.
#[test]
fn red_12_the_enrolment_refusal_is_one_403_true_in_both_modes() {
    let mut bodies = std::collections::BTreeSet::new();
    for message in [IAM_PERMISSION_DENIED_SENTENCE, UPSTREAM_SENTINEL] {
        let seen = seen(
            resolved(true),
            Refusals {
                issue_enrolment: Some(tonic::Status::permission_denied(message)),
                ..Default::default()
            },
            "/admin/issue-enrolment",
            &format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
            &bootstrap(),
        );
        assert_eq!(seen.status, StatusCode::FORBIDDEN);
        assert!(
            !seen.body.contains(message),
            "{message} leaked: {}",
            seen.body
        );
        assert!(
            !seen.body.contains("never held a credential"),
            "{}",
            seen.body
        );
        assert_eq!(seen.outcomes, vec!["PERMISSION_DENIED".to_string()]);
        bodies.insert(seen.body);
    }
    assert_eq!(
        bodies.into_iter().collect::<Vec<_>>(),
        vec![ENROLMENT_REFUSAL_BODY.to_string()]
    );
}

/// Red 13. With derivation off, iam-db refuses the demand with the instruction
/// `INVALID_ARGUMENT` (ADR-0943 point 2, store half). The gateway answers the
/// opaque 503 (ADR-0927), and the request did reach iam.
#[tokio::test]
async fn red_13_the_store_refusing_the_instruction_is_the_opaque_503() {
    let (state, log) = gateway_with(
        resolved(true),
        Refusals {
            issue_enrolment: Some(tonic::Status::invalid_argument(
                "the store refused the request",
            )),
            ..Default::default()
        },
    )
    .await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}","revoke_existing_credentials":true}}"#),
        &bootstrap(),
    )
    .await;
    assert_eq!(
        (status, answer.to_string().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY)
    );
    assert_eq!(log.drain().len(), 1, "the refusal moved to the store");
}

/// Red 14 (stage 3b) and the stage 10 verb-rule red. The verb-rule 403 equals
/// the stage 10 text byte for byte and carries neither "never held a
/// credential", nor "promote", nor any upstream message.
#[tokio::test]
async fn red_14_the_verb_rule_body_is_the_rewritten_text() {
    let (state, _log) = gateway(resolved(true)).await;
    // RAW BYTES, not re-serialised JSON: the stage 10 red is byte for byte.
    let (status, _headers, raw) = post_raw(
        state,
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada"}"#,
        &bootstrap(),
    )
    .await;
    let body = String::from_utf8(raw).expect("a UTF-8 body");
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::FORBIDDEN, VERB_RULE_BODY)
    );
    assert!(!body.contains("never held a credential"));
    assert!(!body.contains("promote"));
    assert!(!body.contains(UPSTREAM_SENTINEL));
}

// ---------------------------------------------------------------------------
// Max's rulings of 2026-10-24 on gateway#139 (yaadgaar #426 item 8)
// ---------------------------------------------------------------------------

/// What the switch answers when engaged. A literal, for
/// `ENROLMENT_REFUSAL_BODY`'s reason.
const SWITCHED_OFF_BODY: &str = r#"{"error":"pre-minted user ids are switched off on this gateway (chart: adminBootstrap.refusePreMintedUserId)"}"#;

/// One response as the caller receives it: status, every header, raw bytes.
async fn post_raw(
    state: Arc<AppState>,
    path: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
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
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.expect("a body");
    (status, headers, bytes.to_vec())
}

/// Ruling (a). On bootstrap `create-user` with a pre-minted id, a TAKEN id
/// (`ALREADY_EXISTS`), a refusal of the predicate (`PERMISSION_DENIED`: no
/// `administrators` team, an administrator exists, or the id is not
/// declared), a malformed id (`INVALID_ARGUMENT`), iam's refusal of a
/// well-formed id while `IAM_ADMIN_FROM_TEAM` is false (`FAILED_PRECONDITION`)
/// and an outage (`UNAVAILABLE`) are ONE answer: the same status, the same headers and the
/// same bytes, whatever message iam sent. So the bootstrap token cannot tell a
/// taken id from any other refusal, nor from an outage (ADR-0927).
#[tokio::test]
async fn ruling_a_every_bootstrap_create_user_refusal_is_one_answer() {
    let mut answers = Vec::new();
    for code in [
        tonic::Code::AlreadyExists,
        tonic::Code::PermissionDenied,
        tonic::Code::InvalidArgument,
        tonic::Code::FailedPrecondition,
        tonic::Code::Unavailable,
    ] {
        for message in [IAM_PERMISSION_DENIED_SENTENCE, UPSTREAM_SENTINEL] {
            let (state, log) = gateway_with(
                resolved(true),
                Refusals {
                    create_user: Some(tonic::Status::new(code, message)),
                    ..Default::default()
                },
            )
            .await;
            let answer = post_raw(
                state,
                "/admin/create-user",
                &create_body(PRE_MINTED),
                &bootstrap(),
            )
            .await;
            assert_eq!(log.drain().len(), 1, "{code:?}: iam was asked once");
            answers.push((code, message, answer));
        }
    }
    let (_, _, first) = &answers[0];
    for (code, message, answer) in &answers {
        assert_eq!(
            answer, first,
            "{code:?} ({message}) must be byte-equal to ALREADY_EXISTS: status, headers and body"
        );
    }
    assert_eq!(first.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        String::from_utf8_lossy(&first.2),
        UNAVAILABLE_BODY,
        "the one answer is the opaque 503"
    );
}

/// Ruling (b), engaged. The pre-minted arm is refused with the switch's own
/// 503, BEFORE the token is compared: nothing reaches iam, the acceptance
/// counter does not register, and a wrong token gets the same answer as the
/// right one.
#[test]
fn ruling_b_the_engaged_switch_refuses_the_pre_minted_arm_before_the_comparison() {
    let engaged = || Refusals {
        refuse_pre_minted: true,
        ..Default::default()
    };
    for token in [BOOTSTRAP_SECRET, "not-the-bootstrap-token"] {
        let seen = seen(
            resolved(true),
            engaged(),
            "/admin/create-user",
            &create_body(PRE_MINTED),
            &[(BOOTSTRAP_HEADER, token)],
        );
        assert_eq!(
            (seen.status, seen.body.as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, SWITCHED_OFF_BODY),
            "{token}: the engaged switch answers its own 503"
        );
        assert!(seen.received.is_empty(), "{token}: zero upstream calls");
        assert!(
            !seen.accepted,
            "{token}: the acceptance counter must not move"
        );
        assert_eq!(seen.outcomes, vec!["FAILED_PRECONDITION".to_string()]);
    }
}

/// Ruling (b), engaged: only the pre-minted arm is in reach. The enrolment
/// still passes for the bootstrap token (since stage 10 the only other arm),
/// and an attested administrator's `create-user` is untouched.
#[tokio::test]
async fn ruling_b_the_engaged_switch_leaves_every_other_arm_open() {
    let bootstrap_arms = [(
        "/admin/issue-enrolment",
        format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
    )];
    for (path, body) in bootstrap_arms {
        let (state, log) = gateway_with(
            resolved(true),
            Refusals {
                refuse_pre_minted: true,
                ..Default::default()
            },
        )
        .await;
        let (status, answer) = post(state, path, &body, &bootstrap()).await;
        assert_eq!(status, StatusCode::OK, "{path}: got {answer}");
        assert_eq!(log.drain().len(), 1, "{path}: iam was asked once");
    }
    let (state, log) = gateway_with(
        resolved(true),
        Refusals {
            refuse_pre_minted: true,
            ..Default::default()
        },
    )
    .await;
    let (status, answer) = post(
        state,
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada"}"#,
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "attested create-user: got {answer}");
    assert_eq!(log.drain().len(), 1);
}

/// Ruling (b), not engaged (the shipped value): the pre-minted arm is open,
/// as before the switch existed.
#[tokio::test]
async fn ruling_b_the_disengaged_switch_admits_the_pre_minted_arm() {
    let (state, log) = gateway_with(
        resolved(true),
        Refusals {
            refuse_pre_minted: false,
            ..Default::default()
        },
    )
    .await;
    let (status, answer) = post(
        state,
        "/admin/create-user",
        &create_body(PRE_MINTED),
        &bootstrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");
    assert_eq!(log.drain().len(), 1);
}

// ---------------------------------------------------------------------------
// Team access stage 10: the retirement release (plans/team-access.md, "Then
// the retirement"; ADR-0962, ADR-0963 (5), ADR-0966)
// ---------------------------------------------------------------------------

/// Stage 10 red: `set-user-admin` answers 404, by any method and from any
/// caller, and nothing reaches `iam`. The route is gone, so the answer is the
/// router's own 404 for a path it does not serve.
#[tokio::test]
async fn stage10_set_user_admin_answers_404() {
    let body = format!(r#"{{"user_id":"{OTHER_ID}","is_admin":true}}"#);
    let callers: [(&str, Vec<(&str, &str)>); 3] = [
        ("an administrator", as_admin()),
        ("the bootstrap token", bootstrap()),
        ("no credential", Vec::new()),
    ];
    for (who, headers) in callers {
        for method in [Method::POST, Method::GET] {
            let (state, log) = gateway(resolved(true)).await;
            let mut req = Request::builder()
                .method(method.clone())
                .uri("/admin/set-user-admin")
                .header("content-type", "application/json");
            for (name, value) in &headers {
                req = req.header(*name, *value);
            }
            let resp = router(state)
                .oneshot(
                    req.body(Body::from(body.clone()))
                        .expect("the request builds"),
                )
                .await
                .expect("the router answers");
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{method} as {who}: set-user-admin is retired (stage 10)"
            );
            assert!(log.drain().is_empty(), "{method} as {who}: zero calls");
        }
    }
}

/// Stage 10 red: a `create-user` body that carries `is_admin`, of any value,
/// `false` included, is the 400 naming the retired field. From the bootstrap
/// token (with and without `user_id`), from an administrator, and before any
/// credential is read; zero upstream calls in every case.
#[tokio::test]
async fn stage10_create_user_refuses_the_retired_is_admin_field() {
    let callers: [(&str, Vec<(&str, &str)>); 3] = [
        ("an administrator", as_admin()),
        ("the bootstrap token", bootstrap()),
        ("no credential", Vec::new()),
    ];
    for (who, headers) in callers {
        for flag in ["true", "false", "null", r#""false""#] {
            for body in [
                format!(r#"{{"external_id":"ada","display_name":"Ada","is_admin":{flag}}}"#),
                format!(
                    r#"{{"external_id":"ada","display_name":"Ada","user_id":"{PRE_MINTED}","is_admin":{flag}}}"#
                ),
            ] {
                let (state, log) = gateway(resolved(true)).await;
                // RAW BYTES, not re-serialised JSON.
                let (status, _headers, raw) =
                    post_raw(state, "/admin/create-user", &body, &headers).await;
                let answer = String::from_utf8(raw).expect("a UTF-8 body");
                assert_eq!(
                    (status, answer.as_str()),
                    (StatusCode::BAD_REQUEST, IS_ADMIN_RETIRED_BODY),
                    "{who}: {body}"
                );
                assert!(answer.contains("`is_admin`"), "the 400 names the field");
                assert!(log.drain().is_empty(), "{who}: {body}: zero calls");
            }
        }
    }
}

/// Stage 10: the retired-field 400 is a shape refusal. It is labelled
/// `INVALID_ARGUMENT`, like every other 400 here, and the bootstrap token is
/// never compared, so no acceptance is counted.
#[test]
fn stage10_the_retired_field_is_a_shape_refusal_and_counts_no_acceptance() {
    let seen = seen(
        resolved(true),
        Refusals::default(),
        "/admin/create-user",
        &format!(
            r#"{{"external_id":"ada","display_name":"Ada","user_id":"{PRE_MINTED}","is_admin":false}}"#
        ),
        &bootstrap(),
    );
    assert_eq!(seen.status, StatusCode::BAD_REQUEST);
    assert_eq!(seen.outcomes, vec!["INVALID_ARGUMENT".to_string()]);
    assert!(
        !seen.accepted,
        "no acceptance is counted for a shape refusal"
    );
    assert!(seen.received.is_empty());
}

/// Stage 10: what still reaches `iam` after the retirement. The bootstrap
/// token's pre-minted arm and an administrator's plain body both send
/// `is_admin: false`, because no caller can set the field any more.
#[tokio::test]
async fn stage10_every_create_user_sends_is_admin_false() {
    for (who, body, headers) in [
        ("the bootstrap token", create_body(PRE_MINTED), bootstrap()),
        (
            "an administrator",
            r#"{"external_id":"ada","display_name":"Ada"}"#.to_string(),
            as_admin(),
        ),
    ] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, answer) = post(state, "/admin/create-user", &body, &headers).await;
        assert_eq!(status, StatusCode::OK, "{who}: got {answer}");
        let received = log.drain();
        assert_eq!(received.len(), 1, "{who}");
        assert_eq!(received[0].creates_admin, Some(false), "{who}");
    }
}

/// Stage 10 guard: the ADR-0966 break-glass enrolment arm is untouched. The
/// bootstrap token's `issue-enrolment` for a declared administrator, without
/// the revoke instruction, is admitted and carries the demand; red 11 covers
/// the arm with the instruction.
#[tokio::test]
async fn stage10_the_break_glass_enrolment_is_still_admitted() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/issue-enrolment",
        &format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        &bootstrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {answer}");
    assert_eq!(answer["revoke_existing_credentials"], false);
    let received = log.drain();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].verb, "IssueEnrolment");
    assert_eq!(received[0].actor, None);
    assert_eq!(received[0].demands_zero_credential_admin, Some(true));
    assert_eq!(received[0].revokes_existing_credentials, Some(false));
}
