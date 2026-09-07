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
//! 3. **D73's self-demotion exclusion**, which needs an administrator with a
//!    resolved id to be the caller.
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
    ResolveCredentialResponse, SetUserAdminRequest, SetUserAdminResponse,
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

/// An `iam` that resolves one canned identity and records the three
/// administrative RPCs it is asked for.
struct AdminIam {
    answer: ResolveCredentialResponse,
    log: Arc<Log>,
    resolves: Arc<AtomicUsize>,
}

/// Write the stub's whole `IamService` impl: four real methods and nine refusals.
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
                self.log.push(Received {
                    verb: "CreateUser",
                    actor: r.unverified_actor,
                    has_idempotency_key: r.idempotency.is_some_and(|i| !i.key.is_empty()),
                });
                Ok(tonic::Response::new(CreateUserResponse {
                    meta: Some(Meta {
                        id: CREATED_ID.to_string(),
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
                });
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
                });
                Ok(tonic::Response::new(SetUserAdminResponse {}))
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
                        "this stub answers ResolveCredential and the three administrative verbs",
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

/// A gateway attesting against a stub `iam`, plus the log of what reached it.
async fn gateway(answer: ResolveCredentialResponse) -> (Arc<AppState>, Arc<Log>) {
    let log = Arc::new(Log::default());
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
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        iam,
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
        )
        .expect("the limiter opens"),
        allowed_origins: Vec::new(),
        trust: TrustBoundary::Undeclared,
        credential_limits: wide(),
        admin_limits: wide(),
        bootstrap: BootstrapToken::from_secret(BOOTSTRAP_SECRET),
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
        // REQUIRED, exactly as on `tools/call`: `Attested` carries a `Scope` and
        // a `Scope` names a workspace, which the gateway does not have to supply
        // and must not invent.
        ("x-yadgar-project", "acme/demo"),
    ]
}

/// The three verbs, with a body each, as an ADMINISTRATOR would send them.
fn admin_verbs() -> Vec<(&'static str, String)> {
    vec![
        (
            "/admin/create-user",
            r#"{"external_id":"ada","display_name":"Ada","is_admin":false}"#.to_string(),
        ),
        (
            "/admin/issue-enrolment",
            format!(r#"{{"user_id":"{OTHER_ID}"}}"#),
        ),
        (
            "/admin/set-user-admin",
            format!(r#"{{"user_id":"{OTHER_ID}","is_admin":true}}"#),
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
        r#"{"external_id":"ada","display_name":"Ada","is_admin":false}"#,
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
        (
            "/admin/create-user",
            r#"{"external_id":"ada","display_name":"Ada","is_admin":true}"#.to_string(),
        ),
        (
            "/admin/set-user-admin",
            format!(r#"{{"user_id":"{OTHER_ID}","is_admin":true}}"#),
        ),
    ] {
        let (state, log) = gateway(resolved(true)).await;
        let (status, answer) =
            post(state, path, &body, &[(BOOTSTRAP_HEADER, BOOTSTRAP_SECRET)]).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{path} is one of ADR-0492's two grants; got {answer}"
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
// D73's self-demotion exclusion, and the last-administrator guard (§ brief B)
// ---------------------------------------------------------------------------

/// `iam.proto:664` defers this rule to the gateway by name, because it is "a rule
/// about who may call this" and the only caller identity `iam` has is the one
/// ADR-0534 forbids authorising on. Here there is a real identity.
///
/// **It is also what keeps the administrator count above zero.** Nothing in `iam`
/// or `iam-db` counts administrators before clearing a flag, and the bootstrap
/// token can only ever SET one — so with self-demotion refused, every demotion
/// has a demoter who stays an administrator. The residual is the cached-flag race
/// named in `admin::is_self_demotion`, which is `iam-db`'s to close.
#[tokio::test]
async fn an_administrator_cannot_clear_their_own_flag() {
    let (state, log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        state,
        "/admin/set-user-admin",
        &format!(r#"{{"user_id":"{ADMIN_ID}","is_admin":false}}"#),
        &as_admin(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "got {answer}");
    assert!(
        log.drain().is_empty(),
        "and the write must not have happened: a refusal that still cleared the flag is the \
         defect wearing the shape of the fix"
    );
}

/// The three neighbouring cells the rule must NOT refuse, so it stays D73's
/// exclusion rather than a ban on the verb.
#[tokio::test]
async fn the_self_demotion_rule_refuses_only_self_demotion() {
    for (body, why) in [
        (
            format!(r#"{{"user_id":"{OTHER_ID}","is_admin":false}}"#),
            "demoting somebody else is the feature, and the demoter stays an administrator",
        ),
        (
            format!(r#"{{"user_id":"{ADMIN_ID}","is_admin":true}}"#),
            "D73 excludes DEMOTION; refusing a self-promotion would invent a rule the contract \
             does not have",
        ),
        (
            format!(r#"{{"user_id":"{OTHER_ID}","is_admin":true}}"#),
            "promoting somebody else is the ordinary case",
        ),
    ] {
        let (state, _log) = gateway(resolved(true)).await;
        let (status, answer) = post(state, "/admin/set-user-admin", &body, &as_admin()).await;
        assert_eq!(status, StatusCode::OK, "{why}; got {answer}");
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
/// what this returns is what `issue-enrolment` and `set-user-admin` take. Handing
/// back anything else would look identical until an administrator tried the next
/// step.
#[tokio::test]
async fn create_user_answers_with_the_id_the_other_verbs_take() {
    let (state, _log) = gateway(resolved(true)).await;
    let (status, answer) = post(
        Arc::clone(&state),
        "/admin/create-user",
        r#"{"external_id":"ada","display_name":"Ada","is_admin":false}"#,
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
