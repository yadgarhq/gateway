//! D67's join key, as each upstream RECEIVES it (ledger 1248).
//!
//! **THE GATEWAY MINTED THE ID AND KEPT IT.** Before ledger 1248 the id lived on
//! the gateway's own `CallRecord` and nowhere else: no outbound request carried
//! `x-yadgar-request-id`, so `iam` forwarded nothing to `iam-db`, and every
//! record downstream of the gateway joined on `""`. `task` was the exception
//! only because its requests carry a `Scope`, whose field 5 is the id.
//!
//! **EVERY ASSERTION HERE COMPARES AGAINST THE GATEWAY'S OWN `CallRecord`**, not
//! against "a UUID arrived". A gateway that minted a SECOND id for the header
//! would send a perfectly well-formed UUIDv7 and break the join exactly as
//! badly as sending none, and only a comparison with the record can see that.
//!
//! **The record is read from a `record::set_sink` capture, which is
//! THREAD-LOCAL.** `#[tokio::test]` runs a current-thread runtime and `send`
//! drives the router with `oneshot` on the test's own task, so the handler's
//! `Call` drops — and emits — on the thread that installed the sink.

use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request as HttpRequest, StatusCode};
use serde_json::{json, Value};
use tonic::transport::Channel;
use tower::ServiceExt;

use super::{post, state_with_upstreams};
use crate::http::router;
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::iam::v1::ResolveCredentialResponse;
use crate::pb::yadgar::taskapi::v1::{
    task_service_server::{TaskService, TaskServiceServer},
    CreateTaskRequest, CreateTaskResponse, EditTaskRequest, EditTaskResponse, FindTasksRequest,
    FindTasksResponse, ReadTaskRequest, ReadTaskResponse, RemoveTaskRequest, RemoveTaskResponse,
    TransitionTaskRequest, TransitionTaskResponse,
};

const HEADER: &str = "x-yadgar-request-id";

/// What one upstream RPC arrived carrying: its name, the header, and — for a
/// request that has one — `Scope.request_id`.
#[derive(Clone, Debug)]
struct Arrival {
    rpc: &'static str,
    header: Option<String>,
    scope: Option<String>,
}

type Arrivals = Arc<Mutex<Vec<Arrival>>>;

fn header_of<T>(req: &tonic::Request<T>) -> Option<String> {
    req.metadata()
        .get(HEADER)
        .map(|v| v.to_str().expect("the header is ASCII").to_string())
}

// ---------------------------------------------------------------------------
// A recording `iam`: every RPC is recorded; only ResolveCredential succeeds.
// ---------------------------------------------------------------------------

struct RecordingIam(Arrivals);

/// Write the whole `IamService` impl. See `stub_iam_service!` in the parent for
/// why the `#[tonic::async_trait]` attribute has to come from inside the macro.
macro_rules! recording_iam_service {
    ($($method:ident($req:ident) -> $resp:ident;)*) => {
        #[tonic::async_trait]
        impl crate::pb::yadgar::iam::v1::iam_service_server::IamService for RecordingIam {
            async fn resolve_credential(
                &self,
                req: tonic::Request<crate::pb::yadgar::iam::v1::ResolveCredentialRequest>,
            ) -> Result<tonic::Response<ResolveCredentialResponse>, tonic::Status> {
                self.0.lock().unwrap().push(Arrival {
                    rpc: "resolve_credential",
                    header: header_of(&req),
                    scope: None,
                });
                // AN ADMINISTRATOR, so the three `/admin` verbs get past
                // `authorise` and reach the RPC this file is about.
                Ok(tonic::Response::new(ResolveCredentialResponse {
                    user_id: "u-that-iam-resolved".to_string(),
                    valid_for_seconds: 300,
                    is_admin: true,
                    ..Default::default()
                }))
            }

            $(
                async fn $method(
                    &self,
                    req: tonic::Request<crate::pb::yadgar::iam::v1::$req>,
                ) -> Result<tonic::Response<crate::pb::yadgar::iam::v1::$resp>, tonic::Status> {
                    self.0.lock().unwrap().push(Arrival {
                        rpc: stringify!($method),
                        header: header_of(&req),
                        scope: None,
                    });
                    // REFUSED, and the outcome does not matter here: the request
                    // has arrived, which is the whole of what is being asserted.
                    Err(tonic::Status::unavailable("recorded, not served"))
                }
            )*
        }
    };
}

recording_iam_service! {
    login(LoginRequest) -> LoginResponse;
    redeem_enrolment(RedeemEnrolmentRequest) -> RedeemEnrolmentResponse;
    issue_credential(IssueCredentialRequest) -> IssueCredentialResponse;
    revoke_credential(RevokeCredentialRequest) -> RevokeCredentialResponse;
    list_credentials(ListCredentialsRequest) -> ListCredentialsResponse;
    issue_enrolment(IssueEnrolmentRequest) -> IssueEnrolmentResponse;
    create_user(CreateUserRequest) -> CreateUserResponse;
    set_user_admin(SetUserAdminRequest) -> SetUserAdminResponse;
    set_rate_limit_override(SetRateLimitOverrideRequest) -> SetRateLimitOverrideResponse;
    add_team_member(AddTeamMemberRequest) -> AddTeamMemberResponse;
    remove_team_member(RemoveTeamMemberRequest) -> RemoveTeamMemberResponse;
    set_inherited_setting(SetInheritedSettingRequest) -> SetInheritedSettingResponse;
}

// ---------------------------------------------------------------------------
// A recording `task`: `find_tasks` answers empty, the rest are refused.
// ---------------------------------------------------------------------------

struct RecordingTask(Arrivals);

impl RecordingTask {
    fn record<T>(
        &self,
        rpc: &'static str,
        req: &tonic::Request<T>,
        scope: Option<&crate::pb::yadgar::common::v1::Scope>,
    ) {
        self.0.lock().unwrap().push(Arrival {
            rpc,
            header: header_of(req),
            scope: scope.map(|s| s.request_id.clone()),
        });
    }
}

#[tonic::async_trait]
impl TaskService for RecordingTask {
    async fn find_tasks(
        &self,
        req: tonic::Request<FindTasksRequest>,
    ) -> Result<tonic::Response<FindTasksResponse>, tonic::Status> {
        self.record("find_tasks", &req, req.get_ref().scope.as_ref());
        Ok(tonic::Response::new(FindTasksResponse::default()))
    }

    async fn edit_task(
        &self,
        req: tonic::Request<EditTaskRequest>,
    ) -> Result<tonic::Response<EditTaskResponse>, tonic::Status> {
        self.record("edit_task", &req, req.get_ref().scope.as_ref());
        Err(tonic::Status::unavailable("recorded, not served"))
    }

    async fn transition_task(
        &self,
        req: tonic::Request<TransitionTaskRequest>,
    ) -> Result<tonic::Response<TransitionTaskResponse>, tonic::Status> {
        self.record("transition_task", &req, req.get_ref().scope.as_ref());
        Err(tonic::Status::unavailable("recorded, not served"))
    }

    async fn create_task(
        &self,
        req: tonic::Request<CreateTaskRequest>,
    ) -> Result<tonic::Response<CreateTaskResponse>, tonic::Status> {
        self.record("create_task", &req, req.get_ref().scope.as_ref());
        Err(tonic::Status::unavailable("recorded, not served"))
    }

    async fn read_task(
        &self,
        req: tonic::Request<ReadTaskRequest>,
    ) -> Result<tonic::Response<ReadTaskResponse>, tonic::Status> {
        self.record("read_task", &req, req.get_ref().scope.as_ref());
        Err(tonic::Status::unavailable("recorded, not served"))
    }

    async fn remove_task(
        &self,
        req: tonic::Request<RemoveTaskRequest>,
    ) -> Result<tonic::Response<RemoveTaskResponse>, tonic::Status> {
        self.record("remove_task", &req, req.get_ref().scope.as_ref());
        Err(tonic::Status::unavailable("recorded, not served"))
    }
}

// ---------------------------------------------------------------------------
// Wiring.
// ---------------------------------------------------------------------------

/// Serve `routes` on an ephemeral port, bound before it is served.
async fn serve(routes: tonic::service::Routes) -> Channel {
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the fake binds");
    let addr = incoming.local_addr().expect("a bound port");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(incoming)
            .await
    });
    tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy()
}

/// A gateway whose `iam` and `task` both record, and the one log they share.
async fn gateway() -> (Arc<crate::http::AppState>, Arrivals) {
    let arrivals = Arrivals::default();
    let iam = serve(tonic::service::Routes::new(
        crate::pb::yadgar::iam::v1::iam_service_server::IamServiceServer::new(RecordingIam(
            Arc::clone(&arrivals),
        )),
    ))
    .await;
    let task = serve(tonic::service::Routes::new(TaskServiceServer::new(
        RecordingTask(Arc::clone(&arrivals)),
    )))
    .await;
    let state = state_with_upstreams(iam, task, std::time::Duration::from_secs(30));
    (state, arrivals)
}

#[derive(Clone, Default)]
struct Records(Arc<Mutex<Vec<String>>>);

impl yadgar_telemetry::record::Sink for Records {
    fn write_record(&self, line: &str) -> std::io::Result<()> {
        self.0.lock().expect("the capture").push(line.to_string());
        Ok(())
    }
}

/// Send `req` through the real router, and return the status and the ONE
/// `CallRecord` the gateway emitted for it.
async fn send_recorded(
    state: Arc<crate::http::AppState>,
    req: HttpRequest<Body>,
) -> (StatusCode, Value) {
    let records = Records::default();
    let status = {
        let _sink = yadgar_telemetry::record::set_sink(Arc::new(records.clone()));
        let resp = router(state)
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = resp.status();
        to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read the body");
        status
    };
    let lines = records.0.lock().expect("the capture").clone();
    assert_eq!(
        lines.len(),
        1,
        "exactly one gateway CallRecord for one inbound request: {lines:?}"
    );
    let record: Value = serde_json::from_str(&lines[0]).expect("a JSON record");
    (status, record)
}

/// The id on the gateway's own record — which must be a real one, or every
/// comparison below would pass on two empty strings.
fn minted(record: &Value) -> String {
    let id = record["request_id"]
        .as_str()
        .expect("a request_id")
        .to_string();
    assert!(
        uuid::Uuid::parse_str(&id).is_ok(),
        "the gateway's record carries a minted UUID, not `{id}`"
    );
    id
}

/// Every arrival carried `want` in the header — and, where the request has a
/// `Scope`, in field 5 too. Also that `rpcs` is exactly what arrived, so a
/// request that never reached the fake cannot pass vacuously.
fn assert_all_carry(arrivals: &Arrivals, rpcs: &[&str], want: &str) {
    let seen = arrivals.lock().unwrap().clone();
    let names: Vec<&str> = seen.iter().map(|a| a.rpc).collect();
    assert_eq!(names, rpcs, "the upstream RPCs this request made: {seen:?}");
    for a in &seen {
        assert_eq!(
            a.header.as_deref(),
            Some(want),
            "`{}` must carry the gateway record's request id as `{HEADER}`: {a:?}",
            a.rpc
        );
        if let Some(scope) = &a.scope {
            assert_eq!(scope, want, "`{}`'s Scope.request_id: {a:?}", a.rpc);
        }
    }
}

fn json_post(uri: &str) -> axum::http::request::Builder {
    HttpRequest::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

/// `tools/call`: BOTH hops — `iam` resolving the credential, and `task` serving
/// the tool — carry the id on the gateway's record.
#[tokio::test]
async fn tools_call_hands_iam_and_task_the_id_on_its_own_record() {
    let (state, arrivals) = gateway().await;
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: {},
            },
            "name": "find_tasks",
            "arguments": {},
        }
    });
    let req = post()
        .header(headers::METHOD, "tools/call")
        .header(headers::NAME, "find_tasks")
        .header("x-yadgar-project", "acme/demo")
        .header(axum::http::header::AUTHORIZATION, "Bearer a-token")
        // A CALLER-SUPPLIED ID IS DISCARDED (D67), so one sent here must not be
        // what any upstream receives.
        .header(HEADER, "a-caller-chose-this")
        .body(Body::from(body.to_string()))
        .expect("request");
    let (status, record) = send_recorded(state, req).await;
    assert_eq!(status, StatusCode::OK, "{record}");
    let id = minted(&record);
    assert_all_carry(&arrivals, &["resolve_credential", "find_tasks"], &id);
}

/// `/auth/login`: unauthenticated, and the `iam` → `iam-db` hop it starts is
/// the one D67's iam-db actor lines join on.
#[tokio::test]
async fn login_hands_iam_the_id_on_its_own_record() {
    let (state, arrivals) = gateway().await;
    let body = r#"{"username":"u","password":"p"}"#;
    let req = json_post("/auth/login")
        .body(Body::from(body))
        .expect("request");
    let (_, record) = send_recorded(state, req).await;
    let id = minted(&record);
    assert_all_carry(&arrivals, &["login"], &id);
}

/// `/auth/enrol`, the other unauthenticated path.
#[tokio::test]
async fn enrol_hands_iam_the_id_on_its_own_record() {
    let (state, arrivals) = gateway().await;
    let body = r#"{"secret":"s","password":"p"}"#;
    let req = json_post("/auth/enrol")
        .body(Body::from(body))
        .expect("request");
    let (_, record) = send_recorded(state, req).await;
    let id = minted(&record);
    assert_all_carry(&arrivals, &["redeem_enrolment"], &id);
}

/// The three administrative verbs: the attestation AND the verb carry the SAME
/// id, because both are one inbound request.
#[tokio::test]
async fn each_admin_verb_hands_iam_one_id_for_attestation_and_verb() {
    let verbs = [
        (
            "/admin/create-user",
            r#"{"external_id":"ada","display_name":"Ada","is_admin":false}"#,
            "create_user",
        ),
        (
            "/admin/issue-enrolment",
            r#"{"user_id":"yadgar:user:someone-else"}"#,
            "issue_enrolment",
        ),
        (
            "/admin/set-user-admin",
            r#"{"user_id":"yadgar:user:someone-else","is_admin":true}"#,
            "set_user_admin",
        ),
    ];
    for (path, body, rpc) in verbs {
        let (state, arrivals) = gateway().await;
        let req = json_post(path)
            .header(axum::http::header::AUTHORIZATION, "Bearer a-token")
            .header("x-yadgar-project", "acme/demo")
            .body(Body::from(body))
            .expect("request");
        let (_, record) = send_recorded(state, req).await;
        let id = minted(&record);
        assert_all_carry(&arrivals, &["resolve_credential", rpc], &id);
    }
}

// ---------------------------------------------------------------------------
// `project`: the fallback `ResolveProject` an enforced refusal dials.
// ---------------------------------------------------------------------------

/// A recording `project`: `ResolveProject` answers, `ListProjects` is refused.
struct RecordingProject(Arrivals);

#[tonic::async_trait]
impl crate::pb::yadgar::project::v1::project_service_server::ProjectService for RecordingProject {
    async fn resolve_project(
        &self,
        req: tonic::Request<crate::pb::yadgar::project::v1::ProjectServiceResolveProjectRequest>,
    ) -> Result<
        tonic::Response<crate::pb::yadgar::project::v1::ProjectServiceResolveProjectResponse>,
        tonic::Status,
    > {
        self.0.lock().unwrap().push(Arrival {
            rpc: "resolve_project",
            header: header_of(&req),
            scope: None,
        });
        Ok(tonic::Response::new(Default::default()))
    }

    async fn list_projects(
        &self,
        _: tonic::Request<crate::pb::yadgar::project::v1::ProjectServiceListProjectsRequest>,
    ) -> Result<
        tonic::Response<crate::pb::yadgar::project::v1::ProjectServiceListProjectsResponse>,
        tonic::Status,
    > {
        Err(tonic::Status::unimplemented(
            "the registry here is loaded_with",
        ))
    }
}

/// `tools/call` under ENFORCEMENT, claiming a workspace the registry refuses
/// beneath a registered namespace anchor: `attest` hands the call's id to
/// `projects.check`, and the fallback `ResolveProject` must carry the id on
/// the call's own record — the same one `iam` was handed.
///
/// **THE MUTANT THIS EXISTS FOR** is `attest` passing a fresh
/// `crate::request_id()` to `check` instead of `attested.scope.request_id`.
/// Every other test in the suite survives it, because `project` reads no header
/// today; the join breaks silently the day it does.
#[tokio::test]
async fn an_enforced_refusal_hands_project_the_id_on_the_calls_own_record() {
    let (state, arrivals) = gateway().await;
    let project = serve(tonic::service::Routes::new(
        crate::pb::yadgar::project::v1::project_service_server::ProjectServiceServer::new(
            RecordingProject(Arc::clone(&arrivals)),
        ),
    ))
    .await;
    let mut state = Arc::try_unwrap(state)
        .ok()
        .expect("the only handle on a fresh state");
    // `yadgarhq` is a registered ANCHOR and `yadgarhq/gateway` is not
    // registered beneath it: an anchored refusal, the one case that dials.
    state.projects = Arc::new(crate::project::Validator::new(
        crate::project::Registry::loaded_with(["yadgarhq".to_string()]),
        crate::project::Mode::Enforcing,
        project,
    ));

    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: {},
            },
            "name": "find_tasks",
            "arguments": {},
        }
    });
    let req = post()
        .header(headers::METHOD, "tools/call")
        .header(headers::NAME, "find_tasks")
        .header("x-yadgar-project", "yadgarhq/gateway")
        .header(axum::http::header::AUTHORIZATION, "Bearer a-token")
        .body(Body::from(body.to_string()))
        .expect("request");
    let (status, record) = send_recorded(Arc::new(state), req).await;
    assert_ne!(status, StatusCode::OK, "the claim is refused: {record}");
    let id = minted(&record);
    assert_all_carry(&arrivals, &["resolve_credential", "resolve_project"], &id);
}
