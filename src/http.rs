//! The HTTP surface: POST only, stateless.
//!
//! TWO paths, and the asymmetry is the thing to know. `/` is MCP and every call
//! through it carries an identity. `/auth/login` is not MCP and carries none —
//! it is where a client with no credential gets one (D75), so it is the only
//! unauthenticated surface this server has.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde_json::{json, Value};
use tonic::transport::Channel;
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::attest::{self, Attestation, Claimed};
use crate::limit::{Decision, Limiter};
use crate::mcp::{self, codes, headers, meta_keys};
use crate::pb::yadgar::iam::v1::{iam_service_client::IamServiceClient, LoginRequest};
use crate::tools;

const SERVICE: &str = "gateway";

/// The bounded labels for the two methods that are not `tools/call`.
///
/// `&'static str` and a closed set, for the same reason `tools::label_for`
/// exists: a metric label must come from a fixed range (D67).
const DISCOVER: &str = "server/discover";
const TOOLS_LIST: &str = "tools/list";
/// The login endpoint's label. A PATH rather than an MCP method, because that is
/// what it is — but bounded and `&'static` for the same D67 reason as the two
/// above.
const AUTH_LOGIN: &str = "auth/login";

/// How long `login` waits on `iam` before answering without it.
///
/// A CONSTANT rather than a setting: it bounds an unauthenticated request, and a
/// bound an operator can raise is one an operator can raise to something useless.
/// Sized well above a healthy call — `iam` spends ~50ms on Argon2id for every
/// attempt, including one for a username it has never seen — so this fires on a
/// stall rather than on load.
const LOGIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

pub struct AppState {
    pub attestation: Attestation,
    pub task: Channel,
    /// The `iam` logic service, for `POST /auth/login` and nothing else (D75).
    /// Attestation still comes from headers — this channel issues credentials, it
    /// does not verify them.
    pub iam: Channel,
    /// D74's token buckets, in the shared cache. Held here rather than built per
    /// request so one connection manager serves the whole process.
    pub limiter: Limiter,
    /// Origins permitted to reach this server from a browser. Empty means no
    /// browser origin is accepted at all, which is the correct default for a
    /// server whose clients are agents.
    pub allowed_origins: Vec<String>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // MCP is ONE endpoint, POST only.
        //
        // GET and DELETE return 405. The spec frames that as a SHOULD, under
        // backward compatibility with the revisions that had a GET/SSE stream —
        // it is not a blanket MUST, and this comment says so because the first
        // reading of the spec recorded it as one. The effect is the same: there
        // is no GET stream in this revision, so there is nothing for a GET to do.
        .route("/", post(handle).fallback(method_not_allowed))
        // NOT MCP, and the one path on this server that is not (D75). `yaadgaar
        // login` has no credential yet, so it cannot speak the authenticated
        // protocol the rest of this router serves — the whole point of the
        // endpoint is to hand it the token every other call carries.
        //
        // BEFORE `.layer(...)`, and that is a security decision rather than
        // formatting. `Router::layer` applies only to routes registered above it,
        // so a route added after this line would be the one unauthenticated
        // endpoint on the server accepting a body of any size.
        .route("/auth/login", post(login).fallback(method_not_allowed))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state)
}

async fn method_not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, "MCP uses POST").into_response()
}

/// Username and password to a token (D72, D75).
///
/// The ONE endpoint on this server that takes no credential, because it is the
/// one that issues them: `yaadgaar login` has nothing to present yet. It is a
/// thin translation of `iam.Login` — the JSON field names are the proto's field
/// names, and what to make of `iam`'s answer is decided entirely by
/// [`login_failure`].
///
/// **Every answer derived from the UPSTREAM is built by [`login_failure`], from a
/// `tonic::Code` and nothing else.** A `Code` is a bare enum with no message
/// attached, so at the point that status, body and headers are chosen there is no
/// upstream text in scope that COULD be interpolated into them. An earlier version
/// of this comment claimed that property for the whole function and was wrong: the
/// failure arm below binds `e`, and the selection used to sit six lines under
/// `e.message()`. Moving the choice behind a function that cannot see `e` is what
/// makes the claim true, and [`login_failure`]'s test asserts it over every code
/// rather than over the one an unreachable upstream happens to produce.
///
/// So this function names no body and no header on any path that has spoken to
/// `iam`. It maps `e.code()` and logs `e`: the real code and message go to the
/// log, where an operator can read them and a caller cannot.
///
/// The two 400s below are the exception, and are not one in substance. They are
/// raised before the request is sent, so they describe THIS server's reading of
/// the caller's own JSON and can disclose nothing about a password nobody has
/// checked yet.
async fn login(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    // Started before the work, and NOT carrying an identity: nothing has been
    // attested on this path — the caller is proving who it is, which is the
    // request rather than a fact about it. Putting the submitted username in the
    // scope would write an unverified claim, and a wrong password's username, to
    // the telemetry store.
    let call = Call::start(SERVICE, AUTH_LOGIN, Kind::Write, tel(crate::request_id()));

    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        call.fail("INVALID_ARGUMENT");
        return text(StatusCode::BAD_REQUEST, r#"{"error":"invalid JSON"}"#);
    };
    let (Some(username), Some(password)) = (
        req.get("username").and_then(Value::as_str),
        req.get("password").and_then(Value::as_str),
    ) else {
        call.fail("INVALID_ARGUMENT");
        return text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`username` and `password` are required"}"#,
        );
    };

    let mut client = IamServiceClient::new(state.iam.clone());
    let rpc = client.login(LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
        // OPTIONAL here, though `yaadgaar` always sends it. It only names the
        // machine so a person can tell their credentials apart when revoking
        // one; refusing a request for want of it would add a rule the
        // contract does not have.
        label: req
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    });
    // A DEADLINE, because this is the first surface reachable with no credential.
    // An `iam` that accepts the connection and then stalls would otherwise hold
    // the request — and the connection under it — open for as long as it liked,
    // and an unauthenticated caller could open as many as it wanted. `task`'s
    // path has no deadline either and that is not made worse here; this one is
    // added because the caller does not have to be anyone to reach it.
    //
    // Generous rather than tight: Argon2id verification is deliberately expensive
    // (~50ms in `iam`, and it runs even for an unknown username), so a budget
    // sized for a healthy RPC would turn load into refusals.
    let resp = match tokio::time::timeout(LOGIN_DEADLINE, rpc).await {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => {
            // THE ONLY PLACE THE REAL CODE IS WRITTEN DOWN, and it goes to the
            // log rather than to the caller. Without this an operator watching a
            // login outage sees an opaque 503 and no reason for it.
            tracing::warn!(code = ?e.code(), message = e.message(), "login refused or failed");
            call.fail(if e.code() == tonic::Code::Unauthenticated {
                "UNAUTHENTICATED"
            } else {
                "UNAVAILABLE"
            });
            // `e.code()`, never `e`. See this function's doc comment.
            return login_failure(e.code());
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_ms = LOGIN_DEADLINE.as_millis(),
                "login timed out waiting for iam"
            );
            call.fail("UNAVAILABLE");
            // Through the SAME builder as every other failure, so a stall is
            // indistinguishable from the codes it is collapsed with rather than
            // being a third answer somebody has to remember to keep opaque.
            return login_failure(tonic::Code::DeadlineExceeded);
        }
    };

    // ONLY `token`. `LoginResponse.credential_id` is dropped: the client's
    // `LoginResponse` has one field, and a value nothing reads is a value that
    // only widens what a successful response discloses.
    let rendered = json!({ "token": resp.token }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        // DELIBERATELY EMPTY, unlike every other record in this file. `payload`
        // is stored in the wide event, and the payload here is a bearer token
        // shown exactly once — copying the idiom from `measured` would write
        // every credential this system issues into the telemetry store. The byte
        // count above is the part that answers D67's question.
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}

/// A JSON response whose body is already rendered.
///
/// Separate from [`reply`], which takes a `Value` and a bare `u16`: rendering
/// through a `Value` would put a `format!` on the login path, where the next
/// person would reasonably add an interpolation. It sets the content type and no
/// other header, and every login response is built through it — so "no
/// `WWW-Authenticate`" is checkable in one place, for whatever a layer may add
/// afterwards (`no_layer_adds_an_authentication_challenge` covers that half).
fn text(status: StatusCode, body: &str) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Reject a browser origin we do not know.
///
/// The spec: "Servers MUST validate the `Origin` header on all incoming
/// connections to prevent DNS rebinding attacks. If the `Origin` header is
/// present and invalid, servers MUST respond with HTTP 403 Forbidden."
///
/// **This is not authentication and must not be mistaken for it.** It stops a web
/// page in a browser from driving this server; it stops nothing that sets its own
/// headers. Absence is allowed because a non-browser client sends no Origin —
/// which is exactly why it cannot substitute for attestation.
fn origin_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(axum::http::header::ORIGIN) else {
        // Absent, and allowed: a non-browser client sends no Origin — which is
        // exactly why this cannot substitute for attestation.
        return true;
    };
    // PRESENT AND UNPARSEABLE IS PRESENT AND INVALID, and the spec's MUST covers
    // it: "If the Origin header is present and invalid, servers MUST respond with
    // HTTP 403 Forbidden."
    //
    // This used to be `.and_then(|v| v.to_str().ok())`, which collapsed a header
    // of non-ASCII bytes into `None` and took the absent arm — so the one Origin
    // that could not be checked was the one that was waved through.
    let Ok(origin) = raw.to_str() else {
        return false;
    };
    // An EMPTY allowlist denies every origin. `is_empty() || any()` is the
    // plausible-looking "fix" that would accept every origin in the default
    // configuration, and it would pass a suite that only tested a populated list.
    state.allowed_origins.iter().any(|a| a == origin)
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

async fn handle(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if !origin_ok(&state, &headers) {
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    let request: mcp::Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return reply(
                400,
                mcp::error(None, codes::PARSE_ERROR, &format!("invalid JSON: {e}")),
            )
        }
    };

    let meta = match request.validate() {
        Ok(m) => m,
        Err(e) => {
            return reply(
                e.http_status(),
                mcp::error(request.id.as_ref(), e.code(), &e.to_string()),
            )
        }
    };

    if let Err(e) = mcp::cross_check_headers(
        &meta,
        header(&headers, headers::PROTOCOL_VERSION),
        header(&headers, headers::METHOD),
        header(&headers, headers::NAME),
    ) {
        return reply(
            e.http_status(),
            mcp::error(request.id.as_ref(), e.code(), &e.to_string()),
        );
    }

    // A notification takes no response at all.
    let Some(id) = request.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };

    match request.method.as_str() {
        DISCOVER => measured(DISCOVER, || discover(&id)),
        TOOLS_LIST => measured(TOOLS_LIST, || tools_list(&id)),
        "tools/call" => tools_call(state, &id, &request.params, &headers).await,
        // NO record for an unknown method, deliberately. Its only available label
        // is the string the caller invented, and D67's cardinality rule means a
        // caller must not be able to mint a Prometheus series — the same reason
        // `tools::label_for` resolves a tool name to a bounded label before
        // anything is measured.
        other => reply(
            200,
            mcp::error(
                Some(&id),
                codes::METHOD_NOT_FOUND,
                &format!("unknown method: {other}"),
            ),
        ),
    }
}

/// The `tools/list` payload.
fn tools_list(id: &Value) -> Value {
    mcp::result(
        id,
        as_object(json!({
            "tools": tools::definitions(),
            // Cacheable by anyone: the tool list is identical for every caller. It
            // becomes `cacheScope: "private"` the day a tool is gated on who is
            // asking.
            "ttlMs": 300_000,
            "cacheScope": "public",
        })),
    )
}

/// Answer, and record what it cost (D67).
///
/// **`Call::start` used to be reached only inside `tools_call`**, so two of the
/// three methods this server implements returned bytes nothing measured — and
/// `tools/list` is the larger payload of the two. A method that emits no record
/// looks exactly like a method nobody calls, which is the reading D15's
/// retirement rule would act on.
fn measured(tool: &'static str, build: impl FnOnce() -> Value) -> Response {
    // Started BEFORE the work, so the duration covers the handler.
    let call = Call::start(SERVICE, tool, Kind::Read, tel(crate::request_id()));
    let rendered = serde_json::to_string(&build()).unwrap_or_default();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        payload: rendered.clone(),
        // One document, not a collection: `tools/list` returns a single result
        // object, and counting its tools as rows would make the number mean
        // something different from what it means on `find_tasks`.
        rows: 1,
        ..Default::default()
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        rendered,
    )
        .into_response()
}

/// A telemetry scope for a call with no attested identity.
///
/// `user_id` and `project_id` stay empty rather than being filled from what the
/// caller claimed: on these paths nothing has been attested, and a scope that
/// carried a claim would put an unverified identity into the record.
fn tel(request_id: String) -> yadgar_telemetry::observe::Scope {
    yadgar_telemetry::observe::Scope {
        request_id,
        instance_id: String::new(),
        user_id: String::new(),
        project_id: String::new(),
    }
}

/// `server/discover` — the spec says "Servers MUST implement it", replacing the
/// `initialize` handshake that a stateless protocol has nowhere to keep.
fn discover(id: &Value) -> Value {
    mcp::result(
        id,
        as_object(json!({
            "supportedVersions": [mcp::PROTOCOL_VERSION],
            "capabilities": { "tools": {} },
            "_meta": {
                meta_keys::SERVER_INFO: {
                    "name": "yadgar-gateway",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            },
            "instructions": "yadgar: durable memory, wiki and tasks for coding agents.",
            "ttlMs": 3_600_000,
            "cacheScope": "public",
        })),
    )
}

async fn tools_call(
    state: Arc<AppState>,
    id: &Value,
    params: &Value,
    headers: &HeaderMap,
) -> Response {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

    // Resolved to BOUNDED values before anything is measured. An unknown tool
    // never reaches the metric layer, so a caller cannot mint Prometheus series
    // by inventing names (D67's cardinality rule) — nor a token bucket per
    // invented name, which would be the same defect in the shared cache.
    //
    // These two are the only components of the bucket key that this bounds. The
    // third, the user id, arrives as a header and is bounded where the key is
    // built instead — see `limit::user_component`, which is where that half of
    // the same argument now lives.
    let (Some(label), Some(module)) = (tools::label_for(name), tools::module_for(name)) else {
        return reply(
            200,
            mcp::error(
                Some(id),
                codes::INVALID_PARAMS,
                &format!("unknown tool: {name}"),
            ),
        );
    };

    // Minted here, never read from the request (D67). See `crate::request_id`.
    let request_id = crate::request_id();

    let attested = match attest::attest(
        &state.attestation,
        Claimed {
            user_id: header(headers, "x-yadgar-user"),
            project_id: header(headers, "x-yadgar-project"),
            instance_id: header(headers, "x-yadgar-instance"),
        },
        request_id.clone(),
    ) {
        Ok(s) => s,
        Err(e) => {
            // A REFUSED call is still a call, and it is the one most worth
            // seeing. Recorded here because the `Call` for the success path
            // cannot be started until there is an attested scope to carry — so
            // without this, every authentication failure in the system is
            // invisible to D67 and a credential-stuffing run looks like silence.
            Call::start(SERVICE, label, kind_of(name), tel(request_id)).fail("UNAUTHENTICATED");
            return reply(
                401,
                mcp::error(Some(id), codes::INVALID_REQUEST, &e.to_string()),
            );
        }
    };
    let scope = attested.scope;

    // D74, and BEFORE any upstream work: refusing here means the loop this
    // protects against costs `task` nothing at all. Enforcing per module would
    // let it cost every service its work before the last one said no.
    let kind = kind_of(name);
    if let Some(refusal) =
        throttled(&state, id, &scope, label, module, kind, &attested.limits).await
    {
        // A throttled call is a call, for the same reason the refusal above is.
        // Without this a throttling storm is indistinguishable from silence,
        // which is the reading D15's retirement rule would act on.
        //
        // The ATTESTED scope rides on it, unlike the UNAUTHENTICATED record above
        // — there identity was never established, here it was, and "who is being
        // throttled" is the first question anyone reading this record has. It
        // goes in the wide event and NOT in a metric label, which is the same
        // split every other record on this path already makes.
        Call::start(
            SERVICE,
            label,
            kind,
            yadgar_telemetry::observe::Scope {
                request_id,
                instance_id: scope.instance_id.clone(),
                user_id: scope.user_id.clone(),
                project_id: scope.project_id.clone(),
            },
        )
        .fail("RESOURCE_EXHAUSTED");
        return refusal;
    }

    let call = Call::start(
        SERVICE,
        label,
        kind,
        yadgar_telemetry::observe::Scope {
            request_id,
            instance_id: scope.instance_id.clone(),
            user_id: scope.user_id.clone(),
            project_id: scope.project_id.clone(),
        },
    );

    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let outcome = tools::call(state.task.clone(), scope, name, &args).await;
    let (status, rows, payload) = shape(id, outcome);

    // Serialise ONCE, and measure exactly what goes on the wire.
    //
    // This is the number D67 exists for: bytes and words returned TO THE CALLER.
    // Every other hop sees protobuf, which is a different size and answers a
    // different question — so if this were measured anywhere else in the system
    // it would quietly be measuring the wrong thing.
    let rendered = serde_json::to_string(&payload).unwrap_or_default();
    call.finish(Outcome {
        status,
        encoded_bytes: Some(rendered.len() as u64),
        payload: rendered.clone(),
        rows,
        ..Default::default()
    });

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        rendered,
    )
        .into_response()
}

/// Spend a token, and build the refusal if there is none to spend (D74).
///
/// `Some` is a 429 the caller must be sent; `None` means carry on. Split out of
/// `tools_call` because a limiter that has three outcomes and only one of them
/// returns is exactly the shape that belongs behind a name.
async fn throttled(
    state: &AppState,
    id: &Value,
    scope: &crate::pb::yadgar::common::v1::Scope,
    label: &'static str,
    module: &'static str,
    kind: Kind,
    overrides: &crate::limit::Overrides,
) -> Option<Response> {
    match state
        .limiter
        .check(&scope.user_id, module, kind, overrides)
        .await
    {
        Decision::Allowed => None,

        Decision::Throttled { retry_after } => Some(refusal(
            id,
            module,
            kind,
            retry_after,
            "the {module} {kind} bucket is empty",
        )),

        // FAIL OPEN ONTO A FLOOR, LOUDLY. The argument is on
        // `Decision::Degraded`; the loudness is here, and it is the condition
        // that argument depends on. No user in the log line and none in the label
        // — D72 and D77 both keep usernames out of both, and an unbounded label
        // would breach D67 besides.
        Decision::Degraded(why) => {
            degraded(label, module, why, "allowed");
            None
        }

        // DEGRADED AND REFUSED, which is what makes the floor a floor. Counted
        // apart from the allowed case: a floor that has started refusing real
        // traffic must be visible, or "the degradation is not silent" — the whole
        // ground the floor is accepted on — is untrue.
        Decision::DegradedThrottled {
            reason,
            retry_after,
        } => {
            degraded(label, module, reason, "throttled");
            Some(refusal(
                id,
                module,
                kind,
                retry_after,
                "the shared cache cannot be reached and this replica's own floor for the \
                 {module} {kind} bucket is empty",
            ))
        }
    }
}

/// Count and log one degraded call.
///
/// `outcome` is `allowed` or `throttled` — two values, so the series stays inside
/// D67's cardinality rule, and the distinction is the one an operator needs:
/// whether the floor is merely in force or is turning traffic away.
fn degraded(
    label: &'static str,
    module: &'static str,
    why: crate::limit::Degrade,
    outcome: &'static str,
) {
    metrics::counter!(
        crate::limit::DEGRADED,
        "service" => SERVICE,
        "tool" => label,
        "reason" => why.label(),
        "outcome" => outcome,
    )
    .increment(1);
    tracing::warn!(
        reason = %why,
        tool = label,
        module,
        outcome,
        "rate limiting is DEGRADED: the shared cache could not answer, so this call is held to \
         this replica's local floor of rate/maxReplicas rather than the shared bucket (D74)"
    );
}

/// The 429 a refused call receives, from either bucket that can refuse it.
///
/// **The two are deliberately indistinguishable to a CLIENT**: the correct client
/// behaviour is identical, and a client that could tell a degraded refusal from an
/// ordinary one would be tempted to treat one of them as advisory. They are
/// distinguished to an operator, in the metric `degraded` emits.
///
/// `what` is a template with `{module}` and `{kind}` in it rather than a formatted
/// string, so the two call sites cannot drift on how they name the bucket.
fn refusal(
    id: &Value,
    module: &'static str,
    kind: Kind,
    retry_after: std::time::Duration,
    what: &str,
) -> Response {
    // WHOLE SECONDS in the header (RFC 9110), and never zero: `0` reads as
    // "retry immediately", which is the herd this exists to avoid. The exact
    // figure rides in `data`.
    let seconds = retry_after.as_secs_f64().ceil().max(1.0) as u64;
    let header_value = seconds.to_string();
    let kind_name = crate::limit::kind_str(kind);
    let message = format!(
        "{}; retry in {seconds}s",
        what.replace("{module}", module)
            .replace("{kind}", kind_name)
    );
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::header::RETRY_AFTER, header_value.as_str()),
        ],
        mcp::error_data(
            Some(id),
            codes::RATE_LIMITED,
            &message,
            json!({
                "retryAfterMs": (retry_after.as_secs_f64() * 1000.0).ceil() as u64,
                "module": module,
                "kind": kind_name,
            }),
        )
        .to_string(),
    )
        .into_response()
}

/// One tool's result, as the three things the record and the reply both need:
/// the bounded status label, the row count, and the JSON-RPC body.
///
/// Split out of `tools_call` because that function crossed the function-size
/// ceiling — along the seam that was already there, since this is the only part
/// of it that is a pure transformation of what the tool returned.
fn shape(
    id: &Value,
    result: Result<tools::Output, tools::ToolError>,
) -> (&'static str, u32, Value) {
    match result {
        Ok(out) => (
            "OK",
            // The count the tool already knew, carried through instead of
            // discarded — see `tools::Output`.
            out.rows,
            mcp::result(
                id,
                as_object(json!({
                    // Structured AND textual. `structuredContent` is what a
                    // program consumes; `content` is what a model reads, and a
                    // client that understands only one still works.
                    "content": [{ "type": "text", "text": out.content.to_string() }],
                    "structuredContent": out.content,
                })),
            ),
        ),
        Err(e) => {
            // A TOOL-level failure, not a protocol error: the MCP request was
            // well formed and the tool ran and failed. Returning a JSON-RPC error
            // here would tell the client its request was malformed, and it would
            // stop retrying things that are worth retrying.
            let status = match &e {
                tools::ToolError::Upstream(s) => yadgar_telemetry::grpc::status_name(s),
                _ => "INVALID_ARGUMENT",
            };
            (
                status,
                0,
                mcp::result(
                    id,
                    as_object(json!({
                        "content": [{ "type": "text", "text": e.to_string() }],
                        "isError": true,
                    })),
                ),
            )
        }
    }
}

/// Read or write, for `CallRecord.kind`. A wrong answer here makes read and
/// write traffic indistinguishable in the roll-ups.
fn kind_of(name: &str) -> Kind {
    if tools::is_write(name) {
        Kind::Write
    } else {
        Kind::Read
    }
}

fn as_object(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

/// What one gRPC code from `iam.Login` becomes on the wire (D72, D75).
///
/// **THIS FUNCTION IS THE SECURITY PROPERTY, which is why it is a pure function
/// with its own test rather than a `match` inside the handler.** It must survive
/// any later rewrite of `login`, and a property asserted only through the handler
/// would not.
///
/// The rule: `UNAUTHENTICATED` is 401, and EVERY other code is one single opaque
/// 503, indistinguishable from every other.
///
/// The reason is an oracle in `iam`. SOME of the non-`UNAUTHENTICATED` codes are
/// raised only after the password has already verified — `Internal` when the
/// token cannot be minted (`iam/src/service.rs`, after `verify_password`
/// returns), and whatever `create_credential` propagates from `iam-db` after
/// that. A caller that saw one of those would have learned from the status alone
/// that the password it sent was correct.
///
/// **The gateway cannot tell which side of the check a code came from, and that
/// is why it collapses ALL of them.** The same `Unavailable` reaches this
/// function from `get_password_hash`, which runs BEFORE any password is checked,
/// and from `create_credential`, which runs after — `upstream_failed` preserves
/// the upstream code in both cases, so the two are identical on arrival. Any rule
/// that distinguished codes would have to distinguish these, and there is nothing
/// in a code to distinguish them by. Collapsing errs conservative: it costs
/// nothing to be opaque about a failure that leaked nothing.
///
/// **Mapping everything to 401 was considered and rejected.** It closes the same
/// leak, and it costs a permanent one: it would tell a person whose password is
/// right that it is wrong, every time `iam-db` is unavailable, and nothing in the
/// answer would say the store was down. A narrow leak that needs an outage to
/// fire is the better trade against a lie told on every outage.
///
/// 503 rather than 500: the codes collapsed into it are dominated by an
/// unreachable or unhappy `iam-db`, and the honest reading of the whole set is
/// "this cannot be answered right now", which is also what makes retrying the
/// right response. The client treats every non-401 alike (`Unexpected(status)`),
/// so this number is for the operator and the proxy, not for `yaadgaar`.
pub fn login_status(status: &tonic::Status) -> StatusCode {
    login_answer(status.code()).0
}

/// The status AND body for one gRPC code.
///
/// **Takes a `tonic::Code`, not a `tonic::Status`, and the difference is the
/// point.** A `Code` is a bare enum with no message attached, so there is no
/// upstream text in scope here to interpolate into a body even by accident. The
/// bodies being constants is then a fact about the signature rather than a habit
/// the next edit has to keep.
///
/// The bodies matter because the CLIENT never reads them: `yaadgaar` branches on
/// the status alone. A body that varied with the upstream would be a leak channel
/// no client-side test could ever catch, sitting behind a status line that was
/// carefully made opaque.
fn login_answer(code: tonic::Code) -> (StatusCode, &'static str) {
    match code {
        tonic::Code::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid username or password"}"#,
        ),
        // ONE ARM, and a catch-all on purpose. Adding a second arm here — a 404
        // for `NotFound`, a 400 for `InvalidArgument` — is the change that
        // reopens the oracle, so there is deliberately nowhere obvious to put
        // one.
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"login is unavailable"}"#,
        ),
    }
}

/// The whole failing response for one gRPC code: status, body and headers.
///
/// **The single builder for every failure that involves `iam`** — a refusal, a
/// broken store, an unreachable pod, a stall — so there is one place to read and
/// one place a test can cover exhaustively. (A malformed request body never gets
/// here; `login` answers those before it sends anything.) It takes a `Code` for
/// the reason given on [`login_answer`], and it adds no header beyond the content
/// type — in particular **no `WWW-Authenticate` on the 401**, which D72 forbids
/// because it advertises an OAuth discovery flow this deployment does not
/// implement.
///
/// Returning a whole `Response` rather than its parts is what lets the test
/// assert the headers too. That gap is why this function exists: the status
/// mapping was pinned across every code while the body and the absent header were
/// pinned only on whichever code an unreachable upstream happened to produce, so
/// adding `WWW-Authenticate` to the refusal passed the entire suite.
fn login_failure(code: tonic::Code) -> Response {
    let (status, body) = login_answer(code);
    text(status, body)
}

fn reply(status: u16, body: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
