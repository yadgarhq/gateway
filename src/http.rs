//! The HTTP surface: one endpoint, POST only, stateless.

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
use crate::mcp::{self, codes, headers, meta_keys};
use crate::tools;

const SERVICE: &str = "gateway";

/// The bounded labels for the two methods that are not `tools/call`.
///
/// `&'static str` and a closed set, for the same reason `tools::label_for`
/// exists: a metric label must come from a fixed range (D67).
const DISCOVER: &str = "server/discover";
const TOOLS_LIST: &str = "tools/list";

pub struct AppState {
    pub attestation: Attestation,
    pub task: Channel,
    /// Origins permitted to reach this server from a browser. Empty means no
    /// browser origin is accepted at all, which is the correct default for a
    /// server whose clients are agents.
    pub allowed_origins: Vec<String>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // ONE endpoint, POST only.
        //
        // GET and DELETE return 405. The spec frames that as a SHOULD, under
        // backward compatibility with the revisions that had a GET/SSE stream —
        // it is not a blanket MUST, and this comment says so because the first
        // reading of the spec recorded it as one. The effect is the same: there
        // is no GET stream in this revision, so there is nothing for a GET to do.
        .route("/", post(handle).fallback(method_not_allowed))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state)
}

async fn method_not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, "MCP uses POST").into_response()
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

    // Resolved to a BOUNDED label before anything is measured. An unknown tool
    // never reaches the metric layer, so a caller cannot mint Prometheus series
    // by inventing names (D67's cardinality rule).
    let Some(label) = tools::label_for(name) else {
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

    let scope = match attest::attest(
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

    let call = Call::start(
        SERVICE,
        label,
        kind_of(name),
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
