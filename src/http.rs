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
    match headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        None => true,
        Some(origin) => state.allowed_origins.iter().any(|a| a == origin),
    }
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
        "server/discover" => reply(200, discover(&id)),
        "tools/list" => reply(
            200,
            mcp::result(
                &id,
                as_object(json!({
                    "tools": tools::definitions(),
                    // Cacheable by anyone: the tool list is identical for every
                    // caller. It becomes `cacheScope: "private"` the day a tool
                    // is gated on who is asking.
                    "ttlMs": 300_000,
                    "cacheScope": "public",
                })),
            ),
        ),
        "tools/call" => tools_call(state, &id, &request.params, &headers).await,
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
            return reply(
                401,
                mcp::error(Some(id), codes::INVALID_REQUEST, &e.to_string()),
            )
        }
    };

    let call = Call::start(
        SERVICE,
        label,
        if tools::is_write(name) {
            Kind::Write
        } else {
            Kind::Read
        },
        yadgar_telemetry::observe::Scope {
            request_id,
            instance_id: scope.instance_id.clone(),
            user_id: scope.user_id.clone(),
            project_id: scope.project_id.clone(),
        },
    );

    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let (status, payload) = match tools::call(state.task.clone(), scope, name, &args).await {
        Ok(content) => (
            "OK",
            mcp::result(
                id,
                as_object(json!({
                    // Structured AND textual. `structuredContent` is what a
                    // program consumes; `content` is what a model reads, and a
                    // client that understands only one still works.
                    "content": [{ "type": "text", "text": content.to_string() }],
                    "structuredContent": content,
                })),
            ),
        ),
        Err(e) => {
            // A TOOL-level failure, not a protocol error: the MCP request was
            // well formed and the tool ran and failed. Returning a JSON-RPC
            // error here would tell the client its request was malformed, and it
            // would stop retrying things that are worth retrying.
            let status = match &e {
                tools::ToolError::Upstream(s) => yadgar_telemetry::grpc::status_name(s),
                _ => "INVALID_ARGUMENT",
            };
            (
                status,
                mcp::result(
                    id,
                    as_object(json!({
                        "content": [{ "type": "text", "text": e.to_string() }],
                        "isError": true,
                    })),
                ),
            )
        }
    };

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
        ..Default::default()
    });

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        rendered,
    )
        .into_response()
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
