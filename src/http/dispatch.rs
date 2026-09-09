//! The MCP envelope: which method arrived, and the two that are not
//! `tools/call`.
//!
//! Split out of [`super`] for the file-size ceiling.
//!
//! **[`tools_call`] IS HERE AND NOT IN [`super::call`], and the co-location is
//! required rather than tidy.** `observe-coverage` follows a route handler's
//! dispatch into the function each arm names and asserts it opens an
//! `observe::Call` — WITHIN THE FILE IT IS READING. A `tools/call` arm calling
//! across a module boundary is one the gate refuses rather than passes, and D67
//! coverage of the busiest path in this service is worth a file boundary drawn
//! where the gate can see it. What `tools/call` does with its answer is
//! [`super::call`]'s, and none of that is reachable from a route arm.

use super::answer::*;
use super::call::*;
use super::gate::*;
use super::*;

/// This module's routes, REGISTERED WHERE THE HANDLERS ARE DEFINED.
///
/// [`super::router`] merges the three `routes()` in this module tree rather
/// than listing every path itself. That keeps each registration beside the
/// handler it names — which is what lets `observe-coverage` verify D67
/// instrumentation for it, since that gate resolves a route handler against
/// the file it is registered in. The body limit and the state stay on
/// [`super::router`], applied after every merge.
pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // MCP is ONE endpoint, POST only.
        //
        // GET and DELETE return 405. The spec frames that as a SHOULD, under
        // backward compatibility with the revisions that had a GET/SSE stream —
        // it is not a blanket MUST, and this comment says so because the first
        // reading of the spec recorded it as one. The effect is the same: there
        // is no GET stream in this revision, so there is nothing for a GET to do.
        .route("/", post(handle).fallback(method_not_allowed))
}

pub(super) async fn handle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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

    // A HEADER THAT CANNOT BE READ IS A REFUSAL, NOT A SKIP, and it is refused
    // here rather than inside `cross_check_headers` because that function
    // compares two decoded strings and this is not a disagreement between them.
    //
    // `INVALID_PARAMS` AND 400, following the precedent one arm below: a missing
    // `MCP-Protocol-Version` — the other header-layer defect that is not a
    // mismatch — already answers exactly that. `-32020 HeaderMismatch` is
    // documented as "a header disagrees with the `_meta` field it mirrors" and
    // saying it here would report a disagreement nobody established. A new code
    // in the MCP-reserved range would need the 2026-07-28 revision to name this
    // condition and a client that recognised it, which is the bar `RATE_LIMITED`
    // had to clear and this does not.
    let (header_version, header_method, header_name) = match (
        readable(&headers, headers::PROTOCOL_VERSION),
        readable(&headers, headers::METHOD),
        readable(&headers, headers::NAME),
    ) {
        (Ok(v), Ok(m), Ok(n)) => (v, m, n),
        (Err(bad), _, _) | (_, Err(bad), _) | (_, _, Err(bad)) => {
            return reply(
                400,
                mcp::error(
                    request.id.as_ref(),
                    codes::INVALID_PARAMS,
                    &format!("the {bad} header is not readable as text"),
                ),
            )
        }
    };

    if let Err(e) = mcp::cross_check_headers(&meta, header_version, header_method, header_name) {
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
pub(super) fn tools_list(id: &Value) -> Value {
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
pub(super) fn measured(tool: &'static str, build: impl FnOnce() -> Value) -> Response {
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
pub(super) fn tel(request_id: String) -> yadgar_telemetry::observe::Scope {
    yadgar_telemetry::observe::Scope {
        request_id,
        instance_id: String::new(),
        user_id: String::new(),
        project_id: String::new(),
    }
}

/// `server/discover` — the spec says "Servers MUST implement it", replacing the
/// `initialize` handshake that a stateless protocol has nowhere to keep.
pub(super) fn discover(id: &Value) -> Value {
    mcp::result(
        id,
        as_object(json!({
            "supportedVersions": [mcp::PROTOCOL_VERSION],
            "capabilities": { "tools": {} },
            "_meta": {
                meta_keys::SERVER_INFO: {
                    "name": "yadgar-gateway",
                    // `crate::VERSION`, NOT `CARGO_PKG_VERSION`. The manifest is a
                    // placeholder nothing writes to; the number here is stamped
                    // from the release tag at build time. See `crate::VERSION`.
                    "version": crate::VERSION,
                },
            },
            "instructions": "yadgar: durable memory, wiki and tasks for coding agents.",
            "ttlMs": 3_600_000,
            "cacheScope": "public",
        })),
    )
}

pub(super) async fn tools_call(
    state: Arc<AppState>,
    id: &Value,
    params: &Value,
    headers: &HeaderMap,
) -> Response {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let (label, module) = match resolved_tool(name, id) {
        Ok(pair) => pair,
        Err(refusal) => return *refusal,
    };

    // Minted here, never read from the request (D67). See `crate::request_id`.
    let request_id = crate::request_id();

    // THE USER IS RESOLVED FROM THE CREDENTIAL AND THE OTHER TWO ARE CLAIMED, and
    // the split is ADR-0488's rule applied field by field. `x-yadgar-user` is not
    // passed on the `iam` path at all — a self-asserted username is forgeable by
    // anyone holding any valid token, so it is the bearer token that names the
    // caller. `x-yadgar-project` and `x-yadgar-instance` stay caller-supplied:
    // they are workspace and session facts, and no token can carry them.
    let attested = match attest::attest(
        &state.attestation,
        &state.iam,
        &state.credentials,
        header(headers, axum::http::header::AUTHORIZATION.as_str()),
        Claimed {
            user_id: header(headers, "x-yadgar-user"),
            project_id: header(headers, "x-yadgar-project"),
            instance_id: header(headers, "x-yadgar-instance"),
        },
        request_id.clone(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return attest_refusal(&e, id, label, name, request_id);
        }
    };
    let scope = attested.scope;

    // D74, and before any TOOL work: refusing here means the loop this protects
    // against costs `task` nothing at all. Enforcing per module would let it cost
    // every service its work before the last one said no.
    //
    // **IT IS NO LONGER BEFORE ALL UPSTREAM WORK, and the comment here used to say
    // it was.** Attestation runs above, and it has to: the bucket keys on the
    // resolved user id, so there is nothing to spend from until the credential has
    // been resolved. An authenticated caller in a loop therefore costs `iam` one
    // `ResolveCredential` this limiter cannot shield — and the bound on that is
    // D72's cache, "on a cache miss, never per request", which `attest::Credentials`
    // now is. It is a bound and not a cure: the loop costs one lookup per TTL
    // rather than one per request, and a caller ROTATING tokens still misses every
    // time. Throttling the lookup itself would need a bucket keyed on something
    // known before the identity is, which is the caller's own claim.
    let kind = kind_of(name);
    if let Some(refusal) =
        throttled(&state, id, &scope, label, module, kind, &attested.limits).await
    {
        record_throttled(label, kind, observed(request_id, &scope));
        return refusal;
    }

    let call = Call::start(SERVICE, label, kind, observed(request_id, &scope));

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
