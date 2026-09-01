//! The MCP wire envelope, for spec revision **2026-07-28**.
//!
//! Every shape here was read from `modelcontextprotocol.io` at that revision and
//! verified twice, the second time adversarially — because this revision
//! post-dates the assistant knowledge cutoff and almost everything "known" about
//! MCP from memory describes a superseded one. See the wiki page
//! `mcp-spec-2026-07-28-shape`, and ADR-0487.
//!
//! **What that revision removed**, and what makes this server simple: protocol
//! sessions, the `initialize` handshake, the GET/SSE stream, and `Last-Event-ID`
//! resumability are all gone. "MCP is a stateless protocol… Servers MUST NOT rely
//! on prior requests over the same connection to establish context." So every
//! POST is self-contained, any replica can serve any request, and the gateway
//! needs no affinity — which is what D47 already assumed when it made notices a
//! pull rather than a push.
//!
//! **What it added**, and what is easy to get wrong: the protocol version and
//! client capabilities now ride in `params._meta` on every request AND are
//! mirrored into headers that the server must cross-validate. Three headers, not
//! one.

use serde::Deserialize;
use serde_json::{json, Value};

/// The only revision this server implements.
///
/// Named as a constant because it appears in three places — `server/discover`'s
/// `supportedVersions`, the `_meta` cross-check, and the header cross-check — and
/// three copies of a version string is how two of them end up disagreeing.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// `_meta` keys are REVERSE-DNS NAMESPACED and the exact strings matter.
///
/// A near-miss here (`protocolVersion` rather than the namespaced form) parses as
/// a missing required field, which the spec says must be rejected — so the
/// failure is at least loud rather than silent.
pub mod meta_keys {
    pub const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
    pub const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
    pub const CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
    pub const SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
}

/// JSON-RPC and MCP error codes.
///
/// The MCP-reserved sub-range is -32020 to -32099. The legacy -32000 to -32019
/// range is closed: the spec says new codes MUST NOT be allocated there.
pub mod codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    /// A header disagrees with the `_meta` field it mirrors.
    pub const HEADER_MISMATCH: i32 = -32020;
    pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021;
    pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

    /// The caller's token bucket is empty (D74).
    ///
    /// ALLOCATED HERE, in the MCP-reserved range, following this module's own
    /// precedent for the three above. The 2026-07-28 revision was read for a code
    /// meaning "slow down" and none was found; if one is added later this
    /// constant is the single place to change. The HTTP status is what a client
    /// will actually key on — 429 with `Retry-After` is unambiguous at the
    /// transport layer regardless of what the JSON-RPC body says.
    pub const RATE_LIMITED: i32 = -32023;
}

/// Headers the client sends, mirroring what is in the body.
///
/// The mirroring exists so an HTTP layer — a proxy, a gateway, a WAF — can route
/// and police MCP traffic without parsing a JSON-RPC body. The server's job is to
/// confirm the two agree; if they do not, one of the two audiences is being told
/// something different from the other, which is exactly the confusion a
/// cross-check exists to refuse.
pub mod headers {
    pub const PROTOCOL_VERSION: &str = "mcp-protocol-version";
    pub const METHOD: &str = "mcp-method";
    /// Present for `tools/call`, `resources/read` and `prompts/get` — the
    /// methods that name a specific thing.
    pub const NAME: &str = "mcp-name";
}

/// One inbound JSON-RPC request. Batches do not exist: JSON-RPC batching was
/// removed in 2025-06-18 and has not returned, so a top-level array is invalid.
#[derive(Debug, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    /// Absent means a NOTIFICATION, which takes no response. Present means a
    /// request, which does.
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// What the client asserted in `params._meta`.
#[derive(Debug)]
pub struct Meta {
    pub protocol_version: String,
    pub method: String,
    /// The tool or resource being named, for the methods that name one.
    pub name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("{message}")]
    Rpc {
        code: i32,
        message: String,
        /// The HTTP status to pair with it. The spec fixes this for some cases —
        /// a malformed request is 400, not 200 with an error body.
        http: u16,
    },
}

impl ProtocolError {
    fn rpc(code: i32, message: impl Into<String>, http: u16) -> Self {
        Self::Rpc {
            code,
            message: message.into(),
            http,
        }
    }

    pub fn code(&self) -> i32 {
        match self {
            Self::Rpc { code, .. } => *code,
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::Rpc { http, .. } => *http,
        }
    }
}

impl Request {
    /// Validate the envelope and pull out `_meta`.
    ///
    /// Required fields are `_meta.protocolVersion` and `_meta.clientCapabilities`;
    /// `clientInfo` is optional. "A request missing any required field is
    /// malformed; the server MUST reject it with JSON-RPC error code -32602
    /// (Invalid params). On HTTP, the response status MUST be 400 Bad Request."
    pub fn validate(&self) -> Result<Meta, ProtocolError> {
        if self.jsonrpc != "2.0" {
            return Err(ProtocolError::rpc(
                codes::INVALID_REQUEST,
                format!("jsonrpc must be \"2.0\", got {:?}", self.jsonrpc),
                400,
            ));
        }

        let meta = self.params.get("_meta").unwrap_or(&Value::Null);

        let protocol_version = meta
            .get(meta_keys::PROTOCOL_VERSION)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProtocolError::rpc(
                    codes::INVALID_PARAMS,
                    format!(
                        "params._meta[\"{}\"] is required",
                        meta_keys::PROTOCOL_VERSION
                    ),
                    400,
                )
            })?;

        // Required, and its ABSENCE is the error — an empty object is a valid
        // value meaning "no capabilities", which is different from not saying.
        if meta.get(meta_keys::CLIENT_CAPABILITIES).is_none() {
            return Err(ProtocolError::rpc(
                codes::INVALID_PARAMS,
                format!(
                    "params._meta[\"{}\"] is required",
                    meta_keys::CLIENT_CAPABILITIES
                ),
                400,
            ));
        }

        if protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::rpc(
                codes::UNSUPPORTED_PROTOCOL_VERSION,
                format!(
                    "this server implements {PROTOCOL_VERSION}; the request declares {protocol_version}"
                ),
                400,
            ));
        }

        Ok(Meta {
            protocol_version: protocol_version.to_string(),
            method: self.method.clone(),
            name: self
                .params
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

/// Confirm the headers agree with the body.
///
/// Disagreement is `-32020 HeaderMismatch` and HTTP 400. This is not pedantry: if
/// a proxy routed on `Mcp-Method: tools/list` while the body said
/// `tools/call`, the thing that policed the request and the thing that executed
/// it saw different requests.
pub fn cross_check_headers(
    meta: &Meta,
    header_version: Option<&str>,
    header_method: Option<&str>,
    header_name: Option<&str>,
) -> Result<(), ProtocolError> {
    let version = header_version.ok_or_else(|| {
        ProtocolError::rpc(
            codes::INVALID_PARAMS,
            "the MCP-Protocol-Version header is required on every POST",
            400,
        )
    })?;
    if version != meta.protocol_version {
        return Err(ProtocolError::rpc(
            codes::HEADER_MISMATCH,
            format!(
                "MCP-Protocol-Version header says {version}, _meta says {}",
                meta.protocol_version
            ),
            400,
        ));
    }
    if let Some(method) = header_method {
        if method != meta.method {
            return Err(ProtocolError::rpc(
                codes::HEADER_MISMATCH,
                format!("Mcp-Method header says {method}, body says {}", meta.method),
                400,
            ));
        }
    }
    // Only cross-checked when both are present. The header is required for the
    // methods that name a thing, and for those `_meta`-side `name` is populated
    // from params — so a mismatch is checkable and an absence is not this
    // function's error to raise.
    if let (Some(header), Some(body)) = (header_name, meta.name.as_deref()) {
        if header != body {
            return Err(ProtocolError::rpc(
                codes::HEADER_MISMATCH,
                format!("Mcp-Name header says {header}, body says {body}"),
                400,
            ));
        }
    }
    Ok(())
}

/// A successful result.
///
/// `resultType` is REQUIRED on every result in this revision — "The `result` MUST
/// include a `resultType` field". `complete` means final content; `input_required`
/// carries an `InputRequiredResult` and is how server-to-client interaction
/// (sampling, elicitation, roots) works now that there is no session to push
/// over. This server only ever returns `complete`.
pub fn result(id: &Value, mut body: serde_json::Map<String, Value>) -> Value {
    body.insert("resultType".to_string(), json!("complete"));
    json!({ "jsonrpc": "2.0", "id": id, "result": Value::Object(body) })
}

/// A protocol-level error — distinct from a tool-level failure, which is a
/// successful result carrying `isError: true`. Confusing the two is how a caller
/// ends up retrying a request that failed for a reason retrying cannot fix.
pub fn error(id: Option<&Value>, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": { "code": code, "message": message },
    })
}

/// The same, carrying machine-readable `data`.
///
/// Exists for D74's `retry-after`, which must be EXACT. The HTTP header is whole
/// seconds by RFC 9110, so a wait of 340ms becomes `Retry-After: 1` — correct but
/// coarse, and a client that honoured only the header would idle three times
/// longer than its own bucket needs. The precise figure rides here.
pub fn error_data(id: Option<&Value>, code: i32, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": { "code": code, "message": message, "data": data },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(meta: Value) -> Request {
        serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": meta }
        }))
        .unwrap()
    }

    fn good_meta() -> Value {
        json!({
            meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
            meta_keys::CLIENT_CAPABILITIES: {},
        })
    }

    #[test]
    fn a_complete_envelope_validates() {
        assert!(req(good_meta()).validate().is_ok());
    }

    #[test]
    fn a_missing_protocol_version_is_invalid_params_and_400() {
        let err = req(json!({ meta_keys::CLIENT_CAPABILITIES: {} }))
            .validate()
            .expect_err("protocolVersion is required");
        assert_eq!(err.code(), codes::INVALID_PARAMS);
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn missing_client_capabilities_is_rejected_even_though_empty_is_valid() {
        // The distinction this pins down: `{}` means "I have no capabilities"
        // and is fine; absent means the client did not say, and is malformed.
        let err = req(json!({ meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION }))
            .validate()
            .expect_err("clientCapabilities is required");
        assert_eq!(err.code(), codes::INVALID_PARAMS);
    }

    #[test]
    fn a_different_revision_is_refused_with_its_own_code() {
        let err = req(json!({
            meta_keys::PROTOCOL_VERSION: "2025-06-18",
            meta_keys::CLIENT_CAPABILITIES: {},
        }))
        .validate()
        .expect_err("a legacy revision is not implemented here");
        assert_eq!(err.code(), codes::UNSUPPORTED_PROTOCOL_VERSION);
    }

    /// A `tools/call` envelope, which is the shape that carries `params.name`.
    fn call_req(name: &str) -> Request {
        serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "_meta": good_meta(), "name": name }
        }))
        .unwrap()
    }

    #[test]
    fn headers_that_agree_with_the_body_are_accepted() {
        // MUTATION THIS CATCHES: `cross_check_headers` returning
        // `Err(HEADER_MISMATCH)` unconditionally. Both mismatch tests below pass
        // under it — they only ever assert that SOMETHING was refused — so every
        // well-formed request in the system would be rejected with the whole
        // suite green. An assertion that a check REJECTS is only half of it.
        let meta = req(good_meta()).validate().unwrap();
        assert!(
            cross_check_headers(&meta, Some(PROTOCOL_VERSION), Some("tools/list"), None).is_ok(),
            "a header triple agreeing with the body must be accepted"
        );

        let meta = call_req("create_task").validate().unwrap();
        assert!(
            cross_check_headers(
                &meta,
                Some(PROTOCOL_VERSION),
                Some("tools/call"),
                Some("create_task"),
            )
            .is_ok(),
            "all three headers agreeing must be accepted"
        );
    }

    #[test]
    fn the_name_header_is_cross_checked_too() {
        // "Three headers, not one" — and until now `meta.name` was None in every
        // test in this file, so this branch was never entered and two of the
        // three were unproven. A proxy routing on `Mcp-Name: read_task` while the
        // body called `create_task` is the failure: the thing that policed the
        // request and the thing that executed it saw different requests.
        let meta = call_req("create_task").validate().unwrap();
        let err = cross_check_headers(
            &meta,
            Some(PROTOCOL_VERSION),
            Some("tools/call"),
            Some("read_task"),
        )
        .expect_err("the Mcp-Name header disagrees with the body");
        assert_eq!(err.code(), codes::HEADER_MISMATCH);
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn an_absent_name_header_is_not_this_functions_error_to_raise() {
        // Deliberate: the header is required for the methods that name a thing,
        // but an ABSENCE is not a disagreement, and refusing it here would move
        // that rule out of the place that knows which methods those are.
        let meta = call_req("create_task").validate().unwrap();
        assert!(
            cross_check_headers(&meta, Some(PROTOCOL_VERSION), Some("tools/call"), None).is_ok()
        );
    }

    #[test]
    fn a_header_disagreeing_with_the_body_is_a_mismatch() {
        let meta = req(good_meta()).validate().unwrap();
        let err = cross_check_headers(&meta, Some(PROTOCOL_VERSION), Some("tools/call"), None)
            .expect_err("header method disagrees with body method");
        assert_eq!(err.code(), codes::HEADER_MISMATCH);
    }

    #[test]
    fn the_protocol_version_header_is_not_optional() {
        let meta = req(good_meta()).validate().unwrap();
        assert!(cross_check_headers(&meta, None, None, None).is_err());
    }

    #[test]
    fn every_result_carries_result_type() {
        let v = result(&json!(1), serde_json::Map::new());
        assert_eq!(v["result"]["resultType"], "complete");
    }
}
