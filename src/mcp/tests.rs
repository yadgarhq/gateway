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
    assert!(cross_check_headers(&meta, Some(PROTOCOL_VERSION), Some("tools/call"), None).is_ok());
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
fn the_wire_codes_are_pinned_as_literals() {
    // AS LITERALS. Every other assertion in this file reads `codes::*` on
    // both sides of the comparison, so it moves with the constant: a code
    // could be renumbered and the suite would say nothing, while a client
    // keying on the old number and this server keying on the new one agree
    // in no place but a green test run. These are a wire contract with
    // software this repository does not build.
    //
    // `INVALID_PARAMS` is deliberately absent: `estate`'s front-end smoke
    // test already pins it, and a second copy is a second thing to keep in
    // step for no gain.
    assert_eq!(codes::PARSE_ERROR, -32700);
    assert_eq!(codes::INVALID_REQUEST, -32600);
    assert_eq!(codes::METHOD_NOT_FOUND, -32601);
    assert_eq!(codes::INTERNAL_ERROR, -32603);
    assert_eq!(codes::HEADER_MISMATCH, -32020);
    assert_eq!(codes::MISSING_REQUIRED_CLIENT_CAPABILITY, -32021);
    assert_eq!(codes::UNSUPPORTED_PROTOCOL_VERSION, -32022);
    assert_eq!(codes::RATE_LIMITED, -32023);
}

#[test]
fn every_code_this_module_allocates_stays_in_the_range_that_is_open() {
    // A RULE RATHER THAN A NUMBER, and the literals above do not carry it.
    // This module's own comment says the MCP-reserved sub-range is -32020 to
    // -32099 and that the legacy -32000 to -32019 range is CLOSED: the spec
    // says new codes MUST NOT be allocated there. Moving any of these four
    // into that closed range is a spec violation that the literals catch only
    // if somebody also changes the test, which is the same edit.
    for (name, code) in [
        ("HEADER_MISMATCH", codes::HEADER_MISMATCH),
        (
            "MISSING_REQUIRED_CLIENT_CAPABILITY",
            codes::MISSING_REQUIRED_CLIENT_CAPABILITY,
        ),
        (
            "UNSUPPORTED_PROTOCOL_VERSION",
            codes::UNSUPPORTED_PROTOCOL_VERSION,
        ),
        ("RATE_LIMITED", codes::RATE_LIMITED),
    ] {
        assert!(
            (-32099..=-32020).contains(&code),
            "{name} is {code}, outside the MCP-reserved range this module \
             allocates in — -32000 to -32019 is closed to new codes"
        );
    }
}

#[test]
fn the_strings_a_client_has_to_spell_exactly_are_pinned_as_literals() {
    // The revision is already pinned OUTSIDE this repository, by
    // `estate/reference.toml` and the harness that reads it, so this is a
    // second reader rather than the only one — worth having in the repository
    // that has to change when the revision moves.
    assert_eq!(PROTOCOL_VERSION, "2026-07-28");

    // The `_meta` keys and the headers have no such reader anywhere. A
    // near-miss on a `_meta` key parses as a field the client never sent, and
    // a near-miss on a header name is a cross-check that silently stops
    // cross-checking — which is the failure the mirroring exists to catch.
    assert_eq!(
        meta_keys::PROTOCOL_VERSION,
        "io.modelcontextprotocol/protocolVersion"
    );
    assert_eq!(
        meta_keys::CLIENT_CAPABILITIES,
        "io.modelcontextprotocol/clientCapabilities"
    );
    assert_eq!(meta_keys::CLIENT_INFO, "io.modelcontextprotocol/clientInfo");
    assert_eq!(meta_keys::SERVER_INFO, "io.modelcontextprotocol/serverInfo");
    // `io.yadgarhq/...` — THIS ESTATE'S OWN NAMESPACE, established here rather
    // than borrowed from `io.modelcontextprotocol` above. Pinned as a literal
    // for the same reason every key above is: `tools_list_reports_the_gateways_
    // chosen_poll_interval` in `http/tests.rs` reads the response through the
    // SAME constant `dispatch::tools_list` writes through, so a rename that
    // kept both sides consistent would pass that test green while every real
    // client silently stopped matching. This line is what a rename has to
    // survive instead.
    assert_eq!(
        meta_keys::TOOLS_POLL_INTERVAL_SECONDS,
        "io.yadgarhq/toolsPollIntervalSeconds"
    );
    assert_eq!(headers::PROTOCOL_VERSION, "mcp-protocol-version");
    assert_eq!(headers::METHOD, "mcp-method");
    assert_eq!(headers::NAME, "mcp-name");
}

#[test]
fn every_result_carries_result_type() {
    let v = result(&json!(1), serde_json::Map::new());
    assert_eq!(v["result"]["resultType"], "complete");
}
