//! The chart's range for `server.limits.headerReadTimeoutSeconds` is the binary's
//! (ADR-1006, yaadgaar #218).
//!
//! The binary refuses a value outside `edge::HEADER_READ_TIMEOUT_RANGE`. A
//! schema range wider than that would let the chart render a pod that
//! crash-loops, and a narrower one would refuse a value the binary accepts. So
//! both ends are pinned to the CRATE'S constant, not restated as literals here.
//! The render itself is `scripts/tests/test_edge_header_read_timeout.py`.

use std::path::PathBuf;

use serde_json::Value;

use yadgar_gateway::edge::HEADER_READ_TIMEOUT_RANGE;

fn limits_block() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/values.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));
    let schema: Value = serde_json::from_str(&text).expect("values.schema.json must be JSON");
    schema["properties"]["server"]["properties"]["limits"].clone()
}

#[test]
fn the_limits_block_is_closed_and_requires_an_integer_bound() {
    let limits = limits_block();
    assert_eq!(
        limits["additionalProperties"],
        Value::Bool(false),
        "server.limits must be a closed block (ADR-0850)"
    );
    let required = limits["required"].as_array().cloned().unwrap_or_default();
    assert!(
        required.contains(&Value::from("headerReadTimeoutSeconds")),
        "server.limits.headerReadTimeoutSeconds must be schema-required (ADR-0569)"
    );
    assert_eq!(
        limits["properties"]["headerReadTimeoutSeconds"]["type"],
        "integer"
    );
}

#[test]
fn the_schema_range_is_the_binarys_range() {
    let knob = limits_block()["properties"]["headerReadTimeoutSeconds"].clone();
    assert_eq!(
        knob["minimum"].as_u64(),
        Some(*HEADER_READ_TIMEOUT_RANGE.start()),
        "the schema minimum must be the binary's"
    );
    assert_eq!(
        knob["maximum"].as_u64(),
        Some(*HEADER_READ_TIMEOUT_RANGE.end()),
        "the schema maximum must be the binary's"
    );
}
