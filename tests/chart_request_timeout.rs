//! The chart's range for each `<upstream>.requestTimeoutSeconds` agrees with
//! `yadgar_dial`'s (ADR-0925 Q-C1).
//!
//! The binary refuses a value outside `min_request_timeout()..=
//! max_request_timeout()`. A schema minimum below the crate's would let a
//! chart render a pod that crash-loops. So the minimum is pinned to the
//! CRATE'S value, not restated as a literal, and a dial release that moves it
//! reds here.
//!
//! `task`'s maximum is deliberately BELOW the crate's: the ledger 1284
//! ordering, pinned in `src/http/tests/request_deadlines.rs`. `iam` and
//! `project` take the crate's whole range.

use std::path::PathBuf;

use serde_json::Value;

fn schema() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/values.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));
    serde_json::from_str(&text).expect("values.schema.json must be JSON")
}

fn knob(schema: &Value, upstream: &str) -> Value {
    schema["properties"][upstream]["properties"]["requestTimeoutSeconds"].clone()
}

#[test]
fn every_upstream_requires_an_integer_request_timeout() {
    let schema = schema();
    for upstream in ["task", "iam", "project"] {
        let block = &schema["properties"][upstream];
        let required = block["required"].as_array().cloned().unwrap_or_default();
        assert!(
            required.contains(&Value::from("requestTimeoutSeconds")),
            "{upstream}.requestTimeoutSeconds must be schema-required (ADR-0569)"
        );
        assert_eq!(knob(&schema, upstream)["type"], "integer", "{upstream}");
    }
}

#[test]
fn every_schema_minimum_is_the_crates_minimum() {
    let schema = schema();
    let min = yadgar_dial::min_request_timeout().as_secs();
    for upstream in ["task", "iam", "project"] {
        assert_eq!(
            knob(&schema, upstream)["minimum"].as_u64(),
            Some(min),
            "{upstream}.requestTimeoutSeconds minimum must be dial's min_request_timeout()"
        );
    }
}

#[test]
fn iam_and_project_take_the_crates_maximum() {
    let schema = schema();
    let max = yadgar_dial::max_request_timeout().as_secs();
    for upstream in ["iam", "project"] {
        assert_eq!(
            knob(&schema, upstream)["maximum"].as_u64(),
            Some(max),
            "{upstream}.requestTimeoutSeconds maximum must be dial's max_request_timeout()"
        );
    }
}

#[test]
fn the_task_maximum_sits_inside_the_crates_range() {
    let schema = schema();
    let task_max = knob(&schema, "task")["maximum"]
        .as_u64()
        .expect("task.requestTimeoutSeconds must declare a maximum");
    assert!(
        (yadgar_dial::min_request_timeout().as_secs()
            ..=yadgar_dial::max_request_timeout().as_secs())
            .contains(&task_max),
        "a task maximum the binary refuses would make the chart's top value crash-loop"
    );
}
