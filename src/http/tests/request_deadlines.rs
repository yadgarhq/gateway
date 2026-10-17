//! The ledger 1284 ordering, pinned: the client gives up AFTER the gateway does.
//!
//! The yadgar client bounds one gateway round trip at 30 s
//! (`yadgarhq/yadgar` `src/proxy.rs:68`, `REQUEST_TIMEOUT`, ADR-0925 Q-C4).
//! On a `tools/call` the gateway can wait on `iam` (attestation, bounded by a
//! `tokio::time::timeout` no longer than [`AUTH_DEADLINE`]) and then on `task`,
//! whose call has NO `tokio::time::timeout` — the dial's per-request bound is
//! the only limit there. If the sum reached the client's bound, the client
//! would give up on an answer the gateway was still about to send, and see a
//! transport error instead of the gateway's status.
//!
//! So the HIGHEST value the chart lets an operator set for
//! `task.requestTimeoutSeconds` — the schema maximum, not the default — plus
//! [`AUTH_DEADLINE`] plus a margin must fit inside the client's bound.

use std::time::Duration;

use super::super::AUTH_DEADLINE;

/// The yadgar client's per-round-trip bound. Restated, not imported: it lives
/// in another repository (`yadgarhq/yadgar` `src/proxy.rs:68`). A change there
/// must be mirrored here, and this test then says whether the chart still fits.
const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30); // ADR-0569-EXCEPTION(CC): mirrors yadgarhq/yadgar src/proxy.rs:68, a test oracle, not a knob.

/// Headroom for the hops the sum does not count: TLS, the ingress, the
/// client's own scheduling.
const MARGIN: Duration = Duration::from_secs(2); // ADR-0569-EXCEPTION(CC): ledger 1284 ordering margin, a test oracle, not a knob.

fn schema_value(pointer: &str) -> u64 {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("chart/values.schema.json");
    let text = std::fs::read_to_string(&path).expect("values.schema.json must be readable");
    let schema: serde_json::Value = serde_json::from_str(&text).expect("schema must be JSON");
    schema
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("{pointer} must be an integer in values.schema.json"))
}

#[test]
fn the_client_outlasts_the_longest_task_bound_plus_auth_deadline() {
    let task_max = Duration::from_secs(schema_value(
        "/properties/task/properties/requestTimeoutSeconds/maximum",
    ));
    assert!(
        task_max + AUTH_DEADLINE + MARGIN <= CLIENT_REQUEST_TIMEOUT,
        "task.requestTimeoutSeconds maximum {task_max:?} + AUTH_DEADLINE {AUTH_DEADLINE:?} + \
         margin {MARGIN:?} must fit inside the client's {CLIENT_REQUEST_TIMEOUT:?} (ledger 1284)"
    );
}
