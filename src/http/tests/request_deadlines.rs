//! The ledger 1284 ordering, pinned: the client gives up AFTER the gateway does.
//!
//! The yadgar client bounds one gateway round trip at 30 s
//! (`yadgarhq/yadgar` `src/proxy.rs:72`, `REQUEST_TIMEOUT`, ADR-0925 Q-C4).
//!
//! THE PATH SUMMED IS A `tools/call`, the one route that reaches `task`:
//!
//! 1. attestation on a credential-cache miss, bounded by [`RESOLVE_DEADLINE`];
//! 2. the task dial's connect bound and TLS handshake bound;
//! 3. the task request bound — the chart's `task.requestTimeoutSeconds`. Every
//!    `task` RPC in `src/tools.rs` and `src/tools/change.rs` is wrapped in
//!    `tools::bounded`, a `tokio::time::timeout` of that same value, so the wait
//!    for a ready endpoint is bounded too (yaadgaar #361).
//!
//! Steps 2 and 3 ADD only inside tonic 0.14.6's own timer: its `GrpcTimeout`
//! starts in `call()`, after `Reconnect` has connected (and handshaken) in
//! `poll_ready`. The outer `tools::bounded` wrapper covers both steps with ONE
//! task bound, so the real worst case is lower than this sum, which is kept as
//! the conservative figure. `AUTH_DEADLINE` is NOT on this path: login and admin never
//! call `task`.
//!
//! If the sum reached the client's bound, the client would give up on an answer
//! the gateway was still about to send. So the HIGHEST value the chart lets an
//! operator set — the schema maximum, not the default — must keep the sum plus
//! a margin STRICTLY below the client's bound (ADR-0928 states `<`).

use std::time::Duration;

use crate::attest::RESOLVE_DEADLINE;

/// The yadgar client's per-round-trip bound. Restated, not imported: it lives
/// in another repository (`yadgarhq/yadgar` `src/proxy.rs:72`). A change there
/// must be mirrored here, and this test then says whether the chart still fits.
const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30); // ADR-0569-EXCEPTION(CC): mirrors yadgarhq/yadgar src/proxy.rs:72, a test oracle, not a knob.

/// `yadgar-dial`'s connect bound plus its TLS handshake bound: 2 s each, one
/// constant (`CONNECT_TIMEOUT`, dial v0.2.20 `src/lib.rs:304`, shared with the
/// handshake bound in `TlsOptions::prepare`). Restated because v0.2.20 does
/// not export it. FOLLOW-UP: once a dial release exports `CONNECT_TIMEOUT`
/// (yadgarhq/dial#35, yaadgaar #365), import it and delete this restatement.
const DIAL_CONNECT_AND_HANDSHAKE: Duration = Duration::from_secs(2 + 2); // ADR-0569-EXCEPTION(CC): mirrors dial v0.2.20 src/lib.rs:304 CONNECT_TIMEOUT x2, a test oracle, not a knob.

/// Headroom for what the sum does not count: the ingress hop, the gateway's
/// own work around the calls, the client's scheduling.
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
fn the_client_outlasts_the_longest_tools_call_path() {
    let task_max = Duration::from_secs(schema_value(
        "/properties/task/properties/requestTimeoutSeconds/maximum",
    ));
    let path = RESOLVE_DEADLINE + DIAL_CONNECT_AND_HANDSHAKE + task_max + MARGIN;
    assert!(
        path < CLIENT_REQUEST_TIMEOUT,
        "RESOLVE_DEADLINE {RESOLVE_DEADLINE:?} + dial connect+handshake \
         {DIAL_CONNECT_AND_HANDSHAKE:?} + task.requestTimeoutSeconds maximum {task_max:?} + \
         margin {MARGIN:?} = {path:?} must stay below the client's {CLIENT_REQUEST_TIMEOUT:?} \
         (ledger 1284, ADR-0928)"
    );
}
