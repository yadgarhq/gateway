//! `tools/call`: running one tool and answering with what came back.
//!
//! Split out of [`super`] for the file-size ceiling. Which MCP method arrived is
//! [`super::dispatch`]'s; this is what happens once it is `tools/call`.

use super::answer::*;
use super::dispatch::*;
use super::*;

/// The answer to a call whose credential did not attest.
///
/// Its own function because it is the RECORD and the ANSWER rather than the
/// decision: `attest::attest` decided and `attest_answer` chose the status.
/// This writes the D67 record a refusal would otherwise not get, and renders
/// the reply.
pub(super) fn attest_refusal(
    e: &attest::AttestError,
    id: &Value,
    label: &'static str,
    name: &str,
    request_id: String,
) -> Response {
    // THE ONLY PLACE THE REAL REASON IS WRITTEN DOWN, and it goes to the
    // log rather than to the caller — the same split `login` makes.
    tracing::warn!(error = %e, "attestation failed");
    let answer = attest_answer(e);
    // A REFUSED call is still a call, and it is the one most worth
    // seeing. Recorded here because the `Call` for the success path
    // cannot be started until there is an attested scope to carry — so
    // without this, every authentication failure in the system is
    // invisible to D67 and a credential-stuffing run looks like silence.
    //
    // THREE LABELS, decided once in `attest_answer` beside the status they
    // must agree with. A bad token is a refusal, an unreachable `iam` is
    // an outage, and an override that cannot be applied is neither — a
    // dashboard that showed any of the three as another would send an
    // operator hunting the wrong thing.
    Call::start(SERVICE, label, kind_of(name), tel(request_id)).fail(answer.label);
    reply(
        answer.status.as_u16(),
        match answer.data {
            Some(data) => mcp::error_data(Some(id), answer.code, &answer.message, data),
            None => mcp::error(Some(id), answer.code, &answer.message),
        },
    )
}

/// The D67 scope for one attested call.
///
/// ONE function because the throttled record and the served record must
/// carry the same four fields, and two copies of this literal are two things
/// that can drift.
pub(super) fn observed(
    request_id: String,
    scope: &crate::pb::yadgar::common::v1::Scope,
) -> yadgar_telemetry::observe::Scope {
    yadgar_telemetry::observe::Scope {
        request_id,
        instance_id: scope.instance_id.clone(),
        user_id: scope.user_id.clone(),
        project_id: scope.project_id.clone(),
    }
}

/// The tool's BOUNDED metric label and module, or the answer for a name that
/// names no tool.
///
/// Its own function because the bound is the point: an unknown name must not
/// reach the metric layer or the bucket key, and that argument reads better
/// beside the lookup than in the middle of a handler.
pub(super) fn resolved_tool(
    name: &str,
    id: &Value,
) -> Result<(&'static str, &'static str), Box<Response>> {
    // Resolved to BOUNDED values before anything is measured. An unknown tool
    // never reaches the metric layer, so a caller cannot mint Prometheus series
    // by inventing names (D67's cardinality rule) — nor a token bucket per
    // invented name, which would be the same defect in the shared cache.
    //
    // These two are the only components of the bucket key that this bounds. The
    // third, the user id, is bounded where the key is built instead — see
    // `limit::user_component`, which is where that half of the same argument
    // lives. Where the id COMES FROM now depends on the identity source: `iam`
    // returns it under `Attestation::Iam`, and only under `TrustedHeaders` is it a
    // header the caller wrote. `user_component` is scoped to that path already and
    // still earns its place there, because `TrustedHeaders` stays reachable via
    // `YADGAR_TRUST_UNAUTHENTICATED_HEADERS` even though the shipped chart
    // leaves `trustUnauthenticatedHeaders` at its `values.yaml` default of
    // `false`, so the var is unset and `Attestation::from_lookup` resolves
    // that to `Iam` instead.
    let (Some(label), Some(module)) = (tools::label_for(name), tools::module_for(name)) else {
        return Err(Box::new(reply(
            200,
            mcp::error(
                Some(id),
                codes::INVALID_PARAMS,
                &format!("unknown tool: {name}"),
            ),
        )));
    };
    Ok((label, module))
}

/// The D67 record for a call D74 refused.
///
/// Its own function for the same reason [`attest_refusal`] is one: it is the
/// RECORD, not the decision. `throttled` already decided and already built
/// the answer the caller sees.
pub(super) fn record_throttled(
    label: &'static str,
    kind: Kind,
    scope: yadgar_telemetry::observe::Scope,
) {
    // A throttled call is a call, for the same reason the refusal above is.
    // Without this a throttling storm is indistinguishable from silence,
    // which is the reading D15's retirement rule would act on.
    //
    // The ATTESTED scope rides on it, unlike the UNAUTHENTICATED record above
    // — there identity was never established, here it was, and "who is being
    // throttled" is the first question anyone reading this record has. It
    // goes in the wide event and NOT in a metric label, which is the same
    // split every other record on this path already makes.
    Call::start(SERVICE, label, kind, scope).fail("RESOURCE_EXHAUSTED");
}

/// Spend a token, and build the refusal if there is none to spend (D74).
///
/// `Some` is a 429 the caller must be sent; `None` means carry on. Split out of
/// `tools_call` because a limiter that has three outcomes and only one of them
/// returns is exactly the shape that belongs behind a name.
pub(super) async fn throttled(
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

        // A 503, AND NOT A 429, because nothing the client does changes it. The
        // two arms above tell a caller to come back later and mean it; this one
        // is a deployment that was assembled wrong, and telling a caller to retry
        // would be telling it to retry for ever. The argument for refusing rather
        // than proceeding on the floor is on `Decision::Unauthenticated`.
        //
        // Counted under the same `degraded` series as the others, with
        // `outcome = "refused"` — a third value, and the set stays closed. It is
        // the one an alert should fire on: `unreachable` ends by itself and this
        // does not.
        Decision::Unauthenticated => {
            degraded(
                label,
                module,
                crate::limit::Degrade::Unauthenticated,
                "refused",
            );
            // NO USER, NO ADDRESS AND NO CREDENTIAL in the message. It reaches an
            // unauthenticated caller, so it says what is wrong in terms only
            // somebody holding this deployment's manifests can act on.
            Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    mcp::error(
                        Some(id),
                        codes::INTERNAL_ERROR,
                        "the shared cache refused this gateway's credential, so no capacity \
                         limit can be enforced (D74). This is a deployment error rather than \
                         an outage: check YADGAR_VALKEY_PASSWORD_FILE against the cache's \
                         requirepass.",
                    )
                    .to_string(),
                )
                    .into_response(),
            )
        }
    }
}

/// Count and log one degraded call.
///
/// `outcome` is `allowed`, `throttled` or `refused` — three values, so the series
/// stays inside D67's cardinality rule, and the distinctions are the ones an
/// operator needs: whether the floor is merely in force, is turning traffic away,
/// or was never reached because the cache refused this gateway's credential.
pub(super) fn degraded(
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
    // TWO MESSAGES, because the two situations are not the same one and an
    // operator greps the text. The floor line describes a cache that could not
    // answer; saying that about a cache which answered "no" would send somebody
    // to look for an outage that is not happening.
    if outcome == "refused" {
        tracing::error!(
            reason = %why,
            tool = label,
            module,
            outcome,
            "rate limiting is UNAUTHENTICATED: the shared cache refused this gateway's \
             credential, so this call was refused rather than held to a floor (D74). This does \
             not recover on its own — check YADGAR_VALKEY_PASSWORD_FILE against the cache's \
             requirepass."
        );
        return;
    }
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
pub(super) fn refusal(
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
pub(super) fn shape(
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
pub(super) fn kind_of(name: &str) -> Kind {
    if tools::is_write(name) {
        Kind::Write
    } else {
        Kind::Read
    }
}

pub(super) fn as_object(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}
