//! `POST /admin/create-user` (ADR-0492, D73; team access stage 3b).
//!
//! Its own file because `http/admin.rs` is near the size ceiling. The ORDER is
//! the security property, so it is stated once here:
//!
//! 1. [`guard`] — the `Origin` check and this route's own throttle key.
//! 2. [`fields`] — JSON SHAPE only: invalid JSON, a missing required field, a
//!    non-string `user_id`. Never an identifier's format or existence
//!    (ADR-0927), because this step runs before authorization and would answer
//!    an unauthenticated caller.
//! 3. [`authorise`] — an attested administrator, or the bootstrap token on one
//!    of its two `create-user` arms (`Verb::accepts_bootstrap`).
//! 4. The bootstrap-only rule of a pre-minted id
//!    (`admin::refuses_pre_minted_id`): the opaque 503, no upstream call.
//! 5. `iam.CreateUser`, bounded by [`AUTH_DEADLINE`].
//! 6. The echo check: a pre-minted id must come back as `meta.id`.

use super::super::authority::*;
use super::super::dispatch::*;
use super::super::gate::*;
use super::super::*;
use crate::admin::{refuses_pre_minted_id, upstream_user_id};
use crate::upstream::CallError;

/// The echo check's answer: an `iam` or `iam-db` that predates the field
/// dropped it (proto3 drops an unknown field silently) and created the user
/// under an id of its own. A constant: the minted id goes to the log only.
const ECHO_MISMATCH_BODY: &str = r#"{"error":"iam predates pre-minted user ids: it created the user under an id of its own, not the one sent"}"#;

/// The opaque answer, byte-identical to every upstream `UNAVAILABLE`.
const UNAVAILABLE_BODY: &str = r#"{"error":"the administrative service is unavailable"}"#;

/// One `create-user` body, judged for SHAPE only.
struct Fields<'a> {
    external_id: &'a str,
    display_name: &'a str,
    /// ABSENT MEANS FALSE, and false is an ordinary account. A bootstrap caller
    /// who omits it and names no `user_id` is refused by `accepts_bootstrap`
    /// rather than quietly creating one.
    is_admin: bool,
    /// The bare pre-minted id, as declared (team access §6, flow F2). Any JSON
    /// string is accepted here, the empty one included: the format is `iam`'s
    /// to judge, after authorization.
    user_id: Option<&'a str>,
}

/// The shape check. `Err` is the 400 body.
fn fields(req: &Value) -> Result<Fields<'_>, &'static str> {
    let (Some(external_id), Some(display_name)) = (
        req.get("external_id").and_then(Value::as_str),
        req.get("display_name").and_then(Value::as_str),
    ) else {
        return Err(r#"{"error":"`external_id` and `display_name` are required"}"#);
    };
    // A NON-STRING `user_id` IS A SHAPE ERROR, `null` included, for
    // `revoke_instruction`'s reason: guessing what a caller meant is not a
    // kindness on the verb that creates administrators.
    let user_id = match req.get("user_id") {
        None => None,
        Some(Value::String(id)) => Some(id.as_str()),
        Some(_) => return Err(r#"{"error":"`user_id` must be a string"}"#),
    };
    Ok(Fields {
        external_id,
        display_name,
        is_admin: req
            .get("is_admin")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        user_id,
    })
}

/// `iam.CreateUser`, behind an administrator or the bootstrap token.
///
/// The FIRST of D73's administrative verbs and the one the bootstrap token
/// exists for: the first administrator has to exist before anyone can log in.
///
/// Body: `external_id` and `display_name` (both required), an optional
/// `is_admin` which DEFAULTS TO FALSE, and an optional `user_id`: the bare
/// lowercase uuidv7 the operator declared in GitOps as the first administrator
/// (flow F2, ADR-0963 (5)). The gateway sends it upstream as
/// `yadgar:user:<value>` with `is_admin` false; only the bootstrap token may
/// send it.
///
/// Answers `{"user_id": ...}` from `CreateUserResponse.meta.id`. That is the same
/// identifier space `ResolveCredential` returns and the same one
/// `admin_issue_enrolment` and `admin_set_user_admin` consume — `iam-db`
/// mints it as `yadgar:user:<uuidv7>` (or stores the pre-minted one) as
/// `iam_user.id`, which is what `iam_credential.user_id` points at — so an
/// administrator can drive the whole ceremony from what this returns.
pub(in crate::http) async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // FIRST, BEFORE THE BODY, exactly as on `/auth/*` — see [`guard`] for why an
    // `/admin` route that skipped it would have no `Origin` check and no
    // throttle, on the surface where a cross-origin POST buys an administrator.
    if let Some(refusal) = guard(
        &state,
        ADMIN_CREATE_USER,
        state.admin_limits,
        peer,
        &headers,
    )
    .await
    {
        return refusal;
    }
    let request_id = crate::request_id();
    let call = Call::start(
        SERVICE,
        ADMIN_CREATE_USER,
        Kind::Write,
        tel(request_id.clone()),
    );

    let Some(req) = parsed(&body) else {
        call.fail("INVALID_ARGUMENT");
        return text(StatusCode::BAD_REQUEST, r#"{"error":"invalid JSON"}"#);
    };
    let f = match fields(&req) {
        Ok(f) => f,
        Err(shape) => {
            call.fail("INVALID_ARGUMENT");
            return text(StatusCode::BAD_REQUEST, shape);
        }
    };

    let ask = Ask {
        wants_admin: f.is_admin,
        pre_minted_id: f.user_id.is_some(),
    };
    let authority = match authorise(
        &state,
        ADMIN_CREATE_USER,
        Verb::CreateUser,
        ask,
        &headers,
        request_id.clone(),
    )
    .await
    {
        Ok(a) => a,
        Err(refusal) => {
            call.fail(refusal.label);
            return refusal.response;
        }
    };

    // BOOTSTRAP-ONLY (§6). The opaque 503 rather than a 403: the answer must
    // not differ from an outage, so a caller learns nothing about the rule's
    // reach. The reason goes to the log; the label records a refusal, not an
    // unavailability, because operators aggregate on it.
    if refuses_pre_minted_id(&authority, ask.pre_minted_id) {
        tracing::warn!(
            endpoint = ADMIN_CREATE_USER,
            "an attested administrator sent `user_id` on create-user; a pre-minted id is \
             bootstrap-only (team access §6), so nothing was sent to iam"
        );
        call.fail("PERMISSION_DENIED");
        return text(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY);
    }

    // EMPTY MEANS "MINT ONE", today's behaviour, and it is what every request
    // without a `user_id` sends.
    let sent = f.user_id.map(upstream_user_id).unwrap_or_default();
    let mut client = IamServiceClient::new(crate::upstream::request_id::carrying(
        state.iam.channel(),
        &request_id,
    ));
    let request = CreateUserRequest {
        // MINTED HERE, PER INBOUND REQUEST, and it buys what `enrol`'s buys and
        // no more: this gateway's own retry to `iam` is safe; a CLIENT's retry is
        // a second inbound request and a second key. See `crate::idempotency_key`.
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        external_id: f.external_id.to_string(),
        display_name: f.display_name.to_string(),
        is_admin: f.is_admin,
        user_id: sent.clone(),
        // ADR-0534's relay, and `None` on the bootstrap path. See
        // `admin::Authority::actor` — an empty actor would reach `iam-db`'s
        // `<unattributed>` by the wrong route and hide a dropped id.
        unverified_actor: authority.actor(),
    };
    let resp = match state.iam_rpc(request, |r| client.create_user(r)).await {
        Ok(r) => r.into_inner(),
        Err(CallError::Answered(e)) => return admin_failure(call, ADMIN_CREATE_USER, e),
        Err(CallError::Expired) => return admin_timeout(call, ADMIN_CREATE_USER),
    };

    let created = resp.meta.map(|m| m.id).unwrap_or_default();
    if !sent.is_empty() && created != sent {
        return echo_mismatch(call, &sent, &created);
    }
    let rendered = json!({ "user_id": created }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}

/// THE ECHO CHECK (team access stage 3b). Detection, not prevention: the stray
/// user row already exists, which is why the stage also carries a version gate.
/// Loud on the first call, so the bootstrap token cannot create ordinary
/// accounts without limit behind a row of 200s.
fn echo_mismatch(call: Call, sent: &str, created: &str) -> Response {
    tracing::warn!(
        endpoint = ADMIN_CREATE_USER,
        sent,
        created,
        "iam predates pre-minted user ids: create-user answered an id other than the one sent, \
         so the user exists under a minted id and is not the declared administrator"
    );
    // A VALUE `yadgar_telemetry::grpc::status_name` PRODUCES (ADR-0558).
    call.fail("INTERNAL");
    text(StatusCode::BAD_GATEWAY, ECHO_MISMATCH_BODY)
}
