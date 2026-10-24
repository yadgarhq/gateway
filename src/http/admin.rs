//! The six administrative endpoints (ADR-0492, D73, ADR-0945, ADR-0972 (2)).
//!
//! Split out of [`super`] for the file-size ceiling; the first,
//! `create-user`, lives in [`create_user`] for the same reason, the fourth,
//! `revoke-credentials`, in [`revoke`], and the
//! fifth and sixth, `list-credentials` and `revoke-credential`, in
//! [`credentials`]. WHO is allowed to reach
//! them is [`super::authority`]'s, and the split is deliberate in that
//! direction: these handlers do the work, and none of them decides the
//! authorization.

use super::authority::*;
use super::dispatch::*;
use super::gate::*;
use super::*;
use crate::upstream::CallError;

pub(in crate::http) mod create_user;
pub(in crate::http) mod credentials;
pub(in crate::http) mod revoke;

/// This module's routes. See [`super::dispatch::routes`] for why each set is
/// registered beside its own handlers.
pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // THE ADMINISTRATIVE SURFACE (ADR-0492, D73, ledger 638), and ABOVE
        // `.layer(...)` for exactly the reason written on `/auth/login` — with
        // one difference worth spelling out, because it is what makes the same
        // mistake cost more here. On the two lines above, a route that slipped
        // below the layer would be an unauthenticated endpoint accepting a body
        // of any size. On these three it would be that on the one surface whose
        // prize is an administrator.
        //
        // **NOT MCP TOOLS, AND STRUCTURALLY INCAPABLE OF BECOMING ONE.**
        // ADR-0492 rules that an administrative verb never appears as an MCP
        // tool. These are axum routes: no name of theirs is in `tools::SERVED`,
        // so `tools::call` cannot dispatch to one and `tools::definitions`
        // cannot advertise one. Nothing here is added to that array, and nothing
        // here is reachable through `/`.
        .route(
            "/admin/create-user",
            post(create_user::admin_create_user).fallback(method_not_allowed),
        )
        .route(
            "/admin/issue-enrolment",
            post(admin_issue_enrolment).fallback(method_not_allowed),
        )
        .route(
            "/admin/set-user-admin",
            post(admin_set_user_admin).fallback(method_not_allowed),
        )
        // ADR-0945. Above the layer and out of `tools::SERVED`, like the three
        // above it.
        .route(
            "/admin/revoke-credentials",
            post(revoke::admin_revoke_credentials).fallback(method_not_allowed),
        )
        // ADR-0972 (2). Above the layer and out of `tools::SERVED`, like the
        // four above them.
        .route(
            "/admin/list-credentials",
            post(credentials::admin_list_credentials).fallback(method_not_allowed),
        )
        .route(
            "/admin/revoke-credential",
            post(credentials::admin_revoke_credential).fallback(method_not_allowed),
        )
}

// ---------------------------------------------------------------------------
// The administrative surface (ADR-0492, D73, ledger 638)
// ---------------------------------------------------------------------------

/// `iam.IssueEnrolment`, behind an administrator OR the bootstrap token under
/// ADR-0655's predicate.
///
/// The second step of ADR-0492's ceremony: the administrator receives the blob
/// the person redeems at `/auth/enrol`, and never learns the password they
/// choose.
///
/// # Two authorities reach this verb, and they send DIFFERENT MESSAGES
///
/// **The bootstrap token used to be excluded here, and ADR-0655 admits it**
/// because the exclusion made ADR-0492's ceremony unstartable — the circle is
/// argued in `admin::Verb::accepts_bootstrap`. The takeover the exclusion
/// prevented is prevented instead by a PREDICATE: the target must be an
/// administrator holding zero credentials (ADR-0656's definition: no
/// `iam_password` row and no `iam_credential` row of any liveness).
///
/// **THE PREDICATE IS A DEMAND THIS HANDLER SENDS, AND ITS ABSENCE IS SILENT.**
/// `require_zero_credential_admin` is a proto3 `bool`, so a request that omits
/// it is indistinguishable at `iam-db` from one that asked for the ORDINARY
/// unrestricted path. Flipping the verb arm and forgetting this field is
/// therefore not a broken feature but a live unrestricted grant with every
/// status-code test green — which is why `tests/admin_http.rs` asserts the
/// message that ARRIVED rather than the answer that came back.
///
/// On the ATTESTED path the demand stays `false`, which is what keeps
/// re-enrolment working as the forgotten-password recovery the contract
/// documents. `admin::Authority::demands_zero_credential_admin` is the whole
/// rule and carries the reasoning.
pub(super) async fn admin_issue_enrolment(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refusal) = guard(
        &state,
        ADMIN_ISSUE_ENROLMENT,
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
        ADMIN_ISSUE_ENROLMENT,
        Kind::Write,
        tel(request_id.clone()),
    );

    let Some(req) = parsed(&body) else {
        call.fail("INVALID_ARGUMENT");
        return text(StatusCode::BAD_REQUEST, r#"{"error":"invalid JSON"}"#);
    };
    let Some(user_id) = req.get("user_id").and_then(Value::as_str) else {
        call.fail("INVALID_ARGUMENT");
        return text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`user_id` is required"}"#,
        );
    };
    let Some(revoke) = revoke_instruction(&req) else {
        call.fail("INVALID_ARGUMENT");
        return text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`revoke_existing_credentials` must be a boolean"}"#,
        );
    };

    let authority = match authorise(
        &state,
        ADMIN_ISSUE_ENROLMENT,
        Verb::IssueEnrolment,
        // NO FLAG ON THIS REQUEST, and `false` is not a value being set — it is
        // the absence of one. `accepts_bootstrap` IGNORES the argument on this
        // verb (it admits the token unconditionally, ADR-0655), so nothing about
        // what is passed here admits or refuses anything. That is why the `false`
        // is safe AND why the arm must not be written `=> wants_admin`: it would
        // read this absence as a refusal and break every enrolment.
        Ask::flag(false),
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

    // NO GATEWAY REFUSAL OF THE BOOTSTRAP REVOKE INSTRUCTION (ADR-0966,
    // ADR-1014 point 1): this gateway does not know `IAM_ADMIN_FROM_TEAM`, so
    // with it off `iam-db` refuses demand plus instruction `INVALID_ARGUMENT`
    // (ADR-1014 point 3), which is the opaque 503 (ADR-0927).

    let mut client = IamServiceClient::new(crate::upstream::request_id::carrying(
        state.iam.channel(),
        &request_id,
    ));
    let request = IssueEnrolmentRequest {
        // SENT, AND NOT SUPPRESSED. `iam-db` discards this key today (ledger 668)
        // and step 1's sensor exists to say so out loud on the day a caller
        // starts sending one. Sending an EMPTY key to keep the sensor quiet would
        // be this gateway asserting a per-RPC exception to D9 it has no authority
        // to make, and would leave a mutating RPC carrying no key at all.
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        user_id: user_id.to_string(),
        unverified_actor: authority.actor(),
        // **FROM THE AUTHORITY, NEVER FROM THE REQUEST BODY.** There is no JSON
        // field for this and there deliberately never will be: a caller who could
        // clear it would turn ADR-0655's narrow grant back into the unrestricted
        // one. The variant is the only input.
        require_zero_credential_admin: authority.demands_zero_credential_admin(),
        // FROM THE BODY, unlike the demand: see `revoke_instruction` (ADR-0943).
        revoke_existing_credentials: revoke,
    };
    let resp = match state.iam_rpc(request, |r| client.issue_enrolment(r)).await {
        Ok(r) => r.into_inner(),
        Err(CallError::Answered(e)) => return admin_failure(call, ADMIN_ISSUE_ENROLMENT, e),
        Err(CallError::Expired) => return admin_timeout(call, ADMIN_ISSUE_ENROLMENT),
    };

    let rendered = json!({
        "token": resp.token,
        "enrolment_id": resp.enrolment_id,
        // AS APPLIED — see `revoke_instruction` for why it is echoed.
        "revoke_existing_credentials": revoke,
    })
    .to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        // DELIBERATELY EMPTY, exactly as on `login` and `enrol`. `payload` is
        // stored in the wide event and this payload carries a single-use secret;
        // copying `measured`'s idiom would write every enrolment token this
        // system issues into the telemetry store.
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}

/// `iam.SetUserAdmin` — promote or demote (D73).
///
/// `is_admin` is REQUIRED and must be a real boolean: an absent flag defaulting
/// to `false` would make a malformed request a demotion.
///
/// **Two rules meet here and neither is `iam`'s.** The bootstrap token reaches
/// only the promotion half (`admin::Verb::accepts_bootstrap`), and an
/// administrator cannot clear their own flag (`admin::is_self_demotion`, which
/// carries D73's citation and the last-administrator argument).
pub(super) async fn admin_set_user_admin(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refusal) = guard(
        &state,
        ADMIN_SET_USER_ADMIN,
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
        ADMIN_SET_USER_ADMIN,
        Kind::Write,
        tel(request_id.clone()),
    );

    let Some(req) = parsed(&body) else {
        call.fail("INVALID_ARGUMENT");
        return text(StatusCode::BAD_REQUEST, r#"{"error":"invalid JSON"}"#);
    };
    let (Some(user_id), Some(is_admin)) = (
        req.get("user_id").and_then(Value::as_str),
        // REQUIRED, and `as_bool` rather than a truthiness reading: `"false"` and
        // `0` are not booleans, and guessing what a caller meant on the verb that
        // removes administrators is not a kindness.
        req.get("is_admin").and_then(Value::as_bool),
    ) else {
        call.fail("INVALID_ARGUMENT");
        return text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`user_id` and a boolean `is_admin` are required"}"#,
        );
    };

    let authority = match authorise(
        &state,
        ADMIN_SET_USER_ADMIN,
        Verb::SetUserAdmin,
        Ask::flag(is_admin),
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

    // D73'S EXCLUSION, AND THE LAST-ADMINISTRATOR GUARD IN ONE. `iam.proto:664`
    // defers it here by name, because it is "a rule about who may call this" and
    // the only caller identity `iam` has is the one ADR-0534 forbids authorising
    // on. See `admin::is_self_demotion` for why this plus the bootstrap token's
    // promote-only grant is what keeps the administrator count above zero, and
    // for the cached-flag race it does NOT close.
    if crate::admin::is_self_demotion(&authority, user_id, is_admin) {
        call.fail("PERMISSION_DENIED");
        return text(
            StatusCode::FORBIDDEN,
            r#"{"error":"an administrator cannot remove their own administrative flag"}"#,
        );
    }

    let mut client = IamServiceClient::new(crate::upstream::request_id::carrying(
        state.iam.channel(),
        &request_id,
    ));
    let request = SetUserAdminRequest {
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        user_id: user_id.to_string(),
        is_admin,
        unverified_actor: authority.actor(),
    };
    match state.iam_rpc(request, |r| client.set_user_admin(r)).await {
        Ok(_) => {}
        Err(CallError::Answered(e)) => return admin_failure(call, ADMIN_SET_USER_ADMIN, e),
        Err(CallError::Expired) => return admin_timeout(call, ADMIN_SET_USER_ADMIN),
    }

    let rendered = json!({ "user_id": user_id, "is_admin": is_admin }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}

/// ADR-0943's optional `revoke_existing_credentials` on `/admin/issue-enrolment`.
///
/// ABSENT IS `false` — the reset path exactly as it was. PRESENT MUST BE A JSON
/// BOOLEAN, and anything else is `None`, which the caller answers with a 400:
/// `"true"` and `1` are not an instruction to sign somebody out everywhere, and
/// `admin_set_user_admin` already refuses to guess at a truthiness reading on
/// the same grounds.
///
/// FROM THE REQUEST BODY, AND THAT IS NOT `admin_issue_enrolment`'s "never from
/// the request body" rule broken. That rule is about the demand, which only ever
/// NARROWS the bootstrap grant, so a caller who could clear it would widen it.
/// This instruction only ever withdraws credentials, and its absence is the
/// reset path exactly as it was. The bootstrap caller may set it too (ADR-0966,
/// ADR-1014); with derivation off `iam-db` refuses it beside the demand.
///
/// THE 200 ECHOES THE VALUE AS APPLIED (ledger 1579). An unknown JSON key is
/// ignored, so a misspelt field is a 200 and a plain reset with every old token
/// still working; the echo is how a client that asked for a revoke learns it
/// did not get one.
fn revoke_instruction(req: &Value) -> Option<bool> {
    match req.get("revoke_existing_credentials") {
        None => Some(false),
        Some(v) => v.as_bool(),
    }
}
