//! The three administrative endpoints (ADR-0492, D73).
//!
//! Split out of [`super`] for the file-size ceiling. WHO is allowed to reach
//! them is [`super::authority`]'s, and the split is deliberate in that
//! direction: these handlers do the work, and none of them decides the
//! authorization.

use super::authority::*;
use super::dispatch::*;
use super::gate::*;
use super::*;

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
            post(admin_create_user).fallback(method_not_allowed),
        )
        .route(
            "/admin/issue-enrolment",
            post(admin_issue_enrolment).fallback(method_not_allowed),
        )
        .route(
            "/admin/set-user-admin",
            post(admin_set_user_admin).fallback(method_not_allowed),
        )
}

// ---------------------------------------------------------------------------
// The administrative surface (ADR-0492, D73, ledger 638)
// ---------------------------------------------------------------------------

/// `iam.CreateUser`, behind an administrator or the bootstrap token.
///
/// The FIRST of D73's three administrative verbs and the one the bootstrap token
/// exists for: the first administrator has to exist before anyone can log in to
/// promote one.
///
/// Body: `external_id` and `display_name` (both required), and an optional
/// `is_admin` which DEFAULTS TO FALSE — an ordinary account, which is the
/// fail-closed reading of an omitted flag and, for a bootstrap caller, a refusal
/// rather than a surprise administrator.
///
/// Answers `{"user_id": ...}` from `CreateUserResponse.meta.id`. That is the same
/// identifier space `ResolveCredential` returns and the same one
/// [`admin_issue_enrolment`] and [`admin_set_user_admin`] consume — `iam-db`
/// mints it as `yadgar:user:<uuidv7>` and stores it as `iam_user.id`, which is
/// what `iam_credential.user_id` points at — so an administrator can drive the
/// whole ceremony from what this returns. Handing back an id the next verb could
/// not accept is §9's step-7 shape: an admin who can create users and not enrol
/// them, every status green.
pub(super) async fn admin_create_user(
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
    let (Some(external_id), Some(display_name)) = (
        req.get("external_id").and_then(Value::as_str),
        req.get("display_name").and_then(Value::as_str),
    ) else {
        call.fail("INVALID_ARGUMENT");
        return text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`external_id` and `display_name` are required"}"#,
        );
    };
    // ABSENT MEANS FALSE, and false is an ordinary account. A bootstrap caller
    // who omits it is refused by `accepts_bootstrap` rather than quietly creating
    // one, which is the direction an omitted flag must fail in.
    let is_admin = req
        .get("is_admin")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let authority = match authorise(
        &state,
        ADMIN_CREATE_USER,
        Verb::CreateUser,
        is_admin,
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

    let mut client = IamServiceClient::new(state.iam.clone());
    let rpc = client.create_user(CreateUserRequest {
        // MINTED HERE, PER INBOUND REQUEST, and it buys what `enrol`'s buys and
        // no more: this gateway's own retry to `iam` is safe; a CLIENT's retry is
        // a second inbound request and a second key. See `crate::idempotency_key`.
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        external_id: external_id.to_string(),
        display_name: display_name.to_string(),
        is_admin,
        // ADR-0534's relay, and `None` on the bootstrap path. See
        // `admin::Authority::actor` — an empty actor would reach `iam-db`'s
        // `<unattributed>` by the wrong route and hide a dropped id.
        unverified_actor: authority.actor(),
    });
    let resp = match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => return admin_failure(call, ADMIN_CREATE_USER, e),
        Err(_elapsed) => return admin_timeout(call, ADMIN_CREATE_USER),
    };

    let rendered = json!({ "user_id": resp.meta.map(|m| m.id).unwrap_or_default() }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}

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
        false,
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

    let mut client = IamServiceClient::new(state.iam.clone());
    let rpc = client.issue_enrolment(IssueEnrolmentRequest {
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
    });
    let resp = match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => return admin_failure(call, ADMIN_ISSUE_ENROLMENT, e),
        Err(_elapsed) => return admin_timeout(call, ADMIN_ISSUE_ENROLMENT),
    };

    let rendered = json!({
        "token": resp.token,
        "enrolment_id": resp.enrolment_id,
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
        is_admin,
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

    let mut client = IamServiceClient::new(state.iam.clone());
    let rpc = client.set_user_admin(SetUserAdminRequest {
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        user_id: user_id.to_string(),
        is_admin,
        unverified_actor: authority.actor(),
    });
    match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return admin_failure(call, ADMIN_SET_USER_ADMIN, e),
        Err(_elapsed) => return admin_timeout(call, ADMIN_SET_USER_ADMIN),
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
