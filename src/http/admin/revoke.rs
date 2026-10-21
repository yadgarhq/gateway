//! `POST /admin/revoke-credentials` (ADR-0945, ledger 1626): revoke every live
//! credential one user holds.
//!
//! Its own file because `http/admin.rs` is near the size ceiling. The ORDER is
//! the security property, so it is stated once here:
//!
//! 1. [`guard`] — the `Origin` check and this route's own throttle key.
//! 2. [`authorise`] — an attested administrator only. The bootstrap token is
//!    refused by `Verb::accepts_bootstrap` before its secret is compared.
//! 3. [`target`] — a strict body: one key, `user_id`, a string.
//! 4. [`is_canonical_user_id`] — BEFORE the self-target check (see there).
//! 5. The self-target refusal.
//! 6. `iam.RevokeAllCredentials`, bounded by [`AUTH_DEADLINE`].
//!
//! `iam` publishes `CREDENTIAL_REVOKED` after its commit, and every replica's
//! consumer evicts the user from its credential cache. Nothing here evicts.

use super::super::authority::*;
use super::super::dispatch::*;
use super::super::gate::*;
use super::super::*;
use crate::pb::yadgar::iam::v1::RevokeAllCredentialsRequest;

/// The canonical-id check, shared with the project membership check
/// (ADR-0954), which reads the same spelling to derive an account segment.
/// One definition, so the two cannot disagree on what `iam-db` mints.
pub(in crate::http) use crate::project::is_canonical_user_id;

/// The one field this route reads, or the message its 400 carries.
///
/// STRICT, unlike the sibling routes: an unknown key is a 400 (ADR-0945). A
/// misspelt field on a route that withdraws credentials must not be a silent
/// success.
fn target(body: &Bytes) -> Result<String, &'static str> {
    let Some(Value::Object(fields)) = parsed(body) else {
        return Err("the body must be a JSON object");
    };
    if fields.keys().any(|k| k != "user_id") {
        return Err("the only accepted key is `user_id`");
    }
    let Some(Value::String(user_id)) = fields.get("user_id") else {
        return Err("`user_id` is required and must be a string");
    };
    if !is_canonical_user_id(user_id) {
        return Err(
            "`user_id` must be exactly as iam stores it: `yadgar:user:` and a lowercase uuidv7",
        );
    }
    Ok(user_id.clone())
}

/// `iam.RevokeAllCredentials`, behind an attested administrator only.
pub(in crate::http) async fn admin_revoke_credentials(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refusal) = guard(
        &state,
        ADMIN_REVOKE_CREDENTIALS,
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
        ADMIN_REVOKE_CREDENTIALS,
        Kind::Write,
        tel(request_id.clone()),
    );

    // AUTHORISE BEFORE THE BODY IS READ. The request carries no flag, so
    // `wants_admin` is `false`, and `accepts_bootstrap` refuses this verb on
    // either value.
    let authority = match authorise(
        &state,
        ADMIN_REVOKE_CREDENTIALS,
        Verb::RevokeCredentials,
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

    let user_id = match target(&body) {
        Ok(id) => id,
        Err(message) => {
            call.fail("INVALID_ARGUMENT");
            return text(
                StatusCode::BAD_REQUEST,
                &json!({ "error": message }).to_string(),
            );
        }
    };

    // THE SELF-TARGET REFUSAL, exact because `target` admitted only the
    // canonical spelling. It keeps a structural last-administrator guard, as
    // `is_self_demotion` does for `SetUserAdmin`.
    if authority == Authority::Administrator(user_id.clone()) {
        call.fail("PERMISSION_DENIED");
        return text(
            StatusCode::FORBIDDEN,
            r#"{"error":"an administrator cannot revoke their own credentials"}"#,
        );
    }

    let mut client = IamServiceClient::new(crate::upstream::request_id::carrying(
        state.iam.clone(),
        &request_id,
    ));
    let rpc = client.revoke_all_credentials(RevokeAllCredentialsRequest {
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        user_id: user_id.clone(),
        unverified_actor: authority.actor(),
    });
    let resp = match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(r)) => r.into_inner(),
        // NOT_FOUND IS 404 HERE AND ONLY HERE (ADR-0945): `iam-db` holds no
        // `iam_user` row for this id. `admin_failure` keeps answering 503 for
        // the other routes.
        Ok(Err(e)) if e.code() == tonic::Code::NotFound => {
            tracing::warn!(
                endpoint = ADMIN_REVOKE_CREDENTIALS,
                "revoke-credentials named no user"
            );
            call.fail("NOT_FOUND");
            return text(StatusCode::NOT_FOUND, r#"{"error":"no such user"}"#);
        }
        Ok(Err(e)) => return admin_failure(call, ADMIN_REVOKE_CREDENTIALS, e),
        Err(_elapsed) => return admin_timeout(call, ADMIN_REVOKE_CREDENTIALS),
    };

    // `revoked` counts the rows THIS delivery changed (iam.proto): a retry may
    // answer 0 after an earlier delivery revoked everything.
    // `voided_enrolments` is counted the same way (ADR-0972 (5)), and an `iam`
    // built before that ADR always answers 0: zero proves nothing.
    let rendered = json!({
        "user_id": user_id,
        "revoked": resp.revoked,
        "voided_enrolments": resp.voided_enrolments,
    })
    .to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}
