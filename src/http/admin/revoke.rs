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

/// The prefix `iam-db` mints every user id with: `yadgar:user:<uuidv7>`.
const USER_ID_PREFIX: &str = "yadgar:user:";

/// Whether `id` is spelt EXACTLY as `iam-db` stores it.
///
/// # Why a spelling check, and why it comes before the self-target check
///
/// `iam-db` mints `format!("yadgar:user:{}", Uuid::now_v7())`: the prefix, then
/// a lowercase, hyphenated 8-4-4-4-12 uuid of version 7 and RFC 4122 variant.
/// Its `id` column compares case- and accent-insensitively, so a variant
/// spelling still finds the row and revokes it. The cache eviction does not:
/// `forget_user` compares bytes against the id `iam` resolved, and `iam`
/// publishes the id it was SENT. A variant spelling would revoke every row and
/// evict nothing, and each token would keep resolving from a replica's cache
/// for the credential TTL.
///
/// The same reasoning orders the checks. The self-target check is also a byte
/// compare, so the caller's own id in upper case would pass it, and the caller
/// would revoke their own credentials. Refusing every non-canonical spelling
/// first makes the byte compare exact.
///
/// ASCII only: an accented or padded spelling fails the length or the
/// character test.
pub(in crate::http) fn is_canonical_user_id(id: &str) -> bool {
    let Some(uuid) = id.strip_prefix(USER_ID_PREFIX) else {
        return false;
    };
    let bytes = uuid.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let shape_ok = bytes.iter().enumerate().all(|(i, &b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
    });
    // VERSION 7 AND THE RFC 4122 VARIANT, which every id `iam-db` has minted
    // carries: `Uuid::now_v7` is the only minting site in its history.
    shape_ok && bytes[14] == b'7' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

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
    let rendered = json!({ "user_id": user_id, "revoked": resp.revoked }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}
