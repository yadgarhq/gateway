//! `POST /admin/list-credentials` and `POST /admin/revoke-credential`
//! (ADR-0972 (2), ledger 1627): list one user's live credentials, and revoke
//! one of them.
//!
//! Its own file because `http/admin.rs` is at the size ceiling. Each handler
//! keeps `revoke.rs`'s order, which is the security property:
//!
//! 1. `guard` — the `Origin` check and this route's own throttle key.
//! 2. `authorise` — an attested administrator only. The bootstrap token is
//!    refused by `Verb::accepts_bootstrap` before its secret is compared, and
//!    there is no owner self-service (ADR-0972 (2)).
//! 3. A strict body: an unknown key is a 400, as on revoke-credentials.
//! 4. The `iam` call, bounded by `AUTH_DEADLINE`.
//!
//! **NO SELF-TARGET REFUSAL on revoke-credential.** An administrator may
//! revoke their own credential (ADR-0972 (2)). Revoke-all keeps its own
//! refusal, as ADR-0945 ruled, because that one can leave no live
//! administrator credential at all.

use super::super::authority::*;
use super::super::dispatch::*;
use super::super::gate::*;
use super::super::*;
use super::revoke::is_canonical_user_id;
use crate::pb::yadgar::iam::v1::{Credential, ListCredentialsRequest, RevokeCredentialRequest};

/// The fixed 400 body for an `iam` INVALID_ARGUMENT. Never `iam`'s own words.
const MALFORMED: &str = r#"{"error":"iam refused the request as malformed"}"#;

/// A strict JSON object: every key in `allowed`, or the 400's message.
fn strict<'a>(
    body: &'a Value,
    allowed: &[&str],
    message: &'static str,
) -> Result<&'a serde_json::Map<String, Value>, &'static str> {
    let Value::Object(fields) = body else {
        return Err("the body must be a JSON object");
    };
    if fields.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(message);
    }
    Ok(fields)
}

/// The canonical `user_id` every credential route requires.
fn user_id(fields: &serde_json::Map<String, Value>) -> Result<String, &'static str> {
    let Some(Value::String(id)) = fields.get("user_id") else {
        return Err("`user_id` is required and must be a string");
    };
    if !is_canonical_user_id(id) {
        return Err(
            "`user_id` must be exactly as iam stores it: `yadgar:user:` and a lowercase uuidv7",
        );
    }
    Ok(id.clone())
}

/// `{user_id, page_token?}`.
fn list_target(body: &Bytes) -> Result<(String, String), &'static str> {
    let parsed = parsed(body).unwrap_or(Value::Null);
    let fields = strict(
        &parsed,
        &["user_id", "page_token"],
        "the only accepted keys are `user_id` and `page_token`",
    )?;
    let page_token = match fields.get("page_token") {
        None => String::new(),
        Some(Value::String(t)) => t.clone(),
        Some(_) => return Err("`page_token` must be a string"),
    };
    Ok((user_id(fields)?, page_token))
}

/// `{user_id, credential_id}`.
fn revoke_target(body: &Bytes) -> Result<(String, String), &'static str> {
    let parsed = parsed(body).unwrap_or(Value::Null);
    let fields = strict(
        &parsed,
        &["user_id", "credential_id"],
        "the only accepted keys are `user_id` and `credential_id`",
    )?;
    let user_id = user_id(fields)?;
    match fields.get("credential_id") {
        Some(Value::String(id)) if !id.is_empty() => Ok((user_id, id.clone())),
        _ => Err("`credential_id` is required and must be a non-empty string"),
    }
}

/// The 400 for a body this gateway refused.
fn bad_body(call: Call, message: &str) -> Response {
    call.fail("INVALID_ARGUMENT");
    text(
        StatusCode::BAD_REQUEST,
        &json!({ "error": message }).to_string(),
    )
}

/// An `iam` refusal on these two routes. NOT_FOUND is a 404 with `not_found`
/// as its fixed body, INVALID_ARGUMENT a 400 with [`MALFORMED`]; everything
/// else is `admin_failure`'s, as on every sibling route.
fn refused(
    call: Call,
    endpoint: &'static str,
    e: tonic::Status,
    not_found: &'static str,
) -> Response {
    let (status, label, body) = match e.code() {
        tonic::Code::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND", not_found),
        tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", MALFORMED),
        _ => return admin_failure(call, endpoint, e),
    };
    tracing::warn!(code = ?e.code(), message = e.message(), endpoint, "iam refused a credential route");
    call.fail(label);
    text(status, body)
}

/// One listed row. ONLY the four projected fields: `iam` sends no token and
/// no hash, and nothing here could add one. Times are RFC 3339; an absent
/// expiry (a row minted before ADR-0972 (3)) is an absent key.
fn row(c: Credential) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("id".into(), Value::String(c.id));
    out.insert("label".into(), Value::String(c.label));
    if let Some(t) = c.created_at {
        out.insert("created_at".into(), Value::String(t.to_string()));
    }
    if let Some(t) = c.expires_at {
        out.insert("expires_at".into(), Value::String(t.to_string()));
    }
    Value::Object(out)
}

/// `iam.ListCredentials`, behind an attested administrator only.
pub(in crate::http) async fn admin_list_credentials(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refusal) = guard(
        &state,
        ADMIN_LIST_CREDENTIALS,
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
        ADMIN_LIST_CREDENTIALS,
        Kind::Read,
        tel(request_id.clone()),
    );
    let authority = match authorise(
        &state,
        ADMIN_LIST_CREDENTIALS,
        Verb::ListCredentials,
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
    let (user_id, page_token) = match list_target(&body) {
        Ok(t) => t,
        Err(message) => return bad_body(call, message),
    };

    let mut client = IamServiceClient::new(crate::upstream::request_id::carrying(
        state.iam.clone(),
        &request_id,
    ));
    let rpc = client.list_credentials(ListCredentialsRequest {
        user_id,
        // 0 is `iam`'s default page size.
        page_size: 0,
        page_token,
        unverified_actor: authority.actor(),
    });
    let resp = match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => {
            return refused(
                call,
                ADMIN_LIST_CREDENTIALS,
                e,
                r#"{"error":"no such user"}"#,
            )
        }
        Err(_elapsed) => return admin_timeout(call, ADMIN_LIST_CREDENTIALS),
    };

    let rows = u32::try_from(resp.credentials.len()).unwrap_or(u32::MAX);
    let credentials: Vec<Value> = resp.credentials.into_iter().map(row).collect();
    let rendered = json!({
        "credentials": credentials,
        "next_page_token": resp.next_page_token,
    })
    .to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        rows,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}

/// `iam.RevokeCredential`, behind an attested administrator only. `iam-db`
/// checks the credential belongs to the named user (ADR-0972 (2)).
pub(in crate::http) async fn admin_revoke_credential(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refusal) = guard(
        &state,
        ADMIN_REVOKE_CREDENTIAL,
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
        ADMIN_REVOKE_CREDENTIAL,
        Kind::Write,
        tel(request_id.clone()),
    );
    let authority = match authorise(
        &state,
        ADMIN_REVOKE_CREDENTIAL,
        Verb::RevokeCredential,
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
    let (user_id, credential_id) = match revoke_target(&body) {
        Ok(t) => t,
        Err(message) => return bad_body(call, message),
    };

    let mut client = IamServiceClient::new(crate::upstream::request_id::carrying(
        state.iam.clone(),
        &request_id,
    ));
    let rpc = client.revoke_credential(RevokeCredentialRequest {
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        credential_id: credential_id.clone(),
        unverified_actor: authority.actor(),
        user_id: user_id.clone(),
    });
    match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(_)) => {}
        // ONE BODY for an unknown id and another user's id: `iam-db` answers
        // NOT_FOUND for both, so the route cannot tell whose a credential is.
        Ok(Err(e)) => {
            return refused(
                call,
                ADMIN_REVOKE_CREDENTIAL,
                e,
                r#"{"error":"no such credential for this user"}"#,
            )
        }
        Err(_elapsed) => return admin_timeout(call, ADMIN_REVOKE_CREDENTIAL),
    }

    let rendered = json!({ "user_id": user_id, "credential_id": credential_id }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}
