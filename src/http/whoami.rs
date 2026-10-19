//! `GET /auth/whoami`: the caller's own `user_id` and `local/` account segment
//! (ADR-0959).
//!
//! **ATTESTED, AND THEREFORE NOT IN [`super::auth`]**, whose module comment says
//! its two routes are the only unauthenticated surfaces this server has. This one
//! takes the same bearer credential every attested route takes and answers only
//! what that credential already proves: who its holder is. It names no other
//! account and reads nothing from the request that could name one.
//!
//! Its own file for the reason [`super::dispatch::routes`] gives: the route is
//! registered beside its handler so `observe-coverage` can see the `Call`.

use super::authority::*;
use super::dispatch::*;
use super::gate::*;
use super::*;

/// The bounded label (D67), and therefore also the throttle key: [`guard`]
/// keys its bucket on `(source address, endpoint)`, so whoami spends its own
/// budget and never login's.
const AUTH_WHOAMI: &str = "auth/whoami";

/// This module's routes. See [`super::dispatch::routes`] for why each set is
/// registered beside its own handlers.
pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET, because it reads and changes nothing, and ABOVE the body limit
        // layer like every other route — a GET carries no body worth reading,
        // and the layer bounds it anyway.
        .route("/auth/whoami", get(whoami).fallback(method_not_allowed))
}

/// The caller's own identity, from its credential (ADR-0959).
///
/// # The identity comes from the credential and from nothing else
///
/// [`attest::attest_admin`] is the attestation the `/admin` routes use: it
/// resolves the bearer token through `iam`, refuses a dead one, and — unlike
/// [`attest::attest`] — requires and checks no workspace, which whoami has no use
/// for. Its name says admin; nothing here reads `is_admin`, and the answer does
/// not carry it. Under the default `Iam` source, `x-yadgar-user` is ignored, so a
/// header naming another account moves nothing. The handler takes no query and no
/// body, so no parameter can name another user either.
///
/// # The refusal is the sibling's, byte for byte
///
/// A dead credential gets [`attested_refusal`], the one rendering `/admin`'s
/// attested branch uses. ADR-0959 requires the same refusal any attested route
/// gives, and a shared function is what keeps that true after an edit to either.
///
/// # `account_segment` is `null` for a non-canonical id
///
/// [`crate::project::account_segment`] answers `None` for an id not spelt as
/// `iam-db` mints it, because such an id names no account (ADR-0954). `iam` only
/// answers canonical ids, so this is reachable on the development
/// trusted-headers path alone. `null` says "no segment"; an empty string would
/// build `local//…`, and a hand-written prefix strip would invent a segment the
/// project check refuses.
pub(super) async fn whoami(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
) -> Response {
    // FIRST, as on every non-MCP route: the Origin check and a source-address
    // bucket, before `iam` is asked anything. `credential_limits` because this is
    // a credential surface: a token-validity answer is what a stranger holding a
    // pile of tokens would come here for, and the bucket bounds that the way it
    // bounds login. The label keeps the budget separate from login's.
    if let Some(refusal) = guard(&state, AUTH_WHOAMI, state.credential_limits, peer, &headers).await
    {
        return refusal;
    }
    let request_id = crate::request_id();
    // Started before attestation and carrying no identity, as on `/admin`:
    // nothing is attested yet, and a refused call must still be recorded.
    let call = Call::start(SERVICE, AUTH_WHOAMI, Kind::Read, tel(request_id.clone()));

    let attested = match attest::attest_admin(
        &state.attestation,
        &state.iam,
        &state.credentials,
        header(&headers, axum::http::header::AUTHORIZATION.as_str()),
        Claimed {
            // Read ONLY under `TrustedHeaders` (development). Under `Iam` the
            // token names the caller and this is ignored.
            user_id: header(&headers, "x-yadgar-user"),
            project_id: None,
            instance_id: header(&headers, "x-yadgar-instance"),
            access: crate::project::Access::Read,
        },
        request_id,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            // THE ONLY PLACE THE REAL REASON IS WRITTEN DOWN; the caller gets
            // the sibling's opaque answer.
            tracing::warn!(error = %e, endpoint = AUTH_WHOAMI, "whoami attestation failed");
            let refusal = attested_refusal(&e);
            call.fail(refusal.label);
            return refusal.response;
        }
    };

    let user_id = attested.scope.user_id;
    let rendered = json!({
        "account_segment": crate::project::account_segment(&user_id),
        "user_id": user_id,
    })
    .to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        // EMPTY PAYLOAD, as on `/admin`: the answer is the caller's id, which the
        // telemetry store does not need a second copy of.
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}
