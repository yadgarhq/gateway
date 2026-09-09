//! The checks every request passes before a handler sees it, and the helpers
//! that answer when one refuses.
//!
//! Split out of [`super`] for the file-size ceiling. Origin, body shape, label
//! length and D74's token bucket, in the order [`guard`] applies them — which is
//! the order an operator sees a broken request refused in, and is not changed
//! here.

use super::call::*;
use super::dispatch::*;
use super::*;

/// Parse one administrative body. `None` is unparseable JSON.
pub(super) fn parsed(body: &Bytes) -> Option<Value> {
    serde_json::from_slice::<Value>(body).ok()
}

/// A JSON response whose body is already rendered.
///
/// Separate from [`reply`], which takes a `Value` and a bare `u16`: rendering
/// through a `Value` would put a `format!` on the login path, where the next
/// person would reasonably add an interpolation. It sets the content type and no
/// other header, and every login response is built through it — so "no
/// `WWW-Authenticate`" is checkable in one place, for whatever a layer may add
/// afterwards (`no_layer_adds_an_authentication_challenge` covers that half).
pub(super) fn text(status: StatusCode, body: &str) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// The ONE request-only check `/auth/login` and `/auth/enrol` share: the `label`.
///
/// # THE RULE THIS FUNCTION EXISTS TO KEEP (task 624)
///
/// [`opaque_status`] collapses every non-`UNAUTHENTICATED` code `iam` returns
/// into one 503, and it must keep doing so — the argument is written out on that
/// function and it is that a code coming BACK cannot be told apart by which side
/// of a lookup produced it. The cost is that a caller who sent a malformed
/// request is told the service is unavailable.
///
/// **THE DISTINCTION THAT MAKES A 400 BUILDABLE IS REQUEST-ONLY.** A field this
/// server can judge from the request ALONE — a length, a charset, a missing
/// field, unparseable JSON — leaks nothing, because the answer does not depend on
/// any stored state. Refusing a 300-character label tells an attacker nothing
/// about who exists. Refusing because a lookup missed does. So the shape is
/// judged HERE, before anything is sent, and everything that comes back from
/// `iam` keeps collapsing.
///
/// **AND REQUEST-ONLY IS NECESSARY, NOT SUFFICIENT.** The enrolment `secret` is
/// judgeable from the request alone and is deliberately never judged: its
/// contract requires ONE FAILURE, NOT THREE, so a 400 where the contract promises
/// a 401 would be the oracle. The second test a check must pass is that the field
/// is not one whose contract mandates a single answer.
///
/// # Why this runs before the call and not after
///
/// `iam::login_inner` places its own copy of this check INSIDE the function that
/// pays the response-time floor, deliberately, "so a refusal placed above the
/// call would be the fast path the floor exists to close". A refusal here IS
/// faster than the floor, and that is safe for the same reason the 400 is safe:
/// the floor equalises answers that depend on STORED STATE, and this one is
/// computed entirely from the caller's own bytes. There is nothing for it to be
/// equalised against — the caller can compute the same answer without asking.
///
/// # Absent is not the same as too long
///
/// An ABSENT label is legal and stays legal on both paths: the proto requires
/// nothing of the field, and `iam` accepts an empty one explicitly. This is a
/// BOUND, not a requirement.
pub(super) fn label_ok(req: &Value) -> Option<Response> {
    let label = req.get("label").and_then(Value::as_str)?;
    // CHARACTERS, counted as `char`s, which is the column's own unit — utf8mb4
    // stores one per Unicode scalar value, so the two counts agree exactly. Bytes
    // would refuse a 100-character emoji label the store holds without complaint.
    (label.chars().count() > MAX_LABEL_CHARS).then(|| {
        text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"the `label` is longer than the store will hold: at most 255 characters"}"#,
        )
    })
}

/// Reject a browser origin we do not know.
///
/// The spec: "Servers MUST validate the `Origin` header on all incoming
/// connections to prevent DNS rebinding attacks. If the `Origin` header is
/// present and invalid, servers MUST respond with HTTP 403 Forbidden."
///
/// **This is not authentication and must not be mistaken for it.** It stops a web
/// page in a browser from driving this server; it stops nothing that sets its own
/// headers. Absence is allowed because a non-browser client sends no Origin —
/// which is exactly why it cannot substitute for attestation.
pub(super) fn origin_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(axum::http::header::ORIGIN) else {
        // Absent, and allowed: a non-browser client sends no Origin — which is
        // exactly why this cannot substitute for attestation.
        return true;
    };
    // PRESENT AND UNPARSEABLE IS PRESENT AND INVALID, and the spec's MUST covers
    // it: "If the Origin header is present and invalid, servers MUST respond with
    // HTTP 403 Forbidden."
    //
    // This used to be `.and_then(|v| v.to_str().ok())`, which collapsed a header
    // of non-ASCII bytes into `None` and took the absent arm — so the one Origin
    // that could not be checked was the one that was waved through.
    let Ok(origin) = raw.to_str() else {
        return false;
    };
    // An EMPTY allowlist denies every origin. `is_empty() || any()` is the
    // plausible-looking "fix" that would accept every origin in the default
    // configuration, and it would pass a suite that only tested a populated list.
    state.allowed_origins.iter().any(|a| a == origin)
}

/// What every non-MCP endpoint passes before it reads a body (task 497).
///
/// `Some` is a response the caller must be sent; `None` means carry on.
///
/// **FIVE CALLERS NOW AND THIS COMMENT USED TO SAY TWO**, which is how an
/// enumeration that reads as complete stops being one — the failure `login`'s
/// "the two 400s" already cost this file once. `/auth/login` and `/auth/enrol`
/// are the two UNAUTHENTICATED ones; `/admin/create-user`,
/// `/admin/issue-enrolment` and `/admin/set-user-admin` are the three
/// administrative ones, and they call it for a reason that is not symmetry.
/// `origin_ok` lives here rather than in a layer, so an `/admin` route that
/// skipped this would have no `Origin` check and no throttle — reproducing the
/// bug this function was written to fix, on the surface where a cross-origin POST
/// buys an administrator. The `limits` parameter is why the three do not thereby
/// share login's budget.
///
/// # Everything decided here is decided WITHOUT the body, and that is the point
///
/// **The response-time floor in `iam` must survive this, and it does.** `iam`
/// holds `Login` and `RedeemEnrolment` to `LOGIN_RESPONSE_FLOOR_MS` and
/// `REDEEM_RESPONSE_FLOOR_MS` so a failure and a success take the same time. A
/// gateway refusal that returned EARLY would reintroduce exactly the timing
/// oracle that floor removes — IF what it varied with were a credential.
///
/// It is not, and the ordering is what makes that structural rather than argued.
/// This runs before `serde_json::from_slice`, so where the decision is made the
/// username and the password are still unparsed bytes: there is no credential in
/// scope that the outcome COULD depend on. That is why this is a function called
/// first rather than a check folded into the handler once the fields are read —
/// the property survives a later rewrite of either handler, because a rewrite
/// would have to move this call to break it.
///
/// So a throttled request is fast, a real attempt is floored, and the difference
/// between them names an ADDRESS's budget rather than an account's existence. An
/// attacker who learns they are throttled learns only what they already knew.
///
/// **A per-username lockout would NOT have this property**, which is one of the
/// two reasons there is not one here: its answer is a function of the username,
/// so returning early on a locked account tells a stranger which usernames exist
/// — the oracle the floor exists to close, reopened one layer up. Any lockout has
/// to be paid BEHIND the floor, inside `iam`.
pub(super) async fn guard(
    state: &AppState,
    endpoint: &'static str,
    limits: CredentialLimits,
    peer: Option<IpAddr>,
    headers: &HeaderMap,
) -> Option<Response> {
    // FIRST, because it is a header comparison and the throttle is a round trip
    // to the shared cache — and because it is the check that closes the cheapest
    // way to get address diversity.
    //
    // **THIS ROUTE DID NOT RUN IT, AND THAT MATTERED MORE THAN IT LOOKED.**
    // `origin_ok` lives inside `handle`, not in a layer, so `/auth/login` and
    // `/auth/enrol` never inherited it. The omission was justified with "yaadgaar
    // is not a browser", which answers the wrong threat: the page driving the
    // browser is the ATTACKER's, not the client's. `axum-core`'s
    // `impl FromRequest for Bytes` performs no `Content-Type` check, so a
    // cross-origin CORS SIMPLE request carrying `text/plain` and a JSON body is
    // delivered and processed with no preflight. The attacker cannot read the
    // response — no CORS headers come back — but the RPC fires and `iam` spends a
    // full Argon2id verification.
    //
    // **It is the throttle below that this actually protects.** What the browser
    // vector buys an attacker is not volume, which curl gives them anyway; it is
    // SOURCE-ADDRESS DIVERSITY — every visitor to their page becomes a distinct
    // address, and a limiter keyed on an address is defeated by a mechanism that
    // costs them nothing. Closing the browser path is what lets the bucket below
    // be worth having.
    //
    // Legitimate clients pay nothing: a non-browser client sends no `Origin`, and
    // `origin_ok` allows an absent one.
    if !origin_ok(state, headers) {
        // `PERMISSION_DENIED`, NOT `FORBIDDEN`, and the difference is the label
        // space rather than the wording. `yadgar_calls_total` carries ONE
        // `outcome` label and this binary writes into it from two seams;
        // `yadgar_telemetry::grpc::status_name` is the one place a status
        // becomes that label, and no arm of it produces `FORBIDDEN`. So the
        // literal that used to be here widened the set an operator has to know
        // by one value that exists nowhere else in the estate — while every
        // other literal on this path already spells a name that mapping returns.
        // ADR-0556 cites this exact value as the reason its KEDA query counts
        // `OK` as a closed POSITIVE set rather than excluding a list of
        // failures.
        //
        // The HTTP status stays 403. `PermissionDenied` is the gRPC code for a
        // caller refused on identity rather than on credentials, which is what
        // an unlisted `Origin` is, and it is what this refusal would report if
        // it were an RPC.
        Call::start(SERVICE, endpoint, Kind::Write, tel(crate::request_id()))
            .fail("PERMISSION_DENIED");
        return Some(text(
            StatusCode::FORBIDDEN,
            r#"{"error":"origin not allowed"}"#,
        ));
    }

    let source = Source::resolve(state.trust, peer, headers);
    // NO ADDRESS AT ALL, so there is no key and nothing to spend. In this binary
    // that is reachable only where the server was not wired with `ConnectInfo` —
    // a test driving `router` directly — because `main` always wires it. It is
    // `None` rather than a refusal so the absence stays visible as absence: an
    // address this process never had is not a caller's doing.
    let addr = source.key()?;
    let bucket = match source {
        // See `CredentialLimits`: which of the two applies is decided by whether
        // the address names a client or the hop in front of everybody.
        //
        // WHICH PAIR is the caller's, not this function's: `/auth/*` passes
        // `state.credential_limits` and `/admin/*` passes `state.admin_limits`.
        // A pair read from `state` here would have made the admin surface share
        // login's budget silently, which is §3.2's named defect.
        Source::Attributed(_) => limits.attributed,
        Source::Observed(_) | Source::Unknown => limits.unattributed,
    };

    match state.limiter.check_source(addr, endpoint, bucket).await {
        Decision::Allowed => None,
        Decision::Throttled { retry_after } => Some(too_many(endpoint, retry_after)),
        Decision::Degraded(why) => {
            degraded(endpoint, AUTH_MODULE, why, "allowed");
            None
        }
        Decision::DegradedThrottled {
            reason,
            retry_after,
        } => {
            degraded(endpoint, AUTH_MODULE, reason, "throttled");
            Some(too_many(endpoint, retry_after))
        }
        // A 503 AND NOT A 429, for `throttled`'s reason: nothing the caller does
        // changes it. The message says nothing an unauthenticated stranger could
        // use — the operator-facing detail is in the counter and the log line
        // `degraded` writes.
        Decision::Unauthenticated => {
            degraded(
                endpoint,
                AUTH_MODULE,
                crate::limit::Degrade::Unauthenticated,
                "refused",
            );
            Call::start(SERVICE, endpoint, Kind::Write, tel(crate::request_id())).fail("INTERNAL");
            Some(text(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"login is unavailable"}"#,
            ))
        }
    }
}

/// The 429 every endpoint behind [`guard`] answers with.
///
/// **FIVE, NOT TWO** — the two credential endpoints and the three administrative
/// ones. See [`guard`] for why the count is spelled out rather than left as
/// "both".
///
/// **OPAQUE, and deliberately more so than [`refusal`].** That one names the
/// module and the kind because it answers an ATTESTED caller who is entitled to
/// know which of their own budgets is empty. This one answers a stranger: naming
/// the address, the bucket or which endpoint's budget ran out would tell them
/// how the limiter is keyed, which is the first thing anyone trying to evade it
/// wants. The `Retry-After` is the whole of the useful content.
pub(super) fn too_many(endpoint: &'static str, retry_after: std::time::Duration) -> Response {
    // A throttled call is a call, for the reason `tools_call` gives: without a
    // record a throttling storm is indistinguishable from silence. NO ADDRESS
    // rides on it — ADR-0491 puts a source address in the audit store and only
    // there, and this is the telemetry store.
    Call::start(SERVICE, endpoint, Kind::Write, tel(crate::request_id()))
        .fail("RESOURCE_EXHAUSTED");
    // WHOLE SECONDS (RFC 9110) and never zero, for `refusal`'s reason: `0` reads
    // as "retry immediately", which is the herd this exists to avoid.
    let seconds = retry_after.as_secs_f64().ceil().max(1.0) as u64;
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (
                axum::http::header::RETRY_AFTER,
                seconds.to_string().as_str(),
            ),
        ],
        r#"{"error":"too many attempts"}"#.to_string(),
    )
        .into_response()
}

/// A header as text, with ABSENT AND UNREADABLE COLLAPSED INTO ONE ANSWER.
///
/// That collapse is safe ONLY where absence and an undecodable value deserve the
/// same treatment, which is true of the CLAIMED values this is left serving: a
/// `x-yadgar-project` nobody can read is a project nobody claimed, and an
/// unreadable `Authorization` is a credential that will fail attestation either
/// way. It is NOT true of anything being VALIDATED — see [`readable`], and the
/// bug it exists to close.
pub(super) fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// The same lookup, keeping PRESENT-BUT-UNREADABLE apart from ABSENT.
///
/// `Ok(None)` is absent, `Ok(Some(_))` is a value, and `Err(name)` is a header
/// the caller sent that this server cannot decode.
///
/// **PRESENT AND UN-DECODABLE IS PRESENT AND INVALID.** `HeaderValue::is_valid`
/// is `b >= 32 && b != 127 || b == b'\t'`, so every byte of a UTF-8 multibyte
/// sequence is at least 0x80 and passes — the value travels as obs-text and
/// arrives whole. `\r`, `\n`, `\0` and `\x7F` are refused outright, so nothing
/// here is request splitting. What it is, is a header that reached the server
/// intact and could not be read.
///
/// [`header`] answers `None` for that, and `None` at the cross-check means THERE
/// IS NOTHING TO COMPARE — so the one `Mcp-Method` or `Mcp-Name` that could not
/// be checked was the one waved through, and a validation that does not validate
/// is worse than none, because the record says the request was policed. This is
/// the identical bug [`origin_ok`] carried until it was fixed, in the identical
/// shape; it became reachable on this path when clients started sending the two
/// mirror headers.
pub(super) fn readable<'a>(h: &'a HeaderMap, name: &'a str) -> Result<Option<&'a str>, &'a str> {
    match h.get(name) {
        None => Ok(None),
        Some(v) => v.to_str().map(Some).map_err(|_| name),
    }
}
