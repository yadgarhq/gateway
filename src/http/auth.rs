//! `/auth/login` and `/auth/enrol`: the only unauthenticated surfaces this
//! server has (D75, D73).
//!
//! Split out of [`super`] for the file-size ceiling. They are together because
//! they are one class — a client with no credential getting one — and they are
//! bounded by one budget and answered by one rule.

use super::answer::*;
use super::dispatch::*;
use super::gate::*;
use super::*;

/// This module's routes. See [`super::dispatch::routes`] for why each set is
/// registered beside its own handlers.
pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // NOT MCP, and the one path on this server that is not (D75). `yaadgaar
        // login` has no credential yet, so it cannot speak the authenticated
        // protocol the rest of this router serves — the whole point of the
        // endpoint is to hand it the token every other call carries.
        //
        // BEFORE `.layer(...)`, and that is a security decision rather than
        // formatting. `Router::layer` applies only to routes registered above it,
        // so a route added after this line would be the one unauthenticated
        // endpoint on the server accepting a body of any size.
        .route("/auth/login", post(login).fallback(method_not_allowed))
        // The OTHER unauthenticated path (D73), and above the layer for exactly
        // the reason stated on the line above it. A person redeeming an enrolment
        // has no credential either — that is the whole point of the endpoint — so
        // it is reachable by anyone who can reach the port, and an unbounded body
        // on it would be the same defect twice.
        .route("/auth/enrol", post(enrol).fallback(method_not_allowed))
}

/// Username and password to a token (D72, D75).
///
/// The ONE endpoint on this server that takes no credential, because it is the
/// one that issues them: `yaadgaar login` has nothing to present yet. It is a
/// thin translation of `iam.Login` — the JSON field names are the proto's field
/// names, and what to make of `iam`'s answer is decided entirely by
/// [`login_failure`].
///
/// **Every answer derived from the UPSTREAM is built by [`login_failure`], from a
/// `tonic::Code` and nothing else.** A `Code` is a bare enum with no message
/// attached, so at the point that status, body and headers are chosen there is no
/// upstream text in scope that COULD be interpolated into them. An earlier version
/// of this comment claimed that property for the whole function and was wrong: the
/// failure arm below binds `e`, and the selection used to sit six lines under
/// `e.message()`. Moving the choice behind a function that cannot see `e` is what
/// makes the claim true, and [`login_failure`]'s test asserts it over every code
/// rather than over the one an unreachable upstream happens to produce.
///
/// So this function names no body and no header on any path that has spoken to
/// `iam`. It maps `e.code()` and logs `e`: the real code and message go to the
/// log, where an operator can read them and a caller cannot.
///
/// The THREE 400s below are the exception, and are not one in substance. They
/// are raised before the request is sent, so they describe THIS server's reading
/// of the caller's own JSON and can disclose nothing about a password nobody has
/// checked yet. In order: unparseable JSON, an absent `username` or `password`,
/// and a `label` past what the store will hold (see [`label_ok`]).
///
/// **THE THIRD ONE IS NEWER THAN THE OTHER TWO AND IT IS WHY THIS COUNT IS
/// SPELLED OUT.** This comment said "the two 400s" while there were three, which
/// is how an enumeration that reads as complete stops being one. The property is
/// what matters and it is unchanged: each of the three is REQUEST-ONLY —
/// answerable from the caller's own bytes, with no dependence on stored state —
/// which is precisely what makes a sharp status safe here and unsafe on anything
/// [`opaque_status`] sees. A check that needed to know whether a username exists
/// would belong on neither list.
///
/// `username` is deliberately NOT bounded, and neither is the length of
/// `password`: `iam` bounds neither on this path, and a refusal invented here
/// would be one no upstream has. See [`MAX_PASSWORD_BYTES`], which is the enrol
/// path's and not this one's.
pub(super) async fn login(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refusal) = guard(&state, AUTH_LOGIN, state.credential_limits, peer, &headers).await
    {
        return refusal;
    }
    // Started before the work, and NOT carrying an identity: nothing has been
    // attested on this path — the caller is proving who it is, which is the
    // request rather than a fact about it. Putting the submitted username in the
    // scope would write an unverified claim, and a wrong password's username, to
    // the telemetry store.
    let call = Call::start(SERVICE, AUTH_LOGIN, Kind::Write, tel(crate::request_id()));

    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        call.fail("INVALID_ARGUMENT");
        return text(StatusCode::BAD_REQUEST, r#"{"error":"invalid JSON"}"#);
    };
    let (Some(username), Some(password)) = (
        req.get("username").and_then(Value::as_str),
        req.get("password").and_then(Value::as_str),
    ) else {
        call.fail("INVALID_ARGUMENT");
        return text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`username` and `password` are required"}"#,
        );
    };
    // REQUEST-ONLY, AND THAT WORD IS DOING ALL THE WORK. See [`label_ok`].
    // `username` is NOT checked here: `iam` blind-indexes it to a fixed-width
    // HMAC and states no bound, so a refusal here would be one no upstream has —
    // and a length-keyed 400 on this path is an account-enumeration oracle the
    // moment it correlates with anything about who exists.
    if let Some(refusal) = label_ok(&req) {
        call.fail("INVALID_ARGUMENT");
        return refusal;
    }

    let mut client = IamServiceClient::new(state.iam.clone());
    let rpc = client.login(LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
        // OPTIONAL here, though `yaadgaar` always sends it. It only names the
        // machine so a person can tell their credentials apart when revoking
        // one; refusing a request for want of it would add a rule the
        // contract does not have.
        label: req
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    });
    // A DEADLINE, because this is the first surface reachable with no credential.
    // An `iam` that accepts the connection and then stalls would otherwise hold
    // the request — and the connection under it — open for as long as it liked,
    // and an unauthenticated caller could open as many as it wanted. `task`'s
    // path has no deadline either and that is not made worse here; this one is
    // added because the caller does not have to be anyone to reach it.
    //
    // Generous rather than tight: Argon2id verification is deliberately expensive
    // (~50ms in `iam`, and it runs even for an unknown username), so a budget
    // sized for a healthy RPC would turn load into refusals.
    let resp = match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => {
            // THE ONLY PLACE THE REAL CODE IS WRITTEN DOWN, and it goes to the
            // log rather than to the caller. Without this an operator watching a
            // login outage sees an opaque 503 and no reason for it.
            tracing::warn!(code = ?e.code(), message = e.message(), "login refused or failed");
            call.fail(if e.code() == tonic::Code::Unauthenticated {
                "UNAUTHENTICATED"
            } else {
                "UNAVAILABLE"
            });
            // `e.code()`, never `e`. See this function's doc comment.
            return login_failure(e.code());
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_ms = AUTH_DEADLINE.as_millis(),
                "login timed out waiting for iam"
            );
            call.fail("UNAVAILABLE");
            // Through the SAME builder as every other failure, so a stall is
            // indistinguishable from the codes it is collapsed with rather than
            // being a third answer somebody has to remember to keep opaque.
            return login_failure(tonic::Code::DeadlineExceeded);
        }
    };

    // ONLY `token`. `LoginResponse.credential_id` is dropped: the client's
    // `LoginResponse` has one field, and a value nothing reads is a value that
    // only widens what a successful response discloses.
    let rendered = json!({ "token": resp.token }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        // DELIBERATELY EMPTY, unlike every other record in this file. `payload`
        // is stored in the wide event, and the payload here is a bearer token
        // shown exactly once — copying the idiom from `measured` would write
        // every credential this system issues into the telemetry store. The byte
        // count above is the part that answers D67's question.
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}

/// An enrolment secret and a chosen password to a token (D72, D73).
///
/// The SECOND endpoint on this server that takes no credential, and it is the one
/// a person reaches before they have an account they can log in to: an admin
/// creates the account and hands over an enrolment token, and the person chooses
/// their own password here. The admin never learns it.
///
/// A thin translation of `iam.RedeemEnrolment`, built on the same three rules as
/// [`login`] — the JSON field names are the proto's, the body is hand-parsed, and
/// **every answer derived from the UPSTREAM is built by [`enrol_failure`] from a
/// `tonic::Code` and nothing else**, so no upstream text is in scope where the
/// status and body are chosen.
///
/// **ONE FAILURE, NOT THREE, and the contract says so in those words.** The RPC is
/// "UNAUTHENTICATED BY CONSTRUCTION — the secret is all the caller has", and it
/// requires that an unknown secret, a spent one and an expired one are one
/// indistinguishable answer: "the server tells them apart and records which; the
/// caller cannot". The gateway must not undo that by giving one of them a status
/// of its own.
///
/// **`INVALID_ARGUMENT` IS COLLAPSED WITH THE REST, and it is the case worth
/// stating.** It looks like the one code that is safe to pass through, because the
/// contract runs VALIDATION BEFORE LOOKUP so that a password-policy refusal
/// arrives without the secret having been checked. But it is ALSO what the RPC
/// answers when an idempotency key is replayed with a different password — and
/// that check runs only after the store has confirmed the secret was good. Two
/// sides of the lookup, one code, nothing in the code to tell them apart: exactly
/// the property that makes `login`'s codes uncollapsible, in the same shape. So
/// the caller is told what was wrong with ITS OWN fields (the 400s below, raised
/// before anything is sent) and nothing about what `iam` made of them.
///
/// **"ABSENT" USED TO BE THE WHOLE OF THAT SENTENCE AND IS NO LONGER.** The 400s
/// below are five: unparseable JSON, an absent `secret` or `password`, an EMPTY
/// `password`, a `password` past [`MAX_PASSWORD_BYTES`], and a `label` past what
/// the store will hold (see [`label_ok`]). The last three are bounds rather than
/// presence checks, and every one of the five is REQUEST-ONLY — answerable from
/// the caller's own bytes with no dependence on stored state — which is the
/// property that makes a sharp status safe before the call and unsafe after it.
///
/// **`secret` IS ON NEITHER LIST BEYOND ITS PRESENCE, AND THAT IS THE CASE THAT
/// DEFINES THE LINE.** A length or charset bound on it WOULD be request-only, so
/// request-only is necessary and not sufficient: ONE FAILURE, NOT THREE means a
/// caller holding a real secret that failed a shape check would meet a 400 where
/// the contract promises a 401, and the two statuses are the oracle. `iam`
/// refuses to check it for the same reason and says so in those words.
///
/// The `label` is optional here for the same reason it is on `login`, and
/// `credential_id` is dropped for the same reason too. `username` is NOT dropped:
/// the contract returns it because a person enrolling on their first machine
/// otherwise has to be told their username separately — "a second artefact to
/// lose, which is the exact failure the token's design exists to remove".
/// What `/auth/enrol`'s body must carry before `iam` is asked.
///
/// Every refusal here is an `INVALID_ARGUMENT`, so the telemetry stays with
/// the caller and is written ONCE rather than beside each of the four. The
/// checks themselves are unchanged and are applied in the order they were.
fn enrolment_fields(req: &Value) -> Result<(&str, &str), Box<Response>> {
    let (Some(secret), Some(password)) = (
        req.get("secret").and_then(Value::as_str),
        req.get("password").and_then(Value::as_str),
    ) else {
        return Err(Box::new(text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`secret` and `password` are required"}"#,
        )));
    };
    // THE PASSWORD IS BOUNDED HERE AND NOT ON `login`, because `iam` bounds it
    // here and not there. See [`MAX_PASSWORD_BYTES`].
    //
    // **`secret` IS NOT CHECKED, AND IT IS THE CASE THAT DEFINES THE LINE.** A
    // length or a charset bound on it would be answerable from the request alone
    // — it passes the same test everything on this list passes — and `iam`
    // refuses to check it anyway, because ONE FAILURE, NOT THREE means an unknown
    // secret, a spent one and an expired one must be one answer. A caller holding
    // a REAL secret that failed a shape check would get a 400 where the contract
    // promises a 401, and the two statuses are the oracle. Request-only is
    // NECESSARY and not SUFFICIENT.
    if password.is_empty() {
        return Err(Box::new(text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"a `password` is required"}"#,
        )));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Box::new(text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"the `password` is longer than this service will hash: at most 1024 bytes"}"#,
        )));
    }
    if let Some(refusal) = label_ok(req) {
        return Err(Box::new(refusal));
    }
    Ok((secret, password))
}

pub(super) async fn enrol(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // THE SAME GUARD AS `login`, and for a stronger reason than symmetry: this
    // path pays TWO Argon2id operations per attempt rather than one — the
    // contract requires the refusal to cost what the success costs — so it is the
    // cheaper of the two surfaces to amplify with.
    if let Some(refusal) = guard(&state, AUTH_ENROL, state.credential_limits, peer, &headers).await
    {
        return refusal;
    }
    // NOT carrying an identity, for the same reason `login`'s does not: nothing
    // has been attested, and the person does not have a user id yet at all.
    let call = Call::start(SERVICE, AUTH_ENROL, Kind::Write, tel(crate::request_id()));

    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        call.fail("INVALID_ARGUMENT");
        return text(StatusCode::BAD_REQUEST, r#"{"error":"invalid JSON"}"#);
    };
    let (secret, password) = match enrolment_fields(&req) {
        Ok(pair) => pair,
        Err(refusal) => {
            call.fail("INVALID_ARGUMENT");
            return *refusal;
        }
    };

    let mut client = IamServiceClient::new(state.iam.clone());
    let rpc = client.redeem_enrolment(RedeemEnrolmentRequest {
        secret: secret.to_string(),
        password: password.to_string(),
        // OPTIONAL, exactly as on `login`: it only names the machine so a person
        // can tell their credentials apart when revoking one.
        label: req
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // MINTED HERE, PER INBOUND REQUEST, and that buys less than the field's
        // name suggests. It makes THIS gateway's own retry to `iam` safe, which is
        // what `crate::idempotency_key` documents and all it claims. It does NOT
        // cover a CLIENT's retry: a client that POSTs here twice is two inbound
        // requests and two keys, so the second presents a SPENT secret and is
        // refused. Covering that needs a key the client supplies and keeps stable
        // across its own retries, and the request shape has no place for one.
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
    });
    // A DEADLINE, for the reason on `login`'s: this is reachable with no
    // credential, so a stalled `iam` would otherwise let an unauthenticated caller
    // hold as many requests open as it liked.
    let resp = match tokio::time::timeout(AUTH_DEADLINE, rpc).await {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => {
            // THE ONLY PLACE THE REAL CODE IS WRITTEN DOWN, and it goes to the
            // log. Without it, an operator watching an enrolment fail sees an
            // opaque status and no reason for it — and here the reason matters
            // more than usual, because the person on the other end has one
            // enrolment token and no way to diagnose it themselves.
            tracing::warn!(code = ?e.code(), message = e.message(), "enrolment refused or failed");
            call.fail(if e.code() == tonic::Code::Unauthenticated {
                "UNAUTHENTICATED"
            } else {
                "UNAVAILABLE"
            });
            return enrol_failure(e.code());
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_ms = AUTH_DEADLINE.as_millis(),
                "enrolment timed out waiting for iam"
            );
            call.fail("UNAVAILABLE");
            // Through the SAME builder as every other failure, so a stall is not a
            // third answer somebody has to remember to keep opaque.
            return enrol_failure(tonic::Code::DeadlineExceeded);
        }
    };

    let rendered = json!({ "token": resp.token, "username": resp.username }).to_string();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        // DELIBERATELY EMPTY, exactly as on `login` and unlike `measured` and
        // `tools_call`. `payload` is stored in the wide event, and this payload is
        // a bearer token shown once — copying the idiom from those two would write
        // every credential this system issues into the telemetry store.
        rows: 1,
        ..Default::default()
    });
    text(StatusCode::OK, &rendered)
}
