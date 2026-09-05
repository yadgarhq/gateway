//! The HTTP surface: POST only, stateless.
//!
//! THREE paths, and the asymmetry is the thing to know. `/` is MCP and every call
//! through it carries a credential the gateway resolves against `iam`.
//! `/auth/login` and `/auth/enrol` are not MCP and carry none — they are where a
//! client with no credential gets one (D75, D73), so they are the only
//! unauthenticated surfaces this server has.
//!
//! **All three answer an upstream refusal by ONE rule** (ADR-0507, superseding
//! ADR-0506): `UNAUTHENTICATED` is 401, and every other gRPC code is one opaque
//! status indistinguishable from the rest. [`opaque_status`] IS that rule, in one
//! function, because it is the security property rather than a mapping table.

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde_json::{json, Value};
use tonic::transport::Channel;
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::attest::{self, Attestation, Claimed, Credentials};
use crate::limit::{Bucket, Decision, Limiter};
use crate::mcp::{self, codes, headers, meta_keys};
use crate::pb::yadgar::common::v1::Idempotency;
use crate::pb::yadgar::iam::v1::{
    iam_service_client::IamServiceClient, LoginRequest, RedeemEnrolmentRequest,
};
use crate::source::{PeerAddr, Source, TrustBoundary};
use crate::tools;

const SERVICE: &str = "gateway";

/// The bounded labels for the two methods that are not `tools/call`.
///
/// `&'static str` and a closed set, for the same reason `tools::label_for`
/// exists: a metric label must come from a fixed range (D67).
const DISCOVER: &str = "server/discover";
const TOOLS_LIST: &str = "tools/list";
/// The two credential endpoints' labels. PATHS rather than MCP methods, because
/// that is what they are — but bounded and `&'static` for the same D67 reason as
/// the two above.
const AUTH_LOGIN: &str = "auth/login";
const AUTH_ENROL: &str = "auth/enrol";
/// The `module` dimension the credential endpoints report under.
///
/// A FOURTH VALUE in an existing closed set rather than a new series: `degraded`
/// is already labelled `(service, tool, reason, outcome)` plus a module, and these
/// two paths degrade for exactly the reasons a `tools/call` does. One value for
/// both, because the operator's question — "is the cache answering?" — is the
/// same for both and splitting it would halve every count.
const AUTH_MODULE: &str = "auth";

/// How long an unauthenticated request waits on `iam` before being answered
/// without it.
///
/// A CONSTANT rather than a setting: it bounds a request from a caller who does
/// not have to be anyone, and a bound an operator can raise is one an operator can
/// raise to something useless. Sized well above a healthy call — `iam` spends
/// ~50ms on Argon2id for every attempt, including one for a username it has never
/// seen, and `RedeemEnrolment` is required to pay the same cost for a secret it
/// has never seen — so this fires on a stall rather than on load.
///
/// ONE constant for both paths, not two: they bound the same class of request for
/// the same reason, and two numbers would be two things to keep in agreement.
/// `attest`'s lookup has its OWN, much shorter, because that one sits on the hot
/// path of every call rather than on a person typing a password.
const AUTH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

pub struct AppState {
    pub attestation: Attestation,
    pub task: Channel,
    /// The `iam` logic service. ONE channel, and it now carries both halves of
    /// the credential lifecycle: `/auth/login` and `/auth/enrol` ISSUE a token
    /// through it, and `attest` RESOLVES one through it on every `tools/call`.
    ///
    /// It used to issue and nothing more, with identity coming from headers the
    /// caller wrote. A second channel for the resolving half would have been a
    /// second address for one service, which is the confusion the deleted
    /// `YADGAR_IAM_ADDR` was.
    pub iam: Channel,
    /// What `iam` last said about each token this replica has seen (D72,
    /// ADR-0491). Held here for the same reason the limiter is: it is process
    /// state, and one built per request would cache nothing.
    pub credentials: Credentials,
    /// D74's token buckets, in the shared cache. Held here rather than built per
    /// request so one connection manager serves the whole process.
    pub limiter: Limiter,
    /// Origins permitted to reach this server from a browser. Empty means no
    /// browser origin is accepted at all, which is the correct default for a
    /// server whose clients are agents.
    pub allowed_origins: Vec<String>,
    /// How many proxies stand in front, as this deployment declares it (D80,
    /// ADR-0491). `Undeclared` is the default and it REFUSES — see
    /// [`crate::source`].
    pub trust: TrustBoundary,
    /// What bounds the two unauthenticated endpoints (task 497). See
    /// [`CredentialLimits`].
    pub credential_limits: CredentialLimits,
}

/// The two buckets that bound `/auth/login` and `/auth/enrol` (task 497).
///
/// # Why TWO numbers rather than one
///
/// The bucket is keyed on a source address, and how much that address is WORTH
/// depends on whether this deployment can attribute it. Those are two different
/// controls wearing one mechanism, and giving them one rate makes whichever
/// deployment you did not think about wrong:
///
/// - **Attributed** — the trust boundary is declared and was met, so the key
///   names one client. The bucket's job is GUESS PREVENTION, and it is sized
///   for a person typing a password: a handful at once and then slowly.
/// - **Unattributed** — the boundary is undeclared, or a request did not arrive
///   through the declared chain, so the key names the nearest hop this process
///   saw. Behind an ingress that is ONE address for every caller in the
///   installation. A guess-prevention rate here would let one attacker at that
///   rate refuse every login for everybody — a limiter that is itself the
///   outage. So this bucket's job is the OTHER half of 497: bounding the
///   Argon2id CPU an unauthenticated stranger can spend, which `iam` pays per
///   attempt whether or not the username exists. It is sized against a core, not
///   against a guesser.
///
/// **Guess prevention arrives when the operator declares the boundary**, and that
/// is the honest statement of what an undeclared deployment gets. It is not a
/// weaker version of the same control; it is the other control. Saying so here
/// rather than letting a reader infer it from two numbers is the point of this
/// type existing at all.
#[derive(Debug, Clone, Copy)]
pub struct CredentialLimits {
    /// Per attributable CLIENT address.
    pub attributed: Bucket,
    /// Per OBSERVED hop, which behind a proxy is shared by everyone.
    pub unattributed: Bucket,
}

impl CredentialLimits {
    /// The shipped default for [`Self::attributed`].
    ///
    /// Sized for a person typing a password: ten at once, then one every five
    /// seconds. Nobody types faster; a guesser is held to roughly 17,000 attempts
    /// a day from one address, each against an Argon2id hash.
    ///
    /// **A CONSTANT RATHER THAN A LITERAL IN `main`, so a test can reach it.** A
    /// shipped default that fails `Bucket::parse` is a pod that exits at boot for
    /// a value nobody chose — the exact failure this whole configuration story
    /// exists to prevent, in the one place no test would otherwise look, because
    /// `cargo test` never calls `main`.
    pub const DEFAULT_ATTRIBUTED: &'static str = "0.2:10";

    /// The shipped default for [`Self::unattributed`], reachable for
    /// [`Self::DEFAULT_ATTRIBUTED`]'s reason.
    ///
    /// Sized against a core rather than against a guesser — see this type's own
    /// comment. `iam` spends ~50ms on Argon2id per attempt, so 10/s is about half
    /// a core's worth of hashing.
    pub const DEFAULT_UNATTRIBUTED: &'static str = "10:100";
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // MCP is ONE endpoint, POST only.
        //
        // GET and DELETE return 405. The spec frames that as a SHOULD, under
        // backward compatibility with the revisions that had a GET/SSE stream —
        // it is not a blanket MUST, and this comment says so because the first
        // reading of the spec recorded it as one. The effect is the same: there
        // is no GET stream in this revision, so there is nothing for a GET to do.
        .route("/", post(handle).fallback(method_not_allowed))
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
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state)
}

async fn method_not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, "MCP uses POST").into_response()
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
/// The two 400s below are the exception, and are not one in substance. They are
/// raised before the request is sent, so they describe THIS server's reading of
/// the caller's own JSON and can disclose nothing about a password nobody has
/// checked yet.
async fn login(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refusal) = guard(&state, AUTH_LOGIN, peer, &headers).await {
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
/// the caller is told which of ITS OWN fields was absent (the 400s below, raised
/// before anything is sent) and nothing about what `iam` made of them.
///
/// The `label` is optional here for the same reason it is on `login`, and
/// `credential_id` is dropped for the same reason too. `username` is NOT dropped:
/// the contract returns it because a person enrolling on their first machine
/// otherwise has to be told their username separately — "a second artefact to
/// lose, which is the exact failure the token's design exists to remove".
async fn enrol(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // THE SAME GUARD AS `login`, and for a stronger reason than symmetry: this
    // path pays TWO Argon2id operations per attempt rather than one — the
    // contract requires the refusal to cost what the success costs — so it is the
    // cheaper of the two surfaces to amplify with.
    if let Some(refusal) = guard(&state, AUTH_ENROL, peer, &headers).await {
        return refusal;
    }
    // NOT carrying an identity, for the same reason `login`'s does not: nothing
    // has been attested, and the person does not have a user id yet at all.
    let call = Call::start(SERVICE, AUTH_ENROL, Kind::Write, tel(crate::request_id()));

    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        call.fail("INVALID_ARGUMENT");
        return text(StatusCode::BAD_REQUEST, r#"{"error":"invalid JSON"}"#);
    };
    let (Some(secret), Some(password)) = (
        req.get("secret").and_then(Value::as_str),
        req.get("password").and_then(Value::as_str),
    ) else {
        call.fail("INVALID_ARGUMENT");
        return text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"`secret` and `password` are required"}"#,
        );
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

/// A JSON response whose body is already rendered.
///
/// Separate from [`reply`], which takes a `Value` and a bare `u16`: rendering
/// through a `Value` would put a `format!` on the login path, where the next
/// person would reasonably add an interpolation. It sets the content type and no
/// other header, and every login response is built through it — so "no
/// `WWW-Authenticate`" is checkable in one place, for whatever a layer may add
/// afterwards (`no_layer_adds_an_authentication_challenge` covers that half).
fn text(status: StatusCode, body: &str) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
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
fn origin_ok(state: &AppState, headers: &HeaderMap) -> bool {
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

/// What both unauthenticated endpoints pass before they read a body (task 497).
///
/// `Some` is a response the caller must be sent; `None` means carry on.
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
async fn guard(
    state: &AppState,
    endpoint: &'static str,
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
        Source::Attributed(_) => state.credential_limits.attributed,
        Source::Observed(_) | Source::Unknown => state.credential_limits.unattributed,
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

/// The 429 both credential endpoints answer with.
///
/// **OPAQUE, and deliberately more so than [`refusal`].** That one names the
/// module and the kind because it answers an ATTESTED caller who is entitled to
/// know which of their own budgets is empty. This one answers a stranger: naming
/// the address, the bucket or which endpoint's budget ran out would tell them
/// how the limiter is keyed, which is the first thing anyone trying to evade it
/// wants. The `Retry-After` is the whole of the useful content.
fn too_many(endpoint: &'static str, retry_after: std::time::Duration) -> Response {
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
fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
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
fn readable<'a>(h: &'a HeaderMap, name: &'a str) -> Result<Option<&'a str>, &'a str> {
    match h.get(name) {
        None => Ok(None),
        Some(v) => v.to_str().map(Some).map_err(|_| name),
    }
}

async fn handle(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if !origin_ok(&state, &headers) {
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    let request: mcp::Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return reply(
                400,
                mcp::error(None, codes::PARSE_ERROR, &format!("invalid JSON: {e}")),
            )
        }
    };

    let meta = match request.validate() {
        Ok(m) => m,
        Err(e) => {
            return reply(
                e.http_status(),
                mcp::error(request.id.as_ref(), e.code(), &e.to_string()),
            )
        }
    };

    // A HEADER THAT CANNOT BE READ IS A REFUSAL, NOT A SKIP, and it is refused
    // here rather than inside `cross_check_headers` because that function
    // compares two decoded strings and this is not a disagreement between them.
    //
    // `INVALID_PARAMS` AND 400, following the precedent one arm below: a missing
    // `MCP-Protocol-Version` — the other header-layer defect that is not a
    // mismatch — already answers exactly that. `-32020 HeaderMismatch` is
    // documented as "a header disagrees with the `_meta` field it mirrors" and
    // saying it here would report a disagreement nobody established. A new code
    // in the MCP-reserved range would need the 2026-07-28 revision to name this
    // condition and a client that recognised it, which is the bar `RATE_LIMITED`
    // had to clear and this does not.
    let (header_version, header_method, header_name) = match (
        readable(&headers, headers::PROTOCOL_VERSION),
        readable(&headers, headers::METHOD),
        readable(&headers, headers::NAME),
    ) {
        (Ok(v), Ok(m), Ok(n)) => (v, m, n),
        (Err(bad), _, _) | (_, Err(bad), _) | (_, _, Err(bad)) => {
            return reply(
                400,
                mcp::error(
                    request.id.as_ref(),
                    codes::INVALID_PARAMS,
                    &format!("the {bad} header is not readable as text"),
                ),
            )
        }
    };

    if let Err(e) = mcp::cross_check_headers(&meta, header_version, header_method, header_name) {
        return reply(
            e.http_status(),
            mcp::error(request.id.as_ref(), e.code(), &e.to_string()),
        );
    }

    // A notification takes no response at all.
    let Some(id) = request.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };

    match request.method.as_str() {
        DISCOVER => measured(DISCOVER, || discover(&id)),
        TOOLS_LIST => measured(TOOLS_LIST, || tools_list(&id)),
        "tools/call" => tools_call(state, &id, &request.params, &headers).await,
        // NO record for an unknown method, deliberately. Its only available label
        // is the string the caller invented, and D67's cardinality rule means a
        // caller must not be able to mint a Prometheus series — the same reason
        // `tools::label_for` resolves a tool name to a bounded label before
        // anything is measured.
        other => reply(
            200,
            mcp::error(
                Some(&id),
                codes::METHOD_NOT_FOUND,
                &format!("unknown method: {other}"),
            ),
        ),
    }
}

/// The `tools/list` payload.
fn tools_list(id: &Value) -> Value {
    mcp::result(
        id,
        as_object(json!({
            "tools": tools::definitions(),
            // Cacheable by anyone: the tool list is identical for every caller. It
            // becomes `cacheScope: "private"` the day a tool is gated on who is
            // asking.
            "ttlMs": 300_000,
            "cacheScope": "public",
        })),
    )
}

/// Answer, and record what it cost (D67).
///
/// **`Call::start` used to be reached only inside `tools_call`**, so two of the
/// three methods this server implements returned bytes nothing measured — and
/// `tools/list` is the larger payload of the two. A method that emits no record
/// looks exactly like a method nobody calls, which is the reading D15's
/// retirement rule would act on.
fn measured(tool: &'static str, build: impl FnOnce() -> Value) -> Response {
    // Started BEFORE the work, so the duration covers the handler.
    let call = Call::start(SERVICE, tool, Kind::Read, tel(crate::request_id()));
    let rendered = serde_json::to_string(&build()).unwrap_or_default();
    call.finish(Outcome {
        status: "OK",
        encoded_bytes: Some(rendered.len() as u64),
        payload: rendered.clone(),
        // One document, not a collection: `tools/list` returns a single result
        // object, and counting its tools as rows would make the number mean
        // something different from what it means on `find_tasks`.
        rows: 1,
        ..Default::default()
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        rendered,
    )
        .into_response()
}

/// A telemetry scope for a call with no attested identity.
///
/// `user_id` and `project_id` stay empty rather than being filled from what the
/// caller claimed: on these paths nothing has been attested, and a scope that
/// carried a claim would put an unverified identity into the record.
fn tel(request_id: String) -> yadgar_telemetry::observe::Scope {
    yadgar_telemetry::observe::Scope {
        request_id,
        instance_id: String::new(),
        user_id: String::new(),
        project_id: String::new(),
    }
}

/// `server/discover` — the spec says "Servers MUST implement it", replacing the
/// `initialize` handshake that a stateless protocol has nowhere to keep.
fn discover(id: &Value) -> Value {
    mcp::result(
        id,
        as_object(json!({
            "supportedVersions": [mcp::PROTOCOL_VERSION],
            "capabilities": { "tools": {} },
            "_meta": {
                meta_keys::SERVER_INFO: {
                    "name": "yadgar-gateway",
                    // `crate::VERSION`, NOT `CARGO_PKG_VERSION`. The manifest is a
                    // placeholder nothing writes to; the number here is stamped
                    // from the release tag at build time. See `crate::VERSION`.
                    "version": crate::VERSION,
                },
            },
            "instructions": "yadgar: durable memory, wiki and tasks for coding agents.",
            "ttlMs": 3_600_000,
            "cacheScope": "public",
        })),
    )
}

async fn tools_call(
    state: Arc<AppState>,
    id: &Value,
    params: &Value,
    headers: &HeaderMap,
) -> Response {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

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
    // still earns its place there, because the chart still enables it.
    let (Some(label), Some(module)) = (tools::label_for(name), tools::module_for(name)) else {
        return reply(
            200,
            mcp::error(
                Some(id),
                codes::INVALID_PARAMS,
                &format!("unknown tool: {name}"),
            ),
        );
    };

    // Minted here, never read from the request (D67). See `crate::request_id`.
    let request_id = crate::request_id();

    // THE USER IS RESOLVED FROM THE CREDENTIAL AND THE OTHER TWO ARE CLAIMED, and
    // the split is ADR-0488's rule applied field by field. `x-yadgar-user` is not
    // passed on the `iam` path at all — a self-asserted username is forgeable by
    // anyone holding any valid token, so it is the bearer token that names the
    // caller. `x-yadgar-project` and `x-yadgar-instance` stay caller-supplied:
    // they are workspace and session facts, and no token can carry them.
    let attested = match attest::attest(
        &state.attestation,
        &state.iam,
        &state.credentials,
        header(headers, axum::http::header::AUTHORIZATION.as_str()),
        Claimed {
            user_id: header(headers, "x-yadgar-user"),
            project_id: header(headers, "x-yadgar-project"),
            instance_id: header(headers, "x-yadgar-instance"),
        },
        request_id.clone(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            // THE ONLY PLACE THE REAL REASON IS WRITTEN DOWN, and it goes to the
            // log rather than to the caller — the same split `login` makes.
            tracing::warn!(error = %e, "attestation failed");
            let answer = attest_answer(&e);
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
            return reply(
                answer.status.as_u16(),
                mcp::error(Some(id), answer.code, &answer.message),
            );
        }
    };
    let scope = attested.scope;

    // D74, and before any TOOL work: refusing here means the loop this protects
    // against costs `task` nothing at all. Enforcing per module would let it cost
    // every service its work before the last one said no.
    //
    // **IT IS NO LONGER BEFORE ALL UPSTREAM WORK, and the comment here used to say
    // it was.** Attestation runs above, and it has to: the bucket keys on the
    // resolved user id, so there is nothing to spend from until the credential has
    // been resolved. An authenticated caller in a loop therefore costs `iam` one
    // `ResolveCredential` this limiter cannot shield — and the bound on that is
    // D72's cache, "on a cache miss, never per request", which `attest::Credentials`
    // now is. It is a bound and not a cure: the loop costs one lookup per TTL
    // rather than one per request, and a caller ROTATING tokens still misses every
    // time. Throttling the lookup itself would need a bucket keyed on something
    // known before the identity is, which is the caller's own claim.
    let kind = kind_of(name);
    if let Some(refusal) =
        throttled(&state, id, &scope, label, module, kind, &attested.limits).await
    {
        // A throttled call is a call, for the same reason the refusal above is.
        // Without this a throttling storm is indistinguishable from silence,
        // which is the reading D15's retirement rule would act on.
        //
        // The ATTESTED scope rides on it, unlike the UNAUTHENTICATED record above
        // — there identity was never established, here it was, and "who is being
        // throttled" is the first question anyone reading this record has. It
        // goes in the wide event and NOT in a metric label, which is the same
        // split every other record on this path already makes.
        Call::start(
            SERVICE,
            label,
            kind,
            yadgar_telemetry::observe::Scope {
                request_id,
                instance_id: scope.instance_id.clone(),
                user_id: scope.user_id.clone(),
                project_id: scope.project_id.clone(),
            },
        )
        .fail("RESOURCE_EXHAUSTED");
        return refusal;
    }

    let call = Call::start(
        SERVICE,
        label,
        kind,
        yadgar_telemetry::observe::Scope {
            request_id,
            instance_id: scope.instance_id.clone(),
            user_id: scope.user_id.clone(),
            project_id: scope.project_id.clone(),
        },
    );

    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let outcome = tools::call(state.task.clone(), scope, name, &args).await;
    let (status, rows, payload) = shape(id, outcome);

    // Serialise ONCE, and measure exactly what goes on the wire.
    //
    // This is the number D67 exists for: bytes and words returned TO THE CALLER.
    // Every other hop sees protobuf, which is a different size and answers a
    // different question — so if this were measured anywhere else in the system
    // it would quietly be measuring the wrong thing.
    let rendered = serde_json::to_string(&payload).unwrap_or_default();
    call.finish(Outcome {
        status,
        encoded_bytes: Some(rendered.len() as u64),
        payload: rendered.clone(),
        rows,
        ..Default::default()
    });

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        rendered,
    )
        .into_response()
}

/// Spend a token, and build the refusal if there is none to spend (D74).
///
/// `Some` is a 429 the caller must be sent; `None` means carry on. Split out of
/// `tools_call` because a limiter that has three outcomes and only one of them
/// returns is exactly the shape that belongs behind a name.
async fn throttled(
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
fn degraded(
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
fn refusal(
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
fn shape(
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
fn kind_of(name: &str) -> Kind {
    if tools::is_write(name) {
        Kind::Write
    } else {
        Kind::Read
    }
}

fn as_object(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

/// What one gRPC code from `iam.Login` becomes on the wire (D72, D75).
///
/// **THIS FUNCTION IS THE SECURITY PROPERTY, which is why it is a pure function
/// with its own test rather than a `match` inside the handler.** It must survive
/// any later rewrite of `login`, and a property asserted only through the handler
/// would not.
///
/// The rule: `UNAUTHENTICATED` is 401, and EVERY other code is one single opaque
/// 503, indistinguishable from every other.
///
/// The reason is an oracle in `iam`. SOME of the non-`UNAUTHENTICATED` codes are
/// raised only after the password has already verified — `Internal` when the
/// token cannot be minted (`iam/src/service.rs`, after `verify_password`
/// returns), and whatever `create_credential` propagates from `iam-db` after
/// that. A caller that saw one of those would have learned from the status alone
/// that the password it sent was correct.
///
/// **The gateway cannot tell which side of the check a code came from, and that
/// is why it collapses ALL of them.** The same `Unavailable` reaches this
/// function from `get_password_hash`, which runs BEFORE any password is checked,
/// and from `create_credential`, which runs after — `upstream_failed` preserves
/// the upstream code in both cases, so the two are identical on arrival. Any rule
/// that distinguished codes would have to distinguish these, and there is nothing
/// in a code to distinguish them by. Collapsing errs conservative: it costs
/// nothing to be opaque about a failure that leaked nothing.
///
/// **Mapping everything to 401 was considered and rejected.** It closes the same
/// leak, and it costs a permanent one: it would tell a person whose password is
/// right that it is wrong, every time `iam-db` is unavailable, and nothing in the
/// answer would say the store was down. A narrow leak that needs an outage to
/// fire is the better trade against a lie told on every outage.
///
/// 503 rather than 500: the codes collapsed into it are dominated by an
/// unreachable or unhappy `iam-db`, and the honest reading of the whole set is
/// "this cannot be answered right now", which is also what makes retrying the
/// right response. The client treats every non-401 alike (`Unexpected(status)`),
/// so this number is for the operator and the proxy, not for `yaadgaar`.
pub fn login_status(status: &tonic::Status) -> StatusCode {
    login_answer(status.code()).0
}

/// **THE STATUS RULE ITSELF, in one function, for all three paths that have one.**
///
/// `UNAUTHENTICATED` is 401. EVERY other code is one single 503, indistinguishable
/// from every other. The long argument for it is on [`login_status`] above; this
/// function is where it is decided, and it is one function rather than three
/// because it is the security property. Three copies would be three places for the
/// rule to drift, and the drift would be invisible — each copy would still look
/// obviously correct on its own.
///
/// The three callers are `/auth/login`, `/auth/enrol` and the attested MCP path,
/// and they arrived at it independently:
///
/// - `login` — `iam` raises the same `Unavailable` from `get_password_hash`, which
///   runs BEFORE any password is checked, and from `create_credential`, which runs
///   after one has verified. `upstream_failed` preserves the upstream code either
///   way, so nothing in a code says which side it came from.
/// - `enrol` — the contract calls `RedeemEnrolment` "UNAUTHENTICATED BY
///   CONSTRUCTION" and mandates ONE FAILURE, NOT THREE. `InvalidArgument` there is
///   the sharpest case: it is raised before the secret is looked up for a password
///   the policy refuses, AND after the store has confirmed the secret for an
///   idempotency key replayed with a different password. Same code, both sides of
///   the lookup, again.
/// - `attest` — a credential that does not resolve and an `iam` that cannot answer
///   must not be told apart by a caller who is guessing tokens.
///
/// **The bodies are NOT shared, and that is deliberate.** "invalid username or
/// password" is a wrong sentence on an enrolment, which checks neither. The
/// STATUS is the property; the words are per-endpoint, and each set is a constant
/// picked by [`opaque_answer`]'s callers rather than anything derived from `iam`.
pub fn opaque_status(code: tonic::Code) -> StatusCode {
    match code {
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        // ONE ARM, and a catch-all on purpose. Adding a second here — a 404 for
        // `NotFound`, a 400 for `InvalidArgument` — is the change that reopens the
        // oracle on every path at once, so there is deliberately nowhere obvious
        // to put one.
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// [`opaque_status`], with the two constant bodies one endpoint answers with.
///
/// **Takes a `tonic::Code`, not a `tonic::Status`, and the difference is the
/// point.** A `Code` is a bare enum with no message attached, so there is no
/// upstream text in scope here to interpolate into a body even by accident. Both
/// bodies are `&'static str` for the same reason: the signature makes the property
/// true rather than the author being careful.
fn opaque_answer(
    code: tonic::Code,
    refused: &'static str,
    unavailable: &'static str,
) -> (StatusCode, &'static str) {
    let status = opaque_status(code);
    let body = if status == StatusCode::UNAUTHORIZED {
        refused
    } else {
        unavailable
    };
    (status, body)
}

/// The status AND body for one gRPC code.
///
/// **Takes a `tonic::Code`, not a `tonic::Status`, and the difference is the
/// point.** A `Code` is a bare enum with no message attached, so there is no
/// upstream text in scope here to interpolate into a body even by accident. The
/// bodies being constants is then a fact about the signature rather than a habit
/// the next edit has to keep.
///
/// The bodies matter because the CLIENT never reads them: `yaadgaar` branches on
/// the status alone. A body that varied with the upstream would be a leak channel
/// no client-side test could ever catch, sitting behind a status line that was
/// carefully made opaque.
fn login_answer(code: tonic::Code) -> (StatusCode, &'static str) {
    opaque_answer(
        code,
        r#"{"error":"invalid username or password"}"#,
        r#"{"error":"login is unavailable"}"#,
    )
}

/// The status AND body for one gRPC code from `iam.RedeemEnrolment`.
///
/// The same rule as [`login_answer`], through the same [`opaque_status`], with its
/// own two constants — because login's words are wrong here. Nothing on this path
/// checks a username or a password against a store: what the caller presented is
/// an enrolment secret, and telling a person their "username or password" was
/// invalid would send them looking for an account they do not have yet.
///
/// **The refusal's wording carries the contract's ONE FAILURE, NOT THREE.** An
/// unknown secret, a spent one and an expired one are one answer here, so the
/// sentence names none of the three: any wording that fitted only one of them
/// would be a hint about which it was.
fn enrol_answer(code: tonic::Code) -> (StatusCode, &'static str) {
    opaque_answer(
        code,
        r#"{"error":"this enrolment cannot be redeemed"}"#,
        r#"{"error":"enrolment is unavailable"}"#,
    )
}

/// What the CALLER is told when attestation fails, and the status it arrives with.
///
/// **Split in two by where the failure was decided**, which is the same split
/// `login` makes between its 400s and everything after them:
///
/// - Decided HERE, before anything was sent — no `Authorization` header, no
///   project. Safe to describe: it is this server's reading of the caller's own
///   request, and no credential has been checked, so it discloses nothing.
/// - Decided by `iam`, or by a limit it returned. Through [`opaque_status`] and a
///   CONSTANT, never `e.to_string()`: a caller working through a list of stolen
///   tokens must not learn from the answer whether one of them exists.
///
/// The real code and message go to the log, where an operator can read them and a
/// caller cannot.
fn attest_answer(e: &attest::AttestError) -> AttestAnswer {
    match e {
        attest::AttestError::MissingIdentity(_) | attest::AttestError::MissingCredential => {
            AttestAnswer {
                status: StatusCode::UNAUTHORIZED,
                code: codes::INVALID_REQUEST,
                label: "UNAUTHENTICATED",
                message: e.to_string(),
            }
        }
        attest::AttestError::Upstream(code) => {
            let status = opaque_status(*code);
            let refused = status == StatusCode::UNAUTHORIZED;
            AttestAnswer {
                status,
                // INTERNAL_ERROR rather than INVALID_REQUEST when the status is
                // not a refusal: the request was well formed and it is this server
                // that could not answer it, and a client told its request was
                // invalid stops retrying something worth retrying.
                code: if refused {
                    codes::INVALID_REQUEST
                } else {
                    codes::INTERNAL_ERROR
                },
                label: if refused {
                    "UNAUTHENTICATED"
                } else {
                    "UNAVAILABLE"
                },
                message: "the credential could not be verified".to_string(),
            }
        }
        // **A THIRD ANSWER, AND IT IS NOT AN OUTAGE.** This used to be the same
        // 503, the same body and the same `UNAVAILABLE` label as an unreachable
        // `iam` — byte-identical, for a condition that is neither transient nor a
        // failure of this service. The credential RESOLVED; what cannot be applied
        // is a rate-limit override an admin set on it, so every call fails
        // identically until somebody clears that row, and an operator reading the
        // metric would hunt an `iam` outage that is not happening.
        //
        // That is the mirror of the argument `login_answer` uses to reject
        // collapsing everything onto 401: an answer that lies about WHICH thing is
        // broken costs more than the opacity buys — and here it buys nothing,
        // because the caller is already authenticated and there is no oracle left
        // to protect.
        //
        // 500 rather than 503, because retrying cannot help. The body names the
        // class of problem and none of the numbers: those are one person's private
        // limits, and they stay in the log.
        attest::AttestError::Unenforceable(_) => AttestAnswer {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: codes::INTERNAL_ERROR,
            label: "FAILED_PRECONDITION",
            message: "a rate limit configured for this credential cannot be applied".to_string(),
        },
    }
}

/// What one failed attestation becomes: a status, a JSON-RPC code, a BOUNDED
/// telemetry label and the sentence the caller reads.
///
/// A struct rather than a tuple because the label is what went wrong while it was
/// computed separately: two matches over one enum drift, and the drift made a
/// permanent configuration failure indistinguishable from an outage in the metric
/// an operator watches.
struct AttestAnswer {
    status: StatusCode,
    code: i32,
    /// `&'static str` from a closed set, for D67's cardinality rule.
    label: &'static str,
    message: String,
}

/// The whole failing response for one gRPC code: status, body and headers.
///
/// **The single builder for every failure that involves `iam`** — a refusal, a
/// broken store, an unreachable pod, a stall — so there is one place to read and
/// one place a test can cover exhaustively. (A malformed request body never gets
/// here; `login` answers those before it sends anything.) It takes a `Code` for
/// the reason given on [`login_answer`], and it adds no header beyond the content
/// type — in particular **no `WWW-Authenticate` on the 401**, which D72 forbids
/// because it advertises an OAuth discovery flow this deployment does not
/// implement.
///
/// Returning a whole `Response` rather than its parts is what lets the test
/// assert the headers too. That gap is why this function exists: the status
/// mapping was pinned across every code while the body and the absent header were
/// pinned only on whichever code an unreachable upstream happened to produce, so
/// adding `WWW-Authenticate` to the refusal passed the entire suite.
fn login_failure(code: tonic::Code) -> Response {
    let (status, body) = login_answer(code);
    text(status, body)
}

/// The whole failing response for one gRPC code from `iam.RedeemEnrolment`.
///
/// [`login_failure`]'s twin, and separate for the one reason the two differ: the
/// bodies. Everything the doc comment there argues holds here unchanged — one
/// builder for every failure that involves `iam` so a test can cover it
/// exhaustively, a `Code` rather than a `Status` so no upstream text is in scope,
/// and no header beyond the content type, in particular **no `WWW-Authenticate` on
/// the 401** (D72).
fn enrol_failure(code: tonic::Code) -> Response {
    let (status, body) = enrol_answer(code);
    text(status, body)
}

fn reply(status: u16, body: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
