//! WHO may call an administrative endpoint.
//!
//! Split out of [`super`] for the file-size ceiling, and cut so that the TWO
//! AUTHORITIES STAY IN ONE FILE: [`authorise`]'s attested administrator and
//! [`bootstrap_authority`]'s D73 token are the two ways `/admin` is reached, and
//! §6's "no actor on the bootstrap path" is a statement about the pair. A seam
//! between them would put half of an authorization decision in another file.

use super::answer::*;
use super::gate::*;
use super::*;

/// A refusal one administrative handler must return, with the D67 label it is
/// recorded under.
///
/// **BOXED at every use, and clippy's `result_large_err` is why rather than
/// taste.** `Response` is 144 bytes here, and a `Result` carrying it in its error
/// variant moves that on every return — including the successful ones, which are
/// the common case on this path. A named struct rather than a boxed tuple so the
/// two fields cannot be swapped at a call site.
pub(super) struct Refusal {
    /// The bounded `outcome` label (D67). Every value here is one
    /// `yadgar_telemetry::grpc::status_name` produces, per ADR-0558.
    pub(super) label: &'static str,
    pub(super) response: Response,
}

impl Refusal {
    fn new(label: &'static str, response: Response) -> Box<Self> {
        Box::new(Self { label, response })
    }
}

/// Who admitted one administrative request, or the refusal and its D67 label.
///
/// # The bootstrap header decides the PATH, and there is no fallback
///
/// A request carrying [`BOOTSTRAP_HEADER`] is a BOOTSTRAP request. It is judged
/// by the bootstrap rules and refused if they do not admit it — it never falls
/// through to the attested branch, and an attested administrator who also sends
/// the header is still on the bootstrap path. That is deliberate and it is what
/// makes §6's property structural: there is no arm in which a bootstrap request
/// holds an identity, so there is no id available to stamp on one by accident.
///
/// # Order, and each step is a different refusal
///
/// 1. **Is the path configured at all?** An absent Secret disables it, whatever
///    was presented and whatever verb was asked for — §7.2's rule 1, and the
///    Secret's own manifest states it in the same words. No comparison runs.
/// 2. **Does the token reach this verb, at this value?** Refused BEFORE the
///    secret is compared, so an excluded verb is not even a comparison oracle.
/// 3. **Does it match?** `BootstrapToken::check`, whose `None` arm returns above
///    rather than defaulting to `""` — §7.2's rule 2.
///
/// # The attested branch, and why its refusal is 403 rather than 401
///
/// A caller with NO credential is 401: they have not said who they are. A caller
/// whose credential `iam` resolved, answering `is_admin: false`, has said who
/// they are and the answer is that they may not do this — which is 403, and it is
/// the row §9 names as the only thing that makes the plumbed flag load-bearing.
/// Routing it through [`attest_answer`] would render it as the 401 that arm
/// produces, and would send an administrator's colleague to re-authenticate
/// against a condition re-authenticating cannot fix.
pub(super) async fn authorise(
    state: &AppState,
    endpoint: &'static str,
    verb: Verb,
    wants_admin: bool,
    headers: &HeaderMap,
    request_id: String,
) -> Result<Authority, Box<Refusal>> {
    // PRESENT-AND-UNREADABLE IS PRESENT, for `readable`'s reason: treating a
    // header that arrived intact and could not be decoded as ABSENT would send
    // the one bootstrap attempt nobody could read down the attested path.
    match readable(headers, BOOTSTRAP_HEADER) {
        Err(_) => {
            return Err(Refusal::new(
                "PERMISSION_DENIED",
                text(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"the bootstrap token is not accepted here"}"#,
                ),
            ))
        }
        Ok(Some(presented)) => {
            return bootstrap_authority(state, endpoint, verb, wants_admin, presented)
        }
        Ok(None) => {}
    }

    let attested = match attest::attest(
        &state.attestation,
        &state.iam,
        &state.credentials,
        &state.projects,
        header(headers, axum::http::header::AUTHORIZATION.as_str()),
        Claimed {
            // NOT PASSED, exactly as on `tools_call`: a self-asserted username is
            // forgeable by anyone holding any valid token, so the bearer token is
            // what names the caller. Under `TrustedHeaders` it is read, and under
            // `TrustedHeaders` `is_admin` is false — so the header buys no
            // authority there either.
            user_id: header(headers, "x-yadgar-user"),
            // REQUIRED HERE FOR THE SAME REASON IT IS ON `tools/call`, and NOT
            // invented. `Attested` carries a `Scope`, `Scope` carries a
            // workspace, and the gateway does not have one to supply — a
            // placeholder would write a workspace nobody named into the type
            // ADR-0511 keeps to what this gateway mints. An absent header is
            // `MissingWorkspace`, which `attest_answer` renders as a 400 naming
            // the header rather than as a credential failure.
            project_id: header(headers, "x-yadgar-project"),
            instance_id: header(headers, "x-yadgar-instance"),
        },
        request_id,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            // THE ONLY PLACE THE REAL REASON IS WRITTEN DOWN, the same split
            // every other handler here makes.
            tracing::warn!(error = %e, endpoint, "administrative attestation failed");
            let answer = attest_answer(&e);
            return Err(Refusal::new(
                answer.label,
                text(
                    answer.status,
                    &json!({ "error": answer.message }).to_string(),
                ),
            ));
        }
    };

    // **THE READ THAT MAKES STEP 3 LOAD-BEARING.** Without it the flag is carried
    // into `Attested` by a plumbing change every test passes, and every
    // administrative route is open to every caller holding any credential.
    if !attested.is_admin {
        tracing::warn!(
            endpoint,
            user_id = %attested.scope.user_id,
            "a non-administrator was refused an administrative verb"
        );
        return Err(Refusal::new(
            "PERMISSION_DENIED",
            text(
                StatusCode::FORBIDDEN,
                r#"{"error":"this endpoint requires an administrator"}"#,
            ),
        ));
    }
    Ok(Authority::Administrator(attested.scope.user_id))
}

/// The bootstrap branch of [`authorise`]. See that function for the order.
/// The audit record for an accepted bootstrap token.
///
/// Its own function because it is the RECORD and not the DECISION: the
/// acceptance is `state.bootstrap.check`'s, and everything here is what
/// ADR-0492 §6.1 requires be written down about an act that has no actor.
fn record_bootstrap_use(endpoint: &'static str) {
    // **§6.1'S THIRD CHANGE, AND IT IS NOT AN AUDIT TRAIL.** ADR-0492's
    // risk acceptance for leaving this credential live is that a leak "is
    // loud and lands in the audit trail". There is no audit store on this
    // boundary — `iam-db` writes an attribution line for exactly one verb
    // and it is not one of these three — so a leaked token today buys a
    // SILENT administrator. This line is the only observability WITH ANY
    // DETAIL on the one path that has no actor to relay, and it is cheap.
    // It does NOT close the gap: a log line is not an audit trail, and
    // §7.3.4 remains the operator's ruling.
    tracing::warn!(
        endpoint,
        "THE BOOTSTRAP TOKEN WAS ACCEPTED. This credential is unattributable by \
         construction (D73), so no actor is recorded for this act and nothing else \
         records it either — see ADR-0492 and plan §6.1"
    );
    // **AND THE LINE ABOVE DIES WITH THE POD, WHICH IS WHY THIS EXISTS.**
    // The estate runs a Prometheus server and NO log shipper — `deploy`'s
    // `infra/prometheus.yaml` says so in as many words, "no promtail,
    // loki, fluent-bit or vector" — so that `warn` reaches `kubectl logs`
    // and an operator who has already guessed the answer. The only record
    // that a stranger became an administrator did not survive the event it
    // recorded. This counter is the same conversion `iam`'s invalidation
    // signal already made: an ERROR nobody reads becomes a series with an
    // alerting rule on it. The `warn` stays, because it carries the
    // `endpoint` and the metric deliberately carries nothing.
    //
    // **REGISTRATION IS LAZY, AND THAT IS THE WHOLE DESIGN.**
    // `metrics::counter!` registers a name with the recorder ONLY when the
    // macro executes. Until the first bootstrap token is accepted, this
    // process has never run this line, so `yadgar_gateway_bootstrap_
    // accepted_total` is ABSENT from `/metrics` — not present at `0`. That
    // is correct here rather than a defect (see `admin::ACCEPTED` for why a
    // security counter has no meaningful zero to publish), but it is NOT
    // free, and it dictates how the alert must be written:
    //
    //  - The SERIES APPEARING IS THE SIGNAL. A rule of the shape
    //    `max_over_time(<name>[24h]) > 0` fires on the first scrape after
    //    the first acceptance, because a series that exists at all here
    //    already means it happened.
    //  - `increase(<name>[..]) > 0` IS WRONG and would be the natural
    //    thing to write. Prometheus takes the first sample in the range as
    //    the baseline, so a counter going absent -> 1 shows an increase of
    //    ~0: such a rule catches the SECOND acceptance and misses the
    //    FIRST, which is exactly backwards for this event.
    //  - `absent(<name>)` IS ALSO WRONG, for the reason
    //    `infra/prometheus.yaml` already argues at length: a name that
    //    never appears fires never.
    //
    // The rule lives in `deploy` at `infra/prometheus.yaml`, named
    // `BootstrapTokenAccepted`, and repeats this reasoning where an
    // operator reading the rule will meet it.
    metrics::counter!(crate::admin::ACCEPTED).increment(1);
}

pub(super) fn bootstrap_authority(
    state: &AppState,
    endpoint: &'static str,
    verb: Verb,
    wants_admin: bool,
    presented: &str,
) -> Result<Authority, Box<Refusal>> {
    // RULE 1 FIRST, AND FOR EVERY VERB. "An absent or empty bootstrap secret
    // DISABLES the bootstrap path. The consumer refuses every request on that
    // path with a status naming the missing configuration — NEVER a comparison
    // against a missing or empty value."
    //
    // A DISTINCT BODY, because the operator problem is distinct: a deployment
    // whose Secret is not mounted has nothing to fix about permissions, and
    // collapsing this into the refusal a wrong token gets would leave them
    // hunting one. 503 rather than 403 for the same reason — nothing the caller
    // did is wrong.
    if !state.bootstrap.is_configured() {
        tracing::warn!(
            endpoint,
            "a bootstrap request arrived and no bootstrap token is configured, so the bootstrap \
             path is disabled; mount the `admin-bootstrap-token` Secret to enable it"
        );
        return Err(Refusal::new(
            "FAILED_PRECONDITION",
            text(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"the bootstrap token is not configured"}"#,
            ),
        ));
    }
    // THE EXCLUSION BEFORE THE COMPARISON. An excluded verb is refused without
    // the secret being looked at, so it cannot be used as an oracle for it — and
    // more importantly, the exclusion cannot be reached by a comparison that
    // succeeded.
    if !verb.accepts_bootstrap(wants_admin) {
        tracing::warn!(
            endpoint,
            "the bootstrap token was presented on a verb ADR-0492 does not grant it"
        );
        return Err(Refusal::new(
            "PERMISSION_DENIED",
            text(
                StatusCode::FORBIDDEN,
                // **REWORDED BY ADR-0655, SAME CONSTANT, SAME TWO REMAINING
                // ARMS.** The old sentence — "may only create an administrator or
                // promote one" — became FALSE the moment `IssueEnrolment` was
                // admitted, and it was still the right refusal for the two cases
                // that keep producing it: a `create-user` whose `is_admin` is
                // false or absent, and a `set-user-admin` demotion. So the text
                // stops overclaiming rather than the refusal moving. It is no
                // longer returned on `issue-enrolment` at all — the only refusals
                // on that path now come from the predicate at `iam-db` and render
                // through `admin_failure`.
                r#"{"error":"the bootstrap token may only create an administrator, promote one, or enrol one who has never held a credential"}"#,
            ),
        ));
    }
    match state.bootstrap.check(presented) {
        Bootstrap::Accepted => {
            record_bootstrap_use(endpoint);
            Ok(Authority::Bootstrap)
        }
        Bootstrap::Refused => Err(Refusal::new(
            "PERMISSION_DENIED",
            text(
                StatusCode::FORBIDDEN,
                r#"{"error":"the bootstrap token is not accepted here"}"#,
            ),
        )),
        // UNREACHABLE THROUGH THE GUARD ABOVE, and answered rather than
        // `unreachable!()`: the two are checked from one place today, and a later
        // edit that moved the guard must meet the disabled answer rather than a
        // panic on the administrative path.
        Bootstrap::NotConfigured => Err(Refusal::new(
            "FAILED_PRECONDITION",
            text(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"the bootstrap token is not configured"}"#,
            ),
        )),
    }
}

/// What an administrative caller is told when `iam` refuses or fails.
///
/// **`FAILED_PRECONDITION` GETS ITS OWN BODY (§2), AND NOT ITS OWN STATUS.**
/// `iam`'s `EnrolmentConfig::from_env` takes an argued exception to ADR-0569
/// (`iam/src/service.rs:490`): an absent `ENROLMENT_GATEWAY` leaves the process
/// SERVING and makes `IssueEnrolment` refuse with `FAILED_PRECONDITION` naming
/// the variable. So a correctly-deployed `/admin` route can meet that code from a
/// perfectly healthy `iam`, every pod Ready and every probe green, and the
/// administrator gets "create a user, then fail to enrol them" — §9's step-7 row
/// exactly. Collapsing it into the opaque "unavailable" body would tell them
/// nothing is available when nothing is wrong.
///
/// The STATUS stays whatever [`opaque_status`] says, which for this code is 503.
/// Adding an arm there is the change that reopens the oracle on `/auth/login` and
/// `/auth/enrol` at once, and that function's own comment says there is
/// deliberately nowhere obvious to put one. §2 asks for a distinct MESSAGE and
/// this is one.
///
/// # `PERMISSION_DENIED` ON ENROLMENT IS 403 (ADR-0655, ADR-0657)
///
/// `iam-db` evaluates ADR-0655's zero-credential predicate inside the enrolment
/// insert and refuses with `PERMISSION_DENIED`; `iam` relays the code untouched.
/// Without an arm here that refusal renders as [`opaque_status`]'s catch-all 503
/// "the administrative service is unavailable" — telling an operator the service
/// is down at the moment it refused them correctly.
///
/// **ONE CODE, ONE CONSTANT BODY, AND NO BRANCH ON THE UPSTREAM MESSAGE.**
/// ADR-0657 rules that a refusal on an authorization path whose predicate has
/// more than one conjunct answers the SAME body whichever conjunct failed:
/// distinct bodies would let a holder of a leaked bootstrap token tell "not an
/// administrator" from "administrator who already holds a credential", which
/// enumerates the administrator set and specifically names the administrators who
/// have NEVER LOGGED IN — exactly the set this grant can still take over. Which
/// conjunct failed is recorded at `iam-db`, in a log line and a closed-set
/// counter label, joined to this 403 by the request id.
///
/// **SCOPED BY ENDPOINT, AND THAT IS NOT A BRANCH ON THE MESSAGE.** This function
/// renders all three administrative endpoints. An arm keyed on the CODE alone
/// would answer a sentence about enrolment to a caller who was creating a user —
/// the same overclaiming that made the exclusion message above false,
/// re-introduced by the change that fixes it. `create-user` and `set-user-admin`
/// keep the opaque catch-all they answer today, because nothing in ADR-0655 gives
/// `iam` a new reason to refuse them and a body invented for a case that does not
/// exist would be a widening by guess.
///
/// Everything else is opaque, from a `tonic::Code` and a constant — never
/// `e.to_string()` — for [`login_failure`]'s reason.
pub(super) fn admin_failure(call: Call, endpoint: &'static str, e: tonic::Status) -> Response {
    // THE ONLY PLACE THE REAL CODE AND MESSAGE ARE WRITTEN DOWN, and they go to
    // the log rather than to the caller.
    tracing::warn!(code = ?e.code(), message = e.message(), endpoint, "an administrative RPC was refused or failed");
    let code = e.code();
    // THE ENROLMENT PREDICATE'S REFUSAL, and only on the endpoint it can come
    // from. Computed once so the label and the body cannot disagree about which
    // case this is.
    let enrolment_refusal =
        code == tonic::Code::PermissionDenied && endpoint == ADMIN_ISSUE_ENROLMENT;
    call.fail(if code == tonic::Code::Unauthenticated {
        "UNAUTHENTICATED"
    } else if code == tonic::Code::FailedPrecondition {
        "FAILED_PRECONDITION"
    } else if enrolment_refusal {
        // **AND NOT `UNAVAILABLE`.** D67's `outcome` label is what an operator
        // aggregates on, and recording a refusal as an unavailability would make
        // the one signal that says "the predicate held" read as an outage. Legal
        // on this surface: `authorise` already emits this exact label, and every
        // value here is one `yadgar_telemetry::grpc::status_name` produces
        // (ADR-0558).
        "PERMISSION_DENIED"
    } else {
        "UNAVAILABLE"
    });
    if enrolment_refusal {
        return text(
            StatusCode::FORBIDDEN,
            // ONE BODY FOR BOTH CONJUNCTS (ADR-0657). If a later edit finds
            // itself wanting to name which conjunct failed, that is the oracle
            // the ADR exists to refuse — the conjunct lives in `iam-db`'s log
            // line and its closed-set counter label, reachable by request id.
            r#"{"error":"the bootstrap token may only enrol an administrator who has never held a credential"}"#,
        );
    }
    if code == tonic::Code::FailedPrecondition {
        return text(
            opaque_status(code),
            r#"{"error":"enrolment is not configured: iam is serving but has no enrolment gateway, so it cannot mint an enrolment token"}"#,
        );
    }
    let (status, body) = opaque_answer(
        code,
        r#"{"error":"refused"}"#,
        r#"{"error":"the administrative service is unavailable"}"#,
    );
    text(status, body)
}

/// An `iam` that accepted the connection and then stalled.
///
/// Through the SAME opaque body as any other upstream problem, so a stall is not
/// a third answer somebody has to remember to keep opaque.
pub(super) fn admin_timeout(call: Call, endpoint: &'static str) -> Response {
    tracing::warn!(
        timeout_ms = AUTH_DEADLINE.as_millis(),
        endpoint,
        "an administrative RPC timed out waiting for iam"
    );
    call.fail("UNAVAILABLE");
    text(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"the administrative service is unavailable"}"#,
    )
}
