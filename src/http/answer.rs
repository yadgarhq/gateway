//! How an upstream refusal becomes an HTTP answer — ADR-0507's one rule.
//!
//! Split out of [`super`] for the file-size ceiling. [`opaque_status`] IS the
//! security property rather than a mapping table, and it stays one function; the
//! per-path wording that surrounds it lives here with it.

use super::gate::*;
use super::*;

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
pub(super) fn opaque_answer(
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
pub(super) fn login_answer(code: tonic::Code) -> (StatusCode, &'static str) {
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
pub(super) fn enrol_answer(code: tonic::Code) -> (StatusCode, &'static str) {
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
pub(super) fn attest_answer(e: &attest::AttestError) -> AttestAnswer {
    match e {
        attest::AttestError::MissingIdentity(_) | attest::AttestError::MissingCredential => {
            AttestAnswer {
                status: StatusCode::UNAUTHORIZED,
                code: codes::INVALID_REQUEST,
                label: "UNAUTHENTICATED",
                message: e.to_string(),
                data: None,
            }
        }
        // **A MISSING WORKSPACE IS NOT A CREDENTIAL FAILURE, AND USED TO BE
        // ANSWERED AS ONE.** This shared the 401 above until ledger 739. The
        // credential is fine — on the DEFAULT arm `iam` has already resolved it,
        // because `from_resolved` is where the refusal is raised — and what is
        // absent is `x-yadgar-project`, a fact about the request rather than about
        // the caller. Answering 401 sent a caller holding a good token to
        // re-authenticate against a condition re-authenticating cannot fix.
        //
        // `yadgar/project/v1/project.proto` states the rule on `ResolveProject`:
        // "IT IS A CALLER ERROR AND MUST NOT BE RENDERED AS `401`."
        //
        // **400 AND NOT 404, AND THE NEIGHBOURING RULE IS WHY.** The same contract
        // gives the registry `NOT_FOUND` for a path with NO REGISTERED ANCESTOR —
        // a workspace that was named and resolves to nothing, which is the code
        // `project-db/src/read.rs` already answers. This gateway cannot produce
        // that condition: `PROTO_PATHS` vendors `yadgar/taskapi/v1` and
        // `yadgar/iam/v1` and reaches no `ProjectService`, so nothing here ever
        // asks the registry anything. Answering 404 would mint, for "you named no
        // workspace", the code that already means "the workspace you named does
        // not exist" — collapsing two conditions into one, which is the failure
        // being fixed rather than a second instance of consistency. Keeping the
        // two consistent means keeping them APART: 400 here, `NOT_FOUND` there.
        //
        // **THE REASON IS A TOKEN AND NOT A SENTENCE.** The JSON-RPC code stays
        // `INVALID_REQUEST` — it IS an invalid request — so without `data` the
        // error object would be byte-identical to the 401 above and a client could
        // tell them apart only by string-matching English. `reason` is what a
        // client branches on; the prose is for a person.
        //
        // Safe to describe in full, for the reason the doc comment above gives:
        // this is decided HERE, before any credential is checked, so naming the
        // header discloses nothing about whether a token exists.
        attest::AttestError::MissingWorkspace(header) => AttestAnswer {
            status: StatusCode::BAD_REQUEST,
            code: codes::INVALID_REQUEST,
            // INVALID_ARGUMENT, not a new word: ADR-0558 closed this label space
            // on the values `yadgar_telemetry::grpc::status_name` produces, and a
            // hand-written literal outside that set is the defect it fixed. A
            // credential-stuffing dashboard counting `UNAUTHENTICATED` also stops
            // counting this, which is the point — it never was one.
            label: "INVALID_ARGUMENT",
            message: e.to_string(),
            data: Some(json!({
                "reason": "MISSING_WORKSPACE",
                "header": header.to_ascii_lowercase(),
            })),
        },
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
                data: None,
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
            data: None,
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
pub(super) struct AttestAnswer {
    pub(super) status: StatusCode,
    pub(super) code: i32,
    /// `&'static str` from a closed set, for D67's cardinality rule.
    pub(super) label: &'static str,
    pub(super) message: String,
    /// The machine-readable reason, for the answers where the status alone does
    /// not carry it.
    ///
    /// **PRESENT ON EXACTLY ONE ARM TODAY, and absent on the rest deliberately.**
    /// Everything derived from `iam` answers a CONSTANT message behind a status
    /// that was made opaque on purpose, and a structured reason beside it would
    /// reopen the channel the constant closes. The one arm that carries it is
    /// decided HERE, before anything was sent, so it discloses nothing.
    pub(super) data: Option<Value>,
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
pub(super) fn login_failure(code: tonic::Code) -> Response {
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
pub(super) fn enrol_failure(code: tonic::Code) -> Response {
    let (status, body) = enrol_answer(code);
    text(status, body)
}

pub(super) fn reply(status: u16, body: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}
