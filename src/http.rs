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

use crate::admin::{Authority, Bootstrap, BootstrapToken, Verb};
use crate::attest::{self, Attestation, Claimed, Credentials};
use crate::limit::{Bucket, Decision, Limiter};
use crate::mcp::{self, codes, headers, meta_keys};
use crate::pb::yadgar::common::v1::Idempotency;
use crate::pb::yadgar::iam::v1::{
    iam_service_client::IamServiceClient, CreateUserRequest, IssueEnrolmentRequest, LoginRequest,
    RedeemEnrolmentRequest, SetUserAdminRequest,
};
use crate::source::{PeerAddr, Source, TrustBoundary};
use crate::tools;

mod admin;
mod answer;
mod auth;
mod authority;
mod call;
mod dispatch;
mod gate;

pub use answer::{login_status, opaque_status};

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

/// The three administrative endpoints' labels (ADR-0492, D73, ledger 638).
///
/// PATHS rather than MCP methods, for [`AUTH_LOGIN`]'s reason — that is what they
/// are — and `&'static` and closed for D67's.
///
/// **THREE VALUES AND NOT ONE, because these ARE the throttle keys.** [`guard`]
/// passes `endpoint` straight to `Limiter::check_source`, so one label across the
/// three verbs would be one bucket across them: an administrator's ordinary work
/// would spend the budget that bounds a bootstrap-token brute force, and the
/// operator watching that budget could not tell the two apart.
const ADMIN_CREATE_USER: &str = "admin/create-user";
const ADMIN_ISSUE_ENROLMENT: &str = "admin/issue-enrolment";
const ADMIN_SET_USER_ADMIN: &str = "admin/set-user-admin";

/// Where a caller presents D73's bootstrap token.
///
/// **ITS OWN HEADER, NOT `Authorization`**, and the separation is what makes §6's
/// "no actor on the bootstrap path" structural rather than remembered. A request
/// carrying this header is a BOOTSTRAP request and is judged by the bootstrap
/// rules alone — there is no arm in which it falls back to the attested path, so
/// there is no arm in which it acquires an identity that could be stamped by
/// accident. Sharing `Authorization` would have made "which mechanism admitted
/// this?" a question about the value's shape, which is the kind of question that
/// gets answered wrongly under a rewrite.
const BOOTSTRAP_HEADER: &str = "x-yadgar-bootstrap-token";

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

/// The longest `label` `iam` accepts, IN CHARACTERS. Its `MAX_LABEL_CHARS`.
///
/// **A SECOND ENFORCEMENT POINT, NOT A SECOND AUTHORITY.** `iam/src/service.rs`
/// owns this number and keeps its check: `iam`'s gRPC is reachable in-cluster
/// without this process — that is how the identity ceremony mints the first
/// administrator — so a bound that lived only here would leave the path this
/// server does not sit on unguarded. What the copy here buys is the STATUS: an
/// over-long label refused upstream comes back as `INVALID_ARGUMENT`, and
/// [`opaque_status`] collapses that into a 503 that says login is unavailable.
/// Nothing is unavailable. The request was measurable from here.
///
/// **DRIFT CUTS BOTH WAYS AND ONLY ONE WAY IS OBVIOUS.** Too LOOSE here and the
/// 503 comes back for the labels between the two numbers, which is the defect
/// this exists to close, quietly reopened. Too TIGHT here and this server refuses
/// a request `iam` would have accepted — a 400 the caller cannot appeal to any
/// upstream, which is worse than what it replaced. If `iam` moves its constant,
/// this one moves with it.
///
/// **CHARACTERS AND NOT BYTES.** The column is `label VARCHAR(255)` on utf8mb4
/// and `VARCHAR(n)` there bounds characters, so 255 four-byte codepoints is 1020
/// bytes and stores without complaint. A `.len()` check here would refuse it and
/// invent a rule `iam` does not have.
const MAX_LABEL_CHARS: usize = 255;

/// The longest password `iam.RedeemEnrolment` will hash, IN BYTES. Its
/// `MAX_PASSWORD_BYTES`.
///
/// **ENROLMENT ONLY, AND THE ASYMMETRY IS THE POINT.** `RedeemEnrolment` hashes
/// the password BEFORE it looks the secret up — which is what stops its
/// `INVALID_ARGUMENT` from reporting that the secret was good — so an unbounded
/// input there is Argon2id work a stranger can ask for. `Login` has no
/// counterpart bound: it verifies against a stored hash and answers 401 whatever
/// the length. Borrowing this number onto the login path would refuse a request
/// `iam` accepts, and an edge check that invents refusals is a defect wearing the
/// shape of a fix.
///
/// The same second-enforcement-point argument as [`MAX_LABEL_CHARS`] above, and
/// `iam` keeps its own check for the same reason.
///
/// BYTES, because that is the unit `iam` uses (`r.password.len()`) and a password
/// is hashed as bytes.
const MAX_PASSWORD_BYTES: usize = 1024;

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
    /// What bounds the three administrative endpoints (§3.2).
    ///
    /// **A THIRD AND FOURTH BUCKET RATHER THAN A SHARE OF
    /// [`Self::credential_limits`].** Sharing login's would make an
    /// administrator's ordinary work consume a budget sized for password
    /// attempts, and would make a bootstrap-token brute force spend a bucket an
    /// operator reads as login pressure. Same TYPE, because the attributed and
    /// unattributed split is the same split for the same reason — see
    /// [`CredentialLimits`], whose whole argument applies here unchanged.
    pub admin_limits: CredentialLimits,
    /// D73's bootstrap token as this deployment holds it (ADR-0492).
    ///
    /// [`BootstrapToken::disabled`] where no Secret is mounted, which disables
    /// the bootstrap path and NOTHING else — see the type for why that is
    /// serve-and-disable rather than ADR-0569's refuse-to-start.
    pub bootstrap: BootstrapToken,
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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(dispatch::routes())
        .merge(auth::routes())
        .merge(admin::routes())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state)
}

async fn method_not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, "MCP uses POST").into_response()
}

#[cfg(test)]
mod tests;
