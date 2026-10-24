//! The administrative surface's decisions, apart from its plumbing (ADR-0492,
//! D73, ledger 638).
//!
//! `http.rs` owns the six handlers — the routes, the bodies, the upstream
//! calls. **This module owns everything about them that can be got wrong without
//! failing**, because every one of those decisions is a per-handler function call
//! in a language whose compiler cannot notice one is missing. Put here, each is a
//! total function over its inputs and each has a test that watches it refuse.
//!
//! Four decisions live here:
//!
//! 1. **[`BootstrapToken`]** — whether the shared secret this deployment holds
//!    accepts a presented one, INCLUDING the two ways that question is not a
//!    comparison at all (see the type).
//! 2. **[`Verb::accepts_bootstrap`]** — which verbs the bootstrap token reaches,
//!    under which condition. ADR-0492 grants it `CreateUser` and the promotion
//!    half of `SetUserAdmin`; ADR-0655, as amended by ADR-0656, admits
//!    `IssueEnrolment` too, narrowed by a zero-credential predicate enforced
//!    inside `iam-db`'s write rather than here. `iam.proto:687-688` states the
//!    two-verb half of this from `iam`'s side: "create an admin, or promote
//!    one … IT IS CHECKED AT THE GATEWAY" — that sentence predates ADR-0655 and
//!    is a `proto` repo carrier of the same stale claim, tracked separately.
//!    ADR-0945's `RevokeCredentials` is never admitted, on any value, and
//!    neither are ADR-0972 (2)'s `ListCredentials` and `RevokeCredential`.
//! 3. **[`Authority::actor`]** — what ADR-0534's relay carries, and on which path
//!    it carries nothing.
//! 4. **[`is_self_demotion`]** — D73's exclusion, which `iam.proto:664` defers to
//!    the gateway by name because it "is a rule about who may call this".
//!
//! **None of these reads `unverified_actor`** (ADR-0534 forbids authorising on
//! it) and none of them is reachable from `tools::call`: an administrative verb
//! is never an MCP tool (ADR-0492), so nothing here is a member of
//! [`crate::tools::SERVED`] and nothing here is dispatched by name.

mod bootstrap;
mod pre_minted;
pub use bootstrap::{Bootstrap, BootstrapToken};
pub use pre_minted::{
    PreMintedIds, PreMintedIdsError, REFUSE_PRE_MINTED_USER_ID, SWITCHED_OFF_BODY,
};

use crate::pb::yadgar::common::v1::UnverifiedActor;

/// Every time this deployment's bootstrap token was ACCEPTED — every time a
/// stranger holding a shared secret became, promoted, or ENROLLED an
/// administrator.
///
/// **ALL THREE VERBS, AND ADR-0655'S THIRD ONE NEEDS NO NEW METRIC.** The
/// counter is incremented at the `Bootstrap::Accepted` arm, which every admitted
/// bootstrap request crosses — so admitting `IssueEnrolment` extends this series'
/// meaning for free and `deploy`'s `BootstrapTokenAccepted` rule keeps firing on
/// the first acceptance of any of the three. That is stated here rather than
/// assumed, because the closed-set reasoning below enumerates the verbs and a
/// third one appearing silently would make that enumeration wrong. (`iam-db`'s
/// per-conjunct refusal counter under ADR-0655 is a DIFFERENT signal — refusals,
/// not acceptances — and replaces nothing here.) ADR-0945's `RevokeCredentials`
/// is the fourth verb and never reaches this counter; ADR-0972 (2)'s
/// `ListCredentials` and `RevokeCredential` are the fifth and sixth, and never
/// reach it either.
///
/// # Why a metric exists for something a log line already says
///
/// ADR-0492 accepts leaving this credential live on the reasoning that a leak
/// "is loud and lands in the audit trail". **There is no audit trail.** The
/// audit store is a deferred future module, and the estate runs a Prometheus
/// server and NO log shipper — no promtail, loki, fluent-bit or vector, which
/// `deploy`'s `infra/prometheus.yaml` states in as many words. So the
/// `tracing::warn!` beside this counter's emit site lives in a pod's stdout and
/// **dies with the pod**: the only record of a stranger becoming an
/// administrator does not survive the event it records.
///
/// This series is that record's replacement, and it is DETECTION RATHER THAN
/// ATTRIBUTION. It cannot say WHO, because the bootstrap path carries no actor
/// by construction (D73, and [`Authority::actor`] returns `None` for it). It
/// says THAT, to somebody who is not tailing a pod. That is strictly less than
/// an audit trail and strictly more than nothing, and ADR-0492's §7.3.4 gap
/// stays open.
///
/// # UNLABELLED, and that is a decision rather than a default
///
/// D67 forbids a label a caller can influence, which rules out the token, the
/// presented value and anything derived from either. It does not rule out
/// `verb`, whose only three reachable values here are closed by [`Verb`] —
/// `CreateUser`, `SetUserAdmin`, `IssueEnrolment` (not `RevokeCredentials`,
/// `ListCredentials` or `RevokeCredential`). That label
/// is omitted anyway, because **it would not change what the operator does**:
/// any of the three sends them to enumerate the administrators `iam` holds and to
/// rotate the Secret, and the split buys a dashboard nobody has. The scrape
/// already attaches `pod` and `namespace`, which is what an operator needs to
/// reach the log line while that pod still lives.
///
/// # NOT published as `0` at boot, unlike [`crate::invalidate::CONSUMING`]
///
/// That gauge is eagerly zeroed so that "not consuming" and "not scraped" stop
/// being the same observation, and the argument is right — for a GAUGE, where
/// `0` and `1` both mean something. **A counter of security events has no
/// meaningful zero to publish.** Every replica emitting `0` at boot would make
/// this series permanently present, and then EXISTENCE would stop being the
/// signal and an alert would have to reason about a rate instead. Here the
/// series is absent until the first acceptance and its appearance IS the event
/// — argued in full at the emit site in `http.rs`, because that property is
/// what decides the shape of `deploy`'s alerting rule.
pub const ACCEPTED: &str = "yadgar_gateway_bootstrap_accepted_total";

/// The six administrative verbs `/admin` serves.
///
/// **A CLOSED ENUM RATHER THAN A STRING**, for `tools::SERVED`'s reason one
/// module over: the set has to be stated once so that widening it is an edit to
/// the set rather than an arm added somewhere nobody is looking. Every rule below
/// matches on it exhaustively, so a seventh verb does not compile until each rule
/// has said what it means for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `iam.CreateUser`. The FIRST admin verb. The bootstrap token reaches it
    /// on two arms: an administrator by the flag (until team access stage 10
    /// retires it), or the GitOps-declared first administrator by a pre-minted
    /// id with the flag false (flow F2, ADR-0963 (5), ADR-1011). See
    /// [`Verb::accepts_bootstrap`].
    CreateUser,
    /// `iam.IssueEnrolment`. Mints the blob a person redeems at `/auth/enrol`.
    /// **The bootstrap token reaches it under ADR-0655's zero-credential
    /// predicate** (as amended by ADR-0656) — never unconditionally, and the
    /// predicate is enforced inside `iam-db`'s write, not here. See
    /// [`Verb::accepts_bootstrap`]'s doc comment for the argument.
    IssueEnrolment,
    /// `iam.SetUserAdmin`. Promote or demote. The bootstrap token reaches the
    /// promotion half only.
    SetUserAdmin,
    /// `iam.RevokeAllCredentials` (ADR-0945). Never the bootstrap token.
    RevokeCredentials,
    /// `iam.ListCredentials` (ADR-0972 (2)). Never the bootstrap token.
    ListCredentials,
    /// `iam.RevokeCredential`, one credential of a named user (ADR-0972 (2)).
    /// Never the bootstrap token.
    RevokeCredential,
}

/// What one administrative request asks for, as far as the bootstrap rule
/// needs to know: the two request fields [`Verb::accepts_bootstrap`] reads.
///
/// A named struct rather than two `bool` parameters, so the two cannot be
/// swapped at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ask {
    /// The request's own `is_admin` field: the value being SET, not a fact
    /// about the caller.
    pub wants_admin: bool,
    /// Whether a `create-user` body carries a `user_id` (team access stage 3b).
    /// Presence only: the gateway does not judge the value (ADR-0927).
    pub pre_minted_id: bool,
}

impl Ask {
    /// A request that names no pre-minted id: every verb except `create-user`,
    /// and a `create-user` body without `user_id`.
    pub fn flag(wants_admin: bool) -> Self {
        Self {
            wants_admin,
            pre_minted_id: false,
        }
    }
}

impl Verb {
    /// Whether the BOOTSTRAP TOKEN authorises this request.
    ///
    /// `ask` carries the request's own fields, not facts about the caller. It
    /// is a parameter rather than a lookup because the rule is about the
    /// request and not about the deployment.
    ///
    /// # The pre-minted `create-user` arm (team access stage 3b)
    ///
    /// `CreateUser` with a `user_id` and the flag false is admitted: it is how
    /// the bootstrap token creates the first administrator that GitOps names
    /// (flow F2, ADR-0963 (5), ADR-1011). This is NOT a grant of ordinary
    /// accounts, because the narrowing is `iam-db`'s bootstrap create-user
    /// predicate inside the insert: the id must be declared pending in
    /// `administrators`, and no administrator may exist yet
    /// (plans/team-access.md §6). A `user_id` WITH the flag is refused here,
    /// because it would set the column beside the membership, the second source
    /// of admin truth ADR-0962 rejects.
    ///
    /// # The narrowest correct rule, and why nothing looser will do
    ///
    /// "The bootstrap token may call `CreateUser`" and "the bootstrap token may
    /// create an admin" are different sentences and only the second is
    /// ADR-0492's. Anything looser hands an unattributable credential the ability
    /// to create ORDINARY accounts — a power ADR-0492 never granted it, and one
    /// that would survive every happy-path test in the suite because the happy
    /// path always sets `is_admin: true`.
    ///
    /// `iam.proto:739-741` states the same exclusion from the other direction for
    /// a verb this surface does not even serve: "Extending the bootstrap path
    /// here would let a token that exists to create the FIRST admin rewrite the
    /// read policy for the whole deployment before an admin exists to notice."
    ///
    /// # `IssueEnrolment` IS ADMITTED, and the narrowing is NOT here
    ///
    /// **This arm used to be `false`, and the argument it carried was correct
    /// about the danger and wrong about the remedy.** The argument was: an
    /// enrolment token redeems into a credential for an ARBITRARY user id, so a
    /// bootstrap token reaching this verb could mint a login for anybody who
    /// already exists — account takeover with an unattributable credential, not
    /// bootstrap. The danger is real and nothing below denies it.
    ///
    /// What the exclusion cost is that ADR-0492's ceremony COULD NOT BE STARTED.
    /// It is circular, and the circle closes on the FIRST administrator only: an
    /// enrolment is issued only to an attested administrator; an attested
    /// administrator needs a credential; a credential is minted only by
    /// redeeming an enrolment. `SetUserAdmin` is not a way round — promoting
    /// needs an existing ENROLLED user, and on a fresh deployment there is none.
    ///
    /// ADR-0655 (amending ADR-0492), as amended by ADR-0656, admits the token to
    /// this verb and answers the takeover argument with a PREDICATE rather than
    /// with an exclusion: the target must be an administrator who holds ZERO
    /// CREDENTIALS — no `iam_password` row and no `iam_credential` row of ANY
    /// LIVENESS, revoked rows included. Such a user is one this token itself
    /// just made, and a row is never deleted (only tombstoned per D26), so once
    /// a user has ever held a credential they are permanently outside the grant.
    ///
    /// **WITH `IAM_ADMIN_FROM_TEAM` ON, THE PREDICATE IS ADR-0966's** (team
    /// access §6): the target is a live user with a member row of the declared
    /// `administrators` team, whatever credentials it holds. That is the
    /// break-glass arm, and the bootstrap caller may then also set the revoke
    /// instruction (ADR-1014). This function does not know iam's setting and
    /// does not need to: it admits the verb, and `iam-db` decides.
    ///
    /// **THE PREDICATE IS NOT ENFORCED HERE AND CANNOT BE.** It is evaluated
    /// INSIDE THE WRITE at `iam-db`, in the same transaction as the enrolment
    /// insert — carried as `IssueEnrolmentRequest.require_zero_credential_admin`,
    /// relayed verbatim by `iam`. A read this gateway performed first would be
    /// true when it ran and stale when it was used, which is the race ADR-0655
    /// puts the predicate in the transaction to close. So this function's job is
    /// only to stop refusing, and `super::http::admin_issue_enrolment`'s job is
    /// to SET the demand — a flipped arm with an unset demand is the false green
    /// the whole design exists to refuse, because proto3 reads the absent bool
    /// as `false` and `iam-db` then takes the ordinary unrestricted path.
    pub fn accepts_bootstrap(self, ask: Ask) -> bool {
        let wants_admin = ask.wants_admin;
        match self {
            // EXACTLY ONE OF THE TWO ARMS. The flag alone is ADR-0492's arm,
            // which stage 10 retires. A pre-minted id alone is F2's, narrowed by
            // `iam-db`'s predicate. Neither is an ordinary account: without a
            // pre-minted id, `false` here is the power that was never granted.
            Verb::CreateUser => wants_admin != ask.pre_minted_id,
            // ONLY THE PROMOTION HALF. A bootstrap token that could set the flag
            // to `false` could remove every administrator in the deployment —
            // the exact denial-of-service an unattributable credential must not
            // be able to cause.
            Verb::SetUserAdmin => wants_admin,
            // **UNCONDITIONALLY, AND `wants_admin` IS DELIBERATELY IGNORED.**
            // `wants_admin` is the request's own `is_admin` field and AN
            // ENROLMENT REQUEST HAS NO SUCH FIELD — `admin_issue_enrolment`
            // passes `false` because there is no value being set, not because it
            // is asking for something lesser. So `Verb::IssueEnrolment =>
            // wants_admin` would refuse EVERY real enrolment while reading like
            // a narrowing, and there is no flag here to narrow with anyway. The
            // narrowing that ADR-0655 actually buys is the zero-credential
            // predicate at `iam-db`, inside the write; see the doc comment.
            Verb::IssueEnrolment => true,
            // NEVER (ADR-0945): a shared secret must not sign anybody out.
            Verb::RevokeCredentials => false,
            // NEVER (ADR-0972 (2)): an attested administrator only, and no
            // owner self-service either.
            Verb::ListCredentials | Verb::RevokeCredential => false,
        }
    }
}

/// Who this gateway decided is making one administrative call.
///
/// **TWO VARIANTS AND THEY ARE NOT INTERCHANGEABLE.** ADR-0492 rules two
/// authority mechanisms and "neither works alone"; this type is which of them
/// admitted THIS request, and every downstream difference — what the relay
/// carries, whether D73's self-demotion rule can even apply — follows from the
/// variant rather than from a flag somebody has to remember to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// An attested administrator: `iam` resolved their credential and answered
    /// `is_admin: true`. Their user id is a REAL identity, which is why D73's
    /// self-demotion rule is enforceable at the gateway and nowhere else.
    Administrator(String),
    /// The bootstrap token. **Nobody**, by construction — D73 calls a shared
    /// secret "unattributable by construction", and that is precisely why the
    /// `is_admin` flag exists beside it.
    Bootstrap,
}

impl Authority {
    /// ADR-0534's relay value for this call.
    ///
    /// # `None` on the bootstrap path, and NOT `Some(user_id: "")`
    ///
    /// **The empty actor is the false green.** `iam-db`'s reader filters empty
    /// ids and logs `<unattributed>` (`iam-db/src/service.rs:1554-1560`), so
    /// stamping `Some(UnverifiedActor { user_id: String::new() })` reaches the
    /// right OUTPUT by the wrong route — and then hides a bug where a REAL id was
    /// dropped, because the two are indistinguishable downstream. There is no
    /// actor on the bootstrap path; sending a message that says there is one and
    /// that it is nobody is a false record, not a null one.
    ///
    /// The variant is what makes that structural: `Authority::Bootstrap` carries
    /// no id to stamp, so the empty string is not available to be stamped by
    /// accident.
    ///
    /// # What the `Some` half is worth, stated so nobody overreads it
    ///
    /// ADR-0534: a recorded actor "is asserted by the caller and verified by
    /// nothing on the wire, so it MUST NOT be read as an authorisation input".
    /// Here it happens to be an id `iam` itself resolved — but `iam` cannot know
    /// that, and must not start believing it. It is useful during an incident and
    /// evidential in nothing.
    pub fn actor(&self) -> Option<UnverifiedActor> {
        match self {
            Authority::Administrator(user_id) => Some(UnverifiedActor {
                user_id: user_id.clone(),
            }),
            Authority::Bootstrap => None,
        }
    }

    /// ADR-0655's demand for this call:
    /// `IssueEnrolmentRequest.require_zero_credential_admin`.
    ///
    /// **`true` ON THE BOOTSTRAP PATH AND `false` ON THE ATTESTED ONE, and the
    /// `false` half is the load-bearing one.** An attested administrator's
    /// re-enrolment is the FORGOTTEN-PASSWORD RECOVERY path the contract
    /// documents (`iam.proto`: "a FRESH enrolment for an EXISTING user, redeemed,
    /// sets the password unconditionally"), and its target holds a credential by
    /// definition. Setting the demand there would refuse every recovery — and no
    /// gateway test would notice, because none of them enrols a credentialed
    /// user. The wire assertion in `tests/admin_http.rs` is the mirror that does.
    ///
    /// # A method rather than a `matches!` at the call site
    ///
    /// [`Authority`]'s own doc comment states the idiom this keeps: "every
    /// downstream difference follows from the VARIANT rather than from a flag
    /// somebody has to remember to read". The demand is such a difference, so it
    /// belongs beside [`Authority::actor`] where the next person adding a variant
    /// meets both at once — and it gives the property a unit-level assertion
    /// that does not need an HTTP request to reach it.
    ///
    /// # What this is NOT
    ///
    /// It is not an authorisation input and it is not an identity claim. The
    /// field only ever NARROWS what an insert can succeed against, so `iam-db`
    /// enforces it identically whoever set it — which is why the contract can
    /// say a direct in-cluster caller who sets it gets the same predicate rather
    /// than having to trust its sender.
    pub fn demands_zero_credential_admin(&self) -> bool {
        match self {
            Authority::Bootstrap => true,
            Authority::Administrator(_) => false,
        }
    }
}

/// The bootstrap-only rule of a pre-minted id (team access stage 3b, §6).
///
/// `true` when an ATTESTED administrator's `create-user` carries a `user_id`.
/// The caller answers that with the opaque 503 and makes no upstream call. A
/// caller-chosen id is needed only for the first administrator, who must be
/// named in GitOps before the user exists; every later user gets an id that
/// `iam-db` mints. `iam-db` would refuse the id anyway once an administrator
/// exists, and an attested administrator is one, so a defect here would still
/// be refused one tier down.
pub fn refuses_pre_minted_id(authority: &Authority, pre_minted_id: bool) -> bool {
    pre_minted_id && matches!(authority, Authority::Administrator(_))
}

/// The upstream form of a pre-minted id: `yadgar:user:` and the bare value, as
/// declared.
///
/// **NOT JUDGED HERE.** Body validation runs before authorization, so a format
/// check at this gateway would answer an unauthenticated caller (an oracle,
/// ADR-0927). `iam` checks the format and refuses a malformed id
/// `INVALID_ARGUMENT`, which answers the opaque 503.
pub fn upstream_user_id(bare: &str) -> String {
    format!("yadgar:user:{bare}")
}

/// D73's excluded case: an administrator removing their own flag.
///
/// # Why this is the gateway's and could not be `iam`'s
///
/// `iam.proto:664` defers it here by name — D73 "excludes admin SELF-demotion
/// from the first cut, which is a rule about who may call this and belongs in the
/// service rather than in the shape" — and `iam` cannot take it, because the only
/// caller identity `iam` has is `unverified_actor`, which ADR-0534 forbids
/// reading as an authorisation input. **At this boundary there is a real
/// identity**: `iam` resolved the credential, so `Authority::Administrator`
/// carries a user id nobody asserted about themselves.
///
/// # It is also the last-administrator guard, and that is worth stating exactly
///
/// Nothing in `iam` or `iam-db` counts administrators before clearing a flag
/// (`iam-db/src/service.rs:1341-1388` has no count check), so `/admin` is where
/// the count is protected or nowhere. It is protected, by two facts together
/// rather than by a count:
///
/// - The bootstrap token can only ever SET the flag ([`Verb::accepts_bootstrap`]),
///   so it can never reduce the number of administrators.
/// - An administrator cannot clear their OWN flag (this function).
///
/// So a demotion always has a demoter who stays an administrator, and `/admin`
/// cannot reach zero. **The residual is a race and it is named rather than
/// claimed away**: two administrators demoting each other are each authorised
/// against a CACHED `is_admin` (`YADGAR_CREDENTIAL_TTL_SECONDS`, shortened but
/// not closed by `SetUserAdmin`'s `CREDENTIAL_REVOKED` publish), so within that
/// window both can be admitted and the deployment can reach zero. Closing it
/// needs a count inside the write's own transaction, which is `iam-db`'s and
/// cannot be done from here.
pub fn is_self_demotion(authority: &Authority, target_user_id: &str, wants_admin: bool) -> bool {
    match authority {
        // NOT `!wants_admin` ALONE, and not `actor == target` alone. Promoting
        // yourself is a no-op for somebody who is already an administrator and
        // D73 excludes DEMOTION, so a rule that refused both would invent a
        // refusal the contract does not have.
        Authority::Administrator(actor) => !wants_admin && actor == target_user_id,
        // THE BOOTSTRAP PATH CANNOT REACH THIS CASE, and the reason is worth
        // reading rather than inferring: `accepts_bootstrap` refuses every
        // `SetUserAdmin` with `wants_admin == false`, so a demotion never
        // arrives here on this variant. `false` is the honest answer for "is this a self-demotion" —
        // there is no self — and it is not what admits the request.
        Authority::Bootstrap => false,
    }
}

#[cfg(test)]
mod tests;
