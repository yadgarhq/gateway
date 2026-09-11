//! The administrative surface's decisions, apart from its plumbing (ADR-0492,
//! D73, ledger 638).
//!
//! `http.rs` owns the three handlers — the routes, the bodies, the upstream
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
//! 3. **[`Authority::actor`]** — what ADR-0534's relay carries, and on which path
//!    it carries nothing.
//! 4. **[`is_self_demotion`]** — D73's exclusion, which `iam.proto:664` defers to
//!    the gateway by name because it "is a rule about who may call this".
//!
//! **None of these reads `unverified_actor`** (ADR-0534 forbids authorising on
//! it) and none of them is reachable from `tools::call`: an administrative verb
//! is never an MCP tool (ADR-0492), so nothing here is a member of
//! [`crate::tools::SERVED`] and nothing here is dispatched by name.

use sha2::{Digest, Sha256};

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
/// not acceptances — and replaces nothing here.)
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
/// `CreateUser`, `SetUserAdmin` and, since ADR-0655, `IssueEnrolment`. That label
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

/// The three administrative verbs `/admin` serves.
///
/// **A CLOSED ENUM RATHER THAN A STRING**, for `tools::SERVED`'s reason one
/// module over: the set has to be stated once so that widening it is an edit to
/// the set rather than an arm added somewhere nobody is looking. Every rule below
/// matches on it exhaustively, so a fourth verb does not compile until each rule
/// has said what it means for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// `iam.CreateUser`. The FIRST admin verb, and the one the bootstrap token
    /// reaches when — and only when — the user being created is an admin.
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
}

impl Verb {
    /// Whether the BOOTSTRAP TOKEN authorises this request.
    ///
    /// `wants_admin` is the request's own `is_admin` field — the value being
    /// SET, not a fact about the caller. It is a parameter rather than a lookup
    /// because the rule is about the request and not about the deployment.
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
    pub fn accepts_bootstrap(self, wants_admin: bool) -> bool {
        match self {
            // ONLY WITH THE FLAG SET. `false` here is an ordinary account, which
            // is the power that was never granted.
            Verb::CreateUser => wants_admin,
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
        }
    }
}

/// This deployment's bootstrap token, as this process holds it.
///
/// # Two rules, and they are two different bugs (§7.2, and the Secret's own manifest)
///
/// `deploy`'s `infra/bootstrap/admin-bootstrap-token.yaml` states the consumer
/// contract this type exists to keep, in two numbered halves, "stated separately
/// because they are two different bugs":
///
/// 1. **An ABSENT OR EMPTY secret DISABLES the bootstrap path**, which refuses
///    every request on it with a status naming the missing configuration — never
///    a comparison against a missing value. That is [`Bootstrap::NotConfigured`].
/// 2. **An ABSENT secret is NEVER EQUAL to a PRESENTED one.** "(1) is about the
///    route's configuration, this is about the comparator. A constant-time
///    comparator written to compare two EMPTY inputs returns TRUE — so 'no secret
///    configured' must short-circuit to refusal before any comparison runs, never
///    fall through into one."
///
/// **The `Option` is how half 2 is made structural rather than remembered.** An
/// absent secret is not a `String` that happens to be empty; it is a variant with
/// no bytes in it at all, so there is nothing for a comparator to be handed. The
/// only way to reintroduce the bug is to write a default INTO the `None` arm,
/// which is a visible act rather than an omission.
///
/// # This is NOT ADR-0569's ordinary rule, and the difference is deliberate
///
/// ADR-0569 would make an absent knob refuse the BOOT, naming it. Applied here
/// that takes MCP and `/auth/login` down over an administrative knob — "an outage
/// priced far above the gap". Serve-and-disable-one-path is the shape of `iam`'s
/// own argued exception (`iam/src/service.rs:458-470,490`), whose reasoning
/// transfers exactly. Both readings are fail-closed for the admin path; this one
/// is fail-closed without collateral.
#[derive(Debug, Clone)]
pub struct BootstrapToken(Option<[u8; 32]>);

/// What [`BootstrapToken::check`] decided.
///
/// **THREE OUTCOMES AND NOT TWO**, because the caller must answer
/// [`Bootstrap::NotConfigured`] differently: a deployment whose Secret is not
/// mounted has an operator problem, and collapsing it into the refusal every
/// wrong token gets would leave that operator reading "forbidden" and looking for
/// a permission they already have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bootstrap {
    /// No secret is configured. **The whole path is disabled** — this is the
    /// answer for every request on it, whatever was presented, and no comparison
    /// was performed to reach it.
    NotConfigured,
    /// A secret is configured, and what was presented is not it.
    Refused,
    /// A secret is configured and what was presented equals it.
    Accepted,
}

impl BootstrapToken {
    /// The disabled token: no secret, so no bootstrap request is ever accepted.
    ///
    /// **The default a deployment gets before its Secret is mounted**, and the
    /// state the route ships in until the chart grows the mount. That is the
    /// manifest's own expectation — "Until the consumer lands, this Secret sits
    /// unread" — rather than a degraded mode.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// The token this deployment holds, from the mounted Secret's contents.
    ///
    /// **BLANK COUNTS AS ABSENT**, and it is `trim` that decides, not
    /// `is_empty`: a Secret whose value is a newline is a Secret nobody set, and
    /// a file that arrived with trailing whitespace is the same token. `iam`'s
    /// `ca_pem` guard tests blankness rather than emptiness for the same reason
    /// and the two were written independently.
    ///
    /// **The DIGEST is stored, not the token.** It makes the comparison
    /// fixed-width whatever was presented — so the comparison cannot leak a
    /// length — and it keeps the secret itself out of every `Debug` rendering of
    /// `AppState` this process might ever write to a log.
    pub fn from_secret(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::disabled();
        }
        Self(Some(digest(trimmed)))
    }

    /// Whether a secret is configured at all.
    ///
    /// For the boot log, which says which of the two states this process is in.
    /// It is deliberately NOT what the handlers branch on — they branch on
    /// [`Self::check`], which answers the same question and the comparison in one
    /// step, so no caller can check one and forget the other.
    pub fn is_configured(&self) -> bool {
        self.0.is_some()
    }

    /// Judge one presented token.
    pub fn check(&self, presented: &str) -> Bootstrap {
        // RULE 1, AND IT RETURNS BEFORE ANY COMPARISON EXISTS. There is no
        // `unwrap_or_default` here and there must never be one: an absent secret
        // defaulted to `""` and then compared is precisely the bug rule 2 is
        // written down separately to prevent, and a constant-time comparator over
        // two empty inputs answers TRUE.
        let Some(want) = self.0 else {
            return Bootstrap::NotConfigured;
        };
        // A PRESENTED EMPTY VALUE IS REFUSED WITHOUT BEING HASHED. The digest
        // comparison below would refuse it anyway — `digest("")` equals no
        // configured secret's digest — so this line buys the property WITHOUT
        // depending on that, which is what makes rule 2 hold for reasons a reader
        // can check rather than for reasons SHA-256 happens to have.
        if presented.is_empty() {
            return Bootstrap::Refused;
        }
        if constant_time_eq(&want, &digest(presented)) {
            Bootstrap::Accepted
        } else {
            Bootstrap::Refused
        }
    }
}

/// SHA-256 of one token.
fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// Compare two digests without an early exit.
///
/// **FIXED WIDTH BY CONSTRUCTION**, because both sides are digests: there is no
/// length to compare first and therefore no length to leak. The accumulator is
/// OR-ed over every byte and read once at the end, so the loop takes the same
/// path whatever the inputs are — the whole point of not using `==` on the
/// secrets themselves.
///
/// `#[inline(never)]` so the comparison stays one function a reader can find,
/// rather than something the optimiser has spread across a caller.
#[inline(never)]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut differing = 0u8;
    for i in 0..32 {
        differing |= a[i] ^ b[i];
    }
    differing == 0
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
        // reading rather than inferring: `accepts_bootstrap` already refused
        // every `wants_admin == false`, so a demotion never arrives here on this
        // variant. `false` is the honest answer for "is this a self-demotion" —
        // there is no self — and it is not what admits the request.
        Authority::Bootstrap => false,
    }
}

#[cfg(test)]
mod tests;
