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
//!    under which condition. ADR-0492 grants it two and `iam.proto:650-656`
//!    states the same exclusion from `iam`'s side: "create an admin, or promote
//!    one … IT IS CHECKED AT THE GATEWAY".
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
    /// **The bootstrap token never reaches it.**
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
    /// **`IssueEnrolment` is the exclusion a reader is most likely to argue
    /// with**, because handing the new admin their enrolment blob is the obvious
    /// next step in the ceremony. It is still excluded: an enrolment token
    /// redeems into a credential for an ARBITRARY user id, so a bootstrap token
    /// that reached it could mint a login for anybody who already exists, admin
    /// or not. That is not "create an admin"; it is account takeover with an
    /// unattributable credential. The ceremony's second step is taken by the
    /// administrator the first step created, logging in first.
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
            // NEVER, on any value of anything. See the doc comment above.
            Verb::IssueEnrolment => false,
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
mod tests {
    use super::*;

    /// A token from a CSPRNG has no structure; these two are literals so the test
    /// does not depend on how the deployment mints one.
    const SECRET: &str = "wDGqZ4t7mQx1sV9k";
    const WRONG: &str = "wDGqZ4t7mQx1sV9j";

    #[test]
    fn an_absent_secret_disables_the_path_rather_than_being_compared() {
        let token = BootstrapToken::disabled();
        assert!(!token.is_configured());
        // THE PRESENTED VALUE DOES NOT MATTER, which is the property: no
        // comparison ran, so nothing about what was sent could have changed the
        // answer.
        assert_eq!(token.check(""), Bootstrap::NotConfigured);
        assert_eq!(token.check(SECRET), Bootstrap::NotConfigured);
        assert_eq!(token.check("anything at all"), Bootstrap::NotConfigured);
    }

    /// §7.2's rule 2, as its own test: the empty presented token.
    ///
    /// **This is the assertion that reds when somebody defaults the absent secret
    /// to `""` and compares.** A constant-time comparator over two empty inputs
    /// answers TRUE, so the mutation turns this exact call into
    /// `Bootstrap::Accepted` — a stranger becoming an administrator by presenting
    /// nothing.
    #[test]
    fn an_absent_secret_is_never_equal_to_an_empty_presented_one() {
        assert_eq!(
            BootstrapToken::disabled().check(""),
            Bootstrap::NotConfigured,
            "an empty token against no secret must be the DISABLED answer, never a match"
        );
    }

    /// A blank file is a Secret nobody set.
    #[test]
    fn a_blank_secret_is_an_absent_one() {
        for blank in ["", " ", "\n", "  \t\n "] {
            let token = BootstrapToken::from_secret(blank);
            assert!(!token.is_configured(), "{blank:?} configures nothing");
            assert_eq!(token.check(""), Bootstrap::NotConfigured);
            assert_eq!(token.check("x"), Bootstrap::NotConfigured);
        }
    }

    #[test]
    fn a_configured_secret_accepts_itself_and_refuses_everything_else() {
        let token = BootstrapToken::from_secret(SECRET);
        assert!(token.is_configured());
        assert_eq!(token.check(SECRET), Bootstrap::Accepted);
        assert_eq!(token.check(WRONG), Bootstrap::Refused);
        // THE FOURTH CELL of the matrix, and the one a suite that only tests the
        // absent-secret half would leave out: a secret IS configured and the
        // caller presents nothing.
        assert_eq!(
            token.check(""),
            Bootstrap::Refused,
            "an empty presented token is refused, never matched against a real secret"
        );
        // A PREFIX, because a comparator that stopped at the shorter length would
        // accept it.
        assert_eq!(token.check(&SECRET[..4]), Bootstrap::Refused);
    }

    /// Surrounding whitespace on the FILE is trimmed; on the PRESENTED value it
    /// is not.
    ///
    /// The asymmetry is deliberate. A mounted file may carry a trailing newline
    /// nobody put there; a header value is exactly what a caller wrote, and
    /// trimming it would make two different presented tokens the same token.
    #[test]
    fn the_file_is_trimmed_and_the_presented_value_is_not() {
        let token = BootstrapToken::from_secret(&format!("{SECRET}\n"));
        assert_eq!(token.check(SECRET), Bootstrap::Accepted);
        assert_eq!(token.check(&format!("{SECRET}\n")), Bootstrap::Refused);
    }

    /// ADR-0492's grant, and every excluded cell around it.
    ///
    /// **The exclusions are the contract; the inclusions are the feature.** A
    /// suite asserting only the two `true` rows passes against a gateway that
    /// accepts the bootstrap token everywhere.
    #[test]
    fn the_bootstrap_token_reaches_exactly_create_an_admin_and_promote_to_admin() {
        assert!(
            Verb::CreateUser.accepts_bootstrap(true),
            "create an admin: ADR-0492's first grant"
        );
        assert!(
            Verb::SetUserAdmin.accepts_bootstrap(true),
            "promote to admin: ADR-0492's second grant"
        );

        assert!(
            !Verb::CreateUser.accepts_bootstrap(false),
            "an ORDINARY account is a power ADR-0492 never granted an unattributable credential"
        );
        assert!(
            !Verb::SetUserAdmin.accepts_bootstrap(false),
            "demotion would let a shared secret remove every administrator in the deployment"
        );
        assert!(
            !Verb::IssueEnrolment.accepts_bootstrap(true),
            "an enrolment mints a credential for an ARBITRARY user, which is takeover and not \
             bootstrap"
        );
        assert!(
            !Verb::IssueEnrolment.accepts_bootstrap(false),
            "and it is excluded on every value of the flag, not only on one"
        );
    }

    /// §6, and the row §9 names: assert ABSENCE, not an empty string.
    #[test]
    fn the_bootstrap_path_stamps_no_actor_at_all() {
        assert_eq!(
            Authority::Bootstrap.actor(),
            None,
            "an empty actor reaches iam-db's `<unattributed>` by the WRONG route and hides a \
             dropped id"
        );
    }

    #[test]
    fn an_administrator_stamps_their_resolved_id() {
        assert_eq!(
            Authority::Administrator("yadgar:user:abc".to_string()).actor(),
            Some(UnverifiedActor {
                user_id: "yadgar:user:abc".to_string(),
            })
        );
    }

    /// D73's exclusion, and the three neighbouring cells that must NOT be refused.
    #[test]
    fn an_administrator_cannot_clear_their_own_flag() {
        let me = Authority::Administrator("yadgar:user:me".to_string());

        assert!(
            is_self_demotion(&me, "yadgar:user:me", false),
            "D73 excludes admin self-demotion, and this boundary is the only one with a real \
             identity to test it against"
        );
        assert!(
            !is_self_demotion(&me, "yadgar:user:other", false),
            "demoting SOMEBODY ELSE is the feature, and the demoter stays an administrator — \
             which is what keeps the count above zero"
        );
        assert!(
            !is_self_demotion(&me, "yadgar:user:me", true),
            "D73 excludes DEMOTION; refusing a self-promotion would invent a rule the contract \
             does not have"
        );
        assert!(
            !is_self_demotion(&Authority::Bootstrap, "yadgar:user:me", false),
            "there is no self on the bootstrap path — and `accepts_bootstrap` already refused \
             this request before it could reach here"
        );
    }
}
