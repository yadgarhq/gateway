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

#[test]
fn the_acceptance_counter_is_named_the_thing_an_operator_alerts_on() {
    // AS A LITERAL, never through `ACCEPTED`. An assertion that read the
    // constant on both sides renames with it, so the series could be called
    // anything at all and stay green.
    //
    // This name is an INTERFACE and it is one whose only consumer is in
    // ANOTHER REPOSITORY: `deploy`'s `infra/prometheus.yaml` hard-codes it in
    // the `BootstrapTokenAccepted` rule, and nothing in that repository is
    // built or tested by this one. A rename here is a rule that matches
    // nothing there, which reads as a deployment where the bootstrap token
    // has never been accepted rather than as a broken metric — the precise
    // false negative this counter exists to remove.
    assert_eq!(ACCEPTED, "yadgar_gateway_bootstrap_accepted_total");
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
