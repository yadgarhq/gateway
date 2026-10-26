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

/// The bootstrap token's grant since team access stage 10, and every
/// excluded cell around it.
///
/// **The exclusions are the contract; the inclusions are the feature.** A
/// suite asserting only the `true` rows passes against a gateway that accepts
/// the bootstrap token everywhere.
///
/// **`IssueEnrolment` IS ADMITTED WHATEVER THE `Ask`** (ADR-0655 as amended by
/// ADR-0656, and ADR-0966's break-glass arm). Both of its rows are POSITIVE and
/// both are load-bearing: `admin_issue_enrolment` passes `Ask::plain()`, so an
/// arm gated on `pre_minted_id` would refuse every real enrolment while the
/// `pre_minted_id: true` row still passed. The plain row is what reds on that
/// mutation.
#[test]
fn the_bootstrap_token_reaches_the_declared_first_administrator_and_enrolment() {
    assert!(
        Verb::CreateUser.accepts_bootstrap(Ask {
            pre_minted_id: true
        }),
        "the F2 arm: the declared first administrator, by its pre-minted id"
    );
    assert!(
        !Verb::CreateUser.accepts_bootstrap(Ask::plain()),
        "stage 10: without a pre-minted id the bootstrap token reaches no create-user arm; \
         an ORDINARY account is a power ADR-0492 never granted an unattributable credential"
    );
    assert!(
        Verb::IssueEnrolment.accepts_bootstrap(Ask::plain()),
        "ADR-0655's grant and ADR-0966's break-glass arm: the enrolment predicate at `iam-db` \
         is what keeps that from being takeover"
    );
    assert!(
        Verb::IssueEnrolment.accepts_bootstrap(Ask {
            pre_minted_id: true
        }),
        "and it is admitted whatever the `Ask`"
    );
}

/// The pre-minted id widens `CreateUser` only. On every other verb it changes
/// nothing, so a handler that passed it by mistake could not open a verb.
#[test]
fn a_pre_minted_id_admits_no_other_verb() {
    for verb in [
        Verb::RevokeCredentials,
        Verb::ListCredentials,
        Verb::RevokeCredential,
    ] {
        assert!(
            !verb.accepts_bootstrap(Ask {
                pre_minted_id: true
            }),
            "{verb:?} must not be opened by a pre-minted id"
        );
    }
}

/// The bootstrap-only rule (§6): an ATTESTED administrator's `create-user`
/// with a `user_id` is refused after authorization; the bootstrap path is not.
#[test]
fn red_06_a_pre_minted_id_is_bootstrap_only() {
    assert!(
        refuses_pre_minted_id(
            &Authority::Administrator("yadgar:user:abc".to_string()),
            true
        ),
        "an attested administrator never names the id of the user it creates"
    );
    assert!(!refuses_pre_minted_id(&Authority::Bootstrap, true));
    assert!(
        !refuses_pre_minted_id(
            &Authority::Administrator("yadgar:user:abc".to_string()),
            false
        ),
        "red 9: without a `user_id` the attested path is today's"
    );
    assert!(!refuses_pre_minted_id(&Authority::Bootstrap, false));
}

/// The bare uuid is sent upstream with the prefix, byte for byte, and the
/// gateway does not judge its format (ADR-0927).
#[test]
fn the_pre_minted_id_is_prefixed_and_not_judged() {
    assert_eq!(
        upstream_user_id("0192f3c1-8a4e-7c2d-9b11-5f0e7a3d84c6"),
        "yadgar:user:0192f3c1-8a4e-7c2d-9b11-5f0e7a3d84c6"
    );
    assert_eq!(upstream_user_id("NOT A UUID"), "yadgar:user:NOT A UUID");
}

/// ADR-0945: the bootstrap token never reaches `RevokeCredentials`, whatever
/// the `Ask`. Both values are asserted so that an `ask`-gated arm cannot pass.
#[test]
fn the_bootstrap_token_never_revokes_credentials() {
    for pre_minted_id in [true, false] {
        assert!(
            !Verb::RevokeCredentials.accepts_bootstrap(Ask { pre_minted_id }),
            "the bootstrap token must never revoke credentials"
        );
    }
}

/// ADR-0972 (2): listing and revoking one credential are for an attested
/// administrator only. Both values, for the reason the test above gives.
#[test]
fn the_bootstrap_token_never_lists_or_revokes_one_credential() {
    for verb in [Verb::ListCredentials, Verb::RevokeCredential] {
        for pre_minted_id in [true, false] {
            assert!(
                !verb.accepts_bootstrap(Ask { pre_minted_id }),
                "the bootstrap token must never reach {verb:?}"
            );
        }
    }
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

/// ADR-0655's demand follows the VARIANT, in both directions.
///
/// **BOTH ROWS, because either alone is worthless.** The `true` row alone passes
/// against a handler that demands the predicate unconditionally — which refuses
/// every forgotten-password recovery (§8.1). The `false` row alone passes against
/// one that never demands it — which is the live unrestricted grant, because
/// proto3 reads the absent bool as `false` and `iam-db` takes the ordinary path.
#[test]
fn only_the_bootstrap_path_demands_a_zero_credential_admin() {
    assert!(
        Authority::Bootstrap.demands_zero_credential_admin(),
        "the bootstrap token's enrolment is admitted ONLY under the predicate, so the demand is \
         what makes ADR-0655's grant narrow rather than total"
    );
    assert!(
        !Authority::Administrator("yadgar:user:abc".to_string()).demands_zero_credential_admin(),
        "an attested administrator demands nothing: their re-enrolment is the documented \
         forgotten-password recovery and its target holds a credential by definition"
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

/// Ruling (b) (Max, 2026-10-24): the switch reads exactly `"1"` or `"0"`, and
/// refuses absence and every other spelling (ADR-0569: no compiled-in default).
#[test]
fn the_pre_minted_switch_reads_one_or_zero_and_nothing_else() {
    let read = |value: Option<&str>| {
        PreMintedIds::from_lookup(|key| {
            assert_eq!(key, REFUSE_PRE_MINTED_USER_ID);
            value.map(str::to_string)
        })
    };
    assert_eq!(read(Some("1")).ok(), Some(PreMintedIds::Refused));
    assert_eq!(read(Some("0")).ok(), Some(PreMintedIds::Admitted));
    assert!(matches!(read(None), Err(PreMintedIdsError::Absent)));
    for other in ["", "true", "false", "yes", " 1", "1 ", "01"] {
        let refusal = read(Some(other)).expect_err(other).to_string();
        assert!(
            refusal.contains(REFUSE_PRE_MINTED_USER_ID)
                && refusal.contains("adminBootstrap.refusePreMintedUserId"),
            "{other:?}: the refusal names the variable and the chart key: {refusal}"
        );
    }
    let absent = read(None).expect_err("absent").to_string();
    assert!(
        absent.contains("adminBootstrap.refusePreMintedUserId"),
        "{absent}"
    );
}

/// Ruling (b): the engaged switch reaches the pre-minted `create-user` arm
/// and no other request; the disengaged one reaches nothing.
#[test]
fn the_pre_minted_switch_reaches_only_the_pre_minted_arm() {
    let pre_minted = Ask {
        pre_minted_id: true,
    };
    assert!(PreMintedIds::Refused.refuses(Verb::CreateUser, pre_minted));
    assert!(!PreMintedIds::Admitted.refuses(Verb::CreateUser, pre_minted));
    for verb in [
        Verb::CreateUser,
        Verb::IssueEnrolment,
        Verb::RevokeCredentials,
        Verb::ListCredentials,
        Verb::RevokeCredential,
    ] {
        assert!(
            !PreMintedIds::Refused.refuses(verb, Ask::plain()),
            "{verb:?} without a pre-minted id is out of the switch's reach"
        );
        assert!(!PreMintedIds::Admitted.refuses(verb, Ask::plain()));
    }
}
