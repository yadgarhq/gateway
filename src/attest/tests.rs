// The items under test now live in `super`'s two submodules. The GLOBS are what
// keep every test body below unchanged: this is the only edit the split made to
// this file.
use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tonic::transport::Channel;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::pb::yadgar::common::v1::InheritedSetting;
use crate::pb::yadgar::iam::v1::{RateLimitOverride, ResolveCredentialResponse};

use super::cache::*;
use super::resolve::*;
use super::*;
use crate::pb::yadgar::common::v1::SettingValue;
use crate::pb::yadgar::iam::v1::RateLimit;

/// A lookup over a fixed table, standing in for the process environment.
fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// A channel to a closed port.
///
/// `connect_lazy` needs a reactor in scope even though it dials nothing, so
/// every caller is a `#[tokio::test]`.
fn nowhere() -> Channel {
    tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy()
}

/// **`..Default::default()` rather than a full literal, deliberately.**
/// `ResolveCredentialResponse` gained two fields at contract v1.6.0, and an
/// exhaustive literal in a fixture turns the next additive contract change
/// into a compile error in a test that does not care about the new field.
/// A LIVE credential, as `iam` returns one.
///
/// `valid_for_seconds` is set explicitly and is load-bearing: `iam` writes
/// `if resolved { 300 } else { 0 }`, and `from_resolved` refuses a zero. A
/// fixture that left it at its `Default` would be the negative answer, and
/// every test built on it would assert against a refusal.
fn resolved(user_id: &str) -> ResolveCredentialResponse {
    ResolveCredentialResponse {
        user_id: user_id.to_string(),
        team_ids: vec!["team-a".to_string()],
        valid_for_seconds: 300,
        ..Default::default()
    }
}

#[test]
fn only_the_exact_string_one_enables_trusted_headers() {
    // MUTATION THIS CATCHES: `== Some("1")` relaxed to `.is_some()`, or to any
    // truthiness parse. Under it, `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=0` —
    // written by somebody deliberately turning the setting OFF — turns
    // authentication off instead, and the gateway trusts whatever the caller
    // claims.
    assert!(matches!(
        Attestation::from_lookup(env(&[(TRUST_HEADERS, "1")])),
        Attestation::TrustedHeaders
    ));
    for off in ["0", "false", "no", "", "true", "yes"] {
        assert!(
            matches!(
                Attestation::from_lookup(env(&[(TRUST_HEADERS, off)])),
                Attestation::Iam
            ),
            "{off:?} must not enable trusted headers"
        );
    }
}

#[test]
fn an_unset_environment_attests_against_iam() {
    // THE DIRECTION OF THIS TEST IS THE POINT, and it is the opposite of what
    // it used to assert. An unconfigured process once refused to start,
    // because the only default available was trusting the caller. The default
    // is the verified source now, so forgetting a variable can no longer reach
    // the trusting one — which is what makes the boot gate unnecessary rather
    // than merely removed.
    assert!(matches!(
        Attestation::from_lookup(env(&[])),
        Attestation::Iam
    ));
    assert!(matches!(Attestation::default(), Attestation::Iam));
}

#[test]
fn the_user_comes_from_the_resolved_credential() {
    // A value no header in this process could have supplied and no default
    // could produce.
    let attested = from_resolved(
        resolved("u-from-the-token"),
        Some("acme/demo"),
        Some("i-1"),
        "REQ-1".to_string(),
    )
    .expect("a resolved credential attests");
    assert_eq!(attested.scope.user_id, "u-from-the-token");
    assert_eq!(attested.scope.request_id, "REQ-1");
    // CLAIMED, and still claimed: a workspace is not a fact about a credential.
    assert_eq!(attested.scope.project_id, "acme/demo");
    assert_eq!(attested.scope.instance_id, "i-1");
    // From the response, and reachable no other way (D12).
    assert_eq!(attested.scope.team_ids, vec!["team-a".to_string()]);
}

#[test]
fn the_negative_answer_is_a_refusal_and_never_an_attestation() {
    // `iam` reports "no live credential" as `Ok` with an empty response, and
    // reading that as a success was an authentication bypass: `Bearer
    // <anything>` attested as `user_id: ""`. `iamdb.proto`: "Empty user_id
    // means no live credential matched. NOT an error… one is a 401, the other
    // is a 503." This gateway is the one that owes the 401.
    //
    // Asserted at the DEFAULT, which is the exact shape `iam` sends: an
    // `is_empty()` check written against a hand-built fixture would pass while
    // missing the response actually on the wire.
    let err = from_resolved(
        ResolveCredentialResponse::default(),
        Some("acme/demo"),
        None,
        "REQ-6".to_string(),
    )
    .expect_err("an unresolvable credential must not attest");
    assert!(
        matches!(err, AttestError::Upstream(tonic::Code::Unauthenticated)),
        "the negative answer is a refusal, not an outage; got {err:?}"
    );

    // EITHER SIGNAL ALONE REFUSES. `iam` writes both together today, and
    // checking both is what keeps a regression on one of them from being
    // believed.
    for answer in [
        ResolveCredentialResponse {
            user_id: String::new(),
            valid_for_seconds: 300,
            ..Default::default()
        },
        ResolveCredentialResponse {
            user_id: "u".to_string(),
            valid_for_seconds: 0,
            ..Default::default()
        },
    ] {
        assert!(
            matches!(
                from_resolved(answer, Some("acme/demo"), None, "REQ-7".to_string()),
                Err(AttestError::Upstream(tonic::Code::Unauthenticated))
            ),
            "half a negative answer is still a negative answer"
        );
    }
}

/// ADR-0522's setting as an organisation that has actually stated one sends
/// it: a value, an ENGAGED lock, and one team holding a contradicting
/// override. Every field differs from its `Default`, so a handler that
/// rebuilt the message instead of moving it cannot produce this by accident.
fn stated() -> InheritedSetting {
    InheritedSetting {
        org_value: SettingValue::On as i32,
        org_locked: true,
        team_override: HashMap::from([("team-zulu-4417".to_string(), SettingValue::Off as i32)]),
    }
}

#[test]
fn the_setting_travels_from_iam_onto_the_scope_whole() {
    // ADR-0522's setting reaches a -db on `Scope` and nowhere else, so this
    // move is the entire contribution the gateway makes to it. `tools::call`
    // takes the `Scope` by value and puts it on every TaskService request, so
    // populating it here is what puts it on all of them.
    //
    // MUTATION THIS CATCHES: rebuilding the message field by field instead of
    // moving it. Dropping `team_override` and flipping either scalar are each
    // caught, because no field here holds its `Default`.
    let answer = ResolveCredentialResponse {
        owner_reads_own_record: Some(stated()),
        ..resolved("u-whiskey-2085")
    };
    let attested = from_resolved(answer, Some("acme/demo"), None, "REQ-8".to_string())
        .expect("a resolved credential attests");
    assert_eq!(
        attested.scope.owner_reads_own_record,
        Some(stated()),
        "the setting must arrive exactly as `iam` sent it"
    );
}

#[test]
fn an_iam_that_states_no_setting_leaves_it_absent_rather_than_defaulted() {
    // MUTATION THIS CATCHES, AND IT IS THE ONE THE WHOLE FIELD EXISTS TO
    // SURVIVE: `resolved.owner_reads_own_record.unwrap_or_default()`. That
    // substitutes `InheritedSetting { org_value: UNSPECIFIED, org_locked:
    // false, team_override: {} }` for absence — and `common.proto` says an
    // absent message and a present one holding UNSPECIFIED are ONE case that
    // an enforcing -db must REFUSE. Under the mutant a gateway too old to be
    // talking to a setting-aware `iam` would hand down a present message
    // stating nothing, and the refusal that makes the whole setting safe
    // becomes unreachable.
    //
    // THE ASSERTION IS ON PRESENCE, NOT ON A FIELD. Every field of the
    // substituted default equals the field of an absent message read through
    // prost, so `org_value == UNSPECIFIED` would pass against the mutant and
    // the test would be green for the wrong reason.
    let attested = from_resolved(
        resolved("u-xray-3390"),
        Some("acme/demo"),
        None,
        "REQ-9".to_string(),
    )
    .expect("a resolved credential attests");
    assert!(
        attested.scope.owner_reads_own_record.is_none(),
        "an unset setting is absence, never a default"
    );
}

#[test]
fn an_unstated_organisation_row_travels_as_sent_rather_than_being_filled_in() {
    // `iam-db` encodes an ABSENT organisation row as `org_value` UNSPECIFIED
    // with `org_locked` FALSE — and false is the PERMISSIVE half of a policy
    // nobody stated. `common.proto` calls org_locked's zero the unsafe
    // direction for exactly this reason.
    //
    // MUTATION THIS CATCHES: any line that reads an UNSPECIFIED org_value as a
    // signal to supply ADR-0522's shipped default — `org_value: ON,
    // org_locked: true`. That default belongs in the STORE, where an operator
    // can see and change it; minted here it is a value the deployment never
    // stated, travelling as though it had, and the refusal a -db owes on it
    // never fires.
    //
    // PAIRED WITH THE TEST ABOVE, AND THEY DIFFER ONLY IN PRESENCE. The
    // contract says these two mean the same thing to a reader; on this hop
    // they are still two distinct wire states, and the gateway's job is to
    // forward whichever one it got rather than to collapse them.
    let empty = InheritedSetting {
        org_value: SettingValue::Unspecified as i32,
        org_locked: false,
        team_override: HashMap::new(),
    };
    let answer = ResolveCredentialResponse {
        owner_reads_own_record: Some(empty.clone()),
        ..resolved("u-yankee-7724")
    };
    let attested = from_resolved(answer, Some("acme/demo"), None, "REQ-10".to_string())
        .expect("a resolved credential attests");
    assert_eq!(
        attested.scope.owner_reads_own_record,
        Some(empty),
        "an organisation that stated nothing must not be made to have stated something"
    );
}

#[tokio::test]
async fn the_trusted_header_path_states_no_policy_rather_than_inventing_one() {
    // THE OTHER ARM, AND IT IS HERE BECAUSE ONE-ARM COVERAGE IS THIS ESTATE'S
    // STANDING FAILURE. `attest` branches on `Attestation`, and a suite whose
    // cases all resolve a credential leaves a mutant in the header arm alive:
    // that arm could mint `Some(InheritedSetting::default())`, or ADR-0522's
    // shipped default, and every test above would still pass.
    //
    // ABSENCE IS THE HONEST ANSWER, for the reason `team_ids: Vec::new()` and
    // `Overrides::default()` are on this same arm: nothing was resolved, and
    // no header can carry a policy — a caller who could name its own would
    // name the permissive one. An enforcing -db REFUSES an absent setting, so
    // a development gateway pointed at one fails loudly rather than reading
    // its own invention as an organisation's policy.
    let attested = attest(
        &Attestation::TrustedHeaders,
        &nowhere(),
        &Credentials::new(TEST_TTL),
        None,
        Claimed {
            user_id: Some("max"),
            project_id: Some("acme/demo"),
            instance_id: None,
        },
        "REQ-11".to_string(),
    )
    .await
    .expect("complete claim attests");
    assert!(
        attested.scope.owner_reads_own_record.is_none(),
        "a path with no policy source states no policy"
    );
}

#[test]
fn a_resolved_credential_without_a_project_is_refused_rather_than_defaulted() {
    // An empty project reads as "everything", not as "none": D12 scopes
    // records by it, so defaulting one is a widening nobody asked for.
    //
    // **THE VARIANT IS ASSERTED BECAUSE THE VARIANT IS THE DIAGNOSIS.** This
    // refusal is reached with a credential `iam` has already RESOLVED, so
    // reporting it as a missing identity is the false diagnosis ledger 739 is
    // about. `MissingIdentity(_)` would still match a refusal that had gone
    // back to blaming the credential, which is the mutation this test exists
    // to catch.
    let err = from_resolved(resolved("u"), None, None, "REQ-2".to_string())
        .expect_err("a missing project must not become an empty one");
    assert!(
        matches!(err, AttestError::MissingWorkspace(_)),
        "a resolved credential with no workspace is not an identity problem; got {err:?}"
    );
}

#[test]
fn overrides_arrive_under_the_key_the_limiter_looks_them_up_by() {
    // MUTATION THIS CATCHES: keying on the proto's enum NAME (`Write`,
    // `KIND_WRITE`) instead of `kind_str`. Nothing fails — the override is
    // simply never found, and a limit an admin set does nothing at all. So
    // this asserts THROUGH `Limits::effective`, the only reader that matters,
    // rather than against the string this code chose for itself.
    let overrides = overrides_from(vec![RateLimitOverride {
        module: "task".to_string(),
        kind: Kind::Write as i32,
        limit: Some(RateLimit {
            rate: 3.0,
            burst: 7,
        }),
    }])
    .expect("a well-formed override is enforceable");
    let limits = crate::limit::Limits::parse("task.write=1:1", "1:1").expect("limits parse");
    let effective = limits.effective("task", Kind::Write, &overrides);
    assert_eq!(effective.rate, 3.0);
    assert_eq!(effective.burst, 7.0);
    // And the bucket NOBODY overrode still comes from configuration.
    assert_eq!(limits.effective("task", Kind::Read, &overrides).rate, 1.0);
}

#[test]
fn an_override_that_cannot_be_enforced_refuses_the_whole_credential() {
    // `rate = 0` is the contract's DENY. `limit::validate` refuses it because
    // the script turns a zero rate into a permanent lockout with a 24-hour
    // `Retry-After`, so it cannot be honoured as written — and dropping it
    // would apply the configured default instead, silently undoing an admin.
    let err = overrides_from(vec![RateLimitOverride {
        module: "task".to_string(),
        kind: Kind::Write as i32,
        limit: Some(RateLimit {
            rate: 0.0,
            burst: 0,
        }),
    }])
    .expect_err("a bucket this gateway cannot enforce must not be dropped");
    assert!(matches!(err, ConfigError::NotPositive(_, _)));
}

#[test]
fn an_entry_with_no_limit_is_no_override_and_not_a_denial() {
    // THE CONTRACT'S OWN INSTRUCTION: an unset `limit` is how an override is
    // CLEARED, so one still in the list is a server bug that "must be read as
    // no override for that bucket rather than as a denial". Reading it as a
    // denial is what `unwrap_or_default()` does — rate 0, burst 0 — and it
    // would refuse the credential outright.
    let overrides = overrides_from(vec![RateLimitOverride {
        module: "task".to_string(),
        kind: Kind::Write as i32,
        limit: None,
    }])
    .expect("a cleared override is not an error");
    assert!(overrides.is_empty());

    // AND NOTHING ELSE ABOUT A CLEARED ENTRY CAN BE WRONG, which is why the
    // `limit` check runs FIRST. It used to run after the kind and module
    // checks, so a cleared override carrying `KIND_JOB` — a server bug in a
    // field that no longer means anything — refused the whole credential,
    // turning "no override for that bucket" into exactly the denial the
    // contract says it must not be read as.
    let odd = overrides_from(vec![RateLimitOverride {
        module: String::new(),
        kind: Kind::Job as i32,
        limit: None,
    }])
    .expect("a cleared override is skipped before anything else is judged");
    assert!(odd.is_empty());
}

#[test]
fn a_kind_this_gateway_has_no_bucket_for_is_refused() {
    // KIND_JOB is outside D74's mechanism and KIND_UNSPECIFIED is a zero value
    // nothing should construct. Accepting either mints a key
    // `Limits::effective` can never be asked for.
    for kind in [Kind::Job, Kind::Unspecified] {
        let err = overrides_from(vec![RateLimitOverride {
            module: "task".to_string(),
            kind: kind as i32,
            limit: Some(RateLimit {
                rate: 1.0,
                burst: 1,
            }),
        }])
        .expect_err("this kind has no bucket");
        assert!(matches!(err, ConfigError::UnknownKind(_)), "{kind:?}");
    }
}

#[tokio::test]
async fn scope_carries_the_request_id_it_was_given() {
    let attested = attest(
        &Attestation::TrustedHeaders,
        &nowhere(),
        &Credentials::new(Duration::from_secs(30)),
        None,
        Claimed {
            user_id: Some("max"),
            project_id: Some("acme/demo"),
            instance_id: Some("i-1"),
        },
        "REQ-3".to_string(),
    )
    .await
    .expect("complete claim attests");
    assert_eq!(attested.scope.request_id, "REQ-3");
    assert_eq!(attested.scope.user_id, "max");
    // No override arrives on this path and none can: see `Attested::limits`.
    assert!(attested.limits.is_empty());
    // Team membership is never taken from the caller, and there is no header
    // that could carry it — this assertion exists so that adding one is a
    // deliberate act rather than an oversight.
    assert!(attested.scope.team_ids.is_empty());
}

#[tokio::test]
async fn an_incomplete_claim_is_refused_rather_than_defaulted() {
    let err = attest(
        &Attestation::TrustedHeaders,
        &nowhere(),
        &Credentials::new(Duration::from_secs(30)),
        None,
        Claimed {
            user_id: None,
            project_id: Some("acme/demo"),
            instance_id: None,
        },
        "REQ-4".to_string(),
    )
    .await
    .expect_err("a missing user must not become an empty one");
    assert!(matches!(err, AttestError::MissingIdentity(_)));
}

#[test]
fn a_bearer_token_is_the_only_credential_this_gateway_reads() {
    assert_eq!(bearer(None), None);
    assert_eq!(bearer(Some("token-with-no-scheme")), None);
    assert_eq!(bearer(Some("Basic dXNlcjpwdw==")), None);
    assert_eq!(bearer(Some("Bearer ")), None, "an empty token is none");
    assert_eq!(bearer(Some("Bearer t0ken")), Some("t0ken"));
    // RFC 9110 makes the scheme case-insensitive, and a client sending the
    // lowercase form would otherwise be refused for a reason no message
    // explains.
    assert_eq!(bearer(Some("bearer t0ken")), Some("t0ken"));
}

#[tokio::test]
async fn a_credentialless_request_under_iam_never_reaches_the_upstream() {
    // The channel points at a closed port, so an RPC would take the transport
    // path and come back `Upstream`. `MissingCredential` proves the refusal
    // happened HERE — which is what keeps an unauthenticated flood off `iam`.
    let err = attest(
        &Attestation::Iam,
        &nowhere(),
        &Credentials::new(Duration::from_secs(30)),
        None,
        Claimed {
            user_id: Some("forged-by-the-caller"),
            project_id: Some("acme/demo"),
            instance_id: None,
        },
        "REQ-5".to_string(),
    )
    .await
    .expect_err("a header is not a credential");
    assert!(
        matches!(err, AttestError::MissingCredential),
        "a self-asserted user must not stand in for a token; got {err:?}"
    );
}

// -----------------------------------------------------------------------
// The cache (D72, ADR-0491).
//
// **EVERY ONE OF THESE COUNTS LOOKUPS.** A test that only asserted the right
// identity came back would pass identically with no cache at all — it is a
// check that cannot fail, which is the antipattern this repository has now
// recorded five times. So the assertion is always on the COUNTER, and the
// fixtures use values no default and no constant in this module could have
// produced.
// -----------------------------------------------------------------------

use std::sync::atomic::{AtomicUsize, Ordering};

/// A lookup that counts, standing in for the RPC.
///
/// It is the closure [`resolve_through`] takes, so the code under test is the
/// production path and only the transport is a fake.
async fn through(
    cache: &Credentials,
    token: &str,
    calls: &AtomicUsize,
    answer: &ResolveCredentialResponse,
) -> ResolveCredentialResponse {
    resolve_through(cache, token, || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(answer.clone())
    })
    .await
    .expect("the fake lookup answers")
}

/// A TTL long enough that nothing in a test expires by accident.
const TEST_TTL: Duration = Duration::from_secs(30);

#[tokio::test(start_paused = true)]
async fn a_second_request_with_the_same_token_costs_iam_nothing() {
    // THE POINT OF THE WHOLE CHANGE, and the only assertion that can tell a
    // cache from no cache: the count, not the answer.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    // A user id no header, no default and no constant in this module could
    // have produced.
    let answer = resolved("u-9137-known-only-to-iam");

    let first = through(&cache, "tok-sentinel-alpha", &calls, &answer).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the first request must ask"
    );

    let second = through(&cache, "tok-sentinel-alpha", &calls, &answer).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second request must not reach iam at all"
    );
    assert_eq!(first.user_id, "u-9137-known-only-to-iam");
    assert_eq!(second.user_id, first.user_id);
    assert_eq!(second.team_ids, first.team_ids);
}

#[tokio::test(start_paused = true)]
async fn two_tokens_are_two_entries_and_never_one() {
    // MUTATION THIS CATCHES: keying on anything that is not the token — the
    // claimed project, a constant, a truncation short enough to collide. Under
    // it the second caller is served the FIRST caller's identity, which is an
    // impersonation rather than a stale answer.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);

    let a = through(&cache, "tok-alpha", &calls, &resolved("u-alpha-4471")).await;
    let b = through(&cache, "tok-bravo", &calls, &resolved("u-bravo-8802")).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a different token is a different entry"
    );
    assert_eq!(a.user_id, "u-alpha-4471");
    assert_eq!(b.user_id, "u-bravo-8802");

    // AND EACH ONE STILL HITS ITS OWN. Two entries that both exist is not the
    // same property as two entries that are both reachable.
    assert_eq!(
        through(&cache, "tok-alpha", &calls, &resolved("u-must-not-be-used"))
            .await
            .user_id,
        "u-alpha-4471"
    );
    assert_eq!(
        through(&cache, "tok-bravo", &calls, &resolved("u-must-not-be-used"))
            .await
            .user_id,
        "u-bravo-8802"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2, "both were already known");
}

#[tokio::test(start_paused = true)]
async fn the_entry_is_filed_under_the_tokens_hash_and_never_the_token() {
    // A map keyed on the token itself puts a live credential into every heap
    // dump of this process. Asserted against a digest computed HERE from the
    // token, which is a value this module's own code did not choose.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    through(&cache, "tok-charlie", &calls, &resolved("u-charlie-2265")).await;

    let expected: [u8; 32] = Sha256::digest(b"tok-charlie").into();
    let live = cache.live.lock().expect("not poisoned");
    assert_eq!(live.len(), 1);
    assert!(
        live.contains_key(&expected),
        "the entry must be filed under the token's digest"
    );
}

#[tokio::test(start_paused = true)]
async fn a_cached_credential_does_not_outlive_its_ttl() {
    // BOTH SIDES OF THE BOUNDARY, because "it expires eventually" is satisfied
    // by a cache that expires immediately, and that is not a cache. Paused time
    // rather than a sleep: deterministic, sub-second, no CI-load dependence.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    let answer = resolved("u-delta-5518");

    through(&cache, "tok-delta", &calls, &answer).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    tokio::time::advance(TEST_TTL - Duration::from_millis(1)).await;
    through(&cache, "tok-delta", &calls, &answer).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "an entry inside its TTL is still served"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    through(&cache, "tok-delta", &calls, &answer).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an entry at its TTL is gone, and the TTL is the whole revocation bound"
    );
}

#[tokio::test(start_paused = true)]
async fn a_cached_credential_never_outlives_iams_own_declared_lifetime() {
    // `valid_for_seconds` is what `iam` says the credential is good for, and a
    // cache of a thing may not outlive the thing. Five seconds is far below
    // TEST_TTL, so a cache that took its own TTL unconditionally would keep
    // serving this for another twenty-five.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    let answer = ResolveCredentialResponse {
        user_id: "u-echo-3390".to_string(),
        valid_for_seconds: 5,
        ..Default::default()
    };

    through(&cache, "tok-echo", &calls, &answer).await;
    tokio::time::advance(Duration::from_secs(5)).await;
    through(&cache, "tok-echo", &calls, &answer).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "iam said five seconds; the configured thirty must not override it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_refused_credential_is_remembered_and_is_still_a_refusal() {
    // TWO PROPERTIES IN ONE TEST, because they are the same decision. Caching
    // the negative is what stops a token-guessing flood being an unthrottled
    // amplifier onto `iam` — attestation runs before D74's limiter, so nothing
    // else throttles it. And a cached negative must NEVER become an
    // attestation: it is re-refused by `from_resolved` on every request,
    // whether it came from `iam` or from this map.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    // Exactly what `iam` sends for a token that is unknown, revoked or expired.
    let refusal = ResolveCredentialResponse::default();

    let first = through(&cache, "tok-guessed", &calls, &refusal).await;
    let second = through(&cache, "tok-guessed", &calls, &refusal).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a repeated junk token must not be a repeated lookup"
    );

    for answer in [first, second] {
        assert!(
            matches!(
                from_resolved(answer, Some("acme/demo"), None, "REQ-8".to_string()),
                Err(AttestError::Upstream(tonic::Code::Unauthenticated))
            ),
            "a cached refusal is still a refusal"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_cache_hit_composes_this_requests_workspace_and_correlation_id() {
    // **THE INVARIANT THAT DECIDES WHAT MAY BE CACHED AT ALL.** The entry holds
    // what `iam` ANSWERED — identity and spending limits, one value, one
    // lifetime — and `from_resolved` composes the per-request half on top of it
    // every time. Caching a composed `Attested` instead would serve the FIRST
    // caller's `request_id` and `project_id` to the second: a broken D67 join
    // key, and a D12 scoping widening into somebody else's workspace, from a
    // cache that looked like it was doing exactly what it was asked.
    //
    // Nothing else in this file reaches composition — every other cache test
    // stops at `resolve_through` — so without this the property is prose.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    // CARRYING ADR-0522'S SETTING, so this test also pins WHICH HALF it is on.
    let answer = ResolveCredentialResponse {
        owner_reads_own_record: Some(stated()),
        ..resolved("u-november-6612")
    };

    let first = from_resolved(
        through(&cache, "tok-shared", &calls, &answer).await,
        Some("acme/first"),
        Some("i-first"),
        "REQ-FIRST".to_string(),
    )
    .expect("a resolved credential attests");
    let second = from_resolved(
        through(&cache, "tok-shared", &calls, &answer).await,
        Some("zeta/second"),
        Some("i-second"),
        "REQ-SECOND".to_string(),
    )
    .expect("a cached credential attests too");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second request must be a hit, or this test proves nothing"
    );
    // SHARED, because it is what the credential resolved to.
    assert_eq!(second.scope.user_id, "u-november-6612");
    assert_eq!(second.scope.team_ids, first.scope.team_ids);
    // NOT SHARED, because these are facts about THIS request.
    assert_eq!(second.scope.project_id, "zeta/second");
    assert_eq!(second.scope.instance_id, "i-second");
    assert_eq!(second.scope.request_id, "REQ-SECOND");
    assert_ne!(first.scope.request_id, second.scope.request_id);
    assert_ne!(first.scope.project_id, second.scope.project_id);

    // AND D74'S BUCKET IS UNMOVED BY THE CLAIMED WORKSPACE. `limit::check` keys
    // on `scope.user_id`, which can only come from `resolved.user_id` — so a
    // caller changing its project header mints no new bucket, cache hit or not.
    assert_eq!(first.scope.user_id, second.scope.user_id);

    // SHARED, BECAUSE IT IS A CREDENTIAL FACT — and this assertion is what
    // makes the module header's claim a checked one rather than prose. The
    // setting rides the CACHED half, so a policy change binds when the entry
    // expires; no invalidation subject exists that could evict it sooner, at
    // either level. Stated here rather than fixed here: the subject that would
    // close it is `iam`'s to publish.
    assert_eq!(second.scope.owner_reads_own_record, Some(stated()));
    assert_eq!(
        first.scope.owner_reads_own_record,
        second.scope.owner_reads_own_record
    );
}

#[tokio::test(start_paused = true)]
async fn a_flood_of_refusals_cannot_deny_the_cache_to_a_real_credential() {
    // WHY THERE ARE TWO MAPS. The writer of a refusal is UNAUTHENTICATED —
    // attestation runs before D74's limiter — so a caller with no credential
    // chooses how many entries the refusal side gains. Sharing one map with the
    // live answers would let that caller fill it, and then every real
    // credential arriving afterwards would be uncacheable and would resolve
    // against `iam` on EVERY request: a guessing run turned into a load
    // amplifier on `iam` for everybody else, which is the failure this whole
    // change exists to stop.
    //
    // **THE FLOOD RUNS FIRST, AND THAT ORDERING IS THE TEST.** Written the
    // other way round — one live entry, then the flood — it passes under a
    // single shared map too, because nothing here evicts: the early entry
    // simply survives and the assertion holds for a reason that is not the
    // property. Confirmed by mutation rather than by reading: collapsing the
    // two maps into one left that ordering green, and leaves this one red.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    let refusal = ResolveCredentialResponse::default();
    for n in 0..CAPACITY + 64 {
        through(&cache, &format!("junk-{n}"), &calls, &refusal).await;
    }

    // A REAL CREDENTIAL, ARRIVING INTO THE FLOOD.
    through(&cache, "tok-foxtrot", &calls, &resolved("u-foxtrot-7724")).await;
    let after_first = calls.load(Ordering::SeqCst);
    assert_eq!(
        through(
            &cache,
            "tok-foxtrot",
            &calls,
            &resolved("u-must-not-be-used")
        )
        .await
        .user_id,
        "u-foxtrot-7724"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        after_first,
        "a real credential must still be cacheable while junk tokens flood in"
    );

    // AND THE FLOOD ITSELF IS BOUNDED. Past capacity the answer is simply not
    // cached; nothing is evicted to make room for it, so the memory an
    // unauthenticated caller can reach has a ceiling.
    assert!(
        cache.refused.lock().expect("not poisoned").len() <= CAPACITY,
        "the refusal map must not grow past its bound"
    );
}

#[tokio::test(start_paused = true)]
async fn forgetting_one_credential_sends_the_next_request_back_to_iam() {
    // THE BY-TOKEN EVICTION. No published subject reaches it — both land on
    // `forget_user`, because `iam` never sees the token — so this test is what
    // keeps it from rotting into a function that compiles and does nothing.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    through(&cache, "tok-golf", &calls, &resolved("u-golf-6103")).await;
    through(&cache, "tok-hotel", &calls, &resolved("u-hotel-1547")).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    cache.forget_credential("tok-golf");

    through(&cache, "tok-golf", &calls, &resolved("u-golf-6103")).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "the forgotten credential is resolved again"
    );
    through(&cache, "tok-hotel", &calls, &resolved("u-hotel-1547")).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "and nothing else was forgotten with it"
    );

    // A REFUSAL IS FORGETTABLE TOO, and it is on the other map — one that
    // cleared only the live side would leave a revocation half-applied.
    let refusal = ResolveCredentialResponse::default();
    through(&cache, "tok-india", &calls, &refusal).await;
    cache.forget_credential("tok-india");
    through(&cache, "tok-india", &calls, &refusal).await;
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}

#[tokio::test(start_paused = true)]
async fn forgetting_a_user_evicts_every_token_that_resolved_to_them() {
    // D72's other invalidation: "revocation OR TEAM CHANGE". A team change names
    // a person and this cache is keyed by token, so one person's several tokens
    // must all go — leaving one behind means the stale team list is still being
    // served, which is the D12 read-scope defect the event exists to close.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    let same_person = resolved("u-juliet-2038");
    through(&cache, "tok-laptop", &calls, &same_person).await;
    through(&cache, "tok-desktop", &calls, &same_person).await;
    through(&cache, "tok-other", &calls, &resolved("u-kilo-9911")).await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    cache.forget_user("u-juliet-2038");

    through(&cache, "tok-laptop", &calls, &same_person).await;
    through(&cache, "tok-desktop", &calls, &same_person).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "both of that person's tokens are resolved again"
    );
    through(&cache, "tok-other", &calls, &resolved("u-kilo-9911")).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "somebody else's token was untouched"
    );
}

#[tokio::test(start_paused = true)]
async fn a_zero_ttl_disables_the_cache_rather_than_caching_forever() {
    // THE REVERT PATH, and the direction it fails in is the point. `0` must
    // mean "ask every time", not "keep it until the process restarts".
    let cache = Credentials::new(Duration::ZERO);
    let calls = AtomicUsize::new(0);
    let answer = resolved("u-lima-8471");
    through(&cache, "tok-lima", &calls, &answer).await;
    through(&cache, "tok-lima", &calls, &answer).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a zero TTL means every request resolves"
    );
    assert!(cache.live.lock().expect("not poisoned").is_empty());
}

#[tokio::test]
async fn an_upstream_failure_is_never_cached() {
    // A transport blip must not become a bounded outage of our own. If the
    // error were remembered, every caller holding that token would be refused
    // until the entry expired — long after `iam` came back.
    let cache = Credentials::new(TEST_TTL);
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let err = resolve_through(&cache, "tok-mike", || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(AttestError::Upstream(tonic::Code::Unavailable))
        })
        .await
        .expect_err("the fake lookup fails");
        assert!(matches!(
            err,
            AttestError::Upstream(tonic::Code::Unavailable)
        ));
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an outage is retried, not remembered"
    );
}

#[test]
fn the_cache_counter_is_named_the_thing_an_operator_queries() {
    // AS A LITERAL, never through `CACHE`. The emitted-name assertion in the
    // test below reads the constant on both sides, so it renames with it: the
    // counter could be called anything at all and stay green. This name is an
    // interface — `chart/values.yaml` points an operator at it by hand and
    // `MIGRATION_NOTES.md` names it as the instrument for deciding whether
    // the hop this cache removed is actually gone — and nothing outside this
    // repository would fail if it moved.
    assert_eq!(CACHE, "yadgar_gateway_credential_cache_total");
}

#[test]
fn the_cache_counter_reports_a_miss_and_then_a_hit() {
    // [`CACHE`] is the only way an operator can tell whether the hop this
    // change removed is actually gone, and a counter emitted under one label
    // only would show a permanent 100% miss rate — indistinguishable from a
    // cache that does not work. Asserted against a recorder rather than against
    // the call site, the way `DEGRADED`'s bounded labels already are.
    //
    // A LOCAL recorder rather than `install()`: a global one is process-wide
    // and this binary runs its tests in parallel, so installing here would race
    // every other test that emits a metric.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime");
    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let cache = Credentials::new(TEST_TTL);
            let calls = AtomicUsize::new(0);
            let answer = resolved("u-oscar-1180");
            through(&cache, "tok-oscar", &calls, &answer).await;
            through(&cache, "tok-oscar", &calls, &answer).await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        });
    });

    // ONE SNAPSHOT, READ TWICE. `Snapshotter::snapshot` DRAINS the registry, so
    // taking one per label leaves the second looking at nothing — and the
    // assertion for whichever label was checked second fails while the counter
    // is being emitted perfectly well. Found by printing the snapshot rather
    // than by assuming the counter was wrong.
    let emitted = snapshotter.snapshot().into_vec();
    let counted = |want: &str| {
        emitted.iter().any(|(key, _, _, value)| {
            key.key().name() == CACHE
                && key
                    .key()
                    .labels()
                    .any(|l| l.key() == "outcome" && l.value() == want)
                && matches!(
                    value,
                    metrics_util::debugging::DebugValue::Counter(n) if *n >= 1
                )
        })
    };
    assert!(counted("miss"), "the cold lookup must be counted as a miss");
    assert!(counted("hit"), "the served lookup must be counted as a hit");
}

#[test]
fn the_ttl_is_read_from_the_environment_and_a_bad_one_fails_boot() {
    assert_eq!(
        Credentials::from_lookup(env(&[]))
            .expect("an unset environment takes the default")
            .ttl(),
        Duration::from_secs(DEFAULT_TTL_SECONDS)
    );
    assert_eq!(
        Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "7")]))
            .expect("seven seconds is usable")
            .ttl(),
        Duration::from_secs(7)
    );
    assert!(Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "0")]))
        .expect("zero is the documented way to disable the cache")
        .ttl()
        .is_zero());

    // AN EMPTY VALUE IS SET-BUT-USELESS, which a manifest reaches by
    // `value: ""`. It reads as unset rather than as an error — the same rule
    // `main.rs` applies to YADGAR_VALKEY_ADDR.
    assert_eq!(
        Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "")]))
            .expect("an empty value is unset")
            .ttl(),
        Duration::from_secs(DEFAULT_TTL_SECONDS)
    );

    // A NUMBER NOBODY CAN READ MUST NOT BECOME THE DEFAULT. Substituting one
    // leaves an operator believing a bound that is not in force — `main.rs`
    // already applies this rule to YADGAR_RATE_LIMIT_TIMEOUT_MS.
    for bad in ["30s", "thirty", "-1", "1.5"] {
        assert!(
            Credentials::from_lookup(env(&[(CREDENTIAL_TTL, bad)])).is_err(),
            "{bad:?} must not be accepted"
        );
    }
}

#[test]
fn a_ttl_above_the_ceiling_is_refused_rather_than_clamped() {
    // MUTATION THIS CATCHES: clamping instead of refusing. A clamp reads as
    // accepted, so an operator who wrote 3600 believes they got it — and the
    // one number that bounds a revocation whose event was missed is then a
    // number nobody agreed on.
    assert!(
        Credentials::from_lookup(env(&[(CREDENTIAL_TTL, &MAX_TTL_SECONDS.to_string())])).is_ok(),
        "the ceiling itself is usable"
    );
    let err = Credentials::from_lookup(env(&[(CREDENTIAL_TTL, "3600")]))
        .expect_err("an hour-long revocation window must not be accepted silently");
    assert!(
        err.contains(&MAX_TTL_SECONDS.to_string()),
        "the message must name the ceiling it refused against: {err}"
    );

    // AND THE CEILING ITSELF, as a literal. Every assertion above reads
    // `MAX_TTL_SECONDS`, including the one about the message, so the whole
    // test moves with the constant: 3599 satisfies its own `expect_err` —
    // 3600 is still above it and the message still names it — while the
    // revocation window this bounds becomes an hour. The number is not a
    // tuning knob: `iam` declares 300 as a live credential's own lifetime,
    // and a cache entry may not outlive the thing it caches.
    assert_eq!(MAX_TTL_SECONDS, 300);
}
