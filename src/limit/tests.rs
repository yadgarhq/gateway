// The items under test now live in `super`'s submodules. The GLOBS are what keep
// every test body below unchanged: this is the only edit the split made to this
// file.
use std::time::Instant;

use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use super::config::*;
use super::floor::*;
use super::*;

#[test]
fn a_named_pair_beats_the_fallback_and_an_override_beats_both() {
    let limits = Limits::parse("task.write=2:20, task.read=50:500", "10:100").expect("parse");

    assert_eq!(
        limits.effective("task", Kind::Write, &Overrides::default()),
        Bucket {
            rate: 2.0,
            burst: 20.0
        }
    );
    // Nobody named `memory.write`, so it is LIMITED rather than unlimited.
    assert_eq!(
        limits.effective("memory", Kind::Write, &Overrides::default()),
        Bucket {
            rate: 10.0,
            burst: 100.0
        }
    );

    let mine = Overrides::from_pairs([(
        "task.write".to_string(),
        Bucket {
            rate: 99.0,
            burst: 999.0,
        },
    )])
    .expect("a usable override");
    assert_eq!(
        limits.effective("task", Kind::Write, &mine),
        Bucket {
            rate: 99.0,
            burst: 999.0
        },
        "a per-user override wins over the configured default (D74)"
    );
    // And it overrides only what it names.
    assert_eq!(
        limits.effective("task", Kind::Read, &mine),
        Bucket {
            rate: 50.0,
            burst: 500.0
        }
    );
}

#[test]
fn an_absent_override_field_degrades_to_the_configured_default() {
    // THE DEGRADATION THAT MUST HOLD while `ResolveCredentialResponse` does
    // not carry the buckets yet. An empty `Overrides` is the state every call
    // is in today, and the deployment must behave exactly as if no user had
    // an override — not fall through to unlimited, and not fail.
    let limits = Limits::parse("task.write=2:20", "10:100").expect("parse");
    let none = Overrides::default();
    assert!(none.is_empty());
    assert_eq!(
        limits.effective("task", Kind::Write, &none),
        Bucket {
            rate: 2.0,
            burst: 20.0
        }
    );
}

#[test]
fn a_malformed_limit_refuses_rather_than_defaulting() {
    // MUTATION THIS CATCHES: a parse that skips what it cannot read. Under
    // it, a typo in the chart silently removes one limit and nothing says so
    // — a limit nobody notices is gone, which is the D76 shape applied to
    // capacity.
    for bad in [
        "task.write",         // no bucket
        "task.write=20",      // no rate:burst split
        "taskwrite=2:20",     // no module.kind split
        "task.wrote=2:20",    // not a kind
        "task.write=0:20",    // a rate of zero never refills
        "task.write=-1:20",   // negative
        "task.write=2:abc",   // not a number
        ".write=2:20",        // no module
        "task.write=2:20,,,", // trailing separators are fine
        // A bucket that takes longer to refill than a key lives. The key
        // expires while the bucket is still empty, and the next call reads
        // absent as FULL — the whole burst, handed over. Refused at boot
        // rather than documented, because there is no correct value of
        // KEY_TTL_SECONDS that covers an arbitrary one.
        "task.write=0.001:100",
    ] {
        let parsed = Limits::parse(bad, "10:100");
        if bad == "task.write=2:20,,," {
            assert!(parsed.is_ok(), "empty entries are skipped, not an error");
        } else {
            assert!(parsed.is_err(), "{bad:?} must be refused");
        }
    }
    assert!(
        Limits::parse("", "nonsense").is_err(),
        "so must the fallback"
    );
}

#[test]
fn a_keys_lifetime_does_not_depend_on_the_bucket_that_wrote_it() {
    // MUTATION THIS CATCHES: `key_ttl_seconds` going back to
    // `refill_seconds().ceil()`. Under it the TTL is the writer's number
    // while correctness needs the reader's, so loosening a limit lets keys
    // written under the old one expire early and be read as full buckets.
    // Measured against a real container before the fix: 600 tokens handed
    // over where 6 had accrued.
    let tight = Bucket {
        rate: 0.5,
        burst: 5.0,
    };
    let loose = Bucket {
        rate: 0.5,
        burst: 600.0,
    };
    assert_eq!(tight.refill_seconds(), 10.0, "ten seconds apart as buckets");
    assert_eq!(loose.refill_seconds(), 1200.0);
    assert_eq!(
        tight.key_ttl_seconds(),
        loose.key_ttl_seconds(),
        "and the SAME lifetime as keys, or the tighter one's key expires \
         before the looser one's refill window has elapsed"
    );
    assert_eq!(tight.key_ttl_seconds(), KEY_TTL_SECONDS as u64);
}

#[test]
fn representative_bucket_shapes_refill_inside_a_keys_lifetime() {
    // The invariant the constant rests on, checked rather than assumed: no
    // bucket that PARSES may outlive the key it writes. If one could, the
    // TTL would have to vary again and the defect above would return.
    //
    // **THE NAME USED TO SAY `every_configurable_bucket`, AND THIS FILE
    // CANNOT KNOW WHAT THOSE ARE.** The list below is four specs written by
    // hand; the buckets a deployment actually configures live in
    // `chart/values.yaml` and reach this process as `YADGAR_RATE_LIMITS`.
    // Nothing links the two, so the old name promised coverage of a set this
    // test never sees, and a reader who trusted it would stop looking for
    // the guard that does cover it. That guard is
    // `ConfigError::Unrefillable`, refused at boot on whatever the chart
    // rendered — this case only fixes the shapes it is worth pinning by
    // hand: a fast bucket, a slow one, and a burst large against its rate.
    //
    // **NOT ONE OF THESE SPECS IS A SHIPPED VALUE, and that is the second
    // half of the same repair.** The list used to spell the chart's own
    // `task.write` and `task.read` buckets, so it read as a copy of the
    // deployment while being answerable to nothing — and the next reader
    // could not tell the copy from the coincidence. `example` is a module
    // this estate does not have, which is what makes these unmistakably
    // fixtures (ADR-0599).
    //
    // `1:3600` IS THE BOUNDARY CASE and the reason the list is worth having:
    // `validate` refuses a window ABOVE `KEY_TTL_SECONDS`, so a bucket that
    // refills in exactly a key's lifetime must pass. An off-by-one there
    // turns a legal configuration into a boot failure.
    for spec in [
        "example.write=3:33",
        "example.read=0.25:600",
        "example.generate=50:900",
        "example.write=1:3600",
    ] {
        let limits = Limits::parse(spec, "2:22").expect("{spec} parses");
        for bucket in limits.per_pair.values().chain([&limits.fallback]) {
            assert!(
                bucket.refill_seconds() <= KEY_TTL_SECONDS,
                "{spec}: a bucket that outlives its key would be refused"
            );
            assert_eq!(bucket.key_ttl_seconds(), KEY_TTL_SECONDS as u64);
        }
    }
}

#[test]
fn a_caller_cannot_choose_the_size_of_its_key_in_the_shared_cache() {
    // MUTATION THIS CATCHES: the key taking the raw header again. The id is
    // caller-supplied under `Attestation::TrustedHeaders`, and the key lands
    // in the one Valkey D21 shares with D17, D29, D46 and D52 under
    // `allkeys-lru` — so a caller who picks the key size evicts other
    // tenants' entries, and evicting D46's throttle counters is itself a
    // limit bypass. Measured before the fix: a 4000-byte id, a 4017-byte key.
    let short = user_component("max");
    let huge = user_component(&"x".repeat(4000));
    assert_eq!(short.len(), 32, "128 bits of SHA-256, as hex");
    assert_eq!(huge.len(), short.len(), "whatever the caller wrote");
    assert!(
        short.chars().all(|c| c.is_ascii_hexdigit()),
        "and nothing of the caller's own bytes survives into the key"
    );
    assert_ne!(short, user_component("ada"), "two callers, two buckets");
    // The same id is the same bucket on every replica, which is the whole
    // point of putting it in a shared store.
    assert_eq!(short, user_component("max"));
    // A colon in the id must not be able to forge another component: the
    // hash is hex, so no separator can survive it.
    assert!(!user_component("max:task:write").contains(':'));
}

#[test]
fn an_override_is_validated_like_a_configured_limit() {
    // TRACED, not guessed: `rate = 0` makes the Lua `(cost - tokens) / rate`
    // evaluate to `inf`, which returns as the string "inf", parses as
    // f64::INFINITY and is clamped to 86_400. No panic — a permanent lockout
    // with a 24-hour Retry-After, on the path `iam` will drive.
    for bad in [
        Bucket {
            rate: 0.0,
            burst: 20.0,
        },
        Bucket {
            rate: -1.0,
            burst: 20.0,
        },
        Bucket {
            rate: 2.0,
            burst: 0.0,
        },
        Bucket {
            rate: f64::NAN,
            burst: 20.0,
        },
        Bucket {
            rate: f64::INFINITY,
            burst: 20.0,
        },
        // Refills more slowly than its key lives, exactly as on the
        // configured path.
        Bucket {
            rate: 0.001,
            burst: 100.0,
        },
    ] {
        assert!(
            Overrides::from_pairs([("task.write".to_string(), bad)]).is_err(),
            "{bad:?} must be refused on the override path too"
        );
    }
    assert!(Overrides::from_pairs([(
        "task.write".to_string(),
        Bucket {
            rate: 2.0,
            burst: 20.0
        }
    )])
    .is_ok());
}

#[test]
fn a_degraded_call_is_held_to_this_replicas_share_and_not_to_the_whole_limit() {
    // THE ARITHMETIC THE FLOOR RESTS ON. Twelve tokens a second over six
    // replicas is two a second each, so six replicas sum to the configured
    // twelve and never more — which is the difference between this and the
    // per-replica bucket D74 rejects, where each replica would hold twelve.
    let floor = Floor::new(6);
    let bucket = Bucket {
        rate: 12.0,
        burst: 12.0,
    };
    let t0 = Instant::now();

    for n in 1..=2 {
        assert!(
            floor.check("k", bucket, t0).is_ok(),
            "spend {n} of this replica's burst of 2"
        );
    }
    let wait = floor
        .check("k", bucket, t0)
        .expect_err("the floor is empty");
    assert!(
        wait > Duration::from_millis(400) && wait < Duration::from_millis(600),
        "a floor of 2/s is half a second from its next token; got {wait:?}"
    );

    // It refills at rate/replicas, from elapsed time, exactly as the shared
    // bucket does — no fresh allowance on the next call.
    assert!(floor
        .check("k", bucket, t0 + Duration::from_millis(500))
        .is_ok());
    assert!(floor
        .check("k", bucket, t0 + Duration::from_millis(500))
        .is_err());

    // And it is keyed, so one caller draining it does not refuse another.
    assert!(floor.check("other", bucket, t0).is_ok());
}

#[test]
fn a_burst_smaller_than_the_replica_count_still_grants_one_call() {
    // Two over six replicas is a third of a token, and a floor that granted
    // nothing would turn the fail-OPEN decision into a fail-closed one by
    // arithmetic. The cost is stated on `Floor`: for a configured burst below
    // the replica count, the aggregate degraded burst can reach the replica
    // count rather than the configured burst. Bounded, and small.
    let floor = Floor::new(6);
    let tiny = Bucket {
        rate: 2.0,
        burst: 2.0,
    };
    assert!(floor.check("k", tiny, Instant::now()).is_ok());
}

#[test]
fn the_degraded_map_is_bounded_and_refuses_rather_than_growing() {
    // THE KEY CARRIES A CALLER-SUPPLIED USER ID, so an unbounded map here
    // would be the same defect as an unbounded key, moved into the process.
    let floor = Floor::new(1);
    // A bucket that takes an hour to refill, so nothing sweeps out.
    let slow = Bucket {
        rate: 1.0,
        burst: 3600.0,
    };
    let t0 = Instant::now();
    for n in 0..FLOOR_CAPACITY {
        assert!(floor.check(&format!("caller-{n}"), slow, t0).is_ok());
    }
    assert!(
        floor.check("one-too-many", slow, t0).is_err(),
        "a new caller past the cap is REFUSED, not allowed untracked — refusing is the \
         safe direction and untracked would be a bypass"
    );
    // A caller already tracked is unaffected: the cap bounds how many are
    // remembered, not how the remembered ones are treated.
    assert!(floor.check("caller-0", slow, t0).is_ok());

    // AND THE SWEEP IS WHAT KEEPS IT USABLE. Every entry has refilled to full
    // an hour later, and a full entry holds exactly what an absent one would,
    // so dropping it changes no answer.
    assert!(floor
        .check("one-too-many", slow, t0 + Duration::from_secs(7200))
        .is_ok());
}

#[test]
fn the_degradation_counter_is_named_the_thing_an_operator_alerts_on() {
    // AS A LITERAL, and there was no assertion on this name at all before —
    // not here and not on the emit path. The labels below were pinned and the
    // series they hang on was not, so the counter could be renamed with the
    // whole suite green.
    //
    // The floor D74 permits is permitted BECAUSE IT IS NOT SILENT. That
    // argument rests entirely on this series reaching an operator, and
    // `reason = "unauthenticated"` is the one value here that does not end by
    // itself. A renamed series is a query that returns nothing, which reads
    // as a gateway with no degradation rather than as a broken metric.
    assert_eq!(DEGRADED, "yadgar_gateway_rate_limit_degraded_total");
}

#[test]
fn every_degrade_reason_has_a_bounded_label() {
    // It is a metric label, so the set must be closed and must not include
    // anything derived from an error string or a user.
    let labels: Vec<&str> = [Degrade::Unreachable, Degrade::Timeout, Degrade::Error]
        .iter()
        .map(|d| d.label())
        .collect();
    assert_eq!(labels, ["unreachable", "timeout", "error"]);
}
