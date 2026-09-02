//! D74's one implementation detail that must not be got wrong, measured.
//!
//! **A test with one caller cannot see the defect this design exists to
//! prevent.** The token bucket's read-compute-write is correct under any
//! sequential test, whether it is atomic or not; the race appears only when two
//! callers are inside it at once, which across gateway replicas is the normal
//! case. So every assertion here drives CONCURRENT callers at a REAL Valkey and
//! counts what was granted.
//!
//! # The control arm is the point
//!
//! `read_then_write` below is the naive implementation — `HMGET`, compute,
//! `HSET` — with exactly the same arithmetic as the shipped Lua script. It is
//! here so the suite measures the difference rather than asserting it. Its result
//! is REPORTED and not asserted, deliberately: a race that happens to not
//! interleave on one run is not a bug in the code under test, and an assertion
//! that the naive version over-grants would be a flaky test asserting a
//! probability.
//!
//! # These tests do not run in CI today, and CANNOT quietly stay that way
//!
//! The shared workflow (`yadgarhq/actions`, `ci-pr.yaml`) supplies MariaDB to
//! every Rust repository and no Valkey, so `YADGAR_TEST_VALKEY` is unset there.
//! Locally that is a loud skip. **On a runner it is a failure** — see
//! `common::resolve`. A skip printed into a green run is a control only while
//! somebody reads it, and after merge nobody does; the panic is what makes the
//! gap impossible to carry silently past the day the shared workflow gains a
//! Valkey, or past a later change that takes it away again. The fix is that
//! Valkey service, the YAML is in `MIGRATION_NOTES.md`, and the workflow's own
//! comment already argues for running one in every Rust repository rather than
//! detecting which need it.
//!
//! Run locally with:
//!
//! ```text
//! podman run -d --rm --name valkey-test -p 16379:6379 \
//!     docker.io/valkey/valkey:9.1.1 --save "" --appendonly no
//! YADGAR_TEST_VALKEY=127.0.0.1:16379 cargo test --test rate_limit -- --nocapture
//! ```

use std::sync::Arc;
use std::time::Duration;

mod common;
use common::addr;

use yadgar_gateway::limit::{Bucket, Decision, Degrade, Limiter, Limits, Overrides};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

/// A limiter over one named bucket, and the key it will use.
fn limiter(addr: &str, module: &str, bucket: Bucket) -> Limiter {
    let limits = Limits::parse(
        &format!("{module}.write={}:{}", bucket.rate, bucket.burst),
        // Deliberately unlike the bucket under test, so a lookup that fell
        // through to the fallback would change the measured number.
        "1000:1000",
    )
    .expect("the limits parse");
    // Six, the chart's `autoscaling.maxReplicas`. It divides only the degraded
    // floor, which these tests do not take — every one of them has a real Valkey.
    Limiter::new(addr, None, limits, Duration::from_millis(500), 6).expect("the limiter opens")
}

/// A module name nothing else will collide with, so a re-run starts empty and
/// two tests never share a bucket.
fn unique_module(what: &str) -> String {
    format!("t{what}{}", uuid::Uuid::now_v7().simple())
}

/// N concurrent callers against one bucket. Returns how many were allowed.
async fn concurrent_grants(limiter: Arc<Limiter>, module: String, callers: usize) -> usize {
    let mut handles = Vec::with_capacity(callers);
    for _ in 0..callers {
        let limiter = Arc::clone(&limiter);
        let module = module.clone();
        handles.push(tokio::spawn(async move {
            matches!(
                limiter
                    .check("max", &module, Kind::Write, &Overrides::default())
                    .await,
                Decision::Allowed
            )
        }));
    }
    let mut granted = 0;
    for h in handles {
        if h.await.expect("the caller finished") {
            granted += 1;
        }
    }
    granted
}

/// The naive implementation: read, compute, write, from the client.
///
/// The same arithmetic as the Lua script, in two round trips instead of one, over
/// ONE multiplexed connection shared by every caller — the same topology the
/// shipped limiter uses, so atomicity is the only difference between the two
/// arms. This is what D74 says must not be built, kept here so the difference is
/// measured rather than asserted.
async fn read_then_write(
    mut conn: redis::aio::MultiplexedConnection,
    key: &str,
    bucket: Bucket,
) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs_f64();

    let state: (Option<String>, Option<String>) = redis::cmd("HMGET")
        .arg(key)
        .arg("tokens")
        .arg("ts")
        .query_async(&mut conn)
        .await
        .expect("read the bucket");

    let (mut tokens, ts) = match (
        state.0.and_then(|t| t.parse::<f64>().ok()),
        state.1.and_then(|t| t.parse::<f64>().ok()),
    ) {
        (Some(t), Some(s)) => (t, s),
        _ => (bucket.burst, now),
    };
    tokens = bucket.burst.min(tokens + (now - ts).max(0.0) * bucket.rate);

    let allowed = tokens >= 1.0;
    if allowed {
        tokens -= 1.0;
    }

    let _: () = redis::cmd("HSET")
        .arg(key)
        .arg("tokens")
        .arg(tokens)
        .arg("ts")
        .arg(now)
        .query_async(&mut conn)
        .await
        .expect("write the bucket");
    allowed
}

/// **The property this module exists for.**
///
/// A rate of 0.1/s is chosen so the bucket refills one token every ten seconds:
/// whatever the run costs in wall time, less than a token can appear during it,
/// so "exactly `burst`" is a deterministic answer and not a race with the clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_callers_are_granted_exactly_the_burst_and_no_more() {
    let Some(addr) = addr() else { return };

    const CALLERS: usize = 200;
    let bucket = Bucket {
        rate: 0.1,
        burst: 20.0,
    };

    // THE CONTROL ARM. Reported, never asserted — see the module comment.
    let client = redis::Client::open(format!("redis://{addr}")).expect("client");
    let shared = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect");
    let naive_key = format!("gw:rl:test:{}", unique_module("naive"));
    let mut naive_handles = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let conn = shared.clone();
        let key = naive_key.clone();
        naive_handles.push(tokio::spawn(async move {
            read_then_write(conn, &key, bucket).await
        }));
    }
    let mut naive_granted = 0;
    for h in naive_handles {
        if h.await.expect("the caller finished") {
            naive_granted += 1;
        }
    }
    eprintln!(
        "read-then-write from the client: {CALLERS} concurrent callers, burst {}, GRANTED {naive_granted}",
        bucket.burst
    );

    // THE SHIPPED IMPLEMENTATION.
    let module = unique_module("atomic");
    let limiter = Arc::new(limiter(&addr, &module, bucket));
    let granted = concurrent_grants(Arc::clone(&limiter), module.clone(), CALLERS).await;
    eprintln!(
        "atomic Lua script:                 {CALLERS} concurrent callers, burst {}, GRANTED {granted}",
        bucket.burst
    );

    assert_eq!(
        granted, bucket.burst as usize,
        "{CALLERS} concurrent callers against a bucket of {} must be granted exactly {} — \
         more means the read-compute-write is not atomic and the limit is multiplied by the \
         number of callers racing inside it (D74)",
        bucket.burst, bucket.burst
    );

    // AND IT STAYS EMPTY. A second wave must be granted nothing: an empty bucket
    // refills at `rate` rather than being handed a fresh allowance, which is the
    // trade-off D74 accepts and the property a fixed window does not have.
    let again = concurrent_grants(limiter, module, CALLERS).await;
    assert_eq!(again, 0, "an empty bucket is not refilled by asking again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_carries_this_callers_own_wait() {
    let Some(addr) = addr() else { return };

    // One token, refilled twice a second: an empty bucket is half a second from
    // its next token, and `retry_after` must say so rather than naming a shared
    // instant every throttled caller would return at together.
    let bucket = Bucket {
        rate: 2.0,
        burst: 1.0,
    };
    let module = unique_module("retry");
    let limiter = limiter(&addr, &module, bucket);
    let overrides = Overrides::default();

    assert_eq!(
        limiter.check("max", &module, Kind::Write, &overrides).await,
        Decision::Allowed
    );

    match limiter.check("max", &module, Kind::Write, &overrides).await {
        Decision::Throttled { retry_after } => {
            // (1 - tokens) / rate, and tokens is ~0 immediately after the spend.
            assert!(
                retry_after > Duration::from_millis(300)
                    && retry_after < Duration::from_millis(600),
                "expected roughly 500ms, got {retry_after:?}"
            );
        }
        other => panic!("a drained bucket must throttle; got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bucket_refills_from_elapsed_time_with_no_timer_anywhere() {
    let Some(addr) = addr() else { return };

    // Twenty tokens a second into a bucket of one: 100ms of waiting is two
    // tokens' worth, so the next call is allowed — with nothing running in the
    // background to make it so.
    let bucket = Bucket {
        rate: 20.0,
        burst: 1.0,
    };
    let module = unique_module("refill");
    let limiter = limiter(&addr, &module, bucket);
    let overrides = Overrides::default();

    assert_eq!(
        limiter.check("max", &module, Kind::Write, &overrides).await,
        Decision::Allowed
    );
    assert!(
        matches!(
            limiter.check("max", &module, Kind::Write, &overrides).await,
            Decision::Throttled { .. }
        ),
        "the bucket holds one token"
    );

    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(
        limiter.check("max", &module, Kind::Write, &overrides).await,
        Decision::Allowed,
        "elapsed time alone refills the bucket"
    );
}

/// **A rejected call must not eat the refill it was rejected for.**
///
/// The script writes `ts = now` on the reject branch as well as the allow branch,
/// which is the line worth checking: if the tokens accrued since the last call
/// were not carried across at the same time, every rejection would reset the
/// clock and a client polling faster than the refill would be throttled FOREVER
/// while its bucket sat at zero. The arithmetic says that cannot happen; this
/// measures it rather than trusting the reading.
///
/// Ten tokens a second into a bucket of one, polled every 10ms for a second: a
/// caller that keeps asking should be granted roughly ten over that second, not
/// one and not none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_a_rejected_bucket_does_not_starve_it() {
    let Some(addr) = addr() else { return };

    let bucket = Bucket {
        rate: 10.0,
        burst: 1.0,
    };
    let module = unique_module("poll");
    let limiter = limiter(&addr, &module, bucket);
    let overrides = Overrides::default();

    // Drain the one token the bucket starts with, so what follows is refill only.
    assert_eq!(
        limiter.check("max", &module, Kind::Write, &overrides).await,
        Decision::Allowed
    );

    let started = std::time::Instant::now();
    let mut granted = 0;
    while started.elapsed() < Duration::from_millis(1000) {
        if limiter.check("max", &module, Kind::Write, &overrides).await == Decision::Allowed {
            granted += 1;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        (8..=12).contains(&granted),
        "one second at 10 tokens/s should grant about ten however often it is asked; got \
         {granted}. Far fewer means a rejection consumed the refill it was rejected for"
    );
}

/// Buckets are keyed on `(user, module, kind)`, so one caller draining one of
/// them must not throttle anybody else — the failure a single global counter has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_drained_bucket_does_not_throttle_another_user_module_or_kind() {
    let Some(addr) = addr() else { return };

    let bucket = Bucket {
        rate: 0.1,
        burst: 1.0,
    };
    let module = unique_module("keyed");
    // Both kinds share the module, so the limits must name both.
    let limits = Limits::parse(
        &format!(
            "{module}.write={}:{},{module}.read={}:{}",
            bucket.rate, bucket.burst, bucket.rate, bucket.burst
        ),
        "1000:1000",
    )
    .expect("the limits parse");
    let limiter =
        Limiter::new(&addr, None, limits, Duration::from_millis(500), 6).expect("limiter");
    let overrides = Overrides::default();

    assert_eq!(
        limiter.check("max", &module, Kind::Write, &overrides).await,
        Decision::Allowed
    );
    assert!(matches!(
        limiter.check("max", &module, Kind::Write, &overrides).await,
        Decision::Throttled { .. }
    ));

    assert_eq!(
        limiter.check("ada", &module, Kind::Write, &overrides).await,
        Decision::Allowed,
        "another USER has their own bucket"
    );
    assert_eq!(
        limiter.check("max", &module, Kind::Read, &overrides).await,
        Decision::Allowed,
        "another KIND has its own bucket"
    );
}

/// A per-user override changes the bucket that is actually enforced, not merely
/// the number a lookup returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_per_user_override_is_what_gets_enforced() {
    let Some(addr) = addr() else { return };

    let module = unique_module("override");
    // Configured at one token; the override raises it to three.
    let limiter = limiter(
        &addr,
        &module,
        Bucket {
            rate: 0.1,
            burst: 1.0,
        },
    );
    let mine = Overrides::from_pairs([(
        format!("{module}.write"),
        Bucket {
            rate: 0.1,
            burst: 3.0,
        },
    )])
    .expect("a usable override");

    for n in 1..=3 {
        assert_eq!(
            limiter.check("max", &module, Kind::Write, &mine).await,
            Decision::Allowed,
            "spend {n} of the overridden burst of 3"
        );
    }
    assert!(
        matches!(
            limiter.check("max", &module, Kind::Write, &mine).await,
            Decision::Throttled { .. }
        ),
        "and the override is a limit, not an exemption"
    );
}

/// Valkey unreachable: the call proceeds, and says so.
///
/// Needs no Valkey — the point is that there is none. The argument for failing
/// open is on `limit::Decision::Degraded`; this pins the behaviour so a later
/// change to fail closed is a deliberate act rather than a side effect.
#[tokio::test]
async fn an_unreachable_cache_degrades_rather_than_refusing_the_call() {
    let limits = Limits::parse("task.write=1:1", "1:1").expect("parse");
    // Port 1: nothing listens, and the refusal is immediate.
    let limiter =
        Limiter::new("127.0.0.1:1", None, limits, Duration::from_millis(500), 6).expect("limiter");

    assert_eq!(
        limiter
            .check("max", "task", Kind::Write, &Overrides::default())
            .await,
        Decision::Degraded(Degrade::Unreachable),
        "a gateway that cannot reach the cache still serves, and reports WHY as `unreachable` \
         rather than `timeout` — an operator reading the counter must not be sent looking for a \
         slow cache when there is an absent one; see limit::Decision::Degraded"
    );
}

/// **The degraded path is floored, not unlimited.**
///
/// While Valkey cannot answer, each replica applies an in-process bucket of
/// `rate / maxReplicas`. The claim that makes this acceptable where D74 rejects a
/// per-replica bucket is that it is BOUNDED: at `maxReplicas` replicas the
/// aggregate can never exceed the configured number. A test that only checked the
/// floor compiles would not measure that, so this drives concurrent callers at an
/// unreachable cache and counts what was granted.
///
/// Needs no Valkey — the point is that there is none.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_unreachable_cache_is_floored_rather_than_unlimited() {
    const CALLERS: usize = 200;
    const REPLICAS: u32 = 6;

    // Twelve tokens a second into a bucket of twelve, divided six ways: this
    // replica's floor is 2/s with a burst of 2. A rate low enough that less than
    // one token can refill during the run, so the answer is deterministic.
    let limits = Limits::parse("task.write=0.6:12", "1000:1000").expect("parse");
    let limiter = Arc::new(
        Limiter::new(
            "127.0.0.1:1",
            None,
            limits,
            Duration::from_millis(50),
            REPLICAS,
        )
        .expect("limiter"),
    );

    let mut handles = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let limiter = Arc::clone(&limiter);
        handles.push(tokio::spawn(async move {
            limiter
                .check("max", "task", Kind::Write, &Overrides::default())
                .await
        }));
    }
    let (mut proceeded, mut refused) = (0, 0);
    for h in handles {
        match h.await.expect("the caller finished") {
            Decision::Degraded(Degrade::Unreachable) => proceeded += 1,
            Decision::DegradedThrottled { .. } => refused += 1,
            other => panic!("with no cache every answer is degraded; got {other:?}"),
        }
    }

    eprintln!(
        "cache unreachable: {CALLERS} concurrent callers, configured burst 12 over {REPLICAS} \
         replicas, PROCEEDED {proceeded}, REFUSED {refused}"
    );
    assert_eq!(
        proceeded + refused,
        CALLERS,
        "every call is answered, degraded or not"
    );
    assert_eq!(
        proceeded, 2,
        "the floor is burst/{REPLICAS} = 2 on this replica; {proceeded} means the degraded \
         path is unlimited, which is what D74 objects to"
    );
    // AND THE AGGREGATE IS THE POINT. Six replicas each holding 2 is 12, the
    // configured burst — the floor cannot multiply the number the way the
    // per-replica bucket D74 rejects would.
    assert_eq!(proceeded * REPLICAS as usize, 12);

    // A second wave finds it empty: the floor refills at rate/replicas rather
    // than being handed a fresh allowance, exactly as the shared bucket does.
    let again = limiter
        .check("max", "task", Kind::Write, &Overrides::default())
        .await;
    assert!(
        matches!(again, Decision::DegradedThrottled { .. }),
        "an empty floor is not refilled by asking again; got {again:?}"
    );
}

/// **A key written by one bucket is read by another, and expiry must not hand
/// over the difference.**
///
/// The TTL is derived from the bucket that WROTE the key; correctness needs the
/// bucket that READS it. Loosen a limit — a rolling deploy that changes
/// `YADGAR_RATE_LIMITS`, or a per-user override from `iam` — and a key written
/// under the old, shorter TTL expires before the new refill window has elapsed.
/// The reader then finds nothing and treats absent as full.
///
/// Measured before the fix, with the same key state and 12 seconds elapsed: the
/// loosened bucket handed over its whole burst instead of the six tokens that had
/// actually accrued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_loosened_bucket_does_not_read_an_expired_key_as_full() {
    let Some(addr) = addr() else { return };

    let module = unique_module("ttl");
    // THE OLD POD's configuration: five tokens, refilling one every two seconds.
    // Its refill window is ten seconds, and that used to be the key's whole life.
    let tight = Bucket {
        rate: 0.5,
        burst: 5.0,
    };
    // THE NEW POD's, after somebody loosened the limit. Same rate, far larger
    // bucket, so the refill window is twenty minutes rather than ten seconds.
    let loose = Bucket {
        rate: 0.5,
        burst: 600.0,
    };

    let writer = limiter(&addr, &module, tight);
    let overrides = Overrides::default();
    // Drain it, so the key holds ~0 tokens and a timestamp.
    let mut drained = 0;
    while writer.check("max", &module, Kind::Write, &overrides).await == Decision::Allowed {
        drained += 1;
        assert!(drained <= 10, "a bucket of 5 granted more than 10");
    }
    assert_eq!(drained, tight.burst as usize, "the tight bucket is empty");

    // LONGER THAN THE TIGHT BUCKET'S REFILL WINDOW, which is what the TTL used to
    // be. Everything the reader sees after this depends on whether the key lived.
    let elapsed = Duration::from_millis(12_000);
    tokio::time::sleep(elapsed).await;

    let reader = limiter(&addr, &module, loose);
    let mut granted = 0;
    while reader.check("max", &module, Kind::Write, &overrides).await == Decision::Allowed {
        granted += 1;
        assert!(
            granted <= loose.burst as usize + 1,
            "granted past the burst"
        );
    }

    let accrued = elapsed.as_secs_f64() * loose.rate;
    eprintln!(
        "loosened bucket after {:?}: GRANTED {granted}, accrued {accrued:.2}, burst {}",
        elapsed, loose.burst
    );
    assert!(
        (granted as f64) < accrued + 3.0,
        "after {elapsed:?} at {}/s the reader may spend about {accrued:.2} tokens; it was \
         granted {granted}. A count near the burst of {} means the key written under the \
         tighter bucket's TTL expired and absent was read as full",
        loose.rate,
        loose.burst
    );
}

/// **A caller-supplied user id reaches a key in a cache four other subsystems
/// share, and nothing bounded it.**
///
/// `header()` does `to_str().ok()` and no more, so under
/// `Attestation::TrustedHeaders` — which the shipped chart enables — the id is
/// whatever the caller wrote. `http.rs` already bounds `label` and `module` for
/// exactly this reason and then the key took the raw header.
///
/// **The bypass half is inside D74's accepted posture** and is asserted here
/// rather than fixed: a caller who rotates its id gets a fresh bucket every time,
/// which is not a runaway loop, and D74 says outright that this is capacity
/// protection rather than authorisation. **The cache-pressure half is the
/// finding**: `deploy/infra/valkey/valkey.yaml` runs `--maxmemory 512mb
/// --maxmemory-policy allkeys-lru`, and that one instance also holds D17's
/// caches, D29's conversation tokens, D46's throttle counters and D52's
/// `last_seen_at`. Evicting D46's throttle counters is itself a limit bypass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_cannot_choose_how_much_of_the_shared_cache_its_key_occupies() {
    use std::collections::HashSet;

    let Some(addr) = addr() else { return };

    let module = unique_module("keysize");
    let limiter = limiter(
        &addr,
        &module,
        Bucket {
            rate: 2.0,
            burst: 2.0,
        },
    );
    let overrides = Overrides::default();

    // 300 distinct ids, exactly as a rotating caller mints them.
    let mut granted = 0;
    for n in 0..300 {
        if limiter
            .check(
                &format!("minted-{n:0>64}"),
                &module,
                Kind::Write,
                &overrides,
            )
            .await
            == Decision::Allowed
        {
            granted += 1;
        }
    }
    // And one absurd id, which nothing rejects on the way in.
    let huge = "x".repeat(4000);
    let _ = limiter.check(&huge, &module, Kind::Write, &overrides).await;

    let client = redis::Client::open(format!("redis://{addr}")).expect("client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("gw:rl:*:{module}:write"))
        .query_async(&mut conn)
        .await
        .expect("list the keys");

    let lengths: HashSet<usize> = keys.iter().map(String::len).collect();
    let longest = keys.iter().map(String::len).max().unwrap_or(0);
    eprintln!(
        "300 distinct user ids and one of 4000 bytes: {} keys minted, {granted} allowed, \
         longest key {longest} bytes, distinct key lengths {}",
        keys.len(),
        lengths.len()
    );

    assert_eq!(
        lengths.len(),
        1,
        "every bucket key must be the same length whatever the caller wrote; got {lengths:?}"
    );
    assert!(
        longest < 128,
        "a 4000-byte user id produced a {longest}-byte key in a cache four other subsystems \
         share under allkeys-lru"
    );

    // THE RESIDUAL, asserted so it is disclosed rather than assumed away: hashing
    // bounds a key's SIZE and not the NUMBER of them. A caller that rotates its
    // id is still not throttled and still mints one bucket per id. That is inside
    // D74's accepted posture — the mechanism is capacity protection, not
    // authorisation — and this assertion is here to fail loudly on the day
    // somebody believes otherwise.
    assert_eq!(
        granted, 300,
        "a rotating id is NOT throttled, by design; each id is a caller of its own"
    );
    assert_eq!(keys.len(), 301, "and each one minted a bucket of its own");
}
