//! The one assertion that cannot pass against an unauthenticated cache.
//!
//! **A test that only proves the credentialled client works is the check that
//! cannot fail.** It passes identically against a Valkey with no `requirepass`
//! at all, because a server that wants no password accepts one and ignores it.
//! So the tests here come in a PAIR against ONE server: a client carrying the
//! password is served, and a client carrying none is REFUSED. Only the pair
//! distinguishes an authenticated cache from an open one.
//!
//! # Why this makes the server demand a password rather than being handed one
//!
//! The Valkey the suite already has — `YADGAR_TEST_VALKEY`, a service container
//! in the shared workflow (`yadgarhq/actions`, `ci-pr.yaml`) — has no
//! `requirepass`, and this repository cannot add a second one to a workflow it
//! does not own. `CONFIG SET requirepass` turns the one it has into an
//! authenticated server for the length of a test and back again, so the property
//! is measured against a REAL Valkey speaking the real protocol on every pull
//! request rather than against a mock that would agree with whatever this code
//! believes.
//!
//! **It mutates a server the other test binaries share**, which is safe for
//! exactly one reason: `cargo test` runs test binaries one after another, never
//! concurrently, so no other binary is talking to it while this one runs. Within
//! this binary the tests DO run concurrently, so every one of them takes
//! [`Locked`], which serialises them on a mutex — two tests toggling
//! `requirepass` on one server would otherwise each see the other's state.
//!
//! [`Locked`] restores the server on the way out, including on a panic, which is
//! when it matters. It also clears first, so a run killed between the set and the
//! restore cannot leave the shared Valkey locked and every later job failing on a
//! `NOAUTH` that has nothing to do with the change under test.
//!
//! Run locally with:
//!
//! ```text
//! podman run -d --rm --name valkey-test -p 16379:6379 \
//!     docker.io/valkey/valkey:9.1.1 --save "" --appendonly no
//! YADGAR_TEST_VALKEY=127.0.0.1:16379 cargo test --test valkey_auth -- --nocapture
//! ```

use std::sync::Mutex;
use std::time::Duration;

mod common;
use common::addr;

use yadgar_gateway::limit::{Decision, Degrade, Limiter, Limits, Overrides};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

/// Deliberately unlike anything the implementation could contain. A fixture that
/// happened to equal a constant in the code under test would pass for a build
/// that ignored the configured password and used one of its own.
const PASSWORD: &str = "sentinel-of-the-requirepass-9d41";

/// Held for the whole of each test that touches the shared server. See the module
/// comment: the binaries are serialised by cargo, the tests inside one are not.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A limiter with a bucket wide enough that nothing here is ever throttled: the
/// answer under test is `Allowed` versus `Unauthenticated`, and a `Throttled`
/// would be a third outcome muddying both.
fn limiter(addr: &str, password: Option<&str>) -> Limiter {
    let limits = Limits::parse("auth.write=1000:1000", "1000:1000").expect("the limits parse");
    Limiter::new(addr, password, limits, Duration::from_millis(500), 6).expect("the limiter opens")
}

async fn spend(limiter: &Limiter) -> Decision {
    limiter
        .check("someone", "auth", Kind::Write, &Overrides::default())
        .await
}

/// A synchronous connection that is authenticated if the server wants it to be.
///
/// Synchronous rather than async because [`Locked::drop`] needs one on a thread
/// that may be unwinding, where there is no runtime left to await on.
fn admin(addr: &str) -> Option<redis::Connection> {
    let client = redis::Client::open(format!("redis://{addr}")).ok()?;
    let mut conn = client.get_connection().ok()?;
    // Unconditional, and its failure is ignored on purpose. Against a server with
    // no password `AUTH` answers `ERR Client sent AUTH, but no password is set`,
    // which is not a problem — the connection is usable either way, and this is
    // the one call site that has to work in BOTH states.
    let _: Result<(), _> = redis::cmd("AUTH").arg(PASSWORD).exec(&mut conn);
    Some(conn)
}

fn set_requirepass(conn: &mut redis::Connection, password: &str) -> redis::RedisResult<()> {
    redis::cmd("CONFIG")
        .arg("SET")
        .arg("requirepass")
        .arg(password)
        .exec(conn)
}

/// The shared server put into a known authentication state for one test, and
/// cleared whatever happens.
///
/// It takes the state rather than assuming it, because one of the tests below
/// needs the server to want NO password — and that test still has to hold the
/// mutex, or a sibling toggling `requirepass` underneath it would decide its
/// answer.
struct Locked {
    addr: String,
    _held: std::sync::MutexGuard<'static, ()>,
}

impl Locked {
    fn requiring_a_password(addr: &str) -> Self {
        Self::new(addr, PASSWORD)
    }

    fn requiring_none(addr: &str) -> Self {
        Self::new(addr, "")
    }

    fn new(addr: &str, password: &str) -> Self {
        let held = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut conn = admin(addr).expect("the test Valkey is reachable");
        // CLEARED FIRST, then set. A previous run killed between the two would
        // otherwise leave the shared server locked, and `admin` above is written
        // to get in from either state.
        let _: Result<(), _> = set_requirepass(&mut conn, "");
        set_requirepass(&mut conn, password).expect("the test Valkey takes CONFIG SET requirepass");
        Self {
            addr: addr.to_string(),
            _held: held,
        }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        if let Some(mut conn) = admin(&self.addr) {
            let _: Result<(), _> = set_requirepass(&mut conn, "");
        }
    }
}

#[tokio::test]
async fn a_client_with_no_password_is_refused_by_a_cache_that_demands_one() {
    let Some(addr) = addr() else { return };
    let _locked = Locked::requiring_a_password(&addr);

    // THE HALF THAT CANNOT PASS AGAINST AN OPEN SERVER. A Valkey with no
    // requirepass answers this client and the decision is `Allowed`.
    assert_eq!(
        spend(&limiter(&addr, None)).await,
        Decision::Unauthenticated,
        "a gateway with no credential reached a cache that demands one and was not refused. \
         Either the cache is not actually authenticated, or the NOAUTH it sent was classified \
         as an ordinary degradation and the call failed OPEN onto the floor."
    );
}

#[tokio::test]
async fn the_same_cache_serves_a_client_that_carries_the_password() {
    let Some(addr) = addr() else { return };
    let _locked = Locked::requiring_a_password(&addr);

    // THE HALF THE MUTATION BITES. Drop the password on the way into
    // `Limiter::new`, or stop `Limiter::new` recording it on the connection, and
    // this goes red — which is what proves the refusal above is about the
    // credential rather than about the server being broken for some unrelated
    // reason.
    assert_eq!(
        spend(&limiter(&addr, Some(PASSWORD))).await,
        Decision::Allowed,
        "the password this gateway was configured with was not accepted by the cache that \
         demands it, so it never reached the handshake"
    );
}

#[tokio::test]
async fn a_wrong_password_is_refused_rather_than_degraded() {
    let Some(addr) = addr() else { return };
    let _locked = Locked::requiring_a_password(&addr);

    // A DIFFERENT ARM OF THE SAME PROPERTY, over a different code path: a
    // password that IS sent and rejected fails inside the handshake, where
    // `redis` reports a failed connection rather than a command error.
    // Classifying only the NOAUTH case would leave this one arriving as
    // `unreachable` and failing open.
    assert_eq!(
        spend(&limiter(&addr, Some("not-the-password"))).await,
        Decision::Unauthenticated,
        "a rejected password was not distinguished from an unreachable cache, so the call \
         proceeded on the degraded floor instead of being refused"
    );
}

#[tokio::test]
async fn a_password_offered_to_a_cache_that_wants_none_is_also_refused() {
    let Some(addr) = addr() else { return };
    let _locked = Locked::requiring_none(&addr);

    // THE MERGE ORDER, PINNED AS A TEST rather than left as a claim in a pull
    // request body. The deployment sequence for ledger 518 rests on this
    // asymmetry: `yadgarhq/deploy` must merge BEFORE this repository, because
    // this direction is an outage and the other is a bounded degradation.
    //
    // - `deploy` first: the cache gains a password while the running gateway has
    //   none. That build classifies the resulting NOAUTH as an ordinary error
    //   and fails OPEN onto its floor — served, bounded, counted.
    // - This repository first: a gateway holds a password for a cache that has
    //   none. `valkey-server` answers `AUTH` with an error when no password is
    //   set, `redis` reports it as `AuthenticationFailed`, and THIS build
    //   refuses. A 503 on every user-attributed call until `deploy` catches up.
    //
    // Asserted rather than reasoned about, because the claim outlives the change:
    // this repository squash-merges with the pull request body as the commit
    // message, so a sentence about deployment order that nothing checks becomes
    // permanent folklore the day the behaviour drifts.
    assert_eq!(
        spend(&limiter(&addr, Some(PASSWORD))).await,
        Decision::Unauthenticated,
        "a gateway carrying a password reached a cache that wants none and was NOT refused. \
         That is a better outcome than the one documented, but the merge order in \
         MIGRATION_NOTES.md and in all three pull request bodies is argued from this refusal — \
         correct them rather than deleting this test."
    );
}

#[tokio::test]
async fn an_unreachable_cache_still_fails_open_onto_the_floor() {
    // THE CONTROL, and it needs no server — so it runs even where the rest of
    // this binary skips. D74's deliberate fail-open for an OUTAGE must survive
    // this change: the argument on `Decision::Degraded` is unchanged, and only
    // the credential case is carved out of it.
    assert_eq!(
        spend(&limiter("127.0.0.1:1", Some(PASSWORD))).await,
        Decision::Degraded(Degrade::Unreachable),
        "a cache that is simply absent must still let the call through under this replica's \
         own floor; only a REFUSED credential is fatal"
    );
}
