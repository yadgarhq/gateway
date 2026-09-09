//! Learning that a cached identity is no longer true.
//!
//! **This is the half of D72's cache that makes it safe**, and until this module
//! existed it was missing. The gateway caches what a credential resolves to; with
//! no signal, a revoked credential keeps working until its entry expires and a
//! removed team member keeps reading that team's records. D72 says in as many
//! words that "the TTL is a backstop, not the mechanism" — treating it as the
//! mechanism means every revocation is honoured late by design.
//!
//! `iam` publishes both events already, from its own `invalidate.rs`. This is the
//! consumer.
//!
//! # The subjects are a contract, and they are duplicated here on purpose
//!
//! [`subject::CREDENTIAL_REVOKED`] and [`subject::TEAMS_CHANGED`] are string
//! literals that must equal `iam`'s. They are not in the proto (D70) because a
//! NATS subject is not a message type, and adding one to make them shareable would
//! change a working publisher to buy nothing. So the copy is deliberate, and
//! `tests/credential_invalidation.rs` is what keeps it honest — it pushes a frame
//! on the subject this module subscribes to and asserts an eviction, so a subject
//! that drifted from `iam`'s would fail rather than go quiet.
//!
//! # Both subjects evict a PERSON, and that is not an approximation
//!
//! Both payloads are a bare user id, and both land on
//! [`crate::attest::Credentials::forget_user`] rather than on `forget_credential`.
//! `iam` holds a credential ID on a revoke and never sees the token, while this
//! cache is keyed on a hash of the token — so there is no key an event could name.
//! The workable unit is the person, and dropping their other credentials' entries
//! costs one resolve each. D72 records that as the deliberate direction to be
//! wrong in; the alternative is a cache the event cannot address at all.
//!
//! # A plain subscription, never a queue group
//!
//! Every replica holds its own in-process cache (see [`crate::attest::Credentials`]),
//! so every replica must receive every message. A queue group delivers to exactly
//! one subscriber, which would evict one pod's entry and leave the others serving
//! the revoked credential to its TTL — a partial invalidation that looks like it
//! worked. `client.subscribe` with no group is the fan-out this needs.
//!
//! **The `SUB` line itself is asserted on**, in
//! `tests/credential_invalidation.rs`, because nothing else can see this. A queue
//! group is invisible to every other observable behaviour of a single-subscriber
//! test: one subscriber in a group receives every message exactly as a plain
//! subscriber does, so an eviction test passes either way. The wire is the only
//! place the difference exists. `SUB <subject> [queue group] <sid>` has two fields
//! without a group and three with one, and the test fails on three.
//!
//! # It runs DEGRADED AND LOUD rather than refusing to boot
//!
//! A broker this gateway cannot reach does not stop it starting, and the choice is
//! not the comfortable one. The gateway is the only ingress in the system: a boot
//! gate here turns a broker outage into a total outage of every MCP call, to bound
//! a revocation window the TTL already bounds to thirty seconds. `main`'s own
//! module comment names the mechanism — under D68 a pod stuck in startup is one
//! the autoscaler cannot help — and a broker outage during a scale-up would leave
//! every new replica in CrashLoopBackOff.
//!
//! **What is NOT permitted is the silent version of that.** [`start`] returns
//! whether this replica is really consuming, and `main` writes its boot line from
//! that answer rather than from whether a broker was configured — so a gateway
//! that could not connect says the TTL is the only bound, out loud, at every boot.
//! The connection is retried on a fixed interval, so the state ends by itself when
//! the broker returns.
//!
//! **A REFUSAL IS NOT AN OUTAGE, and both the boot line and the redial line say
//! which one this is.** A broker with an `authorization` block refuses a
//! connection carrying no credential exactly as it refuses a wrong one — so a
//! gateway pointed at such a broker with no Secret mounted is REFUSED, consuming
//! nothing, rather than connected-but-unauthenticated. That fault does not end by
//! itself, so it is logged as a deployment error, its remedy names which of the
//! two refusals it is, and it is retried on [`REFUSED_RETRY`] rather than on
//! [`RETRY`].
//!
//! # A FORBIDDEN SUBSCRIPTION IS THE SILENT ONE, and it is why this module has an
//! # event callback and a flush
//!
//! A wrong password is loud: the broker answers `-ERR 'Authorization Violation'`
//! and CLOSES the connection, so it surfaces as a
//! [`async_nats::ConnectErrorKind::AuthorizationViolation`] on the dial. **A
//! subscribe permission violation does neither.** The broker leaves the connection
//! open and answers `-ERR 'Permissions Violation for Subscription to ...'`
//! asynchronously — and `Client::subscribe` returns `Ok` the moment the command is
//! queued locally, because NATS acknowledges no `SUB`. So without the two things
//! below, one typo in the broker's `subscribe.allow` list produces a gateway that
//! logs "consuming cache invalidation" at INFO and consumes nothing, for ever:
//! exactly the silent TTL-only fall back this module says is not permitted.
//!
//! - **An [`async_nats::ConnectOptions::event_callback`]**, because that `-ERR`
//!   arrives as an [`async_nats::Event::ServerError`] and nothing else in this
//!   process ACTS on it. An earlier revision of this comment said `async-nats`
//!   logs those at `debug!`, below the `info` these pods run at, so they vanish.
//!   It does not. `async-nats` 0.50 dispatches every event through one loop that
//!   writes `tracing::info!("event: {}", event)` BEFORE calling the callback
//!   (`src/lib.rs:1105`), and `main` builds `EnvFilter::new("info")` with no
//!   per-target restriction — so the line does reach the log. It is still not
//!   the control, and the callback stays. That line is INFO among INFO, worded
//!   as an event rather than as a fault, and it names neither which subject was
//!   refused nor any remedy. It also sets nothing: [`start`] answers off a flag
//!   only `on_event` can raise, so without the callback a forbidden replica
//!   would still report itself as consuming. What the callback adds is the ERROR
//!   level, the permission to check, and the refusal the next bullet acts on.
//! - **A refusal ENDS the subscription**, wherever in its life it turns up. The
//!   message loop in [`drain`] selects against the refusal as well as against the
//!   stream, so a late `-ERR` returns from `drain` and [`run`] redials.
//!
//! **THERE IS NO ACKNOWLEDGEMENT TO WAIT FOR, and this module must not pretend
//! otherwise.** NATS acknowledges no `SUB`, and
//! [`async_nats::Client::flush`] is NOT a round trip in `async-nats` 0.50: it
//! sends `Command::Flush`, which parks an observer resolved by
//! `connection.poll_flush` — a **local socket flush**. No `PING` is enqueued
//! (`ClientOp::Ping` is written only by the ping interval, the initial handshake
//! and `Command::Drain`), so a completed flush means the bytes left this process,
//! not that the server read them. There is also no sound probe available: a
//! `request` to a no-responder inbox would force a real round trip, but this
//! account is `publish: deny: ">"`, so the probe would itself earn a permission
//! violation.
//!
//! So the design splits into a guarantee and a courtesy, and only one of them is
//! load-bearing:
//!
//! - **GUARANTEED:** a refusal, however late, ends the subscription and is logged
//!   at ERROR, and the redial reports it again for as long as it stands. A wrong
//!   boot line self-corrects within one cycle. This is what makes the failure
//!   survivable rather than permanent.
//! - **BEST EFFORT:** [`PERMISSION_GRACE`] gives the refusal a short window to
//!   arrive before [`start`] answers, so the boot line is usually right the first
//!   time. On a slow or loaded broker it will not be, and that is a known and
//!   accepted limit rather than a guarantee this module can make.

use std::time::Duration;

use tokio::sync::oneshot;

mod broker;
mod consume;

use broker::{first_connection, redial, Connection, CONNECT_TIMEOUT, URL};
pub use broker::{Broker, BrokerCredentials};
use consume::{drain, PERMISSION_GRACE};

/// Subjects, matching `iam`'s `invalidate::subject` exactly.
pub mod subject {
    /// A credential was revoked. Payload: the **user id**, not the credential id.
    pub const CREDENTIAL_REVOKED: &str = "yadgar.iam.credential.revoked";
    /// A user's team membership changed. Payload: the user id.
    ///
    /// Deliberately not "removed": adding a team also changes what a cached
    /// identity says, and a consumer that only evicted on removal would serve a
    /// stale answer to somebody who had just been granted access.
    pub const TEAMS_CHANGED: &str = "yadgar.iam.user.teams-changed";
}

/// Whether this replica is consuming D72's invalidation right now: `1` or `0`.
///
/// **A GAUGE BECAUSE A REFUSAL IS A STATE, NOT AN EVENT.** It stands until
/// somebody edits the broker's `subscribe.allow` list, and [`run`] re-enters it
/// every [`REFUSED_RETRY`] for as long as it stands — so a counter would tick
/// monotonically on nothing new, and could never answer the question an operator
/// actually has, which is whether THIS replica is consuming at this moment.
///
/// **AND IT IS THE ONLY ANSWER TO THAT QUESTION OUTSIDE THE LOG.** Everything
/// above this line reports a refusal by writing `tracing::error!`, at the right
/// level and with the right wording, and that is still not an instrument: nothing
/// reads [`start`]'s `bool` past the boot line in `main`, this binary serves no
/// readiness route — its `readinessProbe` is a `tcpSocket` — and the refusal is
/// broker-side, so every replica has it at once. Before this series the question
/// "is anything in this fleet consuming revocations?" was answerable only by
/// grepping each pod's boot log, for the signal that bounds how long a revoked
/// credential keeps working: `attest`'s `MAX_TTL_SECONDS` ceiling, 300 seconds.
///
/// **PUBLISHED AS `0` BEFORE THE FIRST DIAL, so absent never has to mean
/// anything.** A series that appeared only once a subscription succeeded would
/// make "not consuming" and "not scraped" the same observation, which is the
/// silence this module exists to remove.
///
/// UNLABELLED, under D67's cardinality rule. WHICH failure this is — refused
/// credential, unreachable broker, forbidden subscription — is in the ERROR line
/// that accompanies every one of them, and splitting it across label values would
/// buy a dashboard the log already carries.
///
/// The series exists exactly when the cache it protects exists: with
/// `credentialCache.ttlSeconds: 0` there is nothing an event could evict, `main`
/// never calls [`start`], and nothing is published.
pub const CONSUMING: &str = "yadgar_gateway_invalidation_consuming";

/// How long the consumer waits before dialling again.
///
/// Short, because the window it reopens is the one this module exists to close,
/// and a redial costs one TCP connection.
const RETRY: Duration = Duration::from_secs(5);

/// How long the consumer waits before dialling again after the broker REFUSED its
/// credential.
///
/// **Deliberately far longer than [`RETRY`], because the two failures are not the
/// same failure.** An outage ends by itself and is worth asking about every five
/// seconds. A password the broker does not accept ends when somebody changes a
/// Secret, so retrying it at the outage rate buys nothing, writes an error line
/// every five seconds for as long as the mistake stands, and spends an
/// authentication attempt on the broker each time.
const REFUSED_RETRY: Duration = Duration::from_secs(60);

/// How long [`start`] waits for [`run`]'s first answer.
///
/// **DERIVED FROM WHAT `drain` CAN SPEND BEFORE IT ANSWERS, never copied from one
/// of that budget's terms.** `drain` may spend [`CONNECT_TIMEOUT`] on the bounded
/// flush and then [`PERMISSION_GRACE`] on the window, so bounding this at
/// `CONNECT_TIMEOUT` alone leaves a window — a flush landing at 2.75s — where
/// `start` gives up and reports NOT consuming while `drain` goes on consuming
/// perfectly well. That is the inverse of the failure this module exists to
/// remove, and it is worse than it sounds: `drain` has already taken the answer
/// channel, so `redial` is false on that pass and the "consuming again" line
/// never prints. The log would stay wrong for the life of the pod.
///
/// A second of slack on top, because this bounds a boot rather than a request and
/// the cost of being slightly generous is nothing.
const BOOT_ANSWER_TIMEOUT: Duration = CONNECT_TIMEOUT
    .saturating_add(PERMISSION_GRACE)
    .saturating_add(Duration::from_secs(1));

/// Start consuming, and answer whether this replica actually is.
///
/// **THE FIRST CONNECTION IS AWAITED, and that is the whole reason this returns a
/// `bool`.** `async_nats` offers a retry-on-initial-connect mode that returns a
/// client immediately whether or not anything is connected; using it would let
/// `main` log "consuming invalidation" while nothing was, which is exactly the
/// silent fall back to TTL-only eviction that this change exists to remove. So the
/// dial happens here, before the listener binds, and the boot line is written from
/// what it returned.
///
/// After that first attempt a background task owns the subscription: it drains
/// messages until the connection ends, then redials every [`RETRY`]. Nothing is
/// blocked on it and the degraded state ends by itself.
pub async fn start<F>(broker: Option<Broker>, forget_user: F) -> bool
where
    F: Fn(&str) + Send + Sync + 'static,
{
    // BEFORE THE FIRST DIAL, AND BEFORE THE `None` ARM BELOW. See [`CONSUMING`]:
    // a gauge that appeared only on success would make a refused replica and an
    // unscraped one the same observation. Every path out of this function has
    // published a `0` by the time it returns, including the one that never had a
    // broker to dial.
    metrics::gauge!(CONSUMING).set(0.0);

    let Some(broker) = broker else {
        tracing::warn!(
            "NO BROKER IS CONFIGURED ({URL} is unset), so this gateway consumes no cache \
             invalidation and a credential revoked in iam keeps working here until its cache \
             entry expires (D72)."
        );
        return false;
    };

    let first = first_connection(&broker).await;

    if first.is_none() {
        tokio::spawn(run(broker, None, forget_user, None));
        return false;
    }

    // **THE ANSWER COMES BACK FROM THE SUBSCRIBE, NOT FROM THE DIAL**, and that is
    // the difference between this boot line and one that lies. A connection the
    // broker forbids to subscribe stays OPEN, so `first.is_some()` is true for a
    // replica receiving nothing for ever. `run` sends what it learned from the
    // flush after its first subscribe; see the module comment.
    let url = broker.url.clone();
    let authenticated = broker.credentials.is_some();
    let (ready, answer) = oneshot::channel();
    tokio::spawn(run(broker, first, forget_user, Some(ready)));
    // A DROPPED SENDER IS A `false`. It means `run` ended without reaching its
    // first subscribe, and nothing is being consumed either way.
    // BOUNDED, for the reason the flush inside `drain` is: this is what `main`
    // waits on before it binds the listener, and an unbounded wait here would turn
    // a broker that accepts a connection and then stalls into a gateway that never
    // serves. A timeout is not-consuming, which is the safe direction — it
    // understates rather than overstates.
    let consuming = matches!(
        tokio::time::timeout(BOOT_ANSWER_TIMEOUT, answer).await,
        Ok(Ok(true))
    );
    if consuming {
        tracing::info!(
            url = %url,
            // WHETHER, never WHAT. This log is shipped.
            authenticated,
            "consuming cache invalidation (D72)"
        );
    }
    consuming
}

/// Why the subscription ended, said in the operator's terms.
///
/// Its own function because the three endings are three DIFFERENT operator
/// instructions — a subscribe that failed, a refusal that will not fix
/// itself, and a connection that merely dropped — and [`run`] chooses its
/// retry interval from the same `forbidden` it reports here.
fn report_end(broker: &Broker, outcome: Result<(), async_nats::SubscribeError>, forbidden: bool) {
    if let Err(e) = outcome {
        tracing::error!(
            url = %broker.url, error = %e,
            "cannot subscribe to the invalidation subjects; no invalidation is being consumed"
        );
    } else if forbidden {
        // `on_event` already wrote the sentence naming the subjects.
        tracing::error!(
            url = %broker.url,
            "the broker FORBIDS this gateway's subscription; no invalidation is being \
             consumed. Retrying every {} seconds.",
            REFUSED_RETRY.as_secs()
        );
    } else {
        // The stream ended, which means the client is gone for good —
        // `async_nats` reconnects transparently underneath it.
        tracing::error!(
            url = %broker.url,
            "the broker connection ended; no invalidation is being consumed until it is \
             re-established"
        );
    }
}

async fn run<F>(
    broker: Broker,
    mut connection: Option<Connection>,
    forget_user: F,
    // Answered once, from the first subscribe. `start` is blocked on it, so every
    // path out of this function's first pass must either send or drop it.
    mut ready: Option<oneshot::Sender<bool>>,
) where
    F: Fn(&str) + Send + Sync + 'static,
{
    loop {
        let connected = match connection.take() {
            Some(c) => c,
            None => match redial(&broker).await {
                Some(c) => c,
                None => continue,
            },
        };

        let outcome = drain(&connected, &forget_user, &mut ready).await;
        // **`drain` RETURNS ONLY WHEN THIS REPLICA HAS STOPPED CONSUMING**, by
        // every path it has: a subscribe error, a refusal fast or late, a failed
        // flush, or a stream that ended. One write here rather than one per arm,
        // so an arm added later cannot leave the gauge reading `1` for a consumer
        // that is gone. The redial that follows sets it back to `1` from `drain`
        // when, and only when, it earns it.
        metrics::gauge!(CONSUMING).set(0.0);
        // WHATEVER HAPPENED, `start` GETS AN ANSWER. `drain` sends its own on the
        // path that reaches a subscription; this catches the one that does not, so
        // a subscribe error is a `false` boot line rather than a boot that hangs.
        if let Some(tx) = ready.take() {
            let _ = tx.send(false);
        }
        let forbidden = connected.forbidden();
        report_end(&broker, outcome, forbidden);
        // DROPPED BEFORE THE WAIT, NOT AFTER IT. `connected` would otherwise live
        // to the end of this iteration, holding an open connection to a broker
        // this replica has stopped consuming from — for a whole `REFUSED_RETRY` in
        // the case that matters, while the subscription it holds is one the broker
        // has already refused. Closing it is also what makes the refusal
        // observable from outside this process, which is how the late-refusal test
        // sees that it was acted on.
        drop(connected);
        // A FORBIDDEN SUBSCRIPTION IS A DEPLOYMENT ERROR RATHER THAN AN OUTAGE,
        // exactly as a refused credential is, so it backs off the same way. Five
        // seconds would rewrite the broker's permissions no faster and would put
        // an error line in the log twelve times a minute for as long as the
        // mistake stood.
        tokio::time::sleep(if forbidden { REFUSED_RETRY } else { RETRY }).await;
    }
}

#[cfg(test)]
mod tests;
