//! The subscription itself: subscribe, evict, and stop when the broker says so.
//!
//! Split out of [`super`] for the file-size ceiling. The reasoning that governs
//! this code — why a flush is not an acknowledgement, and which of the two
//! refusal paths is a guarantee and which a courtesy — is in [`super`]'s module
//! comment, and is not repeated here.

use std::time::Duration;

use tokio::sync::oneshot;
use tokio_stream::StreamExt;

use super::broker::{Connection, CONNECT_TIMEOUT};
use super::{subject, CONSUMING};

/// How long a refusal is given to arrive before [`start`] answers.
///
/// **BEST EFFORT, AND DELIBERATELY NOT A GUARANTEE.** This is a whole round trip
/// plus a server parse plus an internal channel hop plus a task schedule — see the
/// module comment: the flush before it is local, so nothing here proves the server
/// has even read the `SUB`. A broker slower than this window produces a boot line
/// that says "consuming" when it is not.
///
/// **What makes that survivable rather than permanent is [`drain`]'s select**, not
/// this number: a refusal arriving after the window still ends the subscription,
/// still logs at ERROR, and still makes [`run`] redial and say so again. Raising
/// this would buy a more-often-correct boot line at the cost of that much added to
/// every boot and every redial; a quarter of a second covers a healthy broker on a
/// pod network and is not asked to do more.
///
/// [`forbidden_after_flush`] returns the instant the refusal lands, so a fast
/// refusal costs nothing.
pub(super) const PERMISSION_GRACE: Duration = Duration::from_millis(250);

/// How often the flag is read inside that window.
const PERMISSION_POLL: Duration = Duration::from_millis(5);

/// Whether the broker refused one of this module's subscriptions, given
/// [`PERMISSION_GRACE`] to arrive.
///
/// A `false` here means "no refusal YET", never "not forbidden" — see the module
/// comment. [`drain`] goes on watching after this returns.
pub(super) async fn forbidden_after_flush(connection: &Connection) -> bool {
    let deadline = tokio::time::Instant::now() + PERMISSION_GRACE;
    loop {
        if connection.forbidden() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(PERMISSION_POLL).await;
    }
}

/// Get the two `SUB`s out of this process, within [`CONNECT_TIMEOUT`].
///
/// `false` means the subscription never left, and [`drain`] must not announce
/// one. Its own function because the flush is the step whose BOUND matters —
/// `main` is blocked on it — and the reasoning for that bound is here with it.
async fn flushed(client: &async_nats::Client, ready: &mut Option<oneshot::Sender<bool>>) -> bool {
    // **A LOCAL SOCKET FLUSH, NOT AN ACKNOWLEDGEMENT** — see the module comment.
    // It gets the two `SUB`s out of this process, which is the most any call here
    // can do: NATS acknowledges no `SUB`, and `async-nats`' `flush` enqueues no
    // `PING`. So this bounds when the question was ASKED, and `PERMISSION_GRACE`
    // below is a courtesy window on the answer rather than a wait for one.
    //
    // BOUNDED, because `main` is blocked on this. An unbounded flush on a socket
    // that dies between the connect returning and `poll_flush` completing parks an
    // observer nothing resolves, and `start` would never answer — a boot that
    // hangs for ever behind a `readinessProbe` with no liveness probe to restart
    // it, which is a broker outage turned into a gateway outage.
    //
    // A FLUSH THAT FAILS IS NOT-CONSUMING, and the error is not discarded. The
    // connection is gone, so this reports `false` and lets the loop redial rather
    // than falling through to announce a subscription that never left the process.
    if !matches!(
        tokio::time::timeout(CONNECT_TIMEOUT, client.flush()).await,
        Ok(Ok(()))
    ) {
        tracing::error!(
            "the subscriptions could not be written to the broker within {} seconds; no \
             invalidation is being consumed",
            CONNECT_TIMEOUT.as_secs()
        );
        if let Some(tx) = ready.take() {
            let _ = tx.send(false);
        }
        return false;
    }
    true
}

/// Act on one invalidation frame.
///
/// Its own function because WHICH frames are acted on is the rule worth
/// reading alone: an empty id is dropped rather than passed to `forget_user`.
fn evict<F>(message: &async_nats::Message, forget_user: &F)
where
    F: Fn(&str),
{
    let subject = message.subject.as_str();
    match std::str::from_utf8(&message.payload) {
        // The user id is logged: it is an identity, which D72 and D77 keep out
        // of METRICS, and this is the record of an eviction actually happening.
        Ok(user_id) if !user_id.is_empty() => {
            forget_user(user_id);
            tracing::info!(subject, user_id, "cached identity invalidated (D72)");
        }
        // NEITHER OF THESE CALLS `forget_user`. An empty id matches no cached
        // answer, and passing one through would be a scan of the whole map for
        // nothing on every malformed message.
        Ok(_) => tracing::warn!(
            subject,
            "invalidation carries no user id; nothing to forget"
        ),
        Err(e) => {
            tracing::warn!(subject, error = %e, "invalidation payload is not UTF-8; ignored")
        }
    }
}

/// Subscribe to both subjects and evict until the connection ends.
pub(super) async fn drain<F>(
    connection: &Connection,
    forget_user: &F,
    ready: &mut Option<oneshot::Sender<bool>>,
) -> Result<(), async_nats::SubscribeError>
where
    F: Fn(&str),
{
    let client = &connection.client;
    // **NO REFUSAL CAN BE MISSED, AND THE REASON IS NOT WHERE THIS LINE SITS.**
    // Two documented `watch` invariants carry it, and both are worth naming
    // because the obvious rationale — "clone early so nothing slips past" — is
    // false: `Clone for Receiver` copies the PARENT's version rather than the
    // version current at clone time, and `Connection::forbidden` reads through
    // `borrow`, which does not mark anything seen. So this receiver's version
    // stays where the channel started no matter when it is cloned.
    //
    //   1. A receiver's version advances only when `changed` or
    //      `borrow_and_update` completes, and the shared version is monotonic —
    //      so a refusal sent at ANY point, before this line or long after it,
    //      leaves the two unequal and `changed` returns immediately.
    //   2. `changed` is cancel-safe: when the other arm of the select below wins,
    //      it is guaranteed that no value has been marked seen. A message
    //      arriving in the same breath as a refusal cannot swallow it.
    let mut refused = connection.refused.clone();
    // TWO EXACT SUBJECTS RATHER THAN A WILDCARD. `yadgar.iam.*.*` would match both
    // and also every subject `iam` publishes later — whose payload this code would
    // then read as a user id without knowing whether it is one.
    //
    // NO QUEUE GROUP on either. See the module comment: a group would evict one
    // replica and leave the rest serving the revoked credential.
    let revoked = client.subscribe(subject::CREDENTIAL_REVOKED).await?;
    let teams = client.subscribe(subject::TEAMS_CHANGED).await?;
    let mut events = revoked.merge(teams);

    if !flushed(client, ready).await {
        return Ok(());
    }
    let forbidden = forbidden_after_flush(connection).await;
    // **BEFORE THE ANSWER, NOT AFTER IT**, and the ordering is the whole point:
    // `start` returns the instant this channel is answered, so a caller that reads
    // `true` must be looking at a gauge that already agrees. Written on the same
    // condition as the answer, from the same `forbidden`, so the two cannot say
    // different things about one subscription. The `false` case needs no write —
    // `start` published `0` before the dial and `run` republishes it the moment
    // this function returns.
    if !forbidden {
        metrics::gauge!(CONSUMING).set(1.0);
    }
    // `start` is waiting on the FIRST pass only; every later one is a redial, and
    // is the one that has to announce itself.
    let redial = ready.is_none();
    if let Some(tx) = ready.take() {
        let _ = tx.send(!forbidden);
    }
    if forbidden {
        // `on_event` already wrote the ERROR naming the subjects. Returning here
        // rather than holding a stream nothing will ever push to lets the loop
        // redial, which is what recovers when the broker's permissions are fixed.
        // The redial gets a FRESH connection and a fresh flag, subscribes again,
        // and earns the same `-ERR` — so the fault keeps reporting itself for as
        // long as it stands rather than being announced once and going quiet.
        return Ok(());
    }
    if redial {
        // AFTER THE FLUSH, never before it. This is the only place that can say
        // it and be right: the connection is up AND the broker did not refuse
        // these two subjects.
        tracing::info!("consuming cache invalidation again (D72)");
    }

    loop {
        let message = tokio::select! {
            // BIASED, so a refusal already waiting wins over a message already
            // queued. Nothing this subscription delivers matters once the broker
            // has said it should be delivering nothing.
            biased;
            // **THE LATE REFUSAL, AND THE REASON THIS IS A LOOP WITH A SELECT
            // RATHER THAN A `while let`.** A refusal that arrives after
            // `PERMISSION_GRACE` used to be read by nobody: a forbidden subject
            // delivers no messages, so the stream never ends, `drain` never
            // returns, `run` never redials, and the boot line stays "consuming"
            // for the life of the pod. Returning here makes `run` log it and
            // redial, so a wrong boot line self-corrects in one cycle. It also
            // covers a permission REVOKED while running, which `async-nats`'
            // `handle_reconnect` cannot notice: it re-enqueues every live
            // subscription with no flush and no permission re-check.
            _ = refused.changed() => return Ok(()),
            message = events.next() => match message {
                Some(message) => message,
                None => break,
            },
        };
        evict(&message, forget_user);
    }
    Ok(())
}
