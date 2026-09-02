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
//!   arrives as an [`async_nats::Event::ServerError`] and `async-nats` logs those
//!   at `debug!` — below the `info` these pods run at, so it vanishes.
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

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio_stream::StreamExt;

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

/// Where the broker is. The same name `iam` reads, because it is the same broker.
const URL: &str = "NATS_URL";
/// The account this gateway authenticates as. It is NOT `iam`'s.
const USER: &str = "NATS_USER";
/// A FILE holding the password, never the password itself — an environment
/// variable is visible in `kubectl describe pod` and in `/proc/<pid>/environ`.
const PASSWORD_FILE: &str = "NATS_PASSWORD_FILE";

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

/// How long one dial may take before it counts as unreachable.
///
/// **Set here rather than left to `async-nats`, because [`start`] awaits the first
/// dial BEFORE `main` binds the listener** — so whatever bounds this bounds how
/// long a gateway takes to start serving when the broker's address accepts a
/// connection and then says nothing. The library's own default happens to be five
/// seconds today, and a default in a dependency is not a bound this repository
/// gets to rely on. Below [`RETRY`], so one dial cannot still be outstanding when
/// the next is due.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

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
const PERMISSION_GRACE: Duration = Duration::from_millis(250);

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

/// How often the flag is read inside that window.
const PERMISSION_POLL: Duration = Duration::from_millis(5);

/// What this service presents to the broker.
///
/// `Debug` is written by hand rather than derived. A derived one would print the
/// password into any log line, panic message or test failure that formatted the
/// struct, which is how a credential ends up somewhere nobody meant to put it.
#[derive(Clone)]
pub struct BrokerCredentials {
    pub user: String,
    pub password: String,
}

impl fmt::Debug for BrokerCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrokerCredentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Where the broker is and what this gateway presents to it.
#[derive(Clone, Debug)]
pub struct Broker {
    url: String,
    credentials: Option<BrokerCredentials>,
}

impl Broker {
    pub fn new(url: String, credentials: Option<BrokerCredentials>) -> Self {
        Self { url, credentials }
    }

    /// The broker this process will use, or `None` if none is configured.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same decision over an injected lookup, for the reason
    /// [`crate::attest::Attestation::from_lookup`] gives: a test that sets a real
    /// environment variable steers every other test in the same binary.
    ///
    /// **AN UNSET KEY AND AN EMPTY ONE ARE THE SAME DEPLOYMENT.** A chart that
    /// renders a variable with no value must not be a different configuration
    /// from one that omits it.
    ///
    /// **A HALF-CONFIGURED CREDENTIAL FAILS BOOT, in both directions.** The
    /// broker's `authorization` block names an account and a password together,
    /// so either one alone is a deployment mistake — and the tempting arm, a user
    /// with no password, must not fall back to connecting anonymously. That is
    /// the silent downgrade every other credential in this binary refuses.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let url = lookup(URL).unwrap_or_default();
        if url.is_empty() {
            return Ok(None);
        }
        let user = lookup(USER).unwrap_or_default();
        let path = lookup(PASSWORD_FILE).unwrap_or_default();

        if path.is_empty() {
            if !user.is_empty() {
                return Err(format!(
                    "{USER} is set to {user} and {PASSWORD_FILE} is not. The broker's \
                     authorization block names an account and a password together, and \
                     connecting with no credential instead would be a silent fall back — to a \
                     connection this broker then REFUSES anyway, failing a layer away from its \
                     cause. Either mount the Secret or unset {USER}."
                ));
            }
            return Ok(Some(Self::new(url, None)));
        }

        let raw = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "{PASSWORD_FILE} names {path}, which cannot be read: {e}. It is the password \
                 this gateway presents to the broker that carries D72's cache invalidation. \
                 Refusing to start rather than connecting without one."
            )
        })?;
        // TRAILING NEWLINE ONLY, and this is not tidiness. `kubectl create secret
        // --from-file` of a file a person edited keeps the newline their editor
        // added, and a password with a `\n` on the end is a different password —
        // rejected by a broker configured from the same item, as an authorization
        // violation nobody can see. Inner whitespace is a legitimate part of a
        // password and is left alone.
        let password = raw.trim_end_matches(['\n', '\r']).to_string();
        if password.is_empty() {
            return Err(format!(
                "{PASSWORD_FILE} names {path}, which is empty. A blank password is not one. \
                 Either put the broker password in that file or unset the variable, which is \
                 how a deployment says the broker asks for none."
            ));
        }
        if user.is_empty() {
            return Err(format!(
                "{PASSWORD_FILE} names {path} and {USER} is unset. A password with no account \
                 to present it as cannot authenticate."
            ));
        }
        Ok(Some(Self::new(
            url,
            Some(BrokerCredentials { user, password }),
        )))
    }

    async fn connect(&self) -> Result<Connection, async_nats::ConnectError> {
        // BUILT FROM THE PAIR, never spliced into the URL. `nats://user:pass@host`
        // carries a password only URL-encoded, so one containing `@`, `/` or `#`
        // would be silently truncated and a DIFFERENT password sent than the one
        // in the Secret — a failure with no visible cause at any layer.
        let options = match &self.credentials {
            Some(c) => async_nats::ConnectOptions::with_user_and_password(
                c.user.clone(),
                c.password.clone(),
            ),
            None => async_nats::ConnectOptions::new(),
        };
        // THE CHANNEL THE CALLBACK WRITES. Per connection, because a redial gets a
        // fresh answer from the broker and a stale `true` would keep a recovered
        // consumer reporting itself forbidden.
        let (refusals, refused) = tokio::sync::watch::channel(false);
        let refusals = Arc::new(refusals);
        let sender = Arc::clone(&refusals);
        let client = options
            // BOUNDED HERE, on both arms. See `CONNECT_TIMEOUT`: `start` awaits
            // this before the listener binds, so an unbounded dial is an
            // unbounded boot.
            .connection_timeout(CONNECT_TIMEOUT)
            // WITHOUT THIS THE WORST FAILURE IN THIS MODULE IS INVISIBLE. See the
            // module comment: a forbidden subscription is reported only through
            // this channel, and `async-nats` logs the event at `debug!`.
            .event_callback(move |event| {
                let sender = Arc::clone(&sender);
                async move { on_event(event, &sender) }
            })
            .connect(&self.url)
            .await?;
        // The `Arc` clone inside the callback is what keeps the sender alive for
        // the life of the connection; this handle has done its job.
        drop(refusals);
        Ok(Connection { client, refused })
    }
}

/// A live connection and what the broker has said about it since.
struct Connection {
    client: async_nats::Client,
    /// Carries `true` once the broker refuses one of THIS module's two
    /// subscriptions.
    ///
    /// **A `watch` rather than a flag, because the refusal has to be WAITED ON and
    /// not merely read.** It does not arrive on the call that caused it —
    /// `Client::subscribe` returns as soon as the command is queued locally — so a
    /// single read at subscribe time catches only the refusals fast enough to beat
    /// it. [`drain`] selects on this channel for the whole life of the
    /// subscription, which is what stops a late refusal from becoming a consumer
    /// that reports success and receives nothing for ever. A `watch` cannot lose
    /// the edge the way a `Notify` can, because it carries a version rather than a
    /// wake-up.
    refused: tokio::sync::watch::Receiver<bool>,
}

impl Connection {
    fn forbidden(&self) -> bool {
        *self.refused.borrow()
    }
}

/// Everything the broker says about a connection after it is established.
///
/// **`async-nats` logs these at `debug!` and the pods run at `info`**, so without
/// this function they do not exist. The one that matters is
/// [`async_nats::Event::ServerError`]: a subscribe permission violation arrives
/// there, leaves the connection open, and is otherwise indistinguishable from a
/// healthy consumer that nobody is publishing to.
fn on_event(event: async_nats::Event, refused: &tokio::sync::watch::Sender<bool>) {
    match event {
        async_nats::Event::ServerError(e) => {
            let error = e.to_string();
            // NAMED SUBJECTS ONLY. A `-ERR` about something else is still worth an
            // operator's attention, but it is not a statement that THIS consumer
            // is receiving nothing — and `start` answers `false` off this flag.
            if error.contains(subject::CREDENTIAL_REVOKED) || error.contains(subject::TEAMS_CHANGED)
            {
                let _ = refused.send(true);
                tracing::error!(
                    error,
                    "the broker FORBIDS this gateway's subscription, so NO invalidation is \
                     consumed and a revoked credential is honoured until its cache entry \
                     expires. The connection stays OPEN and nothing else reports this. It is a \
                     deployment error rather than an outage: check the subscribe permissions \
                     for {USER} against {} and {}.",
                    subject::CREDENTIAL_REVOKED,
                    subject::TEAMS_CHANGED
                );
            } else {
                tracing::error!(error, "the broker reported an error on this connection");
            }
        }
        // LOUD, because the window it opens is the one this module exists to
        // close. `async-nats` reconnects and restores subscriptions underneath
        // this, so the matching `Connected` below is the end of the window.
        async_nats::Event::Disconnected => tracing::warn!(
            "disconnected from the broker; no invalidation is being consumed until it reconnects"
        ),
        // CONNECTED IS NOT CONSUMING, and this arm used to say it was. `Connected`
        // fires from `try_connect_to_server` BEFORE a single `SUB` is written, on
        // the first dial and on every internal reconnect — so on a forbidden
        // replica it printed the success line microseconds ahead of the ERROR
        // contradicting it, and reprinted it for ever. The consuming claim belongs
        // only to `drain`, which is downstream of both the subscribe and the
        // window that can disprove it.
        async_nats::Event::Connected => tracing::info!("connected to the broker"),
        async_nats::Event::ClientError(e) => {
            tracing::warn!(error = %e, "the broker connection reported a client error");
        }
        other => tracing::info!(event = %other, "broker event"),
    }
}

/// What to do about a refusal, which depends on whether this process presented
/// anything to be refused.
///
/// Shared by [`start`] and [`run`] so the boot line and the redial line cannot
/// drift into saying different things about one broker.
fn refusal_remedy(broker: &Broker) -> String {
    match &broker.credentials {
        Some(_) => {
            format!("Check {USER} and {PASSWORD_FILE} against the broker's authorization block.")
        }
        // THE CASE THE REFERENCE DEPLOYMENT IS IN. No credential is configured and
        // the broker demands one, which is not "unauthenticated" — it is REFUSED,
        // and nothing is consumed at all.
        None => format!(
            "No {PASSWORD_FILE} is configured and this broker demands a credential, so this \
             gateway is REFUSED rather than connected: give the broker an account for it and \
             mount that account's Secret."
        ),
    }
}

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
    let Some(broker) = broker else {
        tracing::warn!(
            "NO BROKER IS CONFIGURED ({URL} is unset), so this gateway consumes no cache \
             invalidation and a credential revoked in iam keeps working here until its cache \
             entry expires (D72)."
        );
        return false;
    };

    let first = match broker.connect().await {
        Ok(connection) => {
            if broker.credentials.is_none() {
                // REACHING THIS ARM WITH NO CREDENTIAL MEANS THE BROKER ACCEPTED
                // ONE ANYWAY, so this warning is about the broker rather than
                // about this deployment: a server with an `authorization` block
                // and no `no_auth_user` refuses instead, and lands in the arm
                // below. This is the open-broker case, and what it costs is that
                // anything on the pod network can publish a forged invalidation
                // or drown the real ones.
                tracing::warn!(
                    "the broker ACCEPTED a connection carrying no credential, so it declares no \
                     authorization block (or a no_auth_user) and anything on the pod network can \
                     publish D72's invalidation events, or drown them under a flood. Give the \
                     broker an account for this gateway, then set {USER} and {PASSWORD_FILE}."
                );
            }
            Some(connection)
        }
        // SEPARATED FROM THE OUTAGE ARM, and that is what the second error arm
        // buys. An outage ends by itself; a refused credential does not, and an
        // operator who reads "cannot reach the broker" for a refused credential
        // goes looking for a network fault that is not there.
        //
        // **BOTH REFUSALS LAND HERE, and they have different fixes.** A broker
        // with an `authorization` block refuses a connection carrying NO
        // credential exactly as it refuses a wrong one, so the message has to say
        // which of the two this process is — otherwise the deployment whose Secret
        // was never mounted reads an instruction to check a password it does not
        // have.
        Err(e) if e.kind() == async_nats::ConnectErrorKind::AuthorizationViolation => {
            tracing::error!(
                url = %broker.url, error = %e,
                // WHETHER, never WHAT. This log is shipped.
                authenticated = broker.credentials.is_some(),
                "the broker REFUSED this gateway, so NO invalidation is consumed and a revoked \
                 credential is honoured until its cache entry expires. This is a deployment \
                 error rather than an outage: it does not recover on its own. {}",
                refusal_remedy(&broker)
            );
            None
        }
        Err(e) => {
            tracing::error!(
                url = %broker.url, error = %e,
                "cannot reach the broker, so NO invalidation is consumed and a revoked \
                 credential is honoured until its cache entry expires. Retrying every {} \
                 seconds.",
                RETRY.as_secs()
            );
            None
        }
    };

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

/// Hold a subscription for as long as there is one to hold, and redial when there
/// is not.
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
            None => match broker.connect().await {
                Ok(c) => {
                    // RECONNECTED, WHICH IS NOT YET CONSUMING. This line used to
                    // say it was, and on a redial against a broker that forbids
                    // the subscription it said so a few milliseconds before the
                    // ERROR saying the opposite — the same false-boot-line class
                    // this module exists to remove, on the loop instead of at
                    // boot. `drain` writes the consuming line, after the flush
                    // that can disprove it.
                    tracing::info!(url = %broker.url, "reconnected to the broker");
                    c
                }
                // MIRRORS `start`'S SPLIT, and it is not decoration. `start`
                // prints the accurate line ONCE, at boot; this loop prints its
                // line for as long as the fault stands. Without this arm a
                // refused credential produces one true sentence at boot and an
                // untrue "cannot reach the broker" every RETRY for ever after —
                // the network fault that is not there, which is the exact failure
                // the split in `start` exists to avoid.
                Err(e) if e.kind() == async_nats::ConnectErrorKind::AuthorizationViolation => {
                    tracing::error!(
                        url = %broker.url, error = %e,
                        // WHETHER, never WHAT. This log is shipped.
                        authenticated = broker.credentials.is_some(),
                        "the broker still REFUSES this gateway; no invalidation is being \
                         consumed. {} Retrying every {} seconds.",
                        refusal_remedy(&broker),
                        REFUSED_RETRY.as_secs()
                    );
                    // BACKED OFF HARDER THAN AN OUTAGE. A credential the broker
                    // does not accept does not start being accepted five seconds
                    // later; see `REFUSED_RETRY`.
                    tokio::time::sleep(REFUSED_RETRY).await;
                    continue;
                }
                Err(e) => {
                    tracing::error!(
                        url = %broker.url, error = %e,
                        "still cannot reach the broker; no invalidation is being consumed. \
                         Retrying every {} seconds.",
                        RETRY.as_secs()
                    );
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            },
        };

        let outcome = drain(&connected, &forget_user, &mut ready).await;
        // WHATEVER HAPPENED, `start` GETS AN ANSWER. `drain` sends its own on the
        // path that reaches a subscription; this catches the one that does not, so
        // a subscribe error is a `false` boot line rather than a boot that hangs.
        if let Some(tx) = ready.take() {
            let _ = tx.send(false);
        }
        let forbidden = connected.forbidden();
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

/// Whether the broker refused one of this module's subscriptions, given
/// [`PERMISSION_GRACE`] to arrive.
///
/// A `false` here means "no refusal YET", never "not forbidden" — see the module
/// comment. [`drain`] goes on watching after this returns.
async fn forbidden_after_flush(connection: &Connection) -> bool {
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

/// Subscribe to both subjects and evict until the connection ends.
async fn drain<F>(
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
        return Ok(());
    }
    let forbidden = forbidden_after_flush(connection).await;
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_string())
        }
    }

    fn password_file(name: &str, contents: &str) -> String {
        let path = std::env::temp_dir().join(format!("gateway-nats-{name}"));
        std::fs::write(&path, contents).expect("the fixture is written");
        path.to_string_lossy().to_string()
    }

    #[test]
    fn subjects_match_the_ones_iam_publishes() {
        // Copied literals rather than a shared constant — see the module comment.
        // If either drifts, the consumer goes quiet rather than failing, so the
        // pair is pinned here as well as exercised over a socket in
        // `tests/credential_invalidation.rs`.
        assert_eq!(subject::CREDENTIAL_REVOKED, "yadgar.iam.credential.revoked");
        assert_eq!(subject::TEAMS_CHANGED, "yadgar.iam.user.teams-changed");
    }

    #[test]
    fn no_url_is_no_broker_rather_than_an_error() {
        // A LOCAL RUN IS A SUPPORTED DEPLOYMENT. Refusing here would make a
        // developer with no broker unable to start the binary at all.
        assert!(Broker::from_lookup(env_of(&[]))
            .expect("an unconfigured broker is not an error")
            .is_none());
        assert!(Broker::from_lookup(env_of(&[("NATS_URL", "")]))
            .expect("an empty url is the same as an unset one")
            .is_none());
    }

    #[test]
    fn a_url_alone_parses_into_a_broker_carrying_no_credential() {
        // WHAT THIS CHECKS IS THE PARSE, AND ONLY THE PARSE. It used to be named
        // for connecting anonymously, which is a claim about a broker it never
        // dials — and against a broker with an `authorization` block that claim is
        // false: such a server REFUSES a credential-less CONNECT rather than
        // accepting it. What actually happens on the wire is
        // `a_gateway_with_no_credential_is_refused_and_says_so_rather_than_reporting_success`
        // in `tests/credential_invalidation.rs`, over a socket.
        let broker = Broker::from_lookup(env_of(&[("NATS_URL", "nats://nats:4222")]))
            .expect("a url alone is a usable broker")
            .expect("and it is a broker rather than nothing");
        assert!(broker.credentials.is_none());
    }

    #[test]
    fn the_configured_pair_is_loaded_from_the_file() {
        let path = password_file("full", "sentinel-of-the-file-8a44\n");
        let broker = Broker::from_lookup(env_of(&[
            ("NATS_URL", "nats://nats:4222"),
            ("NATS_USER", "gateway"),
            ("NATS_PASSWORD_FILE", path.as_str()),
        ]))
        .expect("a fully configured broker credential loads")
        .expect("and it is a broker");
        let credentials = broker.credentials.expect("a credential");
        assert_eq!(credentials.user, "gateway");
        // THE TRAILING NEWLINE IS GONE. A password with a `\n` on the end is a
        // different password, and the failure it causes is invisible.
        assert_eq!(credentials.password, "sentinel-of-the-file-8a44");
    }

    #[test]
    fn a_user_with_no_password_refuses_the_boot_rather_than_connecting_anonymously() {
        // THE ARM THAT MATTERS. The tempting implementation returns `Ok(None)`
        // whenever the path is empty, which connects with no credential at all and
        // logs a warning nobody reads — the silent downgrade every other
        // credential in this binary refuses.
        let err = Broker::from_lookup(env_of(&[
            ("NATS_URL", "nats://nats:4222"),
            ("NATS_USER", "gateway"),
        ]))
        .expect_err("an account with no password cannot authenticate");
        assert!(err.contains("NATS_PASSWORD_FILE"), "{err}");
    }

    #[test]
    fn a_password_with_no_user_refuses_the_boot() {
        let path = password_file("no-user", "sentinel-of-the-file-8a44");
        let err = Broker::from_lookup(env_of(&[
            ("NATS_URL", "nats://nats:4222"),
            ("NATS_PASSWORD_FILE", path.as_str()),
        ]))
        .expect_err("a password with no account to present it as cannot authenticate");
        assert!(err.contains("NATS_USER"), "{err}");
    }

    #[test]
    fn an_empty_password_file_refuses_the_boot() {
        // A Secret whose key is present and blank is the ordinary way this goes
        // wrong, and a blank password is not one.
        let path = password_file("empty", "\n");
        let err = Broker::from_lookup(env_of(&[
            ("NATS_URL", "nats://nats:4222"),
            ("NATS_USER", "gateway"),
            ("NATS_PASSWORD_FILE", path.as_str()),
        ]))
        .expect_err("a blank password is not a password");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn an_unreadable_password_file_refuses_the_boot_naming_the_path() {
        let err = Broker::from_lookup(env_of(&[
            ("NATS_URL", "nats://nats:4222"),
            ("NATS_USER", "gateway"),
            ("NATS_PASSWORD_FILE", "/nowhere/at/all"),
        ]))
        .expect_err("a deployment that asked for a credential and cannot produce one");
        assert!(err.contains("/nowhere/at/all"), "{err}");
    }

    #[test]
    fn a_credential_never_prints_itself() {
        let printed = format!(
            "{:?}",
            BrokerCredentials {
                user: "gateway".into(),
                password: "sentinel-of-the-nats-password".into(),
            }
        );
        assert!(
            !printed.contains("sentinel-of-the-nats-password"),
            "{printed}"
        );
        assert!(printed.contains("gateway"), "{printed}");
    }

    #[tokio::test]
    async fn an_unconfigured_broker_reports_that_it_is_not_consuming() {
        // THE HONESTY PROPERTY. `main` writes its boot line from this answer, so a
        // `true` here would be a running system asserting an invalidation path it
        // does not have.
        assert!(!start(None, |_: &str| unreachable!()).await);
    }

    #[tokio::test]
    async fn an_unreachable_broker_reports_that_it_is_not_consuming() {
        assert!(
            !start(
                Some(Broker::new("nats://127.0.0.1:1".to_string(), None)),
                |_: &str| unreachable!()
            )
            .await
        );
    }
}
