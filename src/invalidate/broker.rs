//! Where the broker is, what this gateway presents to it, and the live
//! connection that results.
//!
//! Split out of [`super`] for the file-size ceiling. This half is
//! CONFIGURATION AND CONNECTION only: it resolves the environment, dials, and
//! reports what the broker says back. What is done with a connection once it
//! exists is [`super::consume`]'s, and the reasoning for the whole module is in
//! [`super`]'s comment.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{subject, REFUSED_RETRY, RETRY};

/// Where the broker is. The same name `iam` reads, because it is the same broker.
pub(super) const URL: &str = "NATS_URL";
/// The account this gateway authenticates as. It is NOT `iam`'s.
pub(super) const USER: &str = "NATS_USER";
/// A FILE holding the password, never the password itself — an environment
/// variable is visible in `kubectl describe pod` and in `/proc/<pid>/environ`.
pub(super) const PASSWORD_FILE: &str = "NATS_PASSWORD_FILE";

/// How long one dial may take before it counts as unreachable.
///
/// **Set here rather than left to `async-nats`, because [`start`] awaits the first
/// dial BEFORE `main` binds the listener** — so whatever bounds this bounds how
/// long a gateway takes to start serving when the broker's address accepts a
/// connection and then says nothing. The library's own default happens to be five
/// seconds today, and a default in a dependency is not a bound this repository
/// gets to rely on. Below [`RETRY`], so one dial cannot still be outstanding when
/// the next is due.
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// What this service presents to the broker.
///
/// `Debug` is written by hand rather than derived. A derived one would print the
/// password into any log line, panic message or test failure that formatted the
/// struct, which is how a credential ends up somewhere nobody meant to put it.
///
/// **THE PATH IS KEPT BESIDE THE VALUE, and it is not decoration.** ADR-0523's
/// rule is that every file the process read at boot is watched, and the file
/// this password came from is one — mounted as a DIRECTORY by the chart
/// precisely so it can rotate. `crate::rotate::Inputs` is built from the
/// configuration that was already resolved and NEVER by reading the environment
/// a second time, because a second reading could name a different file from the
/// one actually opened. So the resolved credential has to carry its own
/// provenance, or the watch set cannot include it without breaking that rule.
/// `iam::invalidate::Credentials` carries the same field for the same reason.
///
/// A path is not a secret — the chart puts it in `NATS_PASSWORD_FILE`, which is
/// visible in `kubectl describe pod` — so it is printed by `Debug` while the
/// password stays redacted. That is the same split D80 draws everywhere: the
/// location travels, the value does not.
#[derive(Clone)]
pub struct BrokerCredentials {
    pub user: String,
    pub password: String,
    /// The file the password was read from, for the rotation watch set.
    pub password_file: PathBuf,
}

impl fmt::Debug for BrokerCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrokerCredentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("password_file", &self.password_file)
            .finish()
    }
}

/// Where the broker is and what this gateway presents to it.
#[derive(Clone, Debug)]
pub struct Broker {
    pub(super) url: String,
    pub(super) credentials: Option<BrokerCredentials>,
}

impl Broker {
    pub fn new(url: String, credentials: Option<BrokerCredentials>) -> Self {
        Self { url, credentials }
    }

    /// The file this broker's password was read from, or `None` when this broker
    /// asks for no credential.
    ///
    /// The accessor `Broker`'s `Material` implementation reads, so the watch set
    /// is built the same way as every other member: from the resolved
    /// configuration, through a method on it.
    ///
    /// **`None` IS THE ORDINARY ANSWER TODAY, and it must stay a real one.** A
    /// broker that demands no credential named no file, and a path invented here
    /// would sit in the watch set unreadable for ever on a deployment with
    /// nothing wrong with it.
    pub fn password_file(&self) -> Option<&Path> {
        self.credentials.as_ref().map(|c| c.password_file.as_path())
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

        // ADR-0523-WATCHED: Broker
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
            Some(BrokerCredentials {
                user,
                password,
                password_file: PathBuf::from(path),
            }),
        )))
    }

    pub(super) async fn connect(&self) -> Result<Connection, async_nats::ConnectError> {
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
pub(super) struct Connection {
    pub(super) client: async_nats::Client,
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
    pub(super) refused: tokio::sync::watch::Receiver<bool>,
}

impl Connection {
    pub(super) fn forbidden(&self) -> bool {
        *self.refused.borrow()
    }
}

/// The one broker event that DECIDES something rather than reporting it.
///
/// Its own function because a `-ERR` naming one of this module's two subjects
/// flips the refusal flag `start` answers off, and the other four arms of
/// [`on_event`] only log. The decision is worth reading alone.
fn on_server_error(error: String, refused: &tokio::sync::watch::Sender<bool>) {
    // NAMED SUBJECTS ONLY. A `-ERR` about something else is still worth an
    // operator's attention, but it is not a statement that THIS consumer
    // is receiving nothing — and `start` answers `false` off this flag.
    if error.contains(subject::CREDENTIAL_REVOKED) || error.contains(subject::TEAMS_CHANGED) {
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

/// Everything the broker says about a connection after it is established.
///
/// **`async-nats` logs these at `debug!` and the pods run at `info`**, so without
/// this function they do not exist. The one that matters is
/// [`async_nats::Event::ServerError`]: a subscribe permission violation arrives
/// there, leaves the connection open, and is otherwise indistinguishable from a
/// healthy consumer that nobody is publishing to.
pub(super) fn on_event(event: async_nats::Event, refused: &tokio::sync::watch::Sender<bool>) {
    match event {
        // THE ONLY ARM THAT CHANGES ANYTHING. Every other event is reported and
        // then forgotten, which is why they are answered somewhere else.
        async_nats::Event::ServerError(e) => {
            let error = e.to_string();
            on_server_error(error, refused);
        }
        // THE WINDOW THIS MODULE EXISTS TO CLOSE, opened and closed by a pair.
        e @ (async_nats::Event::Disconnected | async_nats::Event::Connected) => {
            report_connection(e)
        }
        other => report(other),
    }
}

/// The broker events this module only REPORTS.
///
/// Separate from [`on_event`] because none of these changes a decision: the
/// refusal flag `start` answers off is set in [`on_server_error`] and nowhere
/// else, and keeping the reporting arms apart is what makes that readable.
/// The pair that marks the window in which nothing is consumed.
///
/// Its own function because the two arms are ONE fact read together: the
/// `Disconnected` opens the window and the `Connected` ends it.
fn report_connection(event: async_nats::Event) {
    match event {
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
        _ => {}
    }
}

fn report(event: async_nats::Event) {
    match event {
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
pub(super) fn refusal_remedy(broker: &Broker) -> String {
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

/// The OPEN-BROKER case: a connection the broker accepted without asking for
/// anything.
///
/// Its own function because it is a statement about the BROKER rather than
/// about this deployment, and it is easy to read past inside the success arm
/// it sits in.
fn warn_if_unauthenticated(broker: &Broker) {
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
}

/// The FIRST dial, and what each of its three outcomes means.
///
/// Its own function because [`start`] awaits it before `main` binds the
/// listener — it is the reason `start` returns a `bool` at all — and because
/// the three outcomes are three different operator instructions rather than
/// one error path.
pub(super) async fn first_connection(broker: &Broker) -> Option<Connection> {
    match broker.connect().await {
        Ok(connection) => {
            warn_if_unauthenticated(broker);
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
                refusal_remedy(broker)
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
    }
}

/// Hold a subscription for as long as there is one to hold, and redial when there
/// is not.
/// WHICH failure this was, and how long a replica waits before dialling again.
///
/// Its own function because the DISTINCTION is the whole content: a
/// credential the broker will not accept does not start being accepted five
/// seconds later, and an operator who reads "cannot reach the broker" for one
/// goes looking for a network fault that is not there.
async fn wait_after(broker: &Broker, e: async_nats::ConnectError) {
    // MIRRORS `start`'S SPLIT, and it is not decoration. `start`
    // prints the accurate line ONCE, at boot; this loop prints its
    // line for as long as the fault stands. Without this arm a
    // refused credential produces one true sentence at boot and an
    // untrue "cannot reach the broker" every RETRY for ever after —
    // the network fault that is not there, which is the exact failure
    // the split in `start` exists to avoid.
    if e.kind() == async_nats::ConnectErrorKind::AuthorizationViolation {
        tracing::error!(
            url = %broker.url, error = %e,
            // WHETHER, never WHAT. This log is shipped.
            authenticated = broker.credentials.is_some(),
            "the broker still REFUSES this gateway; no invalidation is being \
             consumed. {} Retrying every {} seconds.",
            refusal_remedy(broker),
            REFUSED_RETRY.as_secs()
        );
        // BACKED OFF HARDER THAN AN OUTAGE. A credential the broker
        // does not accept does not start being accepted five seconds
        // later; see `REFUSED_RETRY`.
        tokio::time::sleep(REFUSED_RETRY).await;
    } else {
        tracing::error!(
            url = %broker.url, error = %e,
            "still cannot reach the broker; no invalidation is being consumed. \
             Retrying every {} seconds.",
            RETRY.as_secs()
        );
        tokio::time::sleep(RETRY).await;
    }
}

/// Dial again after a connection ended, waiting the interval the FAILURE
/// deserves.
///
/// `None` means the caller should take another turn of the loop; the wait
/// has already been served here, at [`REFUSED_RETRY`] for a credential the
/// broker will not accept and [`RETRY`] for an outage.
pub(super) async fn redial(broker: &Broker) -> Option<Connection> {
    match broker.connect().await {
        Ok(c) => {
            // RECONNECTED, WHICH IS NOT YET CONSUMING. This line used to
            // say it was, and on a redial against a broker that forbids
            // the subscription it said so a few milliseconds before the
            // ERROR saying the opposite — the same false-boot-line class
            // this module exists to remove, on the loop instead of at
            // boot. `drain` writes the consuming line, after the flush
            // that can disprove it.
            tracing::info!(url = %broker.url, "reconnected to the broker");
            Some(c)
        }
        Err(e) => {
            wait_after(broker, e).await;
            None
        }
    }
}
