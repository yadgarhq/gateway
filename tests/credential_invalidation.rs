//! What a revocation published by `iam` actually does to this replica's cache.
//!
//! **Asserting that a SUBSCRIPTION was created is the check that cannot fail.** It
//! passes identically against a consumer subscribed to the wrong subject, against
//! one that reads the payload and drops it, and against one wired to
//! `forget_credential` — which hashes the user id as though it were a token and
//! evicts nothing. So the broker here is a real socket speaking the real NATS
//! protocol: it reads the `SUB` lines the client sends and pushes a `MSG` frame
//! back on the subject and subscription id it actually saw.
//!
//! **AND THE `SUB` LINE ITSELF IS ASSERTED ON, not merely read.** A queue group is
//! invisible to every other observable behaviour of a one-subscriber test — a lone
//! member of a group receives every message exactly as a plain subscriber does —
//! so the wire is the only place fan-out and pick-one differ. `SUB <subject>
//! [queue group] <sid>` carries two arguments without a group and three with one,
//! and `Rig::expect_two_ungrouped_subs` fails on three.
//!
//! **The reconnect is exercised too.** Dropping the socket under a running
//! consumer and publishing on the connection it dials next is the only thing that
//! can tell a redial loop from a dead one — and the rig's subject table is per
//! connection, so a consumer that restored the SOCKET and not the SUBSCRIPTION
//! fails here rather than going quiet in production.
//!
//! The property under test is D72's deliberate over-invalidation: an event names a
//! PERSON, the cache is keyed by TOKEN, so every token that resolved to that person
//! must go. Two tokens are seeded for one user and one event is published; both
//! must be resolved against `iam` again afterwards.
//!
//! # Why a fake broker rather than a real `nats-server`
//!
//! The shared workflow (`yadgarhq/actions`, `ci-pr.yaml`) supplies MariaDB and a
//! Valkey to every Rust repository and no broker, and this repository cannot add a
//! service to a workflow it does not own. A test that needed one would skip in CI,
//! and a skipped test is the green run that measured nothing. `iam`'s
//! `tests/nats_auth.rs` makes the same trade for the same reason.
//!
//! What is given up is worth naming: this proves the bytes on the wire and the
//! eviction they cause, NOT that a real `nats-server` accepts the password the
//! deployment sets or that its `authorization` block permits this subject. That
//! second half belongs to `yadgarhq/deploy`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::Channel;

use yadgar_gateway::attest::{attest, Attestation, Claimed, Credentials};
// `subject` is deliberately NOT imported. See `REVOKED` and `TEAMS_CHANGED`
// below: a wire fixture that reads the implementation's own constant proves
// nothing about what goes on the wire.
use yadgar_gateway::invalidate::{self, Broker, BrokerCredentials};
use yadgar_gateway::pb::yadgar::iam::v1::{
    iam_service_server::{IamService, IamServiceServer},
    ResolveCredentialResponse,
};

/// Deliberately unlike anything the implementation could contain. A fixture equal
/// to a constant in the code under test would pass for a build that invalidated
/// its own idea of a user rather than the one on the wire.
const USER: &str = "u-sentinel-of-the-revoked-3f91";
const NATS_USER: &str = "sentinel-account";
const NATS_PASSWORD: &str = "sentinel-of-the-nats-password-9d2c";

/// The two subjects, **as literals, never as `invalidate::subject::*`**.
///
/// A wire fixture built out of the constant the implementation uses asserts the
/// code's own output against a value the code itself chose. Both sides move
/// together, so renaming the constant to anything at all leaves this file green
/// while the running consumer subscribes to a subject `iam` never publishes on.
/// Written out here, the same rename fails: the frame this test pushes lands on a
/// subject nothing is subscribed to, and the `SUB` assertion names the drift.
const REVOKED: &str = "yadgar.iam.credential.revoked";
const TEAMS_CHANGED: &str = "yadgar.iam.user.teams-changed";

/// Longer than the test runs, so nothing expires and every re-resolve observed is
/// an eviction rather than a timeout. At the ceiling `Credentials::from_lookup`
/// enforces.
const TTL: Duration = Duration::from_secs(300);

/// Bounded, so a consumer that never receives fails the test rather than hanging
/// the job.
const DEADLINE: Duration = Duration::from_secs(10);

/// The same bound for anything that has to wait out a redial.
///
/// `invalidate::RETRY` is five seconds and the loop sleeps it before EVERY dial
/// attempt, so a reconnect can legitimately take longer than [`DEADLINE`]. A
/// shared deadline here would make the reconnect test flaky in the direction that
/// reads as a broken consumer.
const RECONNECT_DEADLINE: Duration = Duration::from_secs(30);

/// Long enough that an OUTAGE back-off (`invalidate::RETRY`, 5s) would have
/// redialled inside it, short enough that a REFUSAL back-off
/// (`invalidate::REFUSED_RETRY`, 60s) cannot have. That gap is what makes which
/// of the two a failure was filed under observable from outside the process.
const ATTRIBUTION_WINDOW: Duration = Duration::from_secs(8);

// ---------------------------------------------------------------------------
// A broker that speaks enough NATS to be subscribed to, and to push one message.
// ---------------------------------------------------------------------------

struct Rig {
    addr: SocketAddr,
    /// `(subject, payload)`. Held until a `SUB` for that subject arrives, so a
    /// test never has to sleep to let the subscription settle.
    ///
    /// **BYTES, not a `String`.** A payload that is not UTF-8 is one of the two
    /// malformed messages this consumer has an arm for, and a `String` cannot
    /// carry one — so a `String` channel makes that arm untestable by
    /// construction.
    push: mpsc::UnboundedSender<(String, Vec<u8>)>,
    /// Every `CONNECT` line this broker saw, verbatim — so a test can assert on
    /// the bytes rather than on what this crate believes it put in them.
    connects: mpsc::UnboundedReceiver<String>,
    /// Every `SUB` line's arguments, verbatim, across every connection.
    ///
    /// **THIS IS THE ONLY PLACE A QUEUE GROUP IS VISIBLE.** One subscriber in a
    /// group receives every message exactly as a plain subscriber does, so no
    /// assertion about an eviction can tell the two apart — the difference exists
    /// on the wire and nowhere else. It doubles as the synchronisation point for
    /// the reconnect test: a `SUB` on a second connection is what proves the
    /// subscription was restored rather than merely the socket.
    subs: mpsc::UnboundedReceiver<String>,
    /// Drops whichever socket the broker is serving, without stopping the broker.
    hangups: mpsc::UnboundedSender<()>,
    /// One item per connection this broker stopped serving.
    ///
    /// **How a REFUSAL BEING ACTED ON is observed.** `invalidate::run` drops the
    /// client at the end of each pass, so a `drain` that returned closes the
    /// socket. That is visible here in milliseconds, where waiting for the redial
    /// itself would mean waiting out `invalidate::REFUSED_RETRY`.
    closes: mpsc::UnboundedReceiver<()>,
}

impl Rig {
    fn publish(&self, subject: &str, payload: &str) {
        self.publish_bytes(subject, payload.as_bytes());
    }

    fn publish_bytes(&self, subject: &str, payload: &[u8]) {
        self.push
            .send((subject.to_string(), payload.to_vec()))
            .expect("the broker is still running");
    }

    /// Close the current connection the way a broker restart or a dropped route
    /// does — the socket goes away and the listener stays.
    fn hang_up(&self) {
        self.hangups.send(()).expect("the broker is still running");
    }

    /// The next `SUB` line's arguments, or a failure that names the wait.
    async fn next_sub(&mut self) -> String {
        tokio::time::timeout(RECONNECT_DEADLINE, self.subs.recv())
            .await
            .expect("the consumer declared a subscription within the deadline")
            .expect("and the broker is still running")
    }

    /// Both subscriptions, asserted to declare NO queue group.
    ///
    /// `SUB <subject> [queue group] <sid>` — two arguments without a group and
    /// three with one. Asserting the count HERE, on the test's own thread, is
    /// deliberate: a `panic!` inside the broker's spawned task would abort a
    /// socket and surface as an unexplained timeout somewhere else.
    async fn expect_two_ungrouped_subs(&mut self) {
        let mut subjects = Vec::new();
        for _ in 0..2 {
            let line = self.next_sub().await;
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(
                fields.len(),
                2,
                "SUB declared a QUEUE GROUP: `SUB {line}`. A group delivers each message to one \
                 member, so one replica would evict and every other would serve the revoked \
                 credential until its entry expired — an invalidation that looks like it worked. \
                 Every replica holds its own map and must receive every message."
            );
            subjects.push(fields[0].to_string());
        }
        subjects.sort();
        assert_eq!(
            subjects,
            vec![REVOKED.to_string(), TEAMS_CHANGED.to_string()],
            "the subjects on the wire are not the ones iam publishes"
        );
    }
}

/// `auth` names the one account this broker accepts. `None` demands nothing.
async fn broker(auth: Option<(&'static str, &'static str)>) -> Rig {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fake broker binds");
    broker_on(listener, auth, None, 0)
}

/// A broker that ACCEPTS the connection and then refuses one subscription.
///
/// **The failure with no other symptom.** A `nats-server` answers a subscribe
/// permission violation with an asynchronous `-ERR` and leaves the connection
/// OPEN — unlike a wrong password, which closes it. So a consumer that does not
/// read that `-ERR` is indistinguishable from a healthy one nobody is publishing
/// to, for ever.
async fn forbidding_broker(subject: &'static str) -> Rig {
    forbidding_broker_after(subject, Duration::ZERO).await
}

/// The same, with the `-ERR` held back — a broker slower than the window
/// `invalidate::start` gives a refusal to arrive.
async fn forbidding_broker_after(subject: &'static str, delay: Duration) -> Rig {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fake broker binds");
    broker_on(listener, None, Some((subject, delay)), 0)
}

/// The broker on a listener the caller already owns, so a test can hold a bound
/// port that answers NOTHING and start serving on it later — which is the only way
/// to make `start`'s first dial fail against an address that then becomes real.
fn broker_on(
    listener: TcpListener,
    auth: Option<(&'static str, &'static str)>,
    forbid: Option<(&'static str, Duration)>,
    // How many connections are accepted and then ignored before this broker
    // speaks. **A DEAF CONNECTION IS HOW A DIAL FAILS AGAINST AN ADDRESS THAT WILL
    // LATER WORK**: the TCP handshake completes out of the backlog, no INFO ever
    // arrives, and the client gives up on `invalidate::CONNECT_TIMEOUT`. A closed
    // port would fail faster but could not become this same broker afterwards
    // without racing the whole machine for the port number.
    deaf: usize,
) -> Rig {
    let addr = listener.local_addr().expect("its address");
    let (push, mut pushes) = mpsc::unbounded_channel::<(String, Vec<u8>)>();
    let (connects_tx, connects) = mpsc::unbounded_channel::<String>();
    let (subs_tx, subs) = mpsc::unbounded_channel::<String>();
    let (hangups, mut hangup_rx) = mpsc::unbounded_channel::<()>();
    let (closes_tx, closes) = mpsc::unbounded_channel::<()>();

    tokio::spawn(async move {
        // SEQUENTIAL, not one task per connection. The consumer redials after a
        // failure, and serving the reconnection on the same receiver is what lets
        // a queued publish survive it.
        let mut accepted = 0usize;
        while let Ok((socket, _)) = listener.accept().await {
            let (reader, mut writer) = socket.into_split();
            let mut lines = BufReader::new(reader).lines();
            accepted += 1;
            if accepted <= deaf {
                // SAY NOTHING and hold the socket until the client gives up. It
                // then drops the connection, this read returns `None`, and the
                // next dial is served — so the count is a number of DIALS, which
                // is what a test wants to reason about.
                while let Ok(Some(_)) = lines.next_line().await {}
                continue;
            }
            // `auth_required` is what a real server sets when it has an
            // `authorization` block. Every other field of `ServerInfo` has a
            // serde default, so this is a complete INFO to the client.
            let info: &[u8] = match auth {
                Some(_) => b"INFO {\"auth_required\":true}\r\n",
                None => b"INFO {}\r\n",
            };
            if writer.write_all(info).await.is_err() {
                return;
            }

            // subject -> subscription id, as the client declared them.
            //
            // **PER CONNECTION, and that is the reconnect test's whole assertion.**
            // A consumer that redialled and did not re-subscribe leaves this map
            // empty on the second socket, so a publish is queued and never
            // delivered — which is exactly what a real broker does, and is the
            // silent half of the failure this loop exists to survive.
            let mut subs: HashMap<String, String> = HashMap::new();
            let mut queued: Vec<(String, Vec<u8>)> = Vec::new();
            let mut authorised = auth.is_none();

            loop {
                tokio::select! {
                    line = lines.next_line() => {
                        let Ok(Some(line)) = line else { break };
                        let line = line.trim_end_matches('\r');
                        if let Some(rest) = line.strip_prefix("CONNECT ") {
                            // THE DECISION IS MADE ON THE BYTES, which is the
                            // point of the rig. A client that read the Secret and
                            // did not send it lands here indistinguishable from
                            // one that was never given a Secret — and that is
                            // correct, because to a broker those two are the same
                            // client.
                            if let Some((user, password)) = auth {
                                authorised = rest.contains(&format!("\"user\":\"{user}\""))
                                    && rest.contains(&format!("\"pass\":\"{password}\""));
                            }
                            let _ = connects_tx.send(rest.to_string());
                        } else if line == "PING" {
                            let reply: &[u8] = if authorised {
                                b"PONG\r\n"
                            } else {
                                // Verbatim what `nats-server` sends. `async-nats`
                                // lowercases and strips the quotes before matching
                                // it to `ConnectErrorKind::AuthorizationViolation`.
                                b"-ERR 'Authorization Violation'\r\n"
                            };
                            if writer.write_all(reply).await.is_err() || !authorised {
                                break;
                            }
                        } else if let Some(rest) = line.strip_prefix("SUB ") {
                            // A PERMISSION VIOLATION, VERBATIM, AND THE CONNECTION
                            // STAYS OPEN. `nats-server` answers exactly this and
                            // keeps serving, so a consumer that ignores it reports
                            // itself healthy and receives nothing for ever. The
                            // subscription is deliberately NOT registered: a
                            // forbidden subject delivers nothing.
                            let subject = rest.split_whitespace().next().unwrap_or_default();
                            if let Some((forbidden, delay)) = forbid.filter(|(f, _)| *f == subject) {
                                // HELD BACK ON PURPOSE when `delay` is non-zero.
                                // Nothing in the protocol says how soon this
                                // arrives, and a broker slower than the
                                // consumer's window is the case that decides
                                // whether the design rests on a guarantee or on a
                                // hope.
                                if !delay.is_zero() {
                                    tokio::time::sleep(delay).await;
                                }
                                let err = format!(
                                    "-ERR 'Permissions Violation for Subscription to \"{forbidden}\"'\r\n"
                                );
                                if writer.write_all(err.as_bytes()).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                            // `SUB <subject> [queue group] <sid>`. The sid is
                            // last; a queue group would sit between the two.
                            //
                            // **THE LINE IS FORWARDED VERBATIM and the field
                            // count is asserted on the TEST's thread**, in
                            // `Rig::expect_two_ungrouped_subs`. Reading it
                            // positionally here and saying nothing is what let a
                            // `queue_subscribe` pass unnoticed: `first` and
                            // `last` are the same two fields whether or not a
                            // group sits between them, so the rig kept working
                            // and nothing looked at the difference. Registering
                            // the subscription anyway is deliberate — a grouped
                            // consumer still receives, so the mutation fails on
                            // the assertion with the line in the message rather
                            // than on a timeout somewhere else.
                            let _ = subs_tx.send(rest.to_string());
                            let fields: Vec<&str> = rest.split_whitespace().collect();
                            if let (Some(s), Some(sid)) = (fields.first(), fields.last()) {
                                subs.insert((*s).to_string(), (*sid).to_string());
                            }
                            let mut ready = Vec::new();
                            queued.retain(|(s, payload)| match subs.get(s) {
                                Some(sid) => {
                                    ready.push(message(s, sid, payload));
                                    false
                                }
                                None => true,
                            });
                            let mut broken = false;
                            for frame in ready {
                                broken |= writer.write_all(&frame).await.is_err();
                            }
                            if broken {
                                break;
                            }
                        }
                    }
                    Some((s, payload)) = pushes.recv() => {
                        match subs.get(&s) {
                            Some(sid) => {
                                let frame = message(&s, sid, &payload);
                                if writer.write_all(&frame).await.is_err() {
                                    break;
                                }
                            }
                            // NOT DROPPED. A publish that arrives before the
                            // subscription is the ordinary race, and dropping it
                            // would make this test flaky in the direction that
                            // reads as a broken consumer.
                            None => queued.push((s, payload)),
                        }
                    }
                    // THE SOCKET GOES, THE LISTENER STAYS — a broker restart or a
                    // dropped route, not a broker that ceased to exist. Breaking
                    // the inner loop drops both halves of this connection and
                    // returns to `accept`, so the consumer's redial is served by
                    // the same broker with the same queued publishes.
                    Some(()) = hangup_rx.recv() => break,
                }
            }
            // The connection ended — the client closed it, or this broker was
            // told to hang up. Either way it is no longer serving.
            let _ = closes_tx.send(());
        }
    });

    Rig {
        addr,
        push,
        connects,
        subs,
        hangups,
        closes,
    }
}

/// One `MSG` frame, as `nats-server` writes it: header line, then the payload and
/// its own terminator.
///
/// **BYTES OUT, because bytes go in.** A payload that is not UTF-8 is one of the
/// two malformed messages the consumer has an arm for, and building the frame
/// through a `String` would make that arm impossible to reach from here.
fn message(subject: &str, sid: &str, payload: &[u8]) -> Vec<u8> {
    let mut frame = format!("MSG {subject} {sid} {}\r\n", payload.len()).into_bytes();
    frame.extend_from_slice(payload);
    frame.extend_from_slice(b"\r\n");
    frame
}

// ---------------------------------------------------------------------------
// An `iam` that answers ResolveCredential and counts how often it was asked.
// ---------------------------------------------------------------------------

/// **The counter is the only thing that can fail here.** Every assertion about the
/// resolved identity passes identically whether the answer came from `iam` or from
/// the cache, so a cache that was never invalidated looks exactly like one that
/// was.
struct StubIam {
    resolves: Arc<AtomicUsize>,
}

/// One real method and twelve refusals.
///
/// **THE MACRO EMITS `#[tonic::async_trait]` ITSELF, and it has to.** That
/// attribute rewrites every `async fn` in the block into the boxed future the
/// generated trait declares; applied around a `macro_rules!` call it sees an
/// unexpanded token tree and leaves the methods alone, and every one of them then
/// fails to match the trait's lifetimes.
macro_rules! stub_iam_service {
    ($($method:ident($req:ident) -> $resp:ident;)*) => {
        #[tonic::async_trait]
        impl IamService for StubIam {
            async fn resolve_credential(
                &self,
                _: tonic::Request<yadgar_gateway::pb::yadgar::iam::v1::ResolveCredentialRequest>,
            ) -> Result<tonic::Response<ResolveCredentialResponse>, tonic::Status> {
                self.resolves.fetch_add(1, Ordering::SeqCst);
                Ok(tonic::Response::new(ResolveCredentialResponse {
                    user_id: USER.to_string(),
                    team_ids: Vec::new(),
                    valid_for_seconds: TTL.as_secs() as i64,
                    rate_limit_overrides: Vec::new(),
                    is_admin: false,
                    // ABSENT, because this suite is about eviction and states no
                    // policy. It is also the honest shape for the property the
                    // file records: no invalidation subject carries a setting
                    // change, so nothing here could evict one.
                    owner_reads_own_record: None,
                }))
            }

            $(
                async fn $method(
                    &self,
                    _: tonic::Request<yadgar_gateway::pb::yadgar::iam::v1::$req>,
                ) -> Result<tonic::Response<yadgar_gateway::pb::yadgar::iam::v1::$resp>, tonic::Status> {
                    Err(tonic::Status::unimplemented(
                        "this stub answers ResolveCredential and nothing else",
                    ))
                }
            )*
        }
    };
}

stub_iam_service! {
    login(LoginRequest) -> LoginResponse;
    redeem_enrolment(RedeemEnrolmentRequest) -> RedeemEnrolmentResponse;
    issue_credential(IssueCredentialRequest) -> IssueCredentialResponse;
    revoke_credential(RevokeCredentialRequest) -> RevokeCredentialResponse;
    list_credentials(ListCredentialsRequest) -> ListCredentialsResponse;
    issue_enrolment(IssueEnrolmentRequest) -> IssueEnrolmentResponse;
    create_user(CreateUserRequest) -> CreateUserResponse;
    set_user_admin(SetUserAdminRequest) -> SetUserAdminResponse;
    set_rate_limit_override(SetRateLimitOverrideRequest) -> SetRateLimitOverrideResponse;
    add_team_member(AddTeamMemberRequest) -> AddTeamMemberResponse;
    remove_team_member(RemoveTeamMemberRequest) -> RemoveTeamMemberResponse;
    set_inherited_setting(SetInheritedSettingRequest) -> SetInheritedSettingResponse;
}

async fn stub_iam() -> (Channel, Arc<AtomicUsize>) {
    let resolves = Arc::new(AtomicUsize::new(0));
    // `TcpIncoming::bind` on port 0 takes an ephemeral port and KEEPS the
    // listener, so there is no window between discovering the port and serving on
    // it.
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the stub binds");
    let addr = incoming.local_addr().expect("a bound port");
    let counted = Arc::clone(&resolves);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(IamServiceServer::new(StubIam { resolves: counted }))
            .serve_with_incoming(incoming)
            .await
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy();
    (channel, resolves)
}

/// Resolve `token` through the cache, exactly as a `tools/call` does.
async fn present(iam: &Channel, cache: &Credentials, token: &str) {
    let attested = attest(
        &Attestation::Iam,
        iam,
        cache,
        Some(&format!("Bearer {token}")),
        Claimed {
            project_id: Some("zeta/invalidation"),
            ..Claimed::default()
        },
        "REQ".to_string(),
    )
    .await
    .expect("the stub credential resolves");
    assert_eq!(attested.scope.user_id, USER);
}

/// The consumer, wired to a cache, with a signal fired after each eviction.
///
/// The signal is for SYNCHRONISATION only — the assertions are on the cache. A
/// test that asserted the message arrived and stopped there would pass for a
/// consumer that received it and evicted nothing.
async fn start(
    rig: &Rig,
    cache: Arc<Credentials>,
    credentials: Option<BrokerCredentials>,
) -> (bool, mpsc::UnboundedReceiver<String>) {
    let (evicted, seen) = mpsc::unbounded_channel::<String>();
    let consuming = invalidate::start(
        Some(Broker::new(format!("nats://{}", rig.addr), credentials)),
        move |user_id: &str| {
            cache.forget_user(user_id);
            let _ = evicted.send(user_id.to_string());
        },
    )
    .await;
    (consuming, seen)
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_revocation_evicts_every_token_that_resolved_to_that_person() {
    let (iam, resolves) = stub_iam().await;
    let cache = Arc::new(Credentials::new(TTL));
    let rig = broker(None).await;
    let (consuming, mut evicted) = start(&rig, Arc::clone(&cache), None).await;
    assert!(consuming, "the consumer did not connect to the broker");

    // TWO TOKENS, ONE PERSON. `iam` holds a credential id on a revoke and never
    // sees the token, so the event names the user and this cache is keyed on a
    // hash of the token — the unit that can be invalidated is the person.
    present(&iam, &cache, "tok-laptop").await;
    present(&iam, &cache, "tok-desktop").await;
    assert_eq!(resolves.load(Ordering::SeqCst), 2);
    present(&iam, &cache, "tok-laptop").await;
    present(&iam, &cache, "tok-desktop").await;
    assert_eq!(
        resolves.load(Ordering::SeqCst),
        2,
        "both tokens must be cached before the event, or this test proves nothing"
    );

    rig.publish(REVOKED, USER);
    let got = tokio::time::timeout(DEADLINE, evicted.recv())
        .await
        .expect("the consumer acted on the revocation within the deadline")
        .expect("and the consumer is still running");
    assert_eq!(got, USER, "the user id on the wire is not the one evicted");

    // THE ASSERTION THAT BITES. A consumer wired to `forget_credential` hashes
    // this user id as though it were a token, evicts nothing, and leaves this at
    // 2 — which is D72's whole reason for choosing `forget_user`.
    present(&iam, &cache, "tok-laptop").await;
    present(&iam, &cache, "tok-desktop").await;
    assert_eq!(
        resolves.load(Ordering::SeqCst),
        4,
        "a revocation must send BOTH of that person's tokens back to iam"
    );
}

#[tokio::test]
async fn a_team_change_invalidates_too_and_not_only_a_revocation() {
    // Deliberately not only "revoked": adding a team also changes what a cached
    // identity says, and a consumer subscribed to one subject would serve a stale
    // team list to somebody who had just been granted access — a permission that
    // takes a TTL to arrive, which reads as a bug in the wrong place.
    let (iam, resolves) = stub_iam().await;
    let cache = Arc::new(Credentials::new(TTL));
    let rig = broker(None).await;
    let (consuming, mut evicted) = start(&rig, Arc::clone(&cache), None).await;
    assert!(consuming);

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(resolves.load(Ordering::SeqCst), 1);

    rig.publish(TEAMS_CHANGED, USER);
    tokio::time::timeout(DEADLINE, evicted.recv())
        .await
        .expect("the consumer acted on the team change within the deadline")
        .expect("and the consumer is still running");

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(
        resolves.load(Ordering::SeqCst),
        2,
        "a team change must send the cached identity back to iam"
    );
}

#[tokio::test]
async fn the_configured_password_is_what_actually_goes_on_the_wire() {
    // THE HALF THE MUTATION BITES. Drop the credential on the way into `connect`
    // and this goes red, which is what proves the refusal below is about the
    // credential rather than about the rig being broken.
    let rig = broker(Some((NATS_USER, NATS_PASSWORD))).await;
    let cache = Arc::new(Credentials::new(TTL));
    let (consuming, _evicted) = start(
        &rig,
        cache,
        Some(BrokerCredentials {
            user: NATS_USER.to_string(),
            password: NATS_PASSWORD.to_string(),
        }),
    )
    .await;
    assert!(
        consuming,
        "the password the gateway was configured with was not accepted by the broker that \
         demands it, so it never reached the CONNECT line"
    );

    let mut rig = rig;
    let line = tokio::time::timeout(DEADLINE, rig.connects.recv())
        .await
        .expect("the broker saw a CONNECT")
        .expect("and it was not dropped");
    assert!(
        line.contains(&format!("\"user\":\"{NATS_USER}\"")),
        "the configured user never reached the wire: {line}"
    );
    assert!(
        line.contains(&format!("\"pass\":\"{NATS_PASSWORD}\"")),
        "the configured password never reached the wire: {line}"
    );
}

#[tokio::test]
async fn a_gateway_with_no_credential_is_refused_and_says_so_rather_than_reporting_success() {
    // THE HALF THAT CANNOT PASS AGAINST AN OPEN BROKER, and the honesty property
    // this whole change turns on: a consumer that could not connect must not
    // report that it is consuming, because `main` writes the boot line from this
    // answer and that line is what tells an operator whether the TTL is still the
    // only bound on a revoked credential.
    let rig = broker(Some((NATS_USER, NATS_PASSWORD))).await;
    let cache = Arc::new(Credentials::new(TTL));
    let (consuming, _evicted) = start(&rig, cache, None).await;
    assert!(
        !consuming,
        "the gateway reported that it was consuming invalidation events while the broker had \
         refused it, which is the false boot line this exists to prevent"
    );
}

#[tokio::test]
async fn the_subscription_declares_no_queue_group_so_every_replica_receives_every_message() {
    // **THE MOST IMPORTANT PROPERTY IN THIS CHANGE, AND THE ONLY ONE WITH NOWHERE
    // ELSE TO LIVE.** Every replica holds its own in-process map, so a queue group
    // would deliver a revocation to exactly one pod and leave the rest serving the
    // revoked credential until its entry expired — a partial invalidation that
    // looks from every metric and every log line like it worked.
    //
    // Nothing about an EVICTION can see the difference: the one subscriber in a
    // group receives the message exactly as a plain subscriber does, so both
    // eviction tests above pass unchanged against `queue_subscribe`. The `SUB`
    // line is the only place the two shapes differ, which is why this test reads
    // it and counts its arguments rather than watching what arrives.
    let cache = Arc::new(Credentials::new(TTL));
    let mut rig = broker(None).await;
    let (consuming, _evicted) = start(&rig, cache, None).await;
    assert!(consuming, "the consumer did not connect to the broker");

    rig.expect_two_ungrouped_subs().await;
}

#[tokio::test]
async fn a_dropped_connection_is_redialled_and_the_subscription_is_restored() {
    // **WHAT THIS CHECKS IS THE PROPERTY, NOT THE LAYER — measured, because the
    // two are not the same here.** `async-nats` owns reconnection within a
    // connection it once had: it redials and restores the subscriptions itself,
    // so `invalidate::run`'s loop is never entered by this test and deleting that
    // loop leaves this green. Confirmed by mutation rather than assumed. The
    // degraded-BOOT case is the one `run` exclusively owns, and
    // `a_gateway_that_booted_with_the_broker_down_starts_consuming_when_it_comes_up`
    // below is what covers it.
    //
    // The property is still worth pinning at whichever layer satisfies it: a
    // dropped connection must end with this replica evicting again.
    //
    // **A SOCKET RESTORED WITHOUT ITS SUBSCRIPTIONS IS THE WORSE OUTCOME**, because
    // it is silent: the connection is up, nothing logs a failure, and no
    // invalidation is ever delivered again. The rig's subject table is per
    // connection, so a consumer that reconnected and did not re-subscribe leaves
    // the publish below queued for ever and this test fails on the deadline.
    let (iam, resolves) = stub_iam().await;
    let cache = Arc::new(Credentials::new(TTL));
    let mut rig = broker(None).await;
    let (consuming, mut evicted) = start(&rig, Arc::clone(&cache), None).await;
    assert!(consuming, "the consumer did not connect to the broker");
    rig.expect_two_ungrouped_subs().await;

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(resolves.load(Ordering::SeqCst), 1);

    // The broker goes away and comes back — a restart, a dropped route, a rolled
    // pod. The listener is untouched, so what the consumer reaches on its next
    // dial is this same broker.
    rig.hang_up();

    // THE SUBSCRIPTIONS, DECLARED AGAIN, ON A SECOND CONNECTION. Waiting for these
    // rather than sleeping is also what keeps this test off the clock: it passes
    // as soon as the consumer has really re-subscribed.
    rig.expect_two_ungrouped_subs().await;

    rig.publish(REVOKED, USER);
    let got = tokio::time::timeout(RECONNECT_DEADLINE, evicted.recv())
        .await
        .expect(
            "the consumer never acted on a revocation published after the connection dropped, so \
             the degraded state did NOT end on its own",
        )
        .expect("and the consumer is still running");
    assert_eq!(got, USER);

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(
        resolves.load(Ordering::SeqCst),
        2,
        "a revocation delivered after a reconnect must still send the cached identity back to iam"
    );
}

#[tokio::test]
async fn a_malformed_payload_evicts_nothing_and_does_not_stop_the_consumer() {
    // Two arms of `drain` that nothing reached: an empty payload and one that is
    // not UTF-8. Deleting the `!user_id.is_empty()` guard changed no assertion in
    // this repository, so `forget_user("")` — a scan of the whole map, on every
    // malformed message, for a key that cannot exist — was untested.
    //
    // **ALL THREE GO ON ONE SUBJECT, deliberately.** `merge` gives no ordering
    // ACROSS two subscriptions, so a barrier published on the other subject could
    // legitimately arrive first and this test would be flaky. On one subject the
    // stream is ordered, so the good message below is a real barrier: whatever
    // reaches `evicted` first is what the malformed ones did.
    let (iam, resolves) = stub_iam().await;
    let cache = Arc::new(Credentials::new(TTL));
    let mut rig = broker(None).await;
    let (consuming, mut evicted) = start(&rig, Arc::clone(&cache), None).await;
    assert!(consuming, "the consumer did not connect to the broker");
    rig.expect_two_ungrouped_subs().await;

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(resolves.load(Ordering::SeqCst), 1);

    rig.publish(REVOKED, "");
    // Not UTF-8 by construction: `0xff` is not a legal byte anywhere in UTF-8.
    rig.publish_bytes(REVOKED, &[0xff, 0xfe, 0xff]);
    rig.publish(REVOKED, USER);

    let got = tokio::time::timeout(DEADLINE, evicted.recv())
        .await
        .expect("the consumer survived both malformed messages and acted on the good one")
        .expect("and the consumer is still running");
    assert_eq!(
        got, USER,
        "a malformed invalidation reached forget_user; an empty user id matches no cached answer \
         and passing one through is a scan of the whole map for nothing"
    );

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(resolves.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_forbidden_subscription_is_reported_as_not_consuming_rather_than_going_quiet() {
    // **THE WORST FAILURE THIS MODULE HAS, BECAUSE IT HAS NO OTHER SYMPTOM.** A
    // wrong password is loud — the broker answers `-ERR 'Authorization Violation'`
    // and CLOSES the connection. A subject this account may not subscribe to is
    // not: the connection stays open, `Client::subscribe` returned `Ok` before the
    // server saw anything, and the `-ERR` arrives asynchronously. So one typo in
    // the broker's `subscribe.allow` list produces a gateway that logs "consuming
    // cache invalidation" and consumes nothing, until somebody revokes a
    // credential and finds it still works.
    //
    // **THIS TEST COVERS THE FAST REFUSAL ONLY, and that is a real limit rather
    // than a deterministic guarantee.** Nothing here waits for an acknowledgement,
    // because NATS gives none for a `SUB` and `async-nats`' `flush` is a local
    // socket flush — see the guarantee-and-courtesy split in `invalidate`'s module
    // comment. This broker answers instantly, so the refusal beats the window and
    // the boot line is right. A broker slower than the window is
    // `a_refusal_that_arrives_after_the_flush_still_ends_the_subscription` below,
    // which pins the half that IS guaranteed.
    let cache = Arc::new(Credentials::new(TTL));
    let rig = forbidding_broker(REVOKED).await;
    let (consuming, _evicted) = start(&rig, cache, None).await;
    assert!(
        !consuming,
        "the gateway reported that it was consuming invalidation events while the broker had \
         FORBIDDEN its subscription, which is the silent fall back to TTL-only eviction this \
         whole change exists to remove"
    );
}

#[tokio::test]
async fn a_gateway_that_booted_with_the_broker_down_starts_consuming_when_it_comes_up() {
    // **THE CLAIM THE DEGRADED-BOOT DECISION RESTS ON.** Not failing the boot on
    // an unreachable broker is only defensible because the gateway recovers by
    // itself, and this is the only test of that. It is `run`'s redial loop and
    // nothing else: `async-nats` restores a connection it once had, but a first
    // dial that never succeeded leaves it with nothing to restore.
    let (iam, resolves) = stub_iam().await;
    let cache = Arc::new(Credentials::new(TTL));

    // A BOUND PORT THAT ANSWERS NOTHING. The TCP handshake completes out of the
    // listen backlog and no INFO ever arrives, so the dial fails on
    // `invalidate::CONNECT_TIMEOUT` — a broker that is not there, on an address
    // that will become one. Holding the listener is what makes that possible
    // without racing another process for the port.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the port is held");
    let addr = listener.local_addr().expect("its address");

    let (evicted_tx, mut evicted) = mpsc::unbounded_channel::<String>();
    let consuming = invalidate::start(Some(Broker::new(format!("nats://{addr}"), None)), {
        let cache = Arc::clone(&cache);
        move |user_id: &str| {
            cache.forget_user(user_id);
            let _ = evicted_tx.send(user_id.to_string());
        }
    })
    .await;
    assert!(
        !consuming,
        "a gateway that never reached the broker must not report that it is consuming"
    );

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(resolves.load(Ordering::SeqCst), 1);

    // **DEAF FOR TWO DIALS, WHICH IS WHAT PUTS THE REDIAL LOOP UNDER TEST.** The
    // first is `start`'s, awaited before `main` would bind its listener. The second
    // is the one `run` makes immediately afterwards, still holding no client. Only
    // the THIRD dial is a redial — the one that comes after the loop has logged,
    // slept `invalidate::RETRY` and gone round again — and deleting that sleep is
    // deleting reconnection. With a broker that answers sooner, `run`'s first dial
    // succeeds and the loop is never entered at all.
    let mut rig = broker_on(listener, None, None, 2);

    // WAITING FOR THE `SUB`s, NOT FOR A CLOCK. This is what separates a redial
    // that restored the connection from one that also restored the subscription —
    // and the second is the one that matters, because the first is silent.
    rig.expect_two_ungrouped_subs().await;

    rig.publish(REVOKED, USER);
    let got = tokio::time::timeout(RECONNECT_DEADLINE, evicted.recv())
        .await
        .expect(
            "the consumer never acted on a revocation after the broker came up, so the degraded \
             state did NOT end on its own",
        )
        .expect("and the consumer is still running");
    assert_eq!(got, USER);

    present(&iam, &cache, "tok-laptop").await;
    assert_eq!(
        resolves.load(Ordering::SeqCst),
        2,
        "an invalidation delivered after the broker came up must still evict"
    );
}

#[tokio::test]
async fn a_refusal_that_arrives_after_the_flush_still_ends_the_subscription() {
    // **THE CASE THAT DECIDES WHETHER THIS DESIGN RESTS ON A GUARANTEE OR A HOPE.**
    // NATS acknowledges no `SUB`, and `async-nats`' `flush` is a LOCAL socket
    // flush — it enqueues no `PING`, so nothing in the client can wait for the
    // server's answer. The window `start` gives a refusal to arrive is therefore
    // a courtesy, and a broker slower than it is not a broken broker.
    //
    // So the property that has to hold is not "the boot line is always right" —
    // it cannot be. It is that a refusal, ARRIVING WHENEVER IT ARRIVES, ends the
    // subscription: the consumer must not sit for ever on a subject that will
    // deliver nothing, reporting success. Here the `-ERR` is held back well past
    // that window, and the consumer must still act on it.
    let cache = Arc::new(Credentials::new(TTL));
    let mut rig = forbidding_broker_after(REVOKED, Duration::from_millis(400)).await;
    let (_consuming, _evicted) = start(&rig, cache, None).await;

    // DELIBERATELY NOT ASSERTED ON. With the refusal held past the window there is
    // nothing `start` could have waited for, so the boot line says "consuming" and
    // is wrong — a known, documented limit rather than a defect. What must not
    // happen is that it stays wrong for ever.
    //
    // `run` drops the client when `drain` returns, which closes the socket. A
    // consumer that ignored the late refusal would still be holding this
    // connection open, waiting on a subscription the broker has already refused,
    // and this would time out.
    // Only the permitted subject's `SUB` is forwarded — the forbidden one is
    // answered with the `-ERR` instead — so this drains the first connection's one
    // entry, leaving the channel empty for the attribution assertion below.
    let _ = rig.next_sub().await;

    tokio::time::timeout(DEADLINE, rig.closes.recv())
        .await
        .expect(
            "the consumer never acted on a refusal that arrived after the flush: it is still \
             holding a subscription the broker refused, reporting that it is consuming, and it \
             will do so until the pod is replaced",
        )
        .expect("and the broker is still running");

    // **ENDING THE SUBSCRIPTION IS NOT ENOUGH; IT HAS TO END AS A REFUSAL.**
    // `run` reads the flag again after `drain` returns, and that read is what
    // picks the FORBIDS line and `REFUSED_RETRY` over "the connection ended" and
    // `RETRY`. Nothing above can see the difference — both close the socket — so
    // hard-coding that read to `false` left every test green while a deployment
    // error was logged as an outage and retried twelve times a minute.
    //
    // The back-off is the observable: a refusal waits `REFUSED_RETRY`, an outage
    // waits `RETRY`. A window comfortably past `RETRY` and far short of
    // `REFUSED_RETRY` tells them apart, and a redial inside it means the refusal
    // was misfiled.
    assert!(
        tokio::time::timeout(ATTRIBUTION_WINDOW, rig.next_sub())
            .await
            .is_err(),
        "the consumer redialled within {:?} of a REFUSED subscription, so it backed off as \
         though the broker were merely unreachable — a deployment error that does not fix \
         itself, logged and retried as an outage that does",
        ATTRIBUTION_WINDOW
    );
}
