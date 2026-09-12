//! Boot phases 3, 5 and 6: what this process connects to, and how it serves.
//!
//! Each function is ONE CONTIGUOUS RUN of what `main` already did — see
//! [`super`]. No dial, bind or listen is reordered.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;

use yadgar_lifecycle::{drain_within, shutdown, Drain, DRAIN_BUDGET};

use yadgar_gateway::admin::BootstrapToken;
use yadgar_gateway::http::{router, AppState};
use yadgar_gateway::invalidate::Broker;
use yadgar_gateway::rotate;
use yadgar_gateway::upstream;

use super::{bootstrap_path_message, bootstrap_token, env_required, refusal};

type Boxed = Box<dyn std::error::Error>;

/// What [`wiring`] resolved: the rotation watch set, and the two upstreams.
pub struct Wiring {
    pub bootstrap: BootstrapToken,
    pub watch_inputs: rotate::Inputs,
    pub schedule: rotate::Schedule,
    /// How often a client should re-poll `tools/list`, resolved from
    /// `gateway.yaml`'s `toolsPoll.intervalSeconds` (ADR-0569/0570). Carried on
    /// [`AppState`](crate::http::AppState) rather than re-read per request.
    pub tools_poll_interval: std::time::Duration,
    pub task: Channel,
    pub iam: Channel,
    /// The registry, the validation mode, and the channel a refusal is composed
    /// over (ledger 881).
    ///
    /// **THE LOAD IS ALREADY RUNNING BEHIND THIS VALUE, and the boot is not
    /// gated on it (ADR-0674).** `Registry::start` publishes its gauge, spawns
    /// the loader and returns; a gateway whose `project` is unreachable therefore
    /// still binds, still logs in, and — in the shipped `counting` mode — still
    /// serves every scoped call.
    pub projects: Arc<yadgar_gateway::project::Validator>,
}

/// PHASE 3. TLS, the bootstrap token, the ADR-0523 watch set, and the two dials.
///
/// ONE PHASE AND NOT TWO, because the watch set is assembled from the same TLS
/// configuration the dials use and must be built from what was RESOLVED rather
/// than re-read (ADR-0523). Both dials are lazy (ADR-0532), so neither gates the
/// boot; the `?`s above them are the permanent-gap failures that do.
pub async fn wiring(
    broker: &Option<Broker>,
    valkey_password: &Option<(String, PathBuf)>,
) -> Result<Wiring, Boxed> {
    let (task_tls, iam_tls, project_tls) = transports()?;

    // STEP 2A OF THE ROTATION-KNOB CUT-OVER (ADR-0569, ADR-0570). The document
    // `yadgarhq/config` renders into the `shared` ConfigMap, mounted at
    // `/etc/yadgar/config/shared/shared.yaml`. There is no compiled-in default
    // behind it any more: an absent, empty, or half-written document refuses the
    // boot and names the file. The chart still sets TLS_ROTATION_POLL_SECS and
    // TLS_ROTATION_SPLAY_MAX_SECS — this binary no longer reads either, but they
    // stay so a rollout that lands this chart before this binary's digest still
    // resolves a schedule on the old one. The runbook is `yadgarhq/deploy`'s
    // MIGRATION_NOTES.md, steps 2a and 2b — NOT this repository's, which has no
    // such section.
    let config = rotate::Configuration::mounted();

    // THE FIRST KNOB IN `gateway.yaml` (this service's OWN document, distinct
    // from `shared.yaml` above). `chart/templates/deployment.yaml` has mounted
    // `config-gateway` since step 2a with nothing reading or watching it; this
    // is the knob that gives it a reader, and `gateway_config` below joins it
    // to the watch set two lines down so the gap that comment named is closed
    // in the same pull request that opened it. See `rotate::GatewayDocument`.
    let gateway_config = rotate::GatewayDocument::mounted();
    let tools_poll_interval = gateway_config
        .tools_poll_interval()
        .map_err(|e| e.to_string())?;

    // THE WATCH SET, ASSEMBLED FROM THE RESOLVED CONFIGURATION AND BEFORE THE
    // DIALS (ADR-0523). The baseline is the bytes each file held when this
    // process read them; deferring the first reading to the watcher's first poll
    // would put the rest of boot inside a window where a kubelet swap quietly
    // becomes the baseline, and the real rotation would never be noticed.
    //
    // BOTH UPSTREAMS, AND ONE CLIENT LEAF BETWEEN THEM. `gateway-client-tls` is
    // presented to `task` and to `iam`, so the same two paths arrive twice; the
    // fold de-duplicates, so the pair is hashed once and named once in the line
    // that reports a change.
    //
    // AND THE TWO PASSWORDS, WHICH ARE NOT TRANSPORT. The broker password and
    // the cache password are files this process read at boot and is about to
    // bake into an `async-nats` client and into `Limiter` for the life of the
    // process. ADR-0523's rule is about provenance rather than payload, so both
    // are watched exactly as the bundles are. Each is passed as the value this
    // boot RESOLVED — `broker` carries its own path, `valkey_password` carries
    // the one it opened — because re-reading the environment here could name a
    // different file from the one actually read.
    //
    // BOTH ARE `Some` ON THE DEPLOYMENT RUNNING TODAY. The chart sets
    // `rateLimit.passwordSecret` by default and points `nats.url` at a broker
    // whose authorization block declares a `gateway` user, so a reference pod
    // watches FIVE files rather than three and a rotation of either credential
    // ends this process from the first release that carries this line. Both
    // reads above are boot-fatal on an unreadable or empty file, so a pod that
    // reached this point has read both. The `Option` is for the off-reference
    // deployment running an open cache or an open broker (D80): there the
    // credential names no file, and nothing is watched for it rather than a path
    // that never existed.
    //
    // THE MOUNTED DOCUMENT JOINS THE SAME SET, last — an operator editing
    // `shared.yaml` now restarts this pod exactly as editing a CA bundle would.
    //
    // ONE CALL, AND THE SAME ONE A TEST MAKES. This used to be two chained
    // builder calls here, where nothing could reach them: no test spawns this
    // binary, so deleting either compiled and passed everything. The list lives
    // in `rotate::watch_set` now and `tests/assembly.rs` calls it.
    // READ HERE, BEFORE THE WATCH SET, because that set is hashed as it is built
    // and every entry has to be a file this process ACTUALLY LOADED. Reading it
    // beside `admin_limits` further down would put the rest of boot inside a
    // window where a kubelet swap quietly becomes the baseline.
    let (bootstrap, bootstrap_file) = bootstrap_token()?;
    if bootstrap.is_configured() {
        tracing::info!("{}", bootstrap_path_message(true));
    } else {
        tracing::warn!("{}", bootstrap_path_message(false));
    }

    let watch_inputs = rotate::watch_set(
        task_tls.as_ref(),
        iam_tls.as_ref(),
        project_tls.as_ref(),
        broker.as_ref(),
        valkey_password.as_ref().map(|(_, file)| file.as_path()),
        bootstrap_file.as_deref(),
        &config,
        &gateway_config,
    );

    // READ FROM THE SAME DOCUMENT THE WATCH SET JUST JOINED, whether or not any
    // TLS is configured. A value the document names and this binary cannot use
    // is a mistake to refuse, not one to paper over with a default nobody
    // chose — and refusing it here means it is refused on a cleartext
    // deployment too, which is where it would otherwise sit unnoticed until the
    // cut-over.
    let schedule = config.schedule().map_err(|e| e.to_string())?;

    let (task, iam, project) =
        upstreams(task_tls.as_ref(), iam_tls.as_ref(), project_tls.as_ref()).await?;

    let projects = validation(project)?;

    Ok(Wiring {
        bootstrap,
        watch_inputs,
        schedule,
        tools_poll_interval,
        task,
        iam,
        projects,
    })
}

/// What transport each of the three hops uses, as this deployment configured it.
///
/// **OPT-IN, OFF UNLESS A DEPLOYMENT ASKS FOR IT, AND READ PER UPSTREAM so the
/// three can be cut over one at a time.** Nothing configured means the cleartext
/// dial this gateway has always done — no module serves TLS yet, so the cut-over
/// is a later change that can be reverted on its own, one hop at a time.
///
/// `.to_string()` on the way out, for the reason `Limits::parse` gives: `main`
/// returns `Box<dyn Error>`, which Rust prints with DEBUG, so a bare `?` would put
/// `NoCaFile("TASK")` on the operator's terminal instead of the sentence naming
/// the missing variable and saying why cleartext is not the answer.
///
/// Its own function since ledger 881 made it three reads rather than two, which
/// took [`wiring`] past the function-length ceiling. The seam is the one the
/// ceiling pointed at: these three are configuration, and everything after them
/// is a resource.
type Transports = (
    Option<upstream::UpstreamTls>,
    Option<upstream::UpstreamTls>,
    Option<upstream::UpstreamTls>,
);

fn transports() -> Result<Transports, Boxed> {
    Ok((
        upstream::UpstreamTls::from_env(upstream::TASK).map_err(|e| e.to_string())?,
        upstream::UpstreamTls::from_env(upstream::IAM).map_err(|e| e.to_string())?,
        upstream::UpstreamTls::from_env(upstream::PROJECT).map_err(|e| e.to_string())?,
    ))
}

/// Ledger 881's two knobs, and the registry load they start.
///
/// Its own function for [`wiring`]'s function-length ceiling, and it is a real
/// seam rather than a split for the gate: everything here is about the PROJECT
/// registry, and none of it is about transport.
///
/// **NO COMPILED-IN DEFAULT BEHIND EITHER KNOB (ADR-0569).** They are environment
/// variables on this gateway's own deployment rather than lines in
/// `gateway.yaml`, and `plans/project-validation.md` licenses exactly that:
/// ADR-0569's template mechanism — the seed repository — is unbuilt, so until it
/// exists, keeping the mode in this chart makes the flip a one-line,
/// one-repository change with a diffable history that cannot happen by omission.
///
/// **THE LOAD IS RUNNING BY THE TIME THIS RETURNS, AND NOTHING WAITED FOR IT.**
/// `Registry::start` publishes its gauge, spawns the loader and returns — so an
/// unreachable `project` costs a degraded window rather than a boot that never
/// finishes (ADR-0674).
///
/// **ONE CHANNEL, CLONED.** The set is filled over it and the refusal path dials
/// `ResolveProject` over it. A second dial would be a second address for one
/// service, which is the confusion the deleted `YADGAR_IAM_ADDR` was — and a
/// `tonic::transport::Channel` clone shares the connection rather than opening
/// another.
fn validation(project: Channel) -> Result<Arc<yadgar_gateway::project::Validator>, Boxed> {
    let mode = yadgar_gateway::project::Mode::from_env().map_err(|e| e.to_string())?;
    let poll = yadgar_gateway::project::poll_from_env().map_err(|e| e.to_string())?;
    tracing::info!(
        ?mode,
        registry_poll_secs = poll.as_secs(),
        "project validation is configured; `counting` refuses nobody and only counts \
         (plans/project-validation.md)"
    );
    Ok(Arc::new(yadgar_gateway::project::Validator::new(
        yadgar_gateway::project::Registry::start(project.clone(), poll),
        mode,
        project,
    )))
}

/// PHASE 5. Start consuming D72's invalidation.
///
/// AFTER the state exists, because the eviction callback closes over the cache
/// that state owns. The `Arc` is taken BY VALUE so the block below keeps the
/// `Arc::clone` it always had.
pub async fn start_invalidation(broker: Option<Broker>, ttl: Duration, state: Arc<AppState>) {
    // D72's invalidation, BEFORE the listener binds. The first dial is awaited so
    // the line below says what is true rather than what was configured: a broker
    // this gateway could not reach must not produce a boot log claiming an
    // invalidation path it does not have. See `invalidate::start` for why an
    // unreachable broker degrades loudly instead of failing the boot.
    //
    // `Arc<AppState>` rather than a share of the cache alone, so `AppState` keeps
    // owning it and no handler changes.
    //
    // **SKIPPED ENTIRELY WHEN THE CACHE IS OFF, and the warning above says so.**
    // With no cache there is nothing an event could evict, so a connection, two
    // subscriptions and a redial loop would all be spent on calling `forget_user`
    // against an empty map. It also keeps `credentialCache.ttlSeconds: 0` the
    // clean revert MIGRATION_NOTES.md says it is: back to a round trip per call,
    // with no dependency on the broker at all. What is NOT skipped is
    // `Broker::from_env` above — a half-configured credential is a deployment
    // mistake at any TTL, and it still fails the boot.
    let consuming = if ttl.is_zero() {
        false
    } else {
        yadgar_gateway::invalidate::start(broker, {
            let state = Arc::clone(&state);
            // BOTH SUBJECTS EVICT A PERSON, never a token: `iam` holds a
            // credential id on a revoke and never sees the token this cache is
            // keyed on. See D72 and `Credentials::forget_user`.
            move |user_id: &str| state.credentials.forget_user(user_id)
        })
        .await
    };
    if !ttl.is_zero() && !consuming {
        // A WARNING, and it is the honest form of the one this used to print
        // unconditionally. It is no longer a statement about what was built; it is
        // a statement about what THIS process managed to connect to.
        tracing::warn!(
            ttl_seconds = ttl.as_secs(),
            "credential cache enabled (D72) with NO INVALIDATION BEING CONSUMED, so a \
             credential revoked in iam keeps working here for up to this long. The TTL is the \
             only bound."
        );
    } else if !ttl.is_zero() {
        tracing::info!(
            ttl_seconds = ttl.as_secs(),
            "credential cache enabled (D72), invalidated by broker events with the TTL as the \
             backstop for a missed one"
        );
    }
}

/// PHASE 6. Bind, serve, and drain within the budget.
pub async fn serve(
    state: Arc<AppState>,
    watch_inputs: rotate::Inputs,
    schedule: rotate::Schedule,
) -> Result<(), Boxed> {
    let addr: SocketAddr = env_required("LISTEN")?.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // ARMED BEFORE THE LISTENER IS SERVED, and that ordering is the fix rather
    // than an accident of where the line sits. `yadgar_lifecycle::shutdown`
    // installs both signal handlers when it is CALLED — a SIGTERM arriving between here and
    // the first poll of the future would otherwise take the process's default
    // disposition and kill it outright.
    let signals = shutdown().map_err(|e| {
        format!(
            "the SIGTERM and SIGINT handlers could not be installed: {e}. Refusing to start: a \
             server that cannot hear SIGTERM cannot drain, and Kubernetes ends every pod with one"
        )
    })?;

    tracing::info!(
        %addr,
        protocol = yadgar_gateway::mcp::PROTOCOL_VERSION,
        watching = watch_inputs.watched().len(),
        rotation_poll_secs = schedule.poll().as_secs(),
        rotation_splay_max_secs = schedule.splay_max().as_secs(),
        drain_budget_secs = DRAIN_BUDGET.as_secs(),
        "gateway listening"
    );

    // THE SERVER IS SPAWNED AND ASKED TO STOP THROUGH A CHANNEL, rather than
    // handed the shutdown future directly, because the drain has to be BOUNDED
    // once something other than a signal can start one, and a budget's clock
    // must start when shutdown is REQUESTED. A `timeout` around the serving
    // future itself would bound the server's whole life instead, and end the
    // process one budget after boot, on every boot — the defect `iam` shipped
    // and `yadgar-lifecycle`'s own `tests/drain.rs` keeps dead.
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(
        axum::serve(
            listener,
            // `into_make_service_with_connect_info`, WHICH THIS CALL DID NOT
            // HAVE. Without it nothing populates `ConnectInfo`, so the peer
            // address is not extractable at all and every request resolves to
            // `Source::Unknown` — an unthrottleable, unattributable request. It
            // is the one line that makes the rest reachable in the shipped
            // binary.
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_requested.await;
        })
        .into_future(),
    );

    // TWO WAYS THIS PROCESS STOPS, and only one of them is a signal. The other
    // is a rotated TLS file (ADR-0523), which is why the drain below is bounded
    // at all: kubelet's grace period never runs for a drain kubelet did not
    // start, and tokio has already swallowed the SIGTERM that would otherwise
    // save it.
    let stop = async {
        tokio::select! {
            () = signals => {}
            () = rotate::watch(watch_inputs, schedule) => {}
        }
    };

    match drain_within(serving, ask_to_stop, stop, DRAIN_BUDGET).await {
        Drain::Finished(result) => result?,
        Drain::Overran => tracing::error!(
            budget_secs = DRAIN_BUDGET.as_secs(),
            "the drain did not finish within its budget; ending anyway with calls still in \
             flight. A request blocked this long is the thing to look at"
        ),
    }
    Ok(())
}

/// The two gRPC upstreams.
///
/// Its own function because it is the one part of [`wiring`] that DIALS, and
/// the reasoning for why both dials are lazy — and for what the `?`s on them
/// still cover — is the comment inside it.
async fn upstreams(
    task_tls: Option<&upstream::UpstreamTls>,
    iam_tls: Option<&upstream::UpstreamTls>,
    project_tls: Option<&upstream::UpstreamTls>,
) -> Result<(Channel, Channel, Channel), Boxed> {
    let task_host = env_required("TASK_HOST")?;
    let task_port: u16 = env_required("TASK_PORT")?.parse()?;
    let task = upstream::connect_task(&task_host, task_port, task_tls)
        .await
        // Same reasoning: `BalanceError`'s messages are paragraphs explaining
        // that an empty bundle trusts nobody and that a missing one is not a
        // reason to connect in cleartext. Debug prints the struct and throws all
        // of that away.
        //
        // `refusal` RATHER THAN `to_string()`, and see its own note for why this
        // site takes it and the other four do not: `BalanceError::Tls` is the one
        // error reaching `main` that hides its reason a layer down.
        .map_err(|e| refusal(&e))?;
    tracing::info!(host = %task_host, port = task_port, tls = task_tls.is_some(), "connected to task");

    // The upstream for BOTH halves of the credential lifecycle: POST /auth/login
    // and POST /auth/enrol issue a token through this channel (D75, D73), and
    // `attest` resolves one through it on every tools/call.
    //
    // **ONE pair, IAM_HOST/IAM_PORT, matching TASK_HOST/TASK_PORT.** There used to
    // be a second variable, YADGAR_IAM_ADDR, reserving the identity half — and it
    // was a boot-killer, because that half was unimplemented. Both halves are this
    // channel now, so the reservation is deleted rather than honoured: two
    // settings that both read as "where iam is" is one too many, and the one that
    // named a service nothing could reach is the one to lose.
    //
    // LAZY — and no longer the ONLY place this file's opening claim is true.
    // `connect_task` above used to resolve DNS eagerly, with `?` turning a name
    // that did not resolve into a failed boot, so the module comment's "the
    // upstream connection is NOT gated" did not hold for `task`. `dial` v0.2.0
    // makes that dial lazy too (ADR-0532), so BOTH upstreams now cost a bounded
    // failure per request rather than a pod that never starts, and the claim
    // holds for the first time since it was written.
    //
    // **`iam` IS NO LONGER A SECONDARY UPSTREAM, and this comment used to say it
    // was.** It said an absent `iam` cost "a 503 on /auth/login and nothing at all
    // on /", which was true while identity came from headers. Attestation resolves
    // the bearer token through this channel now, so an `iam` outage degrades ALL
    // MCP traffic, not one endpoint. Staying lazy is still right — a pod stuck in
    // startup is one D68's autoscaler cannot help, and a per-request failure is
    // recoverable where a refusal to boot is not — but the cost of the outage it
    // survives is larger than it was, and `attest::Credentials` above is what
    // brings it back down: D72's "on a cache miss, never per request", so an `iam`
    // outage now costs the callers whose entries expire during it rather than
    // every call in flight.
    //
    // `?` still stands on both lines, and what it now covers is configuration
    // rather than reachability: a port that is not a number, a host string that
    // cannot form a URI, and a CA bundle that cannot be used. Those are
    // deployment mistakes, which is exactly the class D69 says should fail boot.
    //
    // **THE CA BUNDLE IS READ HERE even though the channel is lazy**, and the
    // two are not in tension: what stays lazy is the part that depends on `iam`
    // EXISTING. A bundle depends only on the deployment that wrote it, so
    // deferring the read would turn an operator's mistake into a per-request
    // failure found under traffic rather than a refusal to boot.
    let iam_host = env_required("IAM_HOST")?;
    let iam_port: u16 = env_required("IAM_PORT")?.parse()?;
    let iam = upstream::connect_iam(&iam_host, iam_port, iam_tls)
        .await
        // `refusal`, for the reason `connect_task` above gives.
        .map_err(|e| refusal(&e))?;
    tracing::info!(
        host = %iam_host,
        port = iam_port,
        tls = iam_tls.is_some(),
        "iam channel ready (connects on first use)"
    );
    // THE REGISTRY'S LOGIC TIER (ledger 881), lazy for the reason the two above
    // are and for one more: `project` is the newest service in the estate, so a
    // cluster without it is the ordinary case rather than the exceptional one,
    // and ADR-0674 rules that its absence must cost a degraded window rather
    // than a front door that never opens.
    let project_host = env_required("PROJECT_HOST")?;
    let project_port: u16 = env_required("PROJECT_PORT")?.parse()?;
    let project = upstream::connect_project(&project_host, project_port, project_tls)
        .await
        .map_err(|e| refusal(&e))?;
    tracing::info!(
        host = %project_host,
        port = project_port,
        tls = project_tls.is_some(),
        "project channel ready (connects on first use)"
    );
    Ok((task, iam, project))
}
