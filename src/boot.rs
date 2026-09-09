//! Everything `main` does before the listener binds, in the order it does it.
//!
//! **THE ORDER IS THE CONTRACT, not the grouping.** An operator debugging a
//! broken deployment reads the FIRST refusal, so which of a pod's two mistakes
//! gets reported is an observable property. Splitting `main` moved nothing
//! across that order: every function in [`config`] and [`wiring`] is ONE
//! CONTIGUOUS RUN of what `main` already did, called from the place it ran, and
//! the phases are called in the sequence they are numbered.
//!
//! The helpers below this comment are the ones the phases share. One knob, one
//! source, no compiled-in default (ADR-0569).

use std::path::PathBuf;

use yadgar_gateway::admin::BootstrapToken;
use yadgar_gateway::limit::Bucket;

mod config;
mod wiring;

pub use config::{http_configuration, identity, rate_limiting};
pub use wiring::{serve, start_invalidation, wiring, Wiring};

/// One configuration knob, read from its ONE source, with no compiled-in
/// default behind it (ADR-0569).
///
/// This replaced `env_or(key, default)`, and the deletion is the point rather
/// than the rename: while the helper took a `default` argument, every knob in
/// this binary had somewhere for a fallback to live, and a fallback is invisible
/// at the point of use, survives an upgrade unnoticed, and makes the effective
/// setting depend on which layer a reader happens to inspect.
///
/// AN EMPTY VALUE REFUSES TOO, and with its own message. A set-but-empty
/// variable and an absent one collapsing into a single branch is a defect this
/// estate found three separate times in one week: Helm renders an unset value as
/// `""`, so the empty case is what a nulled chart value actually produces, and it
/// is the one an operator is most likely to hit. Where an empty value is a
/// DECLARED STATE rather than an oversight, use [`env_required_allow_empty`].
pub(crate) fn env_required(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(format!(
            "{key} is set but EMPTY. It has no compiled-in default (ADR-0569), so there is \
             nothing to fall back to. The chart renders it; a values override that nulls it \
             produces exactly this."
        )),
        Err(_) => Err(format!(
            "{key} is NOT SET. It has no compiled-in default (ADR-0569): this process reads \
             it from the environment alone and refuses to start rather than invent a value. \
             The chart renders it."
        )),
    }
}

/// A knob that must be STATED, but whose empty value is a real instruction.
///
/// The distinction [`env_required`] cannot make on its own. `YADGAR_ALLOWED_ORIGINS`
/// empty means "no browser origin is allowed", which is the correct posture for a
/// server whose clients are agents — it is a choice, not a missing value. Absence
/// still refuses, so the deployment cannot silently omit the decision.
pub(crate) fn env_required_allow_empty(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| {
        format!(
            "{key} is NOT SET. It has no compiled-in default (ADR-0569). An EMPTY value is \
             accepted here and is a deliberate state, but the variable itself must be \
             rendered so the choice is visible. The chart renders it."
        )
    })
}

/// A boot refusal as the TEXT `main` returns, flattened through the estate's one
/// error-chain walker (ledger 733, ADR-0591).
///
/// **NOT A SIXTH COPY.** The body is a call to `yadgar_telemetry::diagnose::chain`
/// and nothing else; the source walk lives there and is written once. What this
/// adds is a SEAM. Every `map_err` in `main` is a closure inside a binary target,
/// so no test in this repository can reach one — routing the two sites that need
/// the walk through a named function is what gives the property somewhere to be
/// asserted, and reverting this body to `error.to_string()` turns
/// `a_refusal_carries_the_layer_below_transport_error` red.
///
/// **ONLY TWO OF THE SIX REFUSALS IN `main` TAKE IT, and the other four keep
/// `to_string()` deliberately.** Ledger 733 asked for all of them; the renderings
/// were measured first, and a substitution that degrades an operator's message to
/// hit a count is the failure this consolidation is arguing against:
///
/// | site | error | measured |
/// | --- | --- | --- |
/// | `connect_task`, `connect_iam` | `yadgar_dial::BalanceError` | TAKES IT. `Tls` renders `TLS could not be configured: transport error` and keeps `invalid dns name` a layer below tonic's own error, where nothing else can reach it. |
/// | `UpstreamTls::from_env` (twice) | `upstream::TlsConfigError` | no. Every variant carries a `&'static str` and no `#[source]`, so `chain` is byte-identical to `to_string()` — measured, both render the same sentence. |
/// | `Configuration::schedule` | `rotate::ScheduleError` | no. Its `#[error]` already interpolates `({source})`, so walking prints the inner text TWICE — and there is no further layer to gain: `serde_norway` 0.9.42's `Error::source()` forwards to `ErrorImpl::source()`, which answers `Some` only for `Io`/`FromUtf8`/`Shared`, and malformed YAML yields `Message` or `Libyaml`, both `None`. `Unreadable`'s `io::Error` has no source either. Settled, not deferred. |
/// | `TrustBoundary::parse` | `source::TrustBoundaryError` | no. Two variants, neither with a source. |
///
/// **The duplication this paragraph used to describe is gone as of `dial`
/// v0.2.5 (ledger 737).** `BalanceError` still has TEN variants, of which
/// exactly SIX carry `#[source]` — `Dns`, `CaUnreadable`, `CaUnparsable`,
/// `ClientCertificateUnreadable`, `ClientKeyUnreadable`, `Tls` — but none of
/// the six interpolates `{source}` into its own `#[error]` string any more
/// (`dial` v0.2.5 `src/lib.rs:1172-1264`, `Tls` at `:1259`, now
/// `#[error("TLS could not be configured")]` with no inlined cause). The
/// chain walk supplies the cause instead of the message printing it twice,
/// which is what the item title says.
///
/// `Tls` is the worked example. Before `v0.2.5` the walk rendered `TLS could
/// not be configured: transport error: transport error: invalid dns name` —
/// `transport error` twice, because `Tls` both interpolated tonic's error AND
/// `chain` walked to it as `#[source]`. After `v0.2.5` it renders `TLS could
/// not be configured: transport error: invalid dns name` — once. What still
/// makes `Tls` worth the walk is unchanged: a THIRD layer sits under it, and
/// nothing else reaches that layer.
///
/// The fix landed where this doc comment used to say it belonged: in
/// `yadgar-dial`, whose `#[error]` strings no longer inline a field they also
/// mark `#[source]`. The walk is still the only way the layer below
/// `transport error` reaches an operator; it just no longer pays a duplicate
/// tail to get there.
pub(crate) fn refusal(error: &dyn std::error::Error) -> String {
    yadgar_telemetry::diagnose::chain(error)
}

/// One `<rate>:<burst>` from the environment, naming the variable when it is
/// wrong.
///
/// The error is stringified for the reason `Limits::parse`'s is: `main` returns
/// `Box<dyn Error>`, which Rust prints with DEBUG — so a bare `?` would put
/// `NotPositive("0", "0:10")` on the operator's terminal instead of the sentence
/// saying which variable is unusable and why.
///
/// NO `default` PARAMETER any more. This helper was the second place a
/// compiled-in default lived in this binary, which is why the ADR-0569 gate
/// forbids the SHAPE — an environment reader taking a fallback — and not merely
/// the name `env_or`.
pub(crate) fn parse_bucket_env(key: &str) -> Result<Bucket, String> {
    Bucket::parse(&env_required(key)?).map_err(|e| format!("{key} is not usable: {e}"))
}

/// D73's bootstrap token, from the file the Secret is mounted at.
///
/// **ABSENT IS A STATE THE DESIGN NEEDS, which is ADR-0569's own revisit
/// trigger** — "a knob whose absence leaves the system correct". An absent
/// variable, an absent file and a blank one all mean the same thing here: the
/// bootstrap path is DISABLED, everything else serves, and every request on that
/// path is refused with a status naming the missing configuration. §7.2 states
/// the rule and `deploy`'s `infra/bootstrap/admin-bootstrap-token.yaml` states
/// it again as the consumer contract this must honour.
///
/// **AN UNREADABLE FILE IS NOT A MISSING ONE and still fails the boot.** The
/// variable naming a path that cannot be read is a deployment that TRIED to
/// configure this and got it wrong, which is `YADGAR_VALKEY_PASSWORD_FILE`'s
/// existing shape and D69's rule: a capability that cannot be configured
/// correctly fails startup rather than serving without it. Absence is a posture;
/// a broken path is a mistake.
pub(crate) fn bootstrap_token() -> Result<(BootstrapToken, Option<PathBuf>), String> {
    // ADR-0569-EXCEPTION
    let Ok(path) = std::env::var("YADGAR_ADMIN_BOOTSTRAP_TOKEN_FILE") else {
        return Ok((BootstrapToken::disabled(), None));
    };
    if path.trim().is_empty() {
        return Ok((BootstrapToken::disabled(), None));
    }
    // ADR-0523-WATCHED: bootstrap_token
    //
    // **A ROTATION MUST TAKE EFFECT, and exit-on-change is how it does.** The
    // token is held as a DIGEST for the life of the process, exactly as the cache
    // password is held as a value, so a Secret updated underneath a running pod
    // would leave this gateway comparing against the old one. The Secret's own
    // manifest warns that a cluster rebuild mints a DIFFERENT token while the
    // operator still holds the old value — "present-and-wrong, which no existence
    // check can discriminate" — so an operator who rotates it must get a pod that
    // restarts, exactly as editing a CA bundle gives them one.
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "YADGAR_ADMIN_BOOTSTRAP_TOKEN_FILE names {path}, which cannot be read: {e}. \
             Unset the variable to run with the administrative bootstrap path disabled; a \
             path that cannot be read is a configuration that was ATTEMPTED and failed, \
             which is D69's rule and the same shape YADGAR_VALKEY_PASSWORD_FILE already has."
        )
    })?;
    // BLANK IS ABSENT, and `from_secret` is what decides that — see the type.
    //
    // **THE PATH COMES OUT BESIDE THE VALUE**, for `valkey_password`'s stated
    // reason: the watch set is built from what this process ACTUALLY READ and
    // never by reading the environment a second time, because a second reading
    // could name a different file from the one opened here.
    Ok((BootstrapToken::from_secret(&raw), Some(PathBuf::from(path))))
}

/// **AN ARGUED EXCEPTION TO ADR-0569, and the only one in this binary.**
///
/// It is a named function rather than a bare fallback at the call site precisely
/// so a reader can tell it apart from an oversight. Every other knob here reads
/// through [`env_required`]; this one does not, and the argument is:
///
/// UNSET IS A STATE THE DESIGN NEEDS. `TrustBoundary::Undeclared` means "nobody
/// has said how many proxies stand in front", which is DIFFERENT from `Hops(0)`
/// meaning "there is no proxy". Making absence fatal would delete the first
/// state and leave no way to express it, and ADR-0569's own revisit trigger
/// names this shape: a knob whose absence leaves the system correct.
///
/// It is not a value nobody chose, either. Undeclared is the SAFE posture, not a
/// convenient one — gateway then records no source address at all rather than
/// trusting a header the caller can write, and bounds the credential endpoints
/// per observed hop. The chart renders the variable unconditionally, empty
/// included, so `kubectl describe pod` still answers the question.
///
/// A MALFORMED value is a different matter and still fails the boot: see the
/// call site.
pub(crate) fn trusted_proxy_hops() -> String {
    // Absence is the declared state `TrustBoundary::Undeclared` ("nobody knows"),
    // which `Hops(0)` ("there is no proxy") cannot express. Full argument above.
    // The marker must sit on the READ ITSELF, so `git grep ADR-0569-EXCEPTION`
    // lands on the line that takes the fallback rather than on prose near it.
    std::env::var("YADGAR_TRUSTED_PROXY_HOPS").unwrap_or_default() // ADR-0569-EXCEPTION
}

#[cfg(test)]
mod tests;
