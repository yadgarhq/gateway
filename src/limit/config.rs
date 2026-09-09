//! What the operator configured: the buckets, the kinds they apply to, and the
//! per-identity overrides `iam` returns.
//!
//! Split out of [`super`] for the file-size ceiling. This half PARSES and
//! VALIDATES and decides nothing; the decision is [`super::Decision`]'s and the
//! shared-cache path is [`super::valkey`]'s.

use std::collections::HashMap;

use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use super::KEY_TTL_SECONDS;

/// One bucket's two numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bucket {
    /// Sustained refill, tokens per second.
    pub rate: f64,
    /// The bucket's size, and therefore the largest burst.
    pub burst: f64,
}

impl Bucket {
    /// Read one `<rate>:<burst>` on its own.
    ///
    /// [`Limits::parse`] reads the same spelling inside a `<module>.<kind>=` list;
    /// this is the bare form, for a bucket that is not keyed on `(module, kind)`
    /// at all — see [`Limiter::check_source`]. It goes through the SAME
    /// [`parse_bucket`], so a rate of zero, a negative burst and a window longer
    /// than a key's life are refused here exactly as they are there, rather than
    /// through a second set of rules that could drift.
    pub fn parse(spec: &str) -> Result<Self, ConfigError> {
        parse_bucket(spec, spec)
    }

    /// How long this bucket takes to refill from empty.
    ///
    /// **This used to be the key's TTL, and that was wrong.** The reasoning is on
    /// [`KEY_TTL_SECONDS`]: the number is a property of the bucket that WROTE a
    /// key, and the correctness argument needs the bucket that READS it. What it
    /// is still good for is stating how long a bucket may take to come back, which
    /// is what [`ConfigError::Unrefillable`] bounds at boot.
    pub(super) fn refill_seconds(&self) -> f64 {
        if self.rate <= 0.0 {
            return 0.0;
        }
        self.burst / self.rate
    }

    /// The TTL a key gets when this bucket writes it. Whole seconds, because
    /// `EXPIRE` takes whole seconds and a sub-second TTL rounds to zero, which
    /// would delete the key on every write.
    ///
    /// The `max` is belt and braces rather than a live branch: [`validate`]
    /// refuses a bucket whose refill window exceeds [`KEY_TTL_SECONDS`], on both
    /// the configured path and the override path, so this cannot exceed the
    /// constant today. It stays because the invariant it protects — a key
    /// outlives its reader's refill window — should not depend on a validation
    /// somewhere else staying correct.
    pub(super) fn key_ttl_seconds(&self) -> u64 {
        KEY_TTL_SECONDS.max(self.refill_seconds()).ceil().max(1.0) as u64
    }
}

/// Refuse a bucket that cannot be enforced correctly, on EITHER path into one.
///
/// **`Limits::parse` validated and `Overrides::from_pairs` did not**, and the
/// unvalidated one is the path `iam` will drive. Traced through the script: a
/// `rate` of zero makes the Lua `(cost - tokens) / rate` evaluate to `inf`, which
/// comes back as the string `"inf"`, parses as `f64::INFINITY` and is clamped to
/// 86,400 — no panic anywhere, and a permanent lockout with a 24-hour
/// `Retry-After`.
fn validate(bucket: Bucket, whole: &str) -> Result<Bucket, ConfigError> {
    for (what, n) in [("rate", bucket.rate), ("burst", bucket.burst)] {
        if !n.is_finite() || n <= 0.0 {
            return Err(ConfigError::NotPositive(
                format!("{what} {n}"),
                whole.to_string(),
            ));
        }
    }
    let window = bucket.refill_seconds();
    if window > KEY_TTL_SECONDS {
        return Err(ConfigError::Unrefillable(whole.to_string(), window));
    }
    Ok(bucket)
}

/// What a limit configuration can be wrong in, refused at boot rather than
/// defaulted.
///
/// **A misparsed limit that silently became the default would be a limit nobody
/// notices is gone** — the D76 failure shape, applied to capacity. D69's rule
/// covers it: a capability that cannot be configured correctly fails startup.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0:?} is not `<module>.<kind>=<rate>:<burst>`")]
    Shape(String),
    #[error("{0:?} in {1:?} is not a positive number")]
    NotPositive(String, String),
    #[error("{0:?} is not a kind; expected one of read, write, generate")]
    UnknownKind(String),
    #[error(
        "{0:?} takes {1:.0}s to refill from empty, and a bucket key lives          {KEY_TTL_SECONDS:.0}s. Beyond that the key expires while the bucket is          still empty and the next call reads absent as FULL, which hands over the          whole burst. Raise `rate` or lower `burst`."
    )]
    Unrefillable(String, f64),
}

/// The configured defaults (D43), and the fallback for a pair nobody named.
///
/// **Configuration has no user axis**, which is what keeps D43 true here: a
/// per-user number is a fact about a person, so it lives in `iam` and arrives as
/// [`Overrides`].
#[derive(Debug, Clone)]
pub struct Limits {
    pub(super) per_pair: HashMap<String, Bucket>,
    pub(super) fallback: Bucket,
}

/// `read`, `write`, `generate` — D67's `Kind`, as the bounded string this module
/// keys on.
///
/// Reusing an existing bounded dimension rather than inventing a taxonomy is what
/// keeps the configuration small: `task.write`, `memory.write`, `recall.read`.
pub fn kind_str(kind: Kind) -> &'static str {
    match kind {
        Kind::Read => "read",
        Kind::Write => "write",
        Kind::Generate => "generate",
        // NEITHER REACHES THIS SERVICE, and both are named rather than folded
        // into a wildcard. `Job` is system-initiated work, which D74 puts outside
        // the first cut because it is not user-attributed and needs its own
        // mechanism; `Unspecified` is a Kind nothing should construct. A wildcard
        // would pool whichever appeared into some other kind's bucket.
        Kind::Job => "job",
        Kind::Unspecified => "unspecified",
    }
}

fn parse_kind(s: &str) -> Result<(), ConfigError> {
    match s {
        "read" | "write" | "generate" => Ok(()),
        other => Err(ConfigError::UnknownKind(other.to_string())),
    }
}

fn parse_bucket(spec: &str, whole: &str) -> Result<Bucket, ConfigError> {
    let (rate, burst) = spec
        .split_once(':')
        .ok_or_else(|| ConfigError::Shape(whole.to_string()))?;
    let number = |s: &str| -> Result<f64, ConfigError> {
        s.trim()
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite() && *n > 0.0)
            .ok_or_else(|| ConfigError::NotPositive(s.to_string(), whole.to_string()))
    };
    validate(
        Bucket {
            rate: number(rate)?,
            burst: number(burst)?,
        },
        whole,
    )
}

impl Limits {
    /// Parse a `<module>.<kind>=<rate>:<burst>` list and a bare
    /// `<rate>:<burst>` fallback — `example.write=3:33,example.read=7:77`, say.
    ///
    /// **THE EXAMPLE NAMES A MODULE THAT DOES NOT EXIST, DELIBERATELY.** A doc
    /// example spelling the shipped buckets is a second statement of
    /// `chart/values.yaml`'s `rateLimit.limits`: nothing recompiles when the
    /// chart moves, no test reads it, and it goes on reading as authoritative
    /// after it stops being true. This example was exactly that and had already
    /// drifted — it spelled a `task.write` bucket the chart had not shipped for
    /// some time. What a deployment actually sets is in the chart and nowhere
    /// else (ADR-0569); this line is here to show the SHAPE.
    ///
    /// The fallback exists because the tool surface grows and the configuration
    /// should not have to grow with it in lockstep. A pair nobody named is
    /// limited rather than unlimited — the opposite default would mean every new
    /// tool ships unprotected until somebody remembers.
    pub fn parse(pairs: &str, fallback: &str) -> Result<Self, ConfigError> {
        let mut per_pair = HashMap::new();
        for entry in pairs.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (name, spec) = entry
                .split_once('=')
                .ok_or_else(|| ConfigError::Shape(entry.to_string()))?;
            let (module, kind) = name
                .trim()
                .split_once('.')
                .ok_or_else(|| ConfigError::Shape(entry.to_string()))?;
            parse_kind(kind)?;
            if module.is_empty() {
                return Err(ConfigError::Shape(entry.to_string()));
            }
            per_pair.insert(format!("{module}.{kind}"), parse_bucket(spec, entry)?);
        }
        Ok(Self {
            per_pair,
            fallback: parse_bucket(fallback, fallback)?,
        })
    }

    /// The bucket in force for one call.
    ///
    /// **The override wins, and its absence is not an error.** `iam` carries the
    /// per-user overrides on `ResolveCredentialResponse` (D74), `attest` maps them
    /// into [`Overrides`], and this merges them over the configured defaults —
    /// which is what "effective" means, and why one lookup answers both questions.
    /// Absence is the ordinary case rather than the only one: it is what a caller
    /// with no override gets, and what EVERY caller gets on the trusted-header
    /// path, where no credential is resolved.
    pub fn effective(&self, module: &str, kind: Kind, overrides: &Overrides) -> Bucket {
        let pair = format!("{module}.{}", kind_str(kind));
        overrides
            .0
            .get(&pair)
            .or_else(|| self.per_pair.get(&pair))
            .copied()
            .unwrap_or(self.fallback)
    }
}

/// The per-user buckets that travel with identity (D74).
///
/// **Filled from a resolved credential, and empty without one.** D74 puts the
/// per-user overrides on `ResolveCredentialResponse` so the gateway learns who you
/// are and what you may spend in one lookup, invalidated together;
/// `attest::attest` is the call site, and it maps the repeated field into this
/// type. On the trusted-header path it stays empty, which is the honest answer
/// rather than a stub: no credential was resolved, and no header could carry a
/// limit. Empty means the configured default applies — the deployment behaves
/// exactly as if no user had an override, which is then true.
#[derive(Debug, Clone, Default)]
pub struct Overrides(HashMap<String, Bucket>);

impl Overrides {
    /// Build from what a resolved credential carried, refusing what cannot be
    /// enforced.
    ///
    /// The call site is `attest::overrides_from`, and the input is the repeated
    /// field D74 describes. Taking `(module.kind, rate, burst)` pairs rather than
    /// a generated protobuf type keeps this module off the contract's schedule —
    /// which is what it bought: `iam.proto` gained the field and `attest.rs`
    /// gained the mapping, and nothing here changed.
    ///
    /// **Validated, because this is the path `iam` drives and it was the
    /// unvalidated one.** `Limits::parse` refuses a `rate` of zero and this did
    /// not; the effect was not a panic but a permanent lockout with a 24-hour
    /// `Retry-After` — see [`validate`].
    ///
    /// **The call site must refuse the credential, not drop the bad bucket.** An
    /// override that cannot be parsed is a limit somebody set on purpose, and
    /// skipping it silently applies the configured default instead — which for an
    /// override that TIGHTENS a limit is the limit-nobody-notices-is-gone shape
    /// D69 and this module's own `ConfigError` both exist to refuse. A refused
    /// credential is an unusable credential, and `attest` already has a shape for
    /// that.
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (String, Bucket)>,
    ) -> Result<Self, ConfigError> {
        pairs
            .into_iter()
            .map(|(pair, bucket)| Ok((pair.clone(), validate(bucket, &pair)?)))
            .collect::<Result<HashMap<_, _>, ConfigError>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
