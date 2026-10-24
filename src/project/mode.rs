//! The ADR-0841 validation mode, and the env variable that chooses it.
//!
//! Split out of [`super`] for the file-size ceiling, unchanged. The second
//! knob, `orgGrants`, is [`super::grants`]'s.

/// Whether a classified refusal is answered or only counted.
///
/// **NO COMPILED-IN DEFAULT (ADR-0569).** An absent or unrecognised value
/// refuses the boot naming the variable, because the two values differ by
/// whether the estate's calls are served — and a mode nobody chose, applied as
/// if somebody had, is exactly what that rule exists to delete. The flip to
/// [`Self::Enforcing`] is a one-line change to this gateway's own deployment,
/// revertable by the same line, gated on the two counters above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Resolve, classify, count — and serve the call anyway. The shipped value.
    #[default]
    Counting,
    /// Answer the refusal. Reachable only by naming it (stage 5).
    Enforcing,
}

/// The environment variable that chooses the mode.
pub const MODE: &str = "YADGAR_PROJECT_VALIDATION_MODE";

impl Mode {
    /// Resolve the mode from this process's environment.
    ///
    /// # Errors
    ///
    /// See [`Self::from_lookup`], which this is: no fallback, and no parameter a
    /// fallback could sit in (ADR-0569).
    pub fn from_env() -> Result<Self, ModeError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Resolve the mode from an injected lookup.
    ///
    /// **A SEAM, for `Attestation::from_lookup`'s reason**: environment
    /// variables are process-global, so a test that set one would steer every
    /// other test in the same binary — and the decision this one makes is
    /// whether the estate's calls are refused.
    ///
    /// # Errors
    ///
    /// An absent value, and any value that is not one of the two names.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ModeError> {
        match lookup(MODE).as_deref().map(str::trim) {
            None => Err(ModeError::Absent),
            Some("counting") => Ok(Self::Counting),
            Some("enforcing") => Ok(Self::Enforcing),
            // THE VALUE IS ECHOED HERE and nowhere a caller can read it: this
            // is a boot refusal naming a deployment's own mistake, on the
            // operator's terminal, and a typo an operator cannot see is a
            // refusal they cannot fix.
            Some(other) => Err(ModeError::Unknown(other.to_string())),
        }
    }
}

/// A mode this deployment did not state, or stated in a word this binary does
/// not know.
#[derive(Debug, thiserror::Error)]
pub enum ModeError {
    #[error(
        "{MODE} is not set. It chooses whether a claimed workspace that resolves to nothing is \
         REFUSED or merely counted, and there is no compiled-in default (ADR-0569) because the \
         two answers differ by whether this estate's calls are served. Set it to \"counting\" \
         — the value every deployment ships until the flip gate in \
         plans/project-validation.md is read — or to \"enforcing\"."
    )]
    Absent,

    #[error(
        "{MODE} is {0:?}, which is neither \"counting\" nor \"enforcing\". A value outside the \
         two names is refused rather than read as the safer one: a deployment that meant to \
         enforce and misspelled it would otherwise enforce nothing, silently, for ever."
    )]
    Unknown(String),
}
