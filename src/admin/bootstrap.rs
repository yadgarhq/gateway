//! [`BootstrapToken`]: whether the shared secret this deployment holds accepts
//! a presented one. Split out of `admin.rs` for the file-size ceiling; the
//! parent re-exports both types, so every path that names them is unchanged.

use sha2::{Digest, Sha256};

/// This deployment's bootstrap token, as this process holds it.
///
/// # Two rules, and they are two different bugs (§7.2, and the Secret's own manifest)
///
/// `deploy`'s `infra/bootstrap/admin-bootstrap-token.yaml` states the consumer
/// contract this type exists to keep, in two numbered halves, "stated separately
/// because they are two different bugs":
///
/// 1. **An ABSENT OR EMPTY secret DISABLES the bootstrap path**, which refuses
///    every request on it with a status naming the missing configuration — never
///    a comparison against a missing value. That is [`Bootstrap::NotConfigured`].
/// 2. **An ABSENT secret is NEVER EQUAL to a PRESENTED one.** "(1) is about the
///    route's configuration, this is about the comparator. A constant-time
///    comparator written to compare two EMPTY inputs returns TRUE — so 'no secret
///    configured' must short-circuit to refusal before any comparison runs, never
///    fall through into one."
///
/// **The `Option` is how half 2 is made structural rather than remembered.** An
/// absent secret is not a `String` that happens to be empty; it is a variant with
/// no bytes in it at all, so there is nothing for a comparator to be handed. The
/// only way to reintroduce the bug is to write a default INTO the `None` arm,
/// which is a visible act rather than an omission.
///
/// # This is NOT ADR-0569's ordinary rule, and the difference is deliberate
///
/// ADR-0569 would make an absent knob refuse the BOOT, naming it. Applied here
/// that takes MCP and `/auth/login` down over an administrative knob — "an outage
/// priced far above the gap". Serve-and-disable-one-path is the shape of `iam`'s
/// own argued exception (`iam/src/service.rs:458-470,490`), whose reasoning
/// transfers exactly. Both readings are fail-closed for the admin path; this one
/// is fail-closed without collateral.
#[derive(Debug, Clone)]
pub struct BootstrapToken(Option<[u8; 32]>);

/// What [`BootstrapToken::check`] decided.
///
/// **THREE OUTCOMES AND NOT TWO**, because the caller must answer
/// [`Bootstrap::NotConfigured`] differently: a deployment whose Secret is not
/// mounted has an operator problem, and collapsing it into the refusal every
/// wrong token gets would leave that operator reading "forbidden" and looking for
/// a permission they already have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bootstrap {
    /// No secret is configured. **The whole path is disabled** — this is the
    /// answer for every request on it, whatever was presented, and no comparison
    /// was performed to reach it.
    NotConfigured,
    /// A secret is configured, and what was presented is not it.
    Refused,
    /// A secret is configured and what was presented equals it.
    Accepted,
}

impl BootstrapToken {
    /// The disabled token: no secret, so no bootstrap request is ever accepted.
    ///
    /// **The default a deployment gets before its Secret is mounted**, and the
    /// state the route ships in until the chart grows the mount. That is the
    /// manifest's own expectation — "Until the consumer lands, this Secret sits
    /// unread" — rather than a degraded mode.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// The token this deployment holds, from the mounted Secret's contents.
    ///
    /// **BLANK COUNTS AS ABSENT**, and it is `trim` that decides, not
    /// `is_empty`: a Secret whose value is a newline is a Secret nobody set, and
    /// a file that arrived with trailing whitespace is the same token. `iam`'s
    /// `ca_pem` guard tests blankness rather than emptiness for the same reason
    /// and the two were written independently.
    ///
    /// **The DIGEST is stored, not the token.** It makes the comparison
    /// fixed-width whatever was presented — so the comparison cannot leak a
    /// length — and it keeps the secret itself out of every `Debug` rendering of
    /// `AppState` this process might ever write to a log.
    pub fn from_secret(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::disabled();
        }
        Self(Some(digest(trimmed)))
    }

    /// Whether a secret is configured at all.
    ///
    /// For the boot log, which says which of the two states this process is in.
    /// It is deliberately NOT what the handlers branch on — they branch on
    /// [`Self::check`], which answers the same question and the comparison in one
    /// step, so no caller can check one and forget the other.
    pub fn is_configured(&self) -> bool {
        self.0.is_some()
    }

    /// Judge one presented token.
    pub fn check(&self, presented: &str) -> Bootstrap {
        // RULE 1, AND IT RETURNS BEFORE ANY COMPARISON EXISTS. There is no
        // `unwrap_or_default` here and there must never be one: an absent secret
        // defaulted to `""` and then compared is precisely the bug rule 2 is
        // written down separately to prevent, and a constant-time comparator over
        // two empty inputs answers TRUE.
        let Some(want) = self.0 else {
            return Bootstrap::NotConfigured;
        };
        // A PRESENTED EMPTY VALUE IS REFUSED WITHOUT BEING HASHED. The digest
        // comparison below would refuse it anyway — `digest("")` equals no
        // configured secret's digest — so this line buys the property WITHOUT
        // depending on that, which is what makes rule 2 hold for reasons a reader
        // can check rather than for reasons SHA-256 happens to have.
        if presented.is_empty() {
            return Bootstrap::Refused;
        }
        if constant_time_eq(&want, &digest(presented)) {
            Bootstrap::Accepted
        } else {
            Bootstrap::Refused
        }
    }
}

/// SHA-256 of one token.
fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// Compare two digests without an early exit.
///
/// **FIXED WIDTH BY CONSTRUCTION**, because both sides are digests: there is no
/// length to compare first and therefore no length to leak. The accumulator is
/// OR-ed over every byte and read once at the end, so the loop takes the same
/// path whatever the inputs are — the whole point of not using `==` on the
/// secrets themselves.
///
/// `#[inline(never)]` so the comparison stays one function a reader can find,
/// rather than something the optimiser has spread across a caller.
#[inline(never)]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut differing = 0u8;
    for i in 0..32 {
        differing |= a[i] ^ b[i];
    }
    differing == 0
}
