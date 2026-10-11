//! Boot must not wait on Valkey (D69/ADR-0555) — including the background
//! warm-up [`Limiter::warm`] added (ledger 1430).
//!
//! **WHY A BLACKHOLE ADDRESS, NOT A CLOSED PORT.** A closed port refuses a
//! connection attempt almost instantly, which would pass this test whether
//! `main` awaits the warm-up or spawns it — the discriminating property needs
//! an address that actually HANGS for a measurable time. `192.0.2.1` is
//! TEST-NET-1 (RFC 5737): reserved, unassigned, and never routed, so a SYN to
//! it is silently dropped rather than answered either way, and the connect
//! attempt hangs until something ELSE bounds it.
//!
//! **WHY `YADGAR_RATE_LIMIT_TIMEOUT_MS` IS RAISED FROM [`support::cleartext_env`]'s
//! "50".** `Limiter::connect_config`'s `inner` budget — what actually bounds
//! the hung connect attempt, both for `warm` and for a real call — is two
//! thirds of this value. At "50" that bound is ~33ms, far too short to tell
//! "awaited directly" apart from "spawned": either shape reaches the
//! "gateway listening" line long before a 3-second deadline could ever catch
//! the bug. Raised to eight seconds, an accidentally-`.await`ed `warm` would
//! hold `run` on that hung connect for ~5.3 seconds (two thirds of it) before
//! the listener ever binds — comfortably past the 3-second deadline this file
//! asserts against.
//!
//! `[limit::valkey::CONNECT_BUDGET]` is 15 seconds and plays no part here: it
//! bounds `warm`'s own task, which this file never waits on either.

mod support;

use std::time::Duration;

use support::{cleartext_env, Booted};

/// Comfortably under the ~5.3-second hang a blocking `warm` would cause
/// (see the module comment), comfortably over how long a boot that never
/// waits on Valkey actually takes.
const DEADLINE: Duration = Duration::from_secs(3);

#[test]
fn boot_reaches_listening_before_a_hung_background_connect_could_finish() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "YADGAR_VALKEY_ADDR" && *k != "YADGAR_RATE_LIMIT_TIMEOUT_MS");
    vars.extend([
        ("YADGAR_VALKEY_ADDR", "192.0.2.1:6379"),
        ("YADGAR_RATE_LIMIT_TIMEOUT_MS", "8000"),
    ]);

    let mut gateway = Booted::start(&vars);
    gateway.wait_for_line("the \"gateway listening\" line", DEADLINE, |l| {
        l.contains("\"gateway listening\"")
    });
}
