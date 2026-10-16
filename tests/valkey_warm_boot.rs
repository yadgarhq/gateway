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
//! **WHAT THE TEST DISCRIMINATES ON: AN UNBOUNDED RETRY LOOP AGAINST A BLACKHOLE.**
//! Since ledger 1438, `Limiter::warm` loops: a failed attempt is logged,
//! `RETRY` (5 seconds) is slept, and it dials again, until `conn` is populated.
//! `CONNECT_BUDGET` (15 seconds) bounds each single attempt and nothing more.
//! Against `192.0.2.1` no attempt ever succeeds, so an awaited `warm` NEVER
//! returns and `run` would never bind its listener. A `main` that spawns `warm`
//! reaches "gateway listening" within `DEADLINE`; a `main` that awaits it does
//! not reach it at all.
//!
//! **THE `YADGAR_RATE_LIMIT_TIMEOUT_MS` OVERRIDE BELOW IS VESTIGIAL.** It was
//! raised from [`support::cleartext_env`]'s "50" when `inner`, two thirds of
//! that value, also bounded the connect. Since ledger 1430 `inner` bounds only
//! each command's response, so the override plays no part in what this test
//! proves. It stays so this change touches no behaviour.

mod support;

use std::time::Duration;

use support::{cleartext_env, Booted};

/// A boot that spawns `warm` binds its listener in well under this. A boot that
/// awaits `warm` against the blackhole address never does, so any finite value
/// separates them; 3 seconds leaves room for a slow runner.
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
