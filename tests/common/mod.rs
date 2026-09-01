//! Shared by the two test binaries that need a real Valkey.
//!
//! `tests/common/` rather than a third `tests/*.rs`: cargo compiles every file
//! directly under `tests/` into its own binary, and a subdirectory module is the
//! way two of them share code without a third empty test binary appearing in the
//! output.

/// The address of a real Valkey, or `None` and a loud line saying why nothing
/// ran. See the module comment for why this is not a panic.
pub fn addr() -> Option<String> {
    match std::env::var("YADGAR_TEST_VALKEY") {
        Ok(a) if !a.is_empty() => Some(a),
        _ => {
            skipped(
                "the concurrency property D74 exists for was NOT exercised. These tests are the \
                 only thing that can tell an atomic read-compute-write from a per-replica one.",
            );
            None
        }
    }
}

/// Say that nothing ran, in a way the CI log actually shows.
///
/// **`eprintln!` is the wrong tool here and the difference is not cosmetic.**
/// libtest captures the print macros for a test that PASSES, so a skip announced
/// with `eprintln!` is swallowed unless somebody passes `--nocapture` — and CI
/// does not. The log then shows six green test names and no hint that every one
/// of them measured nothing, which is precisely the failure D76 names: a
/// mechanism that reads healthy while doing nothing.
///
/// Writing to the handle directly bypasses that capture, because libtest swaps
/// the thread-local the macros go through and not the file descriptor. Verified
/// by running a test both ways.
pub fn skipped(what: &str) {
    use std::io::Write;
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "\nSKIPPED — YADGAR_TEST_VALKEY is unset, so {what} See the module comment on \
         tests/rate_limit.rs to run them against a container.\n"
    );
    let _ = err.flush();
}
