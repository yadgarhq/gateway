//! Shared by the two test binaries that need a real Valkey.
//!
//! `tests/common/` rather than a third `tests/*.rs`: cargo compiles every file
//! directly under `tests/` into its own binary, and a subdirectory module is the
//! way two of them share code without a third empty test binary appearing in the
//! output.

/// The address of a real Valkey, or `None` and a loud line saying why nothing
/// ran. In CI there is no third option — see [`resolve`].
pub fn addr() -> Option<String> {
    resolve(
        std::env::var("YADGAR_TEST_VALKEY").ok(),
        std::env::var("CI").ok(),
    )
}

/// The skip-or-panic decision, as a pure function so it can be tested.
///
/// **Locally the absence of a Valkey is a skip; in CI it is a failure.** The two
/// are different situations and one answer would be wrong for one of them. A
/// developer with no container running should still be able to run the rest of
/// the suite. CI is the opposite case: the day the shared workflow
/// (`yadgarhq/actions`, `ci-pr.yaml`) gains a Valkey beside its MariaDB, nothing
/// would say these tests had started running — and nothing would say if a later
/// change to that workflow stopped them again. After merge, the one defect this
/// module exists to prevent would have no automated coverage at all while seven
/// green test names said otherwise, which is the D76 shape.
///
/// **Printing the skip loudly is not enough on its own**, and this is the
/// correction to what this file used to argue. The `SKIPPED —` lines do reach the
/// log under the exact command CI runs; a line in a log is a control only while
/// somebody reads it, and nobody reads a green run.
fn resolve(valkey: Option<String>, ci: Option<String>) -> Option<String> {
    if let Some(a) = valkey.filter(|a| !a.is_empty()) {
        return Some(a);
    }
    // GitHub Actions sets CI=true on every runner.
    assert!(
        ci.as_deref() != Some("true"),
        "YADGAR_TEST_VALKEY is unset in CI. The concurrency property D74 exists for cannot be \
         exercised without a real Valkey, and a silent skip here is a green run that measured \
         nothing. Add a valkey service to yadgarhq/actions' ci-pr.yaml beside the MariaDB one \
         and set YADGAR_TEST_VALKEY in the same env block — the YAML is in MIGRATION_NOTES.md."
    );
    skipped(
        "the concurrency property D74 exists for was NOT exercised. These tests are the \
         only thing that can tell an atomic read-compute-write from a per-replica one.",
    );
    None
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

/// These run in BOTH test binaries, because this module is compiled into each.
/// That is the cost of `tests/common/`, and it is two duplicated test names
/// rather than two duplicated behaviours.
mod gate {
    use super::resolve;

    #[test]
    #[should_panic(expected = "YADGAR_TEST_VALKEY is unset in CI")]
    fn ci_without_a_valkey_fails_rather_than_skipping() {
        // MUTATION THIS CATCHES: making the skip notice louder, or moving it into
        // Rust, while leaving the skip itself in place on a runner. Both leave
        // seven green tests that measured nothing.
        let _ = resolve(None, Some("true".into()));
    }

    #[test]
    #[should_panic(expected = "YADGAR_TEST_VALKEY is unset in CI")]
    fn an_empty_address_in_ci_is_the_same_as_an_absent_one() {
        // `YADGAR_TEST_VALKEY: ""` in a workflow is the plausible way this
        // reaches a runner set-but-useless, and it must not read as configured.
        let _ = resolve(Some(String::new()), Some("true".into()));
    }

    #[test]
    fn a_configured_address_is_returned_in_ci_and_out_of_it() {
        assert_eq!(
            resolve(Some("127.0.0.1:16379".into()), Some("true".into())),
            Some("127.0.0.1:16379".to_string())
        );
        assert_eq!(
            resolve(Some("127.0.0.1:16379".into()), None),
            Some("127.0.0.1:16379".to_string())
        );
    }

    #[test]
    fn no_valkey_and_no_ci_is_still_a_skip() {
        assert_eq!(resolve(None, None), None);
        // "false" is what says NOT a runner, and it must not trip the assertion.
        assert_eq!(resolve(None, Some("false".into())), None);
    }
}
