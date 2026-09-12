//! ADR-0677's ordering, asserted over the boot sequence that actually runs.
//!
//! **A UNIT TEST CANNOT SEE THIS DEFECT, AND THAT IS WHY THIS FILE IS ODD.** The
//! `metrics` facade accepts a `gauge!` call whenever no recorder is installed and
//! discards it silently — no error, no log line, no panic. Every test harness in
//! this repository installs a recorder before it exercises anything, which is the
//! one condition production did not meet: `tests/telemetry.rs` installs a
//! `DebuggingRecorder` and is green against the defect. So the thing to assert is
//! not that the `gauge!` call fires. It is the ORDER OF TWO STATEMENTS IN
//! `src/main.rs`, and the only instrument that can read that from a test is
//! `src/main.rs` itself.
//!
//! **TEXTUAL, AND STATED AS SUCH.** ADR-0677 rejected this check ALONE — it pins
//! today's statement order and proves nothing reaches a scrape. It is landed
//! anyway because the alternative it prefers (a telemetry-crate marker type
//! making recorder-installed a precondition) does not exist yet, and because the
//! constraint HAD been stated in prose at `watch_inputs.export_not_after()` —
//! seven lines below a violation of the same rule, in the same function. Prose
//! did not generalise. The proof that the series reaches a scrape is a
//! port-forward against a replica whose registry has never loaded, and it belongs
//! to whoever deploys.
//!
//! **COMMENTS ARE STRIPPED BEFORE ANYTHING IS SEARCHED.** `main`'s own comments
//! name both `install_prometheus` and `boot::wiring` — they have to, ADR-0677
//! requires the constraint stated where the boot sequence is written — so a search
//! over the raw file would match prose and red or green on an edit to a sentence.

use std::path::PathBuf;

/// The statements of `main`'s body, as `(line number, text)`, with every comment
/// line dropped.
///
/// **FROM `async fn main(` RATHER THAN THE TOP OF THE FILE.** `use
/// boot::env_required;` sits above it and contains `boot::`, so a rule of the
/// shape "the recorder precedes every `boot::`" is poisoned before `main` begins.
///
/// A missing marker PANICS rather than returning an empty body: a run that found
/// nothing to check must not be a run that passed.
fn main_statements() -> Vec<(usize, String)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));

    let opens = source
        .lines()
        .position(|line| line.starts_with("async fn main("))
        .unwrap_or_else(|| {
            panic!(
                "{} must declare `async fn main(` at the start of a line — this file reads the \
                 boot sequence from that marker and can check nothing without it",
                path.display()
            )
        });

    let statements: Vec<(usize, String)> = source
        .lines()
        .enumerate()
        .skip(opens)
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(at, line)| (at + 1, line.to_string()))
        .collect();

    assert!(
        !statements.is_empty(),
        "`main`'s body in {} is entirely comments, so this file checked nothing",
        path.display()
    );
    statements
}

/// The one line holding `needle`, or a panic naming how many there were.
///
/// Exactly one, for `tests/chart_project_validation.rs`'s reason: an assertion
/// that silently picked the first of several matches would answer about a
/// statement nobody meant.
fn sole_line(statements: &[(usize, String)], needle: &str) -> usize {
    let found: Vec<usize> = statements
        .iter()
        .filter(|(_, line)| line.contains(needle))
        .map(|(at, _)| *at)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one statement in `main` containing `{needle}`, found {}: {found:?}",
        found.len()
    );
    found[0]
}

/// **THE RECORDER IS INSTALLED BEFORE EVERY BOOT PHASE `main` CALLS.**
///
/// A RULE RATHER THAN A LIST: every `boot::` in `main`'s body is checked, so a
/// phase added later is covered without touching this file. `boot::wiring(` is
/// named separately only as a vacuity guard — it is the phase whose gauge the
/// incident was about, and a rename that made this search match nothing would
/// otherwise pass.
///
/// If this reds, something was moved above the `install_prometheus` call. Whatever
/// it publishes at boot now goes into the no-op recorder and vanishes: no error,
/// no log line, and the series simply absent from `/metrics`. Move it back.
#[test]
fn the_recorder_is_installed_before_every_boot_phase() {
    let statements = main_statements();
    let recorder = sole_line(&statements, "install_prometheus(");

    let phases: Vec<(usize, &str)> = statements
        .iter()
        .filter(|(_, line)| line.contains("boot::"))
        .map(|(at, line)| (*at, line.trim()))
        .collect();

    assert!(
        phases
            .iter()
            .any(|(_, line)| line.contains("boot::wiring(")),
        "no statement in `main` calls `boot::wiring(` any more, so this test found no phase to \
         order the recorder against. Rename the needle rather than deleting the check \
         (ADR-0677)"
    );

    for (at, line) in phases {
        assert!(
            recorder < at,
            "`src/main.rs:{at}` runs a boot phase ABOVE the metrics recorder installed at line \
             {recorder}:\n    {line}\nA `gauge!` or `counter!` reached from there is discarded \
             silently and its series never registers (ADR-0677). Install the recorder first."
        );
    }
}

/// **THE CERTIFICATE-EXPIRY GAUGE IS PUBLISHED AFTER THE RECORDER TOO.**
///
/// The third boot publisher in this binary, and the one whose comment already
/// carried ADR-0677's rule in prose before ADR-0677 existed. Pinned here so the
/// rule is asserted for it rather than only asserted about it.
#[test]
fn the_expiry_gauge_is_published_after_the_recorder() {
    let statements = main_statements();
    let recorder = sole_line(&statements, "install_prometheus(");
    let expiry = sole_line(&statements, "export_not_after()");

    assert!(
        recorder < expiry,
        "`src/main.rs:{expiry}` publishes the client leaf's expiry at line {expiry}, above the \
         recorder installed at line {recorder}. `yadgar_certificate_not_after` would be absent \
         from every scrape (ADR-0677, ADR-0516)"
    );
}
