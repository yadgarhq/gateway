//! What an operator reads when the boot refuses (ledger 1258).
//!
//! `main` used to return `Result<(), Box<dyn Error>>`, and Rust prints a `main`
//! that returns `Err` with DEBUG. Every refusal in `src/boot/` was already
//! converted to its sentence, so it did not arrive as a variant name — it
//! arrived as a quoted, escaped string: `Error: "TASK_TLS_ENABLED is set but
//! …"`, every inner quote a `\"`. `main` now calls `run()` and prints
//! `Error: {e}` with Display. The unit tests under `src/` prove the sentences
//! exist; only running the BINARY proves they reach the operator as written.
//!
//! **The exit code is not what these tests discriminate.** An `Err` from
//! `main` exits 1 and so does `ExitCode::FAILURE`, so reverting to
//! `-> Result` turns the Display assertion red and leaves the exit code alone.

mod support;

use std::process::Command;

use support::{cleartext_env, run_to_exit, BIN};

/// The `Error: ` line from a refused boot, held to plain Display.
fn refusal_line(status: std::process::ExitStatus, stderr: &str) -> String {
    assert!(
        !status.success(),
        "a refused boot must exit non-zero: {status:?}"
    );
    let line = stderr
        .lines()
        .rfind(|l| l.starts_with("Error: "))
        .unwrap_or_else(|| panic!("no `Error: ` line on stderr: {stderr}"))
        .to_string();
    assert!(
        !line.starts_with("Error: \"") && !line.contains("\\\""),
        "the refusal was printed as a Debug string: {line}"
    );
    line
}

/// Run the binary directly, for a refusal that comes before either mounted
/// document is read and so needs no mount namespace.
fn refusal_without_mounts(vars: &[(&str, &str)]) -> String {
    let out = Command::new(BIN)
        .env_clear()
        .envs(vars.iter().copied())
        .output()
        .expect("the test rig could not start the binary");
    refusal_line(out.status, &String::from_utf8_lossy(&out.stderr))
}

/// A TYPED error: `upstream::TlsConfigError::NoCaFile`, reached at the first
/// line of `boot::wiring` — `transports()` — before either mounted document is
/// read. Debug of the error would print `NoCaFile("TASK")`; Debug of its
/// sentence printed the sentence in quotes. Display prints the sentence.
#[test]
fn a_typed_refusal_is_printed_as_its_sentence() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "TASK_TLS_ENABLED");
    vars.push(("TASK_TLS_ENABLED", "1"));
    let line = refusal_without_mounts(&vars);
    assert!(
        line.contains("TASK_TLS_ENABLED is set but TASK_TLS_CA_FILE names no CA bundle"),
        "the refusal must name both variables: {line}"
    );
}

/// ADR-0845: `TASK_TLS_ENABLED` has no compiled-in default, so leaving it
/// out of the environment entirely refuses the boot naming both the
/// variable and the chart key that sources it, rather than falling back to
/// cleartext.
#[test]
fn an_absent_tls_enabled_refuses_boot_naming_the_chart_key() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "TASK_TLS_ENABLED");
    let line = refusal_without_mounts(&vars);
    assert!(
        line.contains("TASK_TLS_ENABLED") && line.contains("task.tls.enabled"),
        "the refusal must name both the variable and its chart key: {line}"
    );
}

/// ADR-0569: `YADGAR_CREDENTIAL_TTL_SECONDS` has no compiled-in default
/// either, so an absent value refuses the boot naming it and the chart key
/// that sources it, rather than quietly reusing a compiled-in 30 seconds.
#[test]
fn an_absent_credential_ttl_refuses_boot_naming_the_chart_key() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "YADGAR_CREDENTIAL_TTL_SECONDS");
    let line = refusal_without_mounts(&vars);
    assert!(
        line.contains("YADGAR_CREDENTIAL_TTL_SECONDS")
            && line.contains("credentialCache.ttlSeconds"),
        "the refusal must name both the variable and its chart key: {line}"
    );
}

/// `METRICS_LISTEN` is parsed FIRST of all — PHASE 0 in `run`, ahead of
/// `install_prometheus` (ADR-0677) and ahead of either mounted document — so
/// this case needs no mount namespace, like the typed refusal above.
#[test]
fn an_unparsable_metrics_listen_names_the_variable() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "METRICS_LISTEN");
    vars.push(("METRICS_LISTEN", "notanaddr"));
    let line = refusal_without_mounts(&vars);
    assert!(
        line.contains("METRICS_LISTEN is not a host:port address"),
        "the refusal must name the variable: {line}"
    );
}

/// A bare parse, named on the way out: `TASK_PORT` is read inside
/// `boot::wiring`'s `upstreams()`, after both mounted documents, so this case
/// needs the mount namespace to get that far.
#[test]
fn an_unparsable_task_port_names_the_variable() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "TASK_PORT");
    vars.push(("TASK_PORT", "abc"));
    let (status, stderr) = run_to_exit(&vars);
    let line = refusal_line(status, &stderr);
    assert!(
        line.contains("TASK_PORT is not a port number"),
        "the refusal must name the variable: {line}"
    );
    assert!(
        !line.contains("ParseIntError"),
        "the operator got the Debug of the parse error: {line}"
    );
}

/// `IAM_PORT` and `PROJECT_PORT` are `TASK_PORT`'s two siblings in the same
/// `upstreams()`, parsed second and third — so each also needs the mount
/// namespace, and each needs the OTHER two ports left valid to be sure it is
/// THIS variable the refusal names.
#[test]
fn an_unparsable_iam_or_project_port_names_the_variable() {
    let mut iam_vars = cleartext_env();
    iam_vars.retain(|(k, _)| *k != "IAM_PORT");
    iam_vars.push(("IAM_PORT", "abc"));
    let (status, stderr) = run_to_exit(&iam_vars);
    let line = refusal_line(status, &stderr);
    assert!(
        line.contains("IAM_PORT is not a port number"),
        "the refusal must name the variable: {line}"
    );

    let mut project_vars = cleartext_env();
    project_vars.retain(|(k, _)| *k != "PROJECT_PORT");
    project_vars.push(("PROJECT_PORT", "abc"));
    let (status, stderr) = run_to_exit(&project_vars);
    let line = refusal_line(status, &stderr);
    assert!(
        line.contains("PROJECT_PORT is not a port number"),
        "the refusal must name the variable: {line}"
    );
}

/// `LISTEN` is parsed last, inside `boot::serve`, after the two dials and the
/// project registry's own knobs resolve — so this also needs the mount
/// namespace.
#[test]
fn an_unparsable_listen_names_the_variable() {
    let mut vars = cleartext_env();
    vars.retain(|(k, _)| *k != "LISTEN");
    vars.push(("LISTEN", "notanaddr"));
    let (status, stderr) = run_to_exit(&vars);
    let line = refusal_line(status, &stderr);
    assert!(
        line.contains("LISTEN is not a host:port address"),
        "the refusal must name the variable: {line}"
    );
    assert!(
        !line.contains("AddrParseError"),
        "the operator got the Debug of the parse error: {line}"
    );
}

/// `TcpListener::bind` is the one call in `boot::serve` that was still a bare
/// `?` after the Display cut-over: `io::Error`'s Display is informative about
/// WHY ("Address already in use (os error 98)") but, unlike every other
/// refusal in this binary, named neither the variable nor the address it
/// tried. Held open for the whole run, so the conflict cannot race a port
/// release.
#[test]
fn a_bind_conflict_names_the_listen_address() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port to hold open");
    let addr = held.local_addr().expect("a local address").to_string();

    let mut vars: Vec<(&str, &str)> = cleartext_env();
    vars.retain(|(k, _)| *k != "LISTEN");
    vars.push(("LISTEN", addr.as_str()));
    let (status, stderr) = run_to_exit(&vars);
    let line = refusal_line(status, &stderr);
    assert!(
        line.contains(&format!("LISTEN={addr} could not be bound")),
        "the refusal must name both the variable and the address it tried: {line}"
    );

    drop(held);
}
