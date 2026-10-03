//! `$presentsIdentity` (`chart/templates/deployment.yaml:27`) must name every
//! upstream whose per-hop `<PREFIX>_TLS_CLIENT_CERT_FILE` environment block can
//! render (ledger 770, ADR-0852, B-U2).
//!
//! **THE GAP THIS CATCHES.** `$presentsIdentity` gates the ONE `client-cert`
//! volume and its mount; each upstream's `<PREFIX>_TLS_CLIENT_CERT_FILE` /
//! `<PREFIX>_TLS_CLIENT_KEY_FILE` pair is gated independently, per upstream, by
//! `{{- if $clientCert }}` nested inside `{{- if .Values.<name>.tls.enabled }}`.
//! Those two gates are supposed to agree: an upstream can present a leaf only
//! while a volume carries it. `$presentsIdentity` was defined as
//! `and $clientCert (or .Values.task.tls.enabled .Values.iam.tls.enabled)` —
//! naming `task` and `iam` but not `project`. A deployment with `project.tls`
//! on alone and a client Secret named then renders `PROJECT_TLS_CLIENT_CERT_FILE`
//! pointing at `/var/run/secrets/client-cert/client.crt` with no `client-cert`
//! volume or mount in the pod spec: `connect_project` (through
//! `yadgar_dial::connect_tls`) reads a path kubelet never created, and the hop
//! fails at the first dial rather than at render time.
//!
//! This test reads the rendered template SOURCE rather than the output of
//! `helm template`, the same choice `chart_admin_bootstrap_pairing.rs` and
//! `chart_grace_period.rs` make: this repo's CI does not install `helm`, and
//! the property here is a static relationship between two conditionals rather
//! than a value the chart computes.

use std::path::PathBuf;

/// Every upstream with a per-hop client-cert environment block in
/// `deployment.yaml`, paired with the marker that block's `_CERT_FILE` line
/// carries. `$presentsIdentity` must name each one's `tls.enabled` flag, or a
/// failure here says which upstream's env can render with nothing mounted
/// behind it.
const UPSTREAM_CLIENT_CERT_ENV: [(&str, &str); 3] = [
    (".Values.task.tls.enabled", "TASK_TLS_CLIENT_CERT_FILE"),
    (".Values.iam.tls.enabled", "IAM_TLS_CLIENT_CERT_FILE"),
    (
        ".Values.project.tls.enabled",
        "PROJECT_TLS_CLIENT_CERT_FILE",
    ),
];

#[test]
fn presents_identity_names_every_upstream_with_a_client_cert_env_block() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/templates/deployment.yaml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));

    let presents_identity_line = text
        .lines()
        .find(|line| line.trim_start().starts_with("{{- $presentsIdentity :="))
        .unwrap_or_else(|| panic!("{} must define `$presentsIdentity`", path.display()));

    for (tls_flag, env_marker) in UPSTREAM_CLIENT_CERT_ENV {
        assert!(
            text.contains(env_marker),
            "{} no longer renders `{env_marker}` — update UPSTREAM_CLIENT_CERT_ENV if that \
             upstream's client-cert env block was intentionally removed",
            path.display(),
        );
        assert!(
            presents_identity_line.contains(tls_flag),
            "`$presentsIdentity` at {} does not name `{tls_flag}`, but the chart renders \
             `{env_marker}` whenever `$clientCert` and `{tls_flag}` are both true (ledger 770, \
             ADR-0852, B-U2). A pod with that upstream's TLS on alone and a client Secret named \
             then gets the env var with no `client-cert` volume or mount behind it. Line read: \
             {presents_identity_line}",
            path.display(),
        );
    }
}
