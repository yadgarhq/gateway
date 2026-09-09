//! D73's bootstrap token renders at THREE sites in `deployment.yaml`, all behind
//! one variable, `$bootstrapTokenSecret` (ledger 780).
//!
//! The env var (`YADGAR_ADMIN_BOOTSTRAP_TOKEN_FILE`), the container
//! `volumeMounts` entry, and the pod `volumes` entry each render only when
//! `{{- if $bootstrapTokenSecret }}` is true, and nothing before this test
//! detected an edit that drops one of the three while leaving the other two.
//! **UNPAIRED MEANS A BOOT FAILURE ON EVERY REPLICA.** Drop the volume and keep
//! the env var: the container gets a `*_FILE` path pointing at a directory
//! nothing mounts, `main.rs`'s asymmetric contract for this knob (it is the one
//! variable NOT behind `env_required`, but once set it is a hard prerequisite —
//! see values.yaml) treats a set-but-unreadable path as `CONFIGURED AND BROKEN`
//! rather than `NOT CONFIGURED`, and the process exits at boot naming the path.
//! Drop the volumeMount and keep the volume: kubelet has nothing wrong with the
//! pod spec, so nothing here catches it structurally, but the same exit still
//! fires because the file is still unreachable inside the container. `helm
//! template` renders either mutation without complaint, because both are
//! syntactically valid Helm — only agreement between all three sites is
//! actually correct.
//!
//! This test reads the rendered template SOURCE rather than the output of
//! `helm template`, the same choice `chart_grace_period.rs` makes: this repo's
//! CI does not install `helm`, and the three sites are each one static
//! conditional block rather than a value this chart computes, so the source is
//! sufficient to prove pairing.

use std::path::PathBuf;

/// One row per site D73's bootstrap token must render at. The label is what a
/// failure names; the marker is the line this test finds inside each guarded
/// block.
const EXPECTED_SITES: [(&str, &str); 3] = [
    (
        "the env var (container env: YADGAR_ADMIN_BOOTSTRAP_TOKEN_FILE)",
        "YADGAR_ADMIN_BOOTSTRAP_TOKEN_FILE",
    ),
    (
        "the volumeMount (container volumeMounts: admin-bootstrap-token)",
        "mountPath: /var/run/secrets/admin-bootstrap",
    ),
    (
        "the volume (pod volumes: admin-bootstrap-token)",
        "secretName: {{ $bootstrapTokenSecret | quote }}",
    ),
];

const GUARD: &str = "{{- if $bootstrapTokenSecret }}";
const END: &str = "{{- end }}";

/// Line-index spans `[start, end)` of every `{{- if $bootstrapTokenSecret }}`
/// block in `deployment.yaml`, paired with the next `{{- end }}`.
///
/// The guard never nests in this file — each one closes at the first `{{- end
/// }}` that follows it — so a naive forward scan is exact rather than a
/// simplification.
fn bootstrap_guarded_spans(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == GUARD {
            let start = i;
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim() != END {
                j += 1;
            }
            assert!(
                j < lines.len(),
                "`{GUARD}` at line {} has no matching `{END}` — deployment.yaml is malformed",
                start + 1
            );
            spans.push((start, j));
            i = j + 1;
        } else {
            i += 1;
        }
    }
    spans
}

#[test]
fn admin_bootstrap_token_renders_at_three_paired_sites() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chart/templates/deployment.yaml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()));
    let lines: Vec<&str> = text.lines().collect();

    let spans = bootstrap_guarded_spans(&lines);

    // Checked BEFORE the count below, so a deleted site fails by NAME — the
    // count assertion alone would only say "found 2", not which one is gone.
    for (site_name, marker) in EXPECTED_SITES {
        let found = spans
            .iter()
            .any(|&(start, end)| lines[start..end].iter().any(|l| l.contains(marker)));
        assert!(
            found,
            "no `{GUARD}` block in {} renders {site_name} (looked for a line containing `{marker}`). \
             ledger 780: this render is unpaired — a pod configured with `adminBootstrap.tokenSecret` \
             will boot with some of the three sites present and others missing, and the binary's \
             asymmetric contract for this knob turns that mismatch into a boot failure on every \
             replica, naming the path it cannot read.",
            path.display(),
        );
    }

    assert_eq!(
        spans.len(),
        3,
        "expected exactly 3 `{GUARD}` sites in {}, found {}, though all three expected markers \
         were each found somewhere among them — a duplicate or a fourth unexpected site has \
         appeared. D73's bootstrap token renders at exactly three sites behind this one guard \
         (ledger 780): the env var, the volumeMount, and the volume. If a new, legitimately \
         guarded site was added on purpose, extend `EXPECTED_SITES` to match.",
        path.display(),
        spans.len(),
    );
}
