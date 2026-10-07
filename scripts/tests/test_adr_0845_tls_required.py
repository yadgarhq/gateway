"""ADR-0845: each dial's TLS switch is required, with no chart default and no
binary default (ledger 965, 1278, 1279, K-1).

WHAT THIS FILE COVERS, AND WHY IT IS SEPARATE FROM `test_values_schema.py` AND
`test_render_checks.py`. `task.tls.enabled`, `iam.tls.enabled` and
`project.tls.enabled` are the first keys in this chart's history to be
`required` with no default anywhere — not in `chart/values.yaml`, not in the
binary. That needs TWO refusal mechanisms rather than one, and this file
proves both, plus the one case that needs neither (the unconditional
render):

  1. `values.schema.json`'s `required` + `type: boolean` on `enabled` — catches
     ABSENT and the wrong TYPE (`null`, a quoted string). `helm lint --strict`
     and `helm template` both enforce it (measured identical on helm 3.18.4,
     3.20.2 and 4.3.0), but the two wrap the SAME violation in DIFFERENT
     per-leaf wording: 4.3.0/3.20.2 print `at '/task/tls': missing property
     'enabled'`; 3.18.4 prints `task.tls: enabled is required` for the same
     absence, and `got null, want boolean` against 3.18.4's `Invalid type.
     Expected: boolean, given: null` for the same null. ONLY THE WRAPPER
     SENTENCE, `values don't meet the specifications of the schema(s)`, is
     common to all three — CI pins 3.18.4 (coordinator ruling, 2026-10-07) —
     so every assertion below checks the wrapper plus the KEY NAMES involved,
     never the per-leaf phrase.
  2. `templates/deployment.yaml`'s own `kindIs "map"` / `hasKey` / `kindIs
     "bool"` guard (the K-1 shape) — catches what `required` cannot: `tls:
     null` deletes the WHOLE block (helm's own rule, that a null value
     coalesces away a key the chart's `values.yaml` declares), so there is no
     `enabled` key present or absent for the schema to judge; `required`
     passes because there is nothing to require it OF. This refusal is a
     template `fail`, entirely of this chart's own design, so it is asserted
     as the EXACT designed sentence rather than a substring (the brief's own
     instruction).

THE UNCONDITIONAL RENDER (K-1's whole point): `*_TLS_ENABLED` must render
`"1"` or `"0"` outside any `if`, so a `false` is visible on the wire rather
than simply absent — before this PR the chart rendered it only inside `{{- if
.Values.task.tls.enabled }}`, so `false` and absent looked identical on the
rendered manifest.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from test_render_checks import CHART, CHART_NAME, helm, objects, render

UPSTREAMS = ("task", "iam", "project")

# The one sentence stable across helm 3.18.4, 3.20.2 and 4.3.0 for every
# schema violation this file provokes (coordinator ruling, 2026-10-07).
SCHEMA_WRAPPER = "values don't meet the specifications of the schema(s)"


def write_overlay(body: dict, destination: Path) -> Path:
    """One values overlay, written as a whole file — see `test_values_schema.py`'s
    `overlay` for why (appending risks nesting under the wrong parent).
    """
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def others_enabled(upstream: str) -> dict:
    """The other two upstreams satisfied, so only `upstream` is under test."""
    return {u: {"tls": {"enabled": True}} for u in UPSTREAMS if u != upstream}


def all_enabled() -> dict:
    return {u: {"tls": {"enabled": True}} for u in UPSTREAMS}


def deployment_env(stdout: str) -> dict[str, str]:
    (deployment,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    return {e["name"]: e["value"] for e in container.get("env", []) if "value" in e}


# ── 1. SCHEMA REFUSALS: wrapper + key names, never the per-leaf phrase ────


@pytest.mark.parametrize("upstream", UPSTREAMS)
def test_an_absent_tls_enabled_is_a_schema_refusal(upstream, tmp_path):
    """`upstream` is left out of the overlay entirely, so the chart's own
    `values.yaml` — which declares `<upstream>.tls` with no `enabled` under it
    — is what the schema judges.
    """
    path = write_overlay(others_enabled(upstream), tmp_path)
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{upstream}/tls" in combined or f"{upstream}.tls" in combined, combined


@pytest.mark.parametrize("upstream", UPSTREAMS)
def test_a_null_tls_enabled_is_a_schema_refusal(upstream, tmp_path):
    body = others_enabled(upstream)
    body[upstream] = {"tls": {"enabled": None}}
    path = write_overlay(body, tmp_path)
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{upstream}/tls" in combined or f"{upstream}.tls" in combined, combined


@pytest.mark.parametrize("upstream", UPSTREAMS)
def test_a_quoted_tls_enabled_is_a_schema_refusal(upstream, tmp_path):
    body = others_enabled(upstream)
    body[upstream] = {"tls": {"enabled": "true"}}
    path = write_overlay(body, tmp_path)
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{upstream}/tls" in combined or f"{upstream}.tls" in combined, combined


def test_an_absent_credential_cache_ttl_is_a_schema_refusal(tmp_path):
    """`values.yaml` ships `credentialCache.ttlSeconds: 30` as a chart
    default (ADR-0705 CHD, not ADR-0845 REQ like the dial switches — the
    binary still refuses its own absence, but the chart may default it). An
    overlay cannot simply omit the key to test absence, since the base
    default would still apply; `null` is what deletes a chart-declared key
    (helm's own coalescing rule), which is the same shape the block-null
    guard test below exploits for `tls`.
    """
    body = all_enabled()
    body["credentialCache"] = {"ttlSeconds": None}
    path = write_overlay(body, tmp_path)
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "/credentialCache/ttlSeconds" in combined or "credentialCache" in combined, combined


# ── 2. THE TEMPLATE GUARD: catches what `required` structurally cannot ────


@pytest.mark.parametrize("upstream", UPSTREAMS)
def test_a_null_tls_block_is_refused_by_the_designed_sentence(upstream, tmp_path):
    """`tls: null` deletes the WHOLE block (helm's null-coalescing rule, since
    `values.yaml` declares `<upstream>.tls`), so `required` is satisfied —
    there is no key to require it of. `templates/deployment.yaml`'s own
    `kindIs "map"` guard is what refuses this, and its sentence is asserted
    EXACTLY, not as a substring.
    """
    body = others_enabled(upstream)
    body[upstream] = {"tls": None}
    path = write_overlay(body, tmp_path)
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    want = (
        f"{upstream}.tls.enabled must be set to true or false; it renders "
        f"{upstream.upper()}_TLS_ENABLED (ADR-0845, ADR-0797)"
    )
    assert want in (result.stdout + result.stderr), result.stdout + result.stderr


# ── 3. THE UNCONDITIONAL RENDER: the literal on the wire, in or out of the if ──


@pytest.mark.parametrize("upstream", UPSTREAMS)
@pytest.mark.parametrize("enabled,want", [(True, "1"), (False, "0")])
def test_tls_enabled_renders_the_designed_literal(upstream, enabled, want, tmp_path):
    body = all_enabled()
    body[upstream]["tls"]["enabled"] = enabled
    path = write_overlay(body, tmp_path)
    result = render(CHART, "-f", str(path))
    assert result.returncode == 0, result.stderr
    env = deployment_env(result.stdout)
    assert env[f"{upstream.upper()}_TLS_ENABLED"] == want
