"""`sourceAddress.trustedProxyHops` renders `YADGAR_TRUSTED_PROXY_HOPS`, and a
null value must reach the binary as the EMPTY instruction, never as the string
"null" (yaadgaar 280).

An empty value is the documented closed posture (ADR-0491, D80): the gateway
records no source address and bounds the credential endpoints per observed hop.
A YAML `null` in an overlay makes helm DELETE the key during coalescing, so the
template's `quote` sees nil and renders a bare `value:`. Kubernetes stores that
as an EnvVar with no value, which the container receives as the empty string —
`TrustBoundary::Undeclared`. The string "null" would instead be refused at boot
as not a number (`src/source/tests.rs` pins that half).

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from test_adr_0845_tls_required import all_enabled, write_overlay
from test_render_checks import CHART, CHART_NAME, helm, objects

VAR = "YADGAR_TRUSTED_PROXY_HOPS"


def rendered_entry(body, tmp_path) -> dict:
    result = helm("template", CHART_NAME, str(CHART), "-f", str(write_overlay(body, tmp_path)))
    assert result.returncode == 0, result.stderr
    (deployment,) = [o for o in objects(result.stdout) if o["kind"] == "Deployment"]
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    (entry,) = [e for e in container.get("env", []) if e["name"] == VAR]
    return entry


def test_the_default_renders_the_empty_instruction(tmp_path):
    assert rendered_entry(all_enabled(), tmp_path).get("value") == ""


def test_a_null_value_renders_empty_never_the_string_null(tmp_path):
    body = all_enabled()
    body["sourceAddress"] = {"trustedProxyHops": None}
    entry = rendered_entry(body, tmp_path)
    # ALWAYS RENDERED, per the template's own comment, so the entry exists.
    # Its value is absent or empty — both reach the container as "".
    assert entry.get("value") in (None, ""), entry


def test_a_declared_count_renders_as_a_string(tmp_path):
    body = all_enabled()
    body["sourceAddress"] = {"trustedProxyHops": 1}
    assert rendered_entry(body, tmp_path).get("value") == "1"
