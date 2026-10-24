"""ADR-1006 (yaadgaar #218): the edge's header-read bound is a chart value,
rendered as `LISTEN_HEADER_READ_TIMEOUT_SECS`.

The binary refuses an absent or out-of-range value (ADR-0569). The chart
carries an explicit default of 10 (ADR-0705, ADR-1006) and a schema range, so
a bad value is refused at render rather than as a crash-looping pod. The
range is the binary's `edge::HEADER_READ_TIMEOUT_RANGE`, pinned by
`tests/chart_edge_timeout.rs`.

Assertions check the schema wrapper sentence and the key name only, never the
per-leaf phrase: CI pins helm 3.18.4, whose wording differs from 3.20/4.x.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from test_adr_0845_tls_required import (
    SCHEMA_WRAPPER,
    all_enabled,
    deployment_env,
    write_overlay,
)
from test_render_checks import CHART, CHART_NAME, helm

VAR = "LISTEN_HEADER_READ_TIMEOUT_SECS"
KEY = "headerReadTimeoutSeconds"
DEFAULT = 10
MINIMUM = 1
MAXIMUM = 60


def overlay_with(value, tmp_path):
    body = all_enabled()
    body["server"] = {"limits": {KEY: value}}
    return write_overlay(body, tmp_path)


def rendered_env(path) -> dict[str, str]:
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode == 0, result.stderr
    return deployment_env(result.stdout)


def refused(path) -> str:
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert KEY in combined, combined
    return combined


def test_the_default_renders(tmp_path):
    env = rendered_env(write_overlay(all_enabled(), tmp_path))
    assert env[VAR] == str(DEFAULT), env


def test_the_edges_of_the_range_render(tmp_path):
    for value in (MINIMUM, MAXIMUM):
        env = rendered_env(overlay_with(value, tmp_path))
        assert env[VAR] == str(value), env


def test_out_of_range_is_a_schema_refusal(tmp_path):
    for value in (0, MINIMUM - 1, MAXIMUM + 1, -5):
        refused(overlay_with(value, tmp_path))


def test_a_quoted_value_is_a_schema_refusal(tmp_path):
    refused(overlay_with(str(DEFAULT), tmp_path))


def test_a_fractional_value_is_a_schema_refusal(tmp_path):
    refused(overlay_with(10.5, tmp_path))


def test_a_null_server_block_is_refused_naming_the_key(tmp_path):
    """`server: null` deletes the whole block, so the schema's `required` on
    `server.limits` has nothing to judge. The template's `required` is what
    refuses it, naming the key rather than rendering `"0"`.
    """
    body = all_enabled()
    body["server"] = None
    result = helm("template", CHART_NAME, str(CHART), "-f", str(write_overlay(body, tmp_path)))
    assert result.returncode != 0, result.stdout
    assert "server.limits.headerReadTimeoutSeconds" in result.stdout + result.stderr


def test_a_null_value_is_a_schema_refusal(tmp_path):
    """`null` deletes the chart-declared default (helm's coalescing rule), so
    this is how an overlay states absence. `required` refuses it.
    """
    refused(overlay_with(None, tmp_path))
