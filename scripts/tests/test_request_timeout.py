"""ADR-0925 Q-C1 (ledger 1490, 1284): each upstream's per-request bound is a
chart value, rendered as `<UPSTREAM>_REQUEST_TIMEOUT_SECONDS`.

The binary refuses an absent or out-of-range value (ADR-0569). The chart
carries an explicit default (ADR-0705) and a schema range, so a bad value is
refused at render rather than as a crash-looping pod.

`task` is capped at 18, not at `yadgar_dial`'s 59: the 1284 ordering keeps the
client's 30 s above the gateway's own waits (task dial bound + AUTH_DEADLINE
10 s + 2 s margin). `iam` and `project` use the crate's whole range, because
every call on those channels is already bounded by a shorter
`tokio::time::timeout`. See `chart/values.yaml`.

Assertions check the schema wrapper sentence and the key name only, never the
per-leaf phrase: CI pins helm 3.18.4, whose wording differs from 3.20/4.x.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import pytest

from test_adr_0845_tls_required import (
    SCHEMA_WRAPPER,
    all_enabled,
    deployment_env,
    write_overlay,
)
from test_render_checks import CHART, CHART_NAME, helm

# (upstream, chart default, schema maximum)
UPSTREAMS = (("task", 15, 18), ("iam", 30, 59), ("project", 30, 59))

# `yadgar_dial::min_request_timeout()`; `tests/chart_request_timeout.rs` pins
# the schema to the crate's own value.
MINIMUM = 14


def overlay_with(upstream: str, value, tmp_path):
    body = all_enabled()
    body[upstream]["requestTimeoutSeconds"] = value
    return write_overlay(body, tmp_path)


def refused(path) -> str:
    result = helm("template", CHART_NAME, str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    return combined


def test_the_defaults_render_next_to_each_host(tmp_path):
    result = helm("template", CHART_NAME, str(CHART), "-f", str(write_overlay(all_enabled(), tmp_path)))
    assert result.returncode == 0, result.stderr
    env = deployment_env(result.stdout)
    for upstream, default, _ in UPSTREAMS:
        assert env[f"{upstream.upper()}_REQUEST_TIMEOUT_SECONDS"] == str(default), env


@pytest.mark.parametrize("upstream,default,maximum", UPSTREAMS)
def test_the_edges_of_the_range_render(upstream, default, maximum, tmp_path):
    for value in (MINIMUM, maximum):
        result = helm("template", CHART_NAME, str(CHART), "-f", str(overlay_with(upstream, value, tmp_path)))
        assert result.returncode == 0, result.stderr
        env = deployment_env(result.stdout)
        assert env[f"{upstream.upper()}_REQUEST_TIMEOUT_SECONDS"] == str(value), env


@pytest.mark.parametrize("upstream,default,maximum", UPSTREAMS)
def test_out_of_range_is_a_schema_refusal(upstream, default, maximum, tmp_path):
    for value in (0, MINIMUM - 1, maximum + 1):
        combined = refused(overlay_with(upstream, value, tmp_path))
        assert "requestTimeoutSeconds" in combined, combined


@pytest.mark.parametrize("upstream,default,maximum", UPSTREAMS)
def test_a_quoted_value_is_a_schema_refusal(upstream, default, maximum, tmp_path):
    combined = refused(overlay_with(upstream, str(default), tmp_path))
    assert "requestTimeoutSeconds" in combined, combined


@pytest.mark.parametrize("upstream,default,maximum", UPSTREAMS)
def test_a_null_value_is_a_schema_refusal(upstream, default, maximum, tmp_path):
    """`null` deletes the chart-declared default (helm's coalescing rule), so
    this is how an overlay states absence. `required` refuses it.
    """
    combined = refused(overlay_with(upstream, None, tmp_path))
    assert "requestTimeoutSeconds" in combined, combined
