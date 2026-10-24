"""Max's ruling (b), 2026-10-24: `adminBootstrap.refusePreMintedUserId` is the
fail-closed switch on the pre-minted `create-user` arm, rendered as
`YADGAR_ADMIN_REFUSE_PRE_MINTED_USER_ID`.

The binary refuses an absent value or anything but "1" or "0" (ADR-0569). The
chart ships `false`, which renders "0" and keeps the arm open. The schema
types the key boolean and requires it; the template's K-1 guard refuses
`adminBootstrap: null`, which helm coalesces away before the schema can see a
missing key.

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

VAR = "YADGAR_ADMIN_REFUSE_PRE_MINTED_USER_ID"
KEY = "refusePreMintedUserId"
GUARD = (
    "adminBootstrap.refusePreMintedUserId must be set to true or false; it renders "
    "YADGAR_ADMIN_REFUSE_PRE_MINTED_USER_ID"
)


def render(body, tmp_path):
    return helm("template", CHART_NAME, str(CHART), "-f", str(write_overlay(body, tmp_path)))


def with_switch(value) -> dict:
    body = all_enabled()
    body["adminBootstrap"] = {KEY: value}
    return body


def test_the_default_renders_disengaged(tmp_path):
    result = render(all_enabled(), tmp_path)
    assert result.returncode == 0, result.stderr
    assert deployment_env(result.stdout)[VAR] == "0"


@pytest.mark.parametrize(("value", "rendered"), [(False, "0"), (True, "1")])
def test_both_states_render(tmp_path, value, rendered):
    result = render(with_switch(value), tmp_path)
    assert result.returncode == 0, result.stderr
    assert deployment_env(result.stdout)[VAR] == rendered


@pytest.mark.parametrize("value", ["true", "false", 1, 0, "yes", None])
def test_a_non_boolean_is_a_schema_refusal(tmp_path, value):
    result = render(with_switch(value), tmp_path)
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert KEY in combined, combined


def test_a_null_block_is_refused_naming_the_key(tmp_path):
    body = all_enabled()
    body["adminBootstrap"] = None
    result = render(body, tmp_path)
    assert result.returncode != 0, result.stdout
    assert GUARD in result.stdout + result.stderr
