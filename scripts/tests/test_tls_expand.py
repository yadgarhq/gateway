"""B-V3E: the EXPAND step for the gateway's valkey client TLS switch
(ADR-0852, ADR-0845, K-8 of the October ledger sweep). It shipped folded with
B-N3E (NATS); B-N3 has since CONTRACTED the NATS key, so its cases moved to
`test_nats_tls_contract.py` and this file keeps the valkey hop only.

WHAT AN EXPAND IS, AND WHY THIS ONE IS CHART-ONLY. Every gateway release is
pinned into the parent chart with no PR CI, and this chart's schema closes
every block (`additionalProperties: false`). So the parent cannot state
`gateway.nats.tls.enabled` or `gateway.valkey.tls.enabled` until a gateway
release DECLARES them, and a release that made either key required at once
would turn every parent render red the moment it was pinned. K-8 therefore
moves each key in three steps:

  1. EXPAND (this file): the schema declares `<hop>.tls`; the template renders
     `<HOP>_TLS_ENABLED` only when `enabled` is present and validates it when
     present; the binary is unchanged. An absent key renders exactly what
     `origin/main` renders.
  2. FIXTURE (yadgarhq/chart, B-P2): the parent states `enabled: false`.
  3. CONTRACT (B-N3, B-V3): the binary dials TLS and requires the variable;
     the schema makes `enabled` required; the CA mount lands.

`enabled: true` IS REFUSED IN THIS STEP. The binary reads neither variable
until the contract, and platform serves no TLS on either hop until B-L1, so
a values file that says `true` would look encrypted while the hop stays
cleartext. The refusal is a template `fail` of this chart's own design, so
it is asserted as the exact sentence. The contract lifts it.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from test_render_checks import CHART, CHART_NAME, helm, objects, render

SCHEMA_WRAPPER = "values don't meet the specifications of the schema(s)"

# hop -> (variable, the sentence that refuses `true`)
HOPS = {
    "valkey": (
        "VALKEY_TLS_ENABLED",
        "valkey.tls.enabled: true is refused by this chart version: it declares the key, "
        "but the binary reads VALKEY_TLS_ENABLED only from B-V3 and valkey serves no TLS "
        "until B-L1 and B-V2. Set it to false (ADR-0845, ADR-0852)",
    ),
}


def not_bool(hop: str) -> str:
    variable = HOPS[hop][0]
    return (
        f"{hop}.tls.enabled must be true or false when it is set; it renders "
        f"{variable} (ADR-0845, ADR-0797)"
    )


# The dial switches every render needs (ADR-0845), so only `<hop>.tls` is
# under test. Stated here rather than read from `chart/ci/values.yaml`,
# because that file states both hop switches too and the ABSENT case must not
# see them.
DIALS = {u: {"tls": {"enabled": True}} for u in ("task", "iam", "project")}
# The broker hop is REQUIRED since B-N3 (see `test_nats_tls_contract.py`), so
# every render here states it at the value the parent fixture states.
DIALS["nats"] = {"tls": {"enabled": False}}


def write_overlay(body: dict, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def with_tls(hop: str, tls) -> dict:
    body = {k: {"tls": dict(v["tls"])} for k, v in DIALS.items()}
    body[hop] = {"tls": tls}
    return body


def bare(path: Path, *arguments: str):
    """Rendered WITHOUT `chart/ci/values.yaml`, over this overlay only."""
    return helm("template", CHART_NAME, str(CHART), "-f", str(path), *arguments)


def hop_env(stdout: str) -> dict[str, str]:
    (deployment,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    variables = {v for v, _ in HOPS.values()}
    return {e["name"]: e.get("value") for e in container.get("env", []) if e["name"] in variables}


# ── 1. ABSENT: the render origin/main produces, with neither variable ───────


def test_absent_switches_render_neither_variable(tmp_path):
    result = bare(write_overlay(DIALS, tmp_path))
    assert result.returncode == 0, result.stderr
    assert hop_env(result.stdout) == {}


@pytest.mark.parametrize("hop", HOPS)
def test_an_empty_tls_map_renders_no_variable(hop, tmp_path):
    """Presence is `enabled`, never the `tls` map: the contract adds CA keys
    beside it."""
    result = bare(write_overlay(with_tls(hop, {}), tmp_path))
    assert result.returncode == 0, result.stderr
    assert hop_env(result.stdout) == {}


@pytest.mark.parametrize("hop", HOPS)
def test_a_null_tls_block_is_a_schema_refusal(hop, tmp_path):
    """`values.yaml` declares no `<hop>.tls`, so a null is not coalesced away:
    it reaches the schema, which wants an object."""
    result = bare(write_overlay(with_tls(hop, None), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{hop}/tls" in combined or f"{hop}.tls" in combined, combined


# ── 2. PRESENT AND FALSE: the literal "0" on the wire, and nothing else ─────


@pytest.mark.parametrize("hop", HOPS)
def test_false_renders_the_literal_zero_and_nothing_else(hop, tmp_path):
    result = bare(write_overlay(with_tls(hop, {"enabled": False}), tmp_path))
    assert result.returncode == 0, result.stderr
    assert hop_env(result.stdout) == {HOPS[hop][0]: "0"}


def test_the_ci_values_state_valkey_false():
    """`chart/ci/values.yaml` is the fixture every offline gate renders with."""
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert hop_env(result.stdout) == {"VALKEY_TLS_ENABLED": "0"}


# ── 3. PRESENT AND TRUE: refused until the contract ─────────────────────────


@pytest.mark.parametrize("hop", HOPS)
def test_true_is_refused_by_the_designed_sentence(hop, tmp_path):
    result = bare(write_overlay(with_tls(hop, {"enabled": True}), tmp_path))
    assert result.returncode != 0, result.stdout
    assert HOPS[hop][1] in result.stderr, result.stderr


# ── 4. WRONG SHAPES: schema wrapper plus the path ───────────────────────────


@pytest.mark.parametrize("hop", HOPS)
def test_a_quoted_enabled_is_a_schema_refusal(hop, tmp_path):
    result = bare(write_overlay(with_tls(hop, {"enabled": "false"}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{hop}/tls" in combined or f"{hop}.tls" in combined, combined


@pytest.mark.parametrize("hop", HOPS)
def test_an_unknown_key_under_tls_is_a_schema_refusal(hop, tmp_path):
    result = bare(write_overlay(with_tls(hop, {"enabled": False, "verify": True}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "verify" in combined, combined


@pytest.mark.parametrize("hop", HOPS)
def test_a_null_enabled_is_a_schema_refusal(hop, tmp_path):
    """Measured on helm 4.3.0 and 3.18.4: a null `enabled` survives coalescing
    (`values.yaml` declares no such key) and the schema's `type: boolean`
    refuses it before the template guard is reached."""
    result = bare(write_overlay(with_tls(hop, {"enabled": None}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{hop}/tls/enabled" in combined or f"{hop}.tls.enabled" in combined, combined


@pytest.mark.parametrize("hop", HOPS)
def test_a_non_map_tls_is_a_schema_refusal(hop, tmp_path):
    result = bare(write_overlay(with_tls(hop, "on"), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{hop}/tls" in combined or f"{hop}.tls" in combined, combined


# ── 5. THE TEMPLATE GUARD, with the schema out of the way ───────────────────


@pytest.mark.parametrize("hop", HOPS)
def test_a_null_enabled_past_the_schema_is_the_template_sentence(hop, tmp_path):
    """`--skip-schema-validation` is how a render reaches the template with a
    null `enabled` (hasKey true, not a bool). The guard must refuse it with its
    own sentence; without it the `ternary` below fails with Go's type error,
    which names no key."""
    result = bare(
        write_overlay(with_tls(hop, {"enabled": None}), tmp_path), "--skip-schema-validation"
    )
    assert result.returncode != 0, result.stdout
    assert not_bool(hop) in result.stderr, result.stderr
