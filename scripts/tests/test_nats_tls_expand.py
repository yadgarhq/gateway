"""B-N3E: the EXPAND step for the gateway's NATS client TLS switch (ADR-0852,
ADR-0845, K-8 of the October ledger sweep).

WHAT AN EXPAND IS, AND WHY THIS ONE IS CHART-ONLY. Every gateway release is
pinned into the parent chart with no PR CI, and this chart's schema closes
the `nats` block (`additionalProperties: false`). So the parent cannot state
`gateway.nats.tls.enabled` until a gateway release DECLARES it, and a release
that made the key required at once would turn every parent render red the
moment it was pinned. K-8 therefore moves the key in three steps:

  1. EXPAND (this file): the schema declares `nats.tls`; the template renders
     `NATS_TLS_ENABLED` only when `enabled` is present and validates it when
     present; the binary is unchanged. An absent key renders exactly what
     `origin/main` renders.
  2. FIXTURE (yadgarhq/chart, B-P2): the parent states `enabled: false`.
  3. CONTRACT (B-N3): the binary dials TLS and requires the variable; the
     schema makes `enabled` required; the CA mount lands.

`enabled: true` IS REFUSED IN THIS STEP. The binary does not read
`NATS_TLS_ENABLED` until B-N3, and platform's NATS serves no TLS until B-L1,
so a values file that says `true` would look encrypted while the hop stays
cleartext. The refusal is a template `fail` of this chart's own design, so
it is asserted as the exact sentence. B-N3 lifts it.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import yaml

from test_render_checks import CHART, CHART_NAME, helm, objects, render

SCHEMA_WRAPPER = "values don't meet the specifications of the schema(s)"

REFUSE_TRUE = (
    "nats.tls.enabled: true is refused by this chart version: it declares the key, "
    "but the binary reads NATS_TLS_ENABLED only from B-N3 and the broker serves no TLS "
    "until B-L1. Set it to false (ADR-0845, ADR-0852)"
)

# The dial switches every render needs (ADR-0845), so only `nats.tls` is under
# test. Stated here rather than read from `chart/ci/values.yaml`, because that
# file now states `nats.tls.enabled` too and the ABSENT case must not see it.
DIALS = {u: {"tls": {"enabled": True}} for u in ("task", "iam", "project")}


def write_overlay(body: dict, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def with_nats_tls(tls) -> dict:
    body = {k: {"tls": dict(v["tls"])} for k, v in DIALS.items()}
    body["nats"] = {"tls": tls}
    return body


def bare(path: Path):
    """Rendered WITHOUT `chart/ci/values.yaml`, over this overlay only."""
    return helm("template", CHART_NAME, str(CHART), "-f", str(path))


def nats_env(stdout: str) -> dict[str, str]:
    (deployment,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    return {
        e["name"]: e.get("value")
        for e in container.get("env", [])
        if e["name"].startswith("NATS_TLS_")
    }


# ── 1. ABSENT: the render origin/main produces, with no NATS_TLS_* at all ───


def test_an_absent_nats_tls_enabled_renders_no_nats_tls_variable(tmp_path):
    result = bare(write_overlay(DIALS, tmp_path))
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {}


def test_an_empty_nats_tls_map_renders_no_nats_tls_variable(tmp_path):
    """Presence is `enabled`, never the `tls` map: B-N3 adds CA keys beside it."""
    result = bare(write_overlay(with_nats_tls({}), tmp_path))
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {}


def test_a_null_nats_tls_block_is_a_schema_refusal(tmp_path):
    """`values.yaml` declares no `nats.tls`, so a null is not coalesced away:
    it reaches the schema, which wants an object."""
    result = bare(write_overlay(with_nats_tls(None), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "/nats/tls" in combined or "nats.tls" in combined, combined


# ── 2. PRESENT AND FALSE: the literal "0" on the wire, and nothing else ─────


def test_false_renders_the_literal_zero_and_nothing_else(tmp_path):
    result = bare(write_overlay(with_nats_tls({"enabled": False}), tmp_path))
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {"NATS_TLS_ENABLED": "0"}


def test_the_ci_values_state_false(tmp_path):
    """`chart/ci/values.yaml` is the fixture every offline gate renders with."""
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {"NATS_TLS_ENABLED": "0"}


def test_false_mounts_no_nats_ca(tmp_path):
    result = bare(write_overlay(with_nats_tls({"enabled": False}), tmp_path))
    assert result.returncode == 0, result.stderr
    assert "nats-tls" not in result.stdout


# ── 3. PRESENT AND TRUE: refused until the contract ─────────────────────────


def test_true_is_refused_by_the_designed_sentence(tmp_path):
    result = bare(write_overlay(with_nats_tls({"enabled": True}), tmp_path))
    assert result.returncode != 0, result.stdout
    assert REFUSE_TRUE in result.stderr, result.stderr


# ── 4. WRONG SHAPES: schema wrapper plus the path, or the template sentence ─


def test_a_quoted_enabled_is_a_schema_refusal(tmp_path):
    result = bare(write_overlay(with_nats_tls({"enabled": "false"}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "/nats/tls" in combined or "nats.tls" in combined, combined


def test_an_unknown_key_under_nats_tls_is_a_schema_refusal(tmp_path):
    result = bare(write_overlay(with_nats_tls({"enabled": False, "verify": True}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "verify" in combined, combined


def test_a_null_enabled_is_a_schema_refusal(tmp_path):
    """Measured on helm 4.3.0 and 3.18.4: a null `enabled` survives coalescing
    (`values.yaml` declares no such key) and the schema's `type: boolean`
    refuses it before the template guard is reached."""
    result = bare(write_overlay(with_nats_tls({"enabled": None}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "/nats/tls/enabled" in combined or "nats.tls.enabled" in combined, combined


def test_a_non_map_nats_tls_is_a_schema_refusal(tmp_path):
    result = bare(write_overlay(with_nats_tls("on"), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "/nats/tls" in combined or "nats.tls" in combined, combined
