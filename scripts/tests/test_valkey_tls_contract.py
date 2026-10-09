"""B-V3: the CONTRACT step for the gateway's valkey client TLS switch
(ADR-0852, ADR-0845, K-8 of the October ledger sweep).

The expand (B-V3E, folded with B-N3E) declared `valkey.tls.enabled` optional
and refused `true`; B-N3 contracted the broker hop and moved its own cases to
`test_nats_tls_contract.py`, leaving this file as `test_tls_expand.py`'s last
tenant. This step retires that file (no hop is left in the EXPAND state) and:

  - makes `enabled` REQUIRED with no chart default — the schema's `required`
    plus the template's map / `hasKey` / `kindIs "bool"` guard, the same pair
    every other dial carries (`test_adr_0845_tls_required.py`,
    `test_nats_tls_contract.py`);
  - renders `VALKEY_TLS_ENABLED` unconditionally, so `false` is the literal
    "0" and NOTHING ELSE — the acceptance line: a parent that states `false`
    renders exactly what it rendered against the expand. Unlike
    `NATS_TLS_ENABLED`, this is never conditional on anything: `NATS_URL` may
    be unset, but `YADGAR_VALKEY_ADDR` is always required, so the cache hop's
    switch is unconditionally required too;
  - lifts the `true` refusal: `true` renders the CA path, an item-only mount
    of `ca.crt` from `valkey.tls.caSecret` (`valkey-tls`), and the client pair
    from the ONE `client-cert` mount (`test_client_cert_pairing.py` covers
    that the pair always has a mount behind it, valkey included).

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from test_render_checks import CHART, CHART_NAME, helm, objects

SCHEMA_WRAPPER = "values don't meet the specifications of the schema(s)"
REQUIRED_SENTENCE = (
    "valkey.tls.enabled must be set to true or false; it renders VALKEY_TLS_ENABLED "
    "(ADR-0845, ADR-0797)"
)
CA_PATH = "/var/run/config/valkey-ca/ca.pem"
SECRET = "gateway-client-tls"

# The dials every render needs (ADR-0845), cleartext, so the cache hop is the
# ONLY place a client identity could be presented.
DIALS = {u: {"tls": {"enabled": False}} for u in ("task", "iam", "project", "nats")}
VALKEY_VARIABLES = (
    "VALKEY_TLS_ENABLED",
    "VALKEY_TLS_CA_FILE",
    "VALKEY_TLS_CLIENT_CERT_FILE",
    "VALKEY_TLS_CLIENT_KEY_FILE",
)


def write_overlay(body: dict, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def overlay(valkey_tls, identity: bool = True) -> dict:
    body: dict = {k: {"tls": dict(v["tls"])} for k, v in DIALS.items()}
    body["valkey"] = {"tls": valkey_tls}
    if identity:
        body["clientCertificate"] = {"secret": SECRET}
    return body


def bare(path: Path, *arguments: str):
    """Rendered WITHOUT `chart/ci/values.yaml`, over this overlay only."""
    return helm("template", CHART_NAME, str(CHART), "-f", str(path), *arguments)


def pod_spec(stdout: str) -> dict:
    (deployment,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    return deployment["spec"]["template"]["spec"]


def valkey_env(spec: dict) -> dict[str, str]:
    (container,) = spec["containers"]
    return {
        e["name"]: e.get("value")
        for e in container.get("env", [])
        if e["name"] in VALKEY_VARIABLES
    }


def volume(spec: dict, name: str) -> dict | None:
    return next((v for v in spec.get("volumes", []) if v["name"] == name), None)


def mount(spec: dict, name: str) -> dict | None:
    (container,) = spec["containers"]
    return next((m for m in container.get("volumeMounts", []) if m["name"] == name), None)


def rendered(tmp_path: Path, valkey_tls, identity: bool = True) -> dict:
    result = bare(write_overlay(overlay(valkey_tls, identity), tmp_path))
    assert result.returncode == 0, result.stderr
    return pod_spec(result.stdout)


# ── 1. REQUIRED: absence refuses, by the schema and by the template ─────────


def test_an_absent_switch_is_a_schema_refusal(tmp_path):
    result = bare(write_overlay(overlay({}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "enabled" in combined, combined


def test_a_null_tls_block_is_the_template_sentence(tmp_path):
    """`values.yaml` declares `valkey.tls`, so a null coalesces it AWAY: there
    is no `enabled` for the schema's `required` to judge, and only the
    template's own guard is left to refuse."""
    result = bare(write_overlay(overlay(None), tmp_path))
    assert result.returncode != 0, result.stdout
    assert REQUIRED_SENTENCE in result.stderr, result.stderr


def test_a_null_enabled_past_the_schema_is_the_template_sentence(tmp_path):
    result = bare(
        write_overlay(overlay({"enabled": None}), tmp_path), "--skip-schema-validation"
    )
    assert result.returncode != 0, result.stdout
    assert REQUIRED_SENTENCE in result.stderr, result.stderr


@pytest.mark.parametrize("bad", ["true", "false", 1])
def test_a_non_boolean_switch_is_a_schema_refusal(bad, tmp_path):
    result = bare(write_overlay(overlay({"enabled": bad}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined


def test_an_unknown_key_under_tls_is_a_schema_refusal(tmp_path):
    result = bare(write_overlay(overlay({"enabled": False, "verify": True}), tmp_path))
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert "verify" in combined, combined


# ── 2. FALSE: the literal "0", and nothing else ─────────────────────────────


def test_false_renders_the_literal_zero_and_nothing_else(tmp_path):
    spec = rendered(tmp_path, {"enabled": False})
    assert valkey_env(spec) == {"VALKEY_TLS_ENABLED": "0"}
    assert volume(spec, "valkey-ca") is None
    assert mount(spec, "valkey-ca") is None
    # Every other hop is cleartext too, so no private key is mounted for
    # nothing.
    assert volume(spec, "client-cert") is None


# ── 3. TRUE: the CA, the identity, and the mounts behind both ───────────────


def test_true_renders_the_ca_and_the_identity(tmp_path):
    spec = rendered(tmp_path, {"enabled": True})
    assert valkey_env(spec) == {
        "VALKEY_TLS_ENABLED": "1",
        "VALKEY_TLS_CA_FILE": CA_PATH,
        "VALKEY_TLS_CLIENT_CERT_FILE": "/var/run/secrets/client-cert/client.crt",
        "VALKEY_TLS_CLIENT_KEY_FILE": "/var/run/secrets/client-cert/client.key",
    }


def test_the_ca_is_one_key_of_valkey_tls_mounted_where_the_variable_points(tmp_path):
    spec = rendered(tmp_path, {"enabled": True})
    ca = volume(spec, "valkey-ca")
    assert ca is not None
    # ONE KEY, never the whole Secret: `valkey-tls` also holds the cache's
    # private key.
    assert ca["secret"] == {
        "secretName": "valkey-tls",
        "optional": True,
        "items": [{"key": "ca.crt", "path": "ca.pem"}],
    }
    ca_mount = mount(spec, "valkey-ca")
    assert ca_mount is not None
    assert ca_mount["readOnly"] is True
    assert "subPath" not in ca_mount
    assert f"{ca_mount['mountPath']}/ca.pem" == CA_PATH


def test_the_cache_hop_alone_mounts_the_client_identity(tmp_path):
    """THE B-V4.2 SHAPE: valkey over TLS while every other hop is cleartext.
    The client pair must have the `client-cert` volume behind it, or the pod
    exits at boot naming a path nothing mounted."""
    spec = rendered(tmp_path, {"enabled": True})
    cert = volume(spec, "client-cert")
    assert cert is not None
    assert cert["secret"]["secretName"] == SECRET
    assert mount(spec, "client-cert")["mountPath"] == "/var/run/secrets/client-cert"


def test_true_with_no_client_secret_presents_no_identity(tmp_path):
    spec = rendered(tmp_path, {"enabled": True}, identity=False)
    assert valkey_env(spec) == {"VALKEY_TLS_ENABLED": "1", "VALKEY_TLS_CA_FILE": CA_PATH}
    assert volume(spec, "client-cert") is None


def test_true_with_no_ca_secret_is_refused_naming_the_key(tmp_path):
    result = bare(write_overlay(overlay({"enabled": True, "caSecret": ""}), tmp_path))
    assert result.returncode != 0, result.stdout
    assert "valkey.tls.caSecret" in result.stderr, result.stderr
