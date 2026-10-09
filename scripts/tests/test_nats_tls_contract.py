"""B-N3: the CONTRACT step for the gateway's NATS client TLS switch (ADR-0852,
ADR-0845, K-8 of the October ledger sweep).

The expand (B-N3E) declared `nats.tls.enabled` optional and refused `true`. The
parent fixture (yadgarhq/chart B-P2) now states `false`. This step:

  - makes `enabled` REQUIRED with no chart default — the schema's `required`
    plus the template's map / `hasKey` / `kindIs "bool"` guard, the same pair
    the three dials carry (`test_adr_0845_tls_required.py`);
  - renders `NATS_TLS_ENABLED` unconditionally, so `false` is the literal "0"
    and NOTHING ELSE — the acceptance line: a parent that states `false`
    renders exactly what it rendered against the expand;
  - lifts the `true` refusal: `true` renders the CA path, an item-only mount of
    `ca.crt` from `nats.tls.caSecret` (`nats-tls`), and the client pair from
    the ONE `client-cert` mount (`test_client_cert_pairing.py` covers that the
    pair always has a mount behind it, nats included).

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from test_render_checks import CHART, CHART_NAME, helm, objects

SCHEMA_WRAPPER = "values don't meet the specifications of the schema(s)"
REQUIRED_SENTENCE = (
    "nats.tls.enabled must be set to true or false; it renders NATS_TLS_ENABLED "
    "(ADR-0845, ADR-0797)"
)
CA_PATH = "/var/run/config/nats-ca/ca.pem"
SECRET = "gateway-client-tls"

# The dials every render needs (ADR-0845), cleartext, so the broker hop is the
# ONLY place a client identity could be presented.
DIALS = {u: {"tls": {"enabled": False}} for u in ("task", "iam", "project")}
NATS_VARIABLES = (
    "NATS_TLS_ENABLED",
    "NATS_TLS_CA_FILE",
    "NATS_TLS_CLIENT_CERT_FILE",
    "NATS_TLS_CLIENT_KEY_FILE",
)


def write_overlay(body: dict, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def overlay(nats_tls, identity: bool = True) -> dict:
    body: dict = {k: {"tls": dict(v["tls"])} for k, v in DIALS.items()}
    body["nats"] = {"tls": nats_tls}
    if identity:
        body["clientCertificate"] = {"secret": SECRET}
    return body


def bare(path: Path, *arguments: str):
    """Rendered WITHOUT `chart/ci/values.yaml`, over this overlay only."""
    return helm("template", CHART_NAME, str(CHART), "-f", str(path), *arguments)


def pod_spec(stdout: str) -> dict:
    (deployment,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    return deployment["spec"]["template"]["spec"]


def nats_env(spec: dict) -> dict[str, str]:
    (container,) = spec["containers"]
    return {
        e["name"]: e.get("value")
        for e in container.get("env", [])
        if e["name"] in NATS_VARIABLES
    }


def volume(spec: dict, name: str) -> dict | None:
    return next((v for v in spec.get("volumes", []) if v["name"] == name), None)


def mount(spec: dict, name: str) -> dict | None:
    (container,) = spec["containers"]
    return next((m for m in container.get("volumeMounts", []) if m["name"] == name), None)


def rendered(tmp_path: Path, nats_tls, identity: bool = True) -> dict:
    result = bare(write_overlay(overlay(nats_tls, identity), tmp_path))
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
    """`values.yaml` declares `nats.tls`, so a null coalesces it AWAY: there is
    no `enabled` for the schema's `required` to judge, and only the template's
    own guard is left to refuse."""
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
    assert nats_env(spec) == {"NATS_TLS_ENABLED": "0"}
    assert volume(spec, "nats-ca") is None
    assert mount(spec, "nats-ca") is None
    # Every dial is cleartext too, so no private key is mounted for nothing.
    assert volume(spec, "client-cert") is None


# ── 3. TRUE: the CA, the identity, and the mounts behind both ───────────────


def test_true_renders_the_ca_and_the_identity(tmp_path):
    spec = rendered(tmp_path, {"enabled": True})
    assert nats_env(spec) == {
        "NATS_TLS_ENABLED": "1",
        "NATS_TLS_CA_FILE": CA_PATH,
        "NATS_TLS_CLIENT_CERT_FILE": "/var/run/secrets/client-cert/client.crt",
        "NATS_TLS_CLIENT_KEY_FILE": "/var/run/secrets/client-cert/client.key",
    }


def test_the_ca_is_one_key_of_nats_tls_mounted_where_the_variable_points(tmp_path):
    spec = rendered(tmp_path, {"enabled": True})
    ca = volume(spec, "nats-ca")
    assert ca is not None
    # ONE KEY, never the whole Secret: `nats-tls` also holds the broker's
    # private key.
    assert ca["secret"] == {
        "secretName": "nats-tls",
        "optional": True,
        "items": [{"key": "ca.crt", "path": "ca.pem"}],
    }
    ca_mount = mount(spec, "nats-ca")
    assert ca_mount is not None
    assert ca_mount["readOnly"] is True
    assert "subPath" not in ca_mount
    assert f"{ca_mount['mountPath']}/ca.pem" == CA_PATH


def test_the_broker_hop_alone_mounts_the_client_identity(tmp_path):
    """THE B-N4.2 SHAPE: NATS over TLS while every gRPC hop is cleartext. The
    client pair must have the `client-cert` volume behind it, or the pod exits
    at boot naming a path nothing mounted."""
    spec = rendered(tmp_path, {"enabled": True})
    cert = volume(spec, "client-cert")
    assert cert is not None
    assert cert["secret"]["secretName"] == SECRET
    assert mount(spec, "client-cert")["mountPath"] == "/var/run/secrets/client-cert"


def test_true_with_no_client_secret_presents_no_identity(tmp_path):
    spec = rendered(tmp_path, {"enabled": True}, identity=False)
    assert nats_env(spec) == {"NATS_TLS_ENABLED": "1", "NATS_TLS_CA_FILE": CA_PATH}
    assert volume(spec, "client-cert") is None


def test_true_with_no_ca_secret_is_refused_naming_the_key(tmp_path):
    result = bare(write_overlay(overlay({"enabled": True, "caSecret": ""}), tmp_path))
    assert result.returncode != 0, result.stdout
    assert "nats.tls.caSecret" in result.stderr, result.stderr
