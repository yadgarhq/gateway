"""EVERY RENDERED CLIENT-CERT PATH HAS A MOUNT AND A VOLUME BEHIND IT (ledger 770, B-U2).

Each upstream's `<PREFIX>_TLS_CLIENT_CERT_FILE` / `_KEY_FILE` pair is gated on
that upstream's `tls.enabled` and `clientCertificate.secret`; the ONE
`client-cert` volume and mount are gated on `$presentsIdentity`. The two gates
must agree. This reads the RENDERED pod spec, so it is red for any template
change that breaks the agreement — a dropped term, a `not`, a term moved out of
the `or`, a later reassignment, or a narrowed guard on the mount itself.

THE UPSTREAMS ARE DERIVED from `values.yaml` (every top-level key with a
`tls.enabled`), so a fourth upstream is covered the day it is added, and
pinned against a literal so the derivation cannot silently shrink.
"""

from __future__ import annotations

import posixpath

import pytest
import yaml

from test_render_checks import CHART, objects, render

EXPECTED_UPSTREAMS = {"task", "iam", "project"}
SECRET = "gateway-client-tls-m-agahi"
IDENTITY = (
    "--set", f"clientCertificate.secret={SECRET}",
    "--set", "clientCertificate.certSecretKey=tls.crt",
    "--set", "clientCertificate.keySecretKey=tls.key",
)


def upstreams() -> list[str]:
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    return sorted(
        key
        for key, block in values.items()
        if isinstance(block, dict)
        and isinstance(block.get("tls"), dict)
        and "enabled" in block["tls"]
    )


def pod_spec(*arguments: str) -> dict:
    result = render(CHART, *arguments)
    assert result.returncode == 0, result.stderr
    (deployment,) = [o for o in objects(result.stdout) if o["kind"] == "Deployment"]
    return deployment["spec"]["template"]["spec"]


def unbacked_client_cert_paths(spec: dict) -> list[str]:
    """Every `*_TLS_CLIENT_{CERT,KEY}_FILE` path with no Secret-backed mount over it."""
    volumes = {v["name"]: v for v in spec.get("volumes", [])}
    missing = []
    for container in spec["containers"]:
        mounts = container.get("volumeMounts", [])
        for env in container.get("env", []):
            name = env["name"]
            if not (name.endswith("_TLS_CLIENT_CERT_FILE") or name.endswith("_TLS_CLIENT_KEY_FILE")):
                continue
            directory = posixpath.dirname(env["value"])
            backed = any(
                m["mountPath"].rstrip("/") == directory
                and volumes.get(m["name"], {}).get("secret", {}).get("secretName") == SECRET
                for m in mounts
            )
            if not backed:
                missing.append(f"{name}={env['value']}")
    return missing


def client_cert_env(spec: dict) -> list[str]:
    return [
        e["name"]
        for c in spec["containers"]
        for e in c.get("env", [])
        if e["name"].endswith("_TLS_CLIENT_CERT_FILE")
    ]


def test_the_upstream_set_is_the_one_the_chart_declares() -> None:
    assert set(upstreams()) == EXPECTED_UPSTREAMS


@pytest.mark.parametrize("upstream", upstreams())
def test_one_upstream_alone_presents_a_mounted_identity(upstream: str) -> None:
    spec = pod_spec(*IDENTITY, "--set", f"{upstream}.tls.enabled=true")
    # NOT VACUOUS: the env pair this case is about must actually render.
    assert client_cert_env(spec) == [f"{upstream.upper()}_TLS_CLIENT_CERT_FILE"]
    assert unbacked_client_cert_paths(spec) == [], (
        f"{upstream}.tls.enabled alone with clientCertificate.secret renders client-cert "
        "env vars with no Secret-backed mount: `$presentsIdentity` disagrees with the env gate"
    )


def test_no_upstream_on_mounts_no_private_key() -> None:
    spec = pod_spec(*IDENTITY)
    assert client_cert_env(spec) == []
    assert not any(
        v.get("secret", {}).get("secretName") == SECRET for v in spec.get("volumes", [])
    )
