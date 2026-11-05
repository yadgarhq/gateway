"""THE BROWSER ORIGIN THIS GATEWAY ADMITS IS DERIVED FROM `global.hostname` (yaadgaar #294).

Max ruled that the Origin allowlist (`YADGAR_ALLOWED_ORIGINS`, read by the
binary's `origin_ok` check, which is not CORS) derives from the estate's one
hostname (ADR-0808). `templates/_origins.tpl` holds the order:

  1. `cors.allowedOrigins`, when it is set: an explicit value still wins;
  2. `https://` + `global.hostname`, when `cors.allowedOrigins` is empty. NO
     PORT, as in iam's enrolment URL: the edge listener answers on 443;
  3. EMPTY, when neither is set: no browser origin, the shipped closed posture.
     So a render with no hostname anywhere is byte-identical to the render
     before this change.

The ruling also refuses `http://` origins unless a development switch is on.
The binary refuses them at boot; the chart renders the switch
(`cors.allowHttpOrigins`, a boolean) as `YADGAR_ALLOWED_ORIGINS_ALLOW_HTTP`,
"1" or "0", unconditionally, because the binary requires it (ADR-0569).

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
GLOBAL = "yadgar.example.com"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), the same wording as the sibling suites.
    assert binary, (
        "helm is not on PATH. This suite renders the chart — install helm rather "
        "than letting it report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm(
        "template", "gateway", str(CHART), "-f", str(CHART / "ci" / "values.yaml"), *arguments
    )


def env(*arguments: str) -> dict[str, str]:
    result = render(*arguments)
    assert result.returncode == 0, result.stderr
    deployments = [
        d
        for d in yaml.safe_load_all(result.stdout)
        if isinstance(d, dict) and d.get("kind") == "Deployment"
    ]
    assert len(deployments) == 1
    (container,) = deployments[0]["spec"]["template"]["spec"]["containers"]
    return {e["name"]: e.get("value") for e in container["env"]}


def test_no_hostname_anywhere_renders_the_closed_posture() -> None:
    rendered = env()
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == ""
    assert rendered["YADGAR_ALLOWED_ORIGINS_ALLOW_HTTP"] == "0"


def test_the_origin_derives_from_global_hostname() -> None:
    assert env("--set", f"global.hostname={GLOBAL}")["YADGAR_ALLOWED_ORIGINS"] == f"https://{GLOBAL}"


def test_an_explicit_allowlist_wins_over_global_hostname() -> None:
    explicit = "https://gateway.yadgar.internal:18443"
    rendered = env("--set", f"global.hostname={GLOBAL}", "--set", f"cors.allowedOrigins={explicit}")
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == explicit


def test_the_route_hostname_override_does_not_move_the_origin() -> None:
    # The origin follows the ESTATE's hostname, not this chart's route override:
    # `gateway.hostname` alone leaves the allowlist closed.
    assert env("--set", "gateway.hostname=edge.local.example")["YADGAR_ALLOWED_ORIGINS"] == ""


def test_a_null_global_falls_through_to_closed() -> None:
    assert env("--set", "global=null")["YADGAR_ALLOWED_ORIGINS"] == ""


def test_the_development_switch_renders_one_when_on() -> None:
    assert env("--set", "cors.allowHttpOrigins=true")["YADGAR_ALLOWED_ORIGINS_ALLOW_HTTP"] == "1"


def test_the_development_switch_is_a_boolean_and_required() -> None:
    # A string "false" would read as on in a template; the include refuses it,
    # and a null (helm deletes the key) too.
    result = render("--set-string", "cors.allowHttpOrigins=false")
    assert result.returncode != 0
    assert "`cors.allowHttpOrigins` must be true or false" in result.stderr
    assert 'is "false"' in result.stderr
    result = render("--set", "cors.allowHttpOrigins=null")
    assert result.returncode != 0
    assert "`cors.allowHttpOrigins` must be true or false and is absent" in result.stderr


def test_a_wildcard_global_hostname_is_refused_at_render() -> None:
    # The binary would refuse `https://*.example.com` at boot, as a crash-loop on
    # rollout. The chart names the key at render instead.
    result = render("--set", "global.hostname=*.example.com")
    assert result.returncode != 0
    assert "`global.hostname`" in result.stderr and "wildcard" in result.stderr
    # An explicit allowlist does not read `global.hostname` for the origin.
    explicit = "https://gateway.example.com"
    rendered = env("--set", "global.hostname=*.example.com", "--set", f"cors.allowedOrigins={explicit}")
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == explicit


# ── THE OFF SWITCH, `cors.enabled` (yaadgaar #582, ruled by Max 2026-11-05) ──
#
# Shipped `true`, so every render that does not state the key is the render
# before it. `false` renders NO origin, whatever `global.hostname` says.
# `false` WINS over a non-empty `cors.allowedOrigins` too, with no refusal: in
# an incident the off switch must close the origin with one key, and a refused
# render would leave the running pods open.

EXPLICIT = "https://gateway.yadgar.internal:18443"


def test_enabled_an_explicit_allowlist_wins() -> None:
    rendered = env(
        "--set", "cors.enabled=true",
        "--set", f"global.hostname={GLOBAL}",
        "--set", f"cors.allowedOrigins={EXPLICIT}",
    )
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == EXPLICIT


def test_enabled_the_hostname_alone_derives_the_origin() -> None:
    rendered = env("--set", "cors.enabled=true", "--set", f"global.hostname={GLOBAL}")
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == f"https://{GLOBAL}"


def test_enabled_with_neither_renders_the_closed_posture() -> None:
    assert env("--set", "cors.enabled=true")["YADGAR_ALLOWED_ORIGINS"] == ""


def test_disabled_a_set_hostname_renders_no_origin() -> None:
    rendered = env("--set", "cors.enabled=false", "--set", f"global.hostname={GLOBAL}")
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == ""
    # The variable is still rendered: the binary refuses to boot without it.
    assert "YADGAR_ALLOWED_ORIGINS" in rendered


def test_disabled_does_not_read_the_hostname_at_all() -> None:
    # A wildcard hostname is refused only when the origin derives from it. Off,
    # nothing derives, so the render succeeds and stays closed.
    rendered = env("--set", "cors.enabled=false", "--set", "global.hostname=*.example.com")
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == ""


def test_disabled_wins_over_an_explicit_allowlist_and_a_hostname() -> None:
    rendered = env(
        "--set", "cors.enabled=false",
        "--set", f"global.hostname={GLOBAL}",
        "--set", f"cors.allowedOrigins={EXPLICIT}",
    )
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == ""


def test_disabled_wins_over_an_explicit_allowlist_alone() -> None:
    rendered = env("--set", "cors.enabled=false", "--set", f"cors.allowedOrigins={EXPLICIT}")
    assert rendered["YADGAR_ALLOWED_ORIGINS"] == ""


# The schema refuses a non-boolean before any template runs. Helm 4 and helm 3
# word the refusal differently; each assertion accepts exactly those two
# sentences for the key and the type found.
def schema_refusal(stderr: str, found_v4: str, found_v3: str) -> bool:
    return (
        f"at '/cors/enabled': got {found_v4}, want boolean" in stderr
        or f"cors.enabled: Invalid type. Expected: boolean, given: {found_v3}" in stderr
    )


def test_the_off_switch_is_a_boolean() -> None:
    # A string "false" is truthy in a template and would leave the origin OPEN.
    result = render("--set-string", "cors.enabled=false", "--set", f"global.hostname={GLOBAL}")
    assert result.returncode != 0
    assert schema_refusal(result.stderr, "string", "string"), result.stderr


def test_the_string_true_is_refused() -> None:
    result = render("--set-string", "cors.enabled=true")
    assert result.returncode != 0
    assert schema_refusal(result.stderr, "string", "string"), result.stderr


def test_a_number_is_refused() -> None:
    result = render("--set", "cors.enabled=0", "--set", f"global.hostname={GLOBAL}")
    assert result.returncode != 0
    assert schema_refusal(result.stderr, "number", "integer"), result.stderr


def test_the_off_switch_is_refused_when_absent() -> None:
    # `null` deletes the key in helm. Absent is not read as on or as off.
    result = render("--set", "cors.enabled=null", "--set", f"global.hostname={GLOBAL}")
    assert result.returncode != 0
    assert "`cors.enabled` must be true or false and is absent" in result.stderr
