"""NO SPELLING OF ZERO, THROUGH ANY INPUT CHANNEL, RENDERS A 0 FIELD (yaadgaar 639).

The invariant behind the fix, stated once: for `terminationGracePeriodSeconds` and
`preStopSleepSeconds`, every zero spelling through `--set`, `--set-string`, `--set-json`
and a values file is either refused or renders no field. It never renders
`terminationGracePeriodSeconds: 0` (an immediate SIGKILL) or `seconds: 0`.

"00", "000", "08" and "09" are here on purpose. `int64` parses a string base 0, so each
casts to 0. Today the whole-number regex refuses them first, but the refusal compares
`int64 $value` with 0 rather than the exact string "0" (the reviewer's hardening on
yadgarhq/iam#173), so they stay refused even if that regex is ever loosened.

Run: python3 -m pytest scripts/tests/test_zero_string_every_spelling.py -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
GRACE = "terminationGracePeriodSeconds"
PRESTOP = "preStopSleepSeconds"
CARVED_OUT = (GRACE, PRESTOP)


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED, so a "0" reaches helm as a string and not the number 0."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def template(*extra: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), *extra)


def render_file(body: dict, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump(body, Dumper=QuotingDumper))
    return template("-f", str(values))


def combined(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def deployment(stdout: str) -> dict:
    (found,) = [
        d for d in yaml.safe_load_all(stdout)
        if isinstance(d, dict) and d.get("kind") == "Deployment"
    ]
    return found


def pod_spec(stdout: str) -> dict:
    return deployment(stdout)["spec"]["template"]["spec"]


def lifecycles(stdout: str) -> list:
    return [c.get("lifecycle") for c in pod_spec(stdout)["containers"]]

STRINGS = ["0", "00", "000", "08", "09", " 0", "0 ", "0.0", "-0", "+0", "0x0", "0e0", ""]
NUMBERS = [0, 0.0, -0.0]


def rendered_zero(result: subprocess.CompletedProcess[str], key: str) -> bool:
    if result.returncode != 0:
        return False
    if key == GRACE:
        return pod_spec(result.stdout).get(GRACE, None) == 0
    for lc in lifecycles(result.stdout):
        if lc is not None and lc["preStop"]["sleep"]["seconds"] == 0:
            return True
    return False


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("value", STRINGS + NUMBERS, ids=repr)
def test_values_file(key, value, tmp_path):
    result = render_file({key: value}, tmp_path)
    assert not rendered_zero(result, key), result.stdout


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("flag", ["--set", "--set-string"])
@pytest.mark.parametrize("value", [s for s in STRINGS if "," not in s], ids=repr)
def test_set_flags(key, flag, value):
    result = template(flag, f"{key}={value}")
    assert not rendered_zero(result, key), result.stdout


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("value", ['"0"', '"00"', '"08"', "0", "0.0", "-0"], ids=repr)
def test_set_json(key, value):
    result = template("--set-json", f"{key}={value}")
    assert not rendered_zero(result, key), result.stdout


@pytest.mark.parametrize("key", CARVED_OUT)
def test_the_control_a_string_seven_renders_seven(key, tmp_path):
    # Control: the detector sees a rendered field, so "not zero" above means something.
    result = render_file({key: "7"}, tmp_path)
    assert result.returncode == 0, result.stderr
    if key == GRACE:
        assert pod_spec(result.stdout)[GRACE] == 7
    else:
        assert lifecycles(result.stdout)[0]["preStop"]["sleep"]["seconds"] == 7
