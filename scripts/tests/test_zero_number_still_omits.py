"""THE NUMBER 0, A YAML NULL AND AN ABSENT VALUE STILL RENDER NO FIELD (yaadgaar 639).

`terminationGracePeriodSeconds` and `preStopSleepSeconds` sit behind `{{- with }}`, which
skips nil and the number 0: "`0` renders nothing and returns the field to kubelet's 30s
default" (`chart/values.yaml`). The string "0" is refused by name; this file pins that the
NUMBER 0 and null are NOT refused and render nothing, through every input channel.
Ported from yadgarhq/iam#173.

Run: python3 -m pytest scripts/tests/test_zero_number_still_omits.py -q
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


def assert_omitted(result: subprocess.CompletedProcess[str], key: str) -> None:
    assert result.returncode == 0, result.stderr
    if key == GRACE:
        assert GRACE not in pod_spec(result.stdout)
    else:
        assert all(lc is None for lc in lifecycles(result.stdout))


def test_default_render_has_both_fields():
    # Control: with no overlay both fields DO render, so absence below means something.
    result = template()
    assert result.returncode == 0, result.stderr
    assert pod_spec(result.stdout)[GRACE] == 35
    assert any(lc is not None for lc in lifecycles(result.stdout))


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("zero", [0, 0.0], ids=["int0", "float0"])
def test_number_zero_in_a_values_file_renders_no_field(key, zero, tmp_path):
    assert_omitted(render_file({key: zero}, tmp_path), key)


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("flag", ["--set", "--set-json"])
def test_number_zero_on_the_command_line_renders_no_field(key, flag):
    assert_omitted(template(flag, f"{key}=0"), key)


@pytest.mark.parametrize("key", CARVED_OUT)
def test_null_renders_no_field(key, tmp_path):
    assert_omitted(render_file({key: None}, tmp_path), key)
    assert_omitted(template("--set", f"{key}=null"), key)


def test_both_number_zero_together(tmp_path):
    result = render_file({GRACE: 0, PRESTOP: 0}, tmp_path)
    assert_omitted(result, GRACE)
    assert_omitted(result, PRESTOP)


@pytest.mark.parametrize("key", CARVED_OUT)
def test_null_of_one_key_leaves_the_other_rendered(key, tmp_path):
    # Triangulation: null removes only its own field, so a blanket omit fails.
    result = render_file({key: None}, tmp_path)
    assert result.returncode == 0, result.stderr
    present = {
        GRACE: GRACE in pod_spec(result.stdout),
        PRESTOP: any(lc is not None for lc in lifecycles(result.stdout)),
    }
    assert present == {k: k != key for k in CARVED_OUT}
