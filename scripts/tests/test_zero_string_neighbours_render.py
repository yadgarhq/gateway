"""EVERY VALID VALUE OTHER THAN THE STRING "0" RENDERS THE SAME FIELD AS BEFORE (yaadgaar 639).

The fix refuses only the string "0" for `terminationGracePeriodSeconds` and
`preStopSleepSeconds`. A string of digits stays valid (ADR-0847). These cases pass before
and after the fix. Ported from yadgarhq/iam#173.

Run: python3 -m pytest scripts/tests/test_zero_string_neighbours_render.py -q
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


def prestop_seconds(stdout: str):
    (container,) = pod_spec(stdout)["containers"]
    return container["lifecycle"]["preStop"]["sleep"]["seconds"]


def test_the_default_render_keeps_both_field_lines():
    result = template()
    assert result.returncode == 0, result.stderr
    assert pod_spec(result.stdout)[GRACE] == 35
    assert prestop_seconds(result.stdout) == 5


@pytest.mark.parametrize("value", [1, 35, 999999, 35.0, "1", "35", "999999"], ids=repr)
def test_a_grace_period_renders_as_a_plain_integer(value, tmp_path):
    result = render_file({GRACE: value}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert pod_spec(result.stdout)[GRACE] == int(value)
    assert type(pod_spec(result.stdout)[GRACE]) is int


@pytest.mark.parametrize("value", [1, 5, 999999, 5.0, "1", "35"], ids=repr)
def test_a_prestop_sleep_renders_as_a_plain_integer(value, tmp_path):
    result = render_file({PRESTOP: value}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert prestop_seconds(result.stdout) == int(value)


@pytest.mark.parametrize("flag", ["--set", "--set-string", "--set-json"])
def test_a_digit_on_the_command_line_renders(flag):
    result = template(flag, f"{GRACE}=7", flag, f"{PRESTOP}=7")
    assert result.returncode == 0, result.stderr
    assert pod_spec(result.stdout)[GRACE] == 7
    assert prestop_seconds(result.stdout) == 7
