"""THE STRING "0" FOR preStopSleepSeconds IS REFUSED AT RENDER, NAMING THE KEY (yaadgaar 639).

`{{- with .Values.preStopSleepSeconds }}` skips nil and the NUMBER 0, but a Go template treats every
non-empty string as true, so the string "0" passed the guard and rendered `seconds: 0`, a preStop sleep of nothing.
The render now refuses that string by name. The number 0 is covered in
`test_zero_number_still_omits.py`. Ported from yadgarhq/iam#173.

Run: python3 -m pytest scripts/tests/test_zero_string_prestop.py -q
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

KEY = PRESTOP


def assert_refused_naming_key_and_zero(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode != 0, result.stdout
    assert KEY in combined(result), combined(result)
    assert '"0"' in combined(result), combined(result)
    assert "with` guard treats as set" in combined(result), combined(result)


def test_set_string_zero_is_refused_naming_the_key():
    assert_refused_naming_key_and_zero(template("--set-string", f"{KEY}=0"))


def test_set_json_string_zero_is_refused_naming_the_key():
    assert_refused_naming_key_and_zero(template("--set-json", f'{KEY}="0"'))


def test_quoted_zero_in_a_values_file_is_refused_naming_the_key(tmp_path):
    assert_refused_naming_key_and_zero(render_file({KEY: "0"}, tmp_path))


def test_the_refusal_names_this_key_and_not_a_valid_neighbour(tmp_path):
    # Triangulation: the other carved-out key holds a valid value and is not named.
    other = PRESTOP if KEY == GRACE else GRACE
    result = render_file({KEY: "0", other: 7}, tmp_path)
    assert_refused_naming_key_and_zero(result)
    assert other not in combined(result), combined(result)


@pytest.mark.parametrize("value", ["7", "35"])
def test_another_digit_string_still_renders(value, tmp_path):
    # Triangulation: only "0" is refused, so a blanket refusal of strings fails.
    result = render_file({KEY: value}, tmp_path)
    assert result.returncode == 0, result.stderr
    if KEY == GRACE:
        assert pod_spec(result.stdout)[GRACE] == int(value)
    else:
        (container,) = pod_spec(result.stdout)["containers"]
        assert container["lifecycle"]["preStop"]["sleep"]["seconds"] == int(value)
