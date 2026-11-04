"""THE STRING "0" CARVE-OUT IS NARROW AND LOOSENS NOTHING (yaadgaar 639, ADR-0645).

Only the string "0" for terminationGracePeriodSeconds and preStopSleepSeconds is refused
by name. Every other knob keeps its behaviour for "0", and a malformed zero string
("00", "0123", "") keeps the existing whole-number refusal. Ported from yadgarhq/iam#173.

Run: python3 -m pytest scripts/tests/test_zero_string_scope.py -q
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

DIGIT_OK = ['projectValidation.registryPollSeconds', 'rateLimit.timeoutMs']
PORT = 'task.port'


@pytest.mark.parametrize("flag", ["--set-string", "--set"])
def test_zero_string_replica_count_still_renders_zero_replicas(flag):
    result = template(flag, "replicaCount=0")
    assert result.returncode == 0, result.stderr
    assert "replicas: 0\n" in result.stdout


def test_values_file_zero_string_replica_count_still_renders_zero_replicas(tmp_path):
    result = render_file({"replicaCount": "0"}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "replicas: 0\n" in result.stdout


def test_other_digit_string_replica_count_still_renders_its_value():
    result = template("--set-string", "replicaCount=3")
    assert result.returncode == 0, result.stderr
    assert "replicas: 3\n" in result.stdout


@pytest.mark.parametrize("key", DIGIT_OK or ["replicaCount"])
def test_other_numeric_knob_still_accepts_the_zero_string(key):
    result = template("--set-string", f"{key}=0")
    assert result.returncode == 0, combined(result)


@pytest.mark.parametrize("flag", ["--set-string", "--set"])
def test_zero_port_keeps_the_minimum_refusal_not_the_zero_string_one(flag):
    result = template(flag, f"{PORT}=0")
    assert result.returncode != 0, result.stdout
    assert PORT in combined(result)
    assert "at least 1" in combined(result)
    assert "guard treats as set" not in combined(result)


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("value", ["00", "000", "08", "0123", "007", "01", ""], ids=repr)
def test_malformed_zero_string_keeps_the_whole_number_refusal(key, value, tmp_path):
    result = render_file({key: value}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert key in combined(result)
    assert "must be a whole number" in combined(result)


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("value", ["abc", " 0", "0 ", "0.0", "-0", "+0", "0x0", "0e0"], ids=repr)
def test_every_other_string_that_could_mean_zero_is_refused_as_not_whole(key, value, tmp_path):
    result = render_file({key: value}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert key in combined(result)
    assert "must be a whole number" in combined(result)
