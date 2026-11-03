"""NUMERIC KNOBS RENDER AS WHOLE NUMBERS, OR THE RENDER REFUSES NAMING THE KEY (yaadgaar 482, 485, 513).

A values FILE decodes every number as float64, and `quote` prints a float64 with `%v`:
1000000 becomes "1e+06" and 2147483648 becomes "2.147483648e+09". The binary parses
neither. `int64` repairs the rendering but is silent on a value that does not fit
(a 20-digit string becomes 0, 1e20 becomes -9223372036854775808) and reads a string
base 0 ("0123" is 83, "08" is 0). So every numeric knob this chart renders is
checked BEFORE the cast: a string is at most 18 digits with no leading zero, a number
is whole and below 1e18, and the refusal names the key (`templates/render-checks.yaml`).

`sourceAddress.trustedProxyHops` (yaadgaar 513) is the same class one step earlier: the
schema accepted any type and the binary refused at boot (`TrustBoundary::parse`:
NotANumber, TooDeep). It now allows null, "" or 0..16 and refuses the rest at render.

Zero is NOT refused for any replica count and no floor is added: both are pending
rulings, and `test_zero_replicas_still_render` pins that nothing here decided them.

Assertions check the key name and the schema wrapper sentence only, never a per-leaf
phrase: CI pins helm 3.18.4, whose wording differs from 4.x.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import pytest
import yaml

from test_adr_0845_tls_required import SCHEMA_WRAPPER, all_enabled, deployment_env
from pathlib import Path

from test_render_checks import CHART, CHART_NAME, helm, objects

KEDA = ("--api-versions", "keda.sh/v1alpha1")
INT32_MAX = 2147483647


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED. PyYAML leaves `1e3` and `08` bare, and helm's
    parser then reads them as the numbers 1000 and 8, so a case meant to hand the chart
    a string would hand it a number and test a different input."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def write_overlay(body: dict, destination) -> "Path":
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(yaml.dump(body, Dumper=QuotingDumper))
    return path


def overlay(path: str, value, *, autoscaling: bool = False) -> dict:
    """`all_enabled()` with `path` (dotted) set to `value`."""
    body = all_enabled()
    if autoscaling:
        body["autoscaling"] = {"enabled": True}
    node = body
    *parents, leaf = path.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value
    return body


def render(body: dict, tmp_path, *extra: str):
    return helm("template", CHART_NAME, str(CHART), "-f", str(write_overlay(body, tmp_path)), *extra)


def refused_naming(body: dict, key: str, tmp_path, *extra: str) -> str:
    result = render(body, tmp_path, *extra)
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert key in combined, combined
    return combined


def rendered(body: dict, tmp_path, *extra: str) -> str:
    result = render(body, tmp_path, *extra)
    assert result.returncode == 0, result.stderr
    return result.stdout


def deployment(stdout: str) -> dict:
    (found,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    return found


# ── 1. trustedProxyHops (yaadgaar 513) ───────────────────────────────────────

HOPS = "sourceAddress.trustedProxyHops"
HOPS_VAR = "YADGAR_TRUSTED_PROXY_HOPS"


def hops_entry(stdout: str) -> dict:
    (container,) = deployment(stdout)["spec"]["template"]["spec"]["containers"]
    (entry,) = [e for e in container["env"] if e["name"] == HOPS_VAR]
    return entry


@pytest.mark.parametrize(
    "value",
    ["null", "abc", "NULL", " 1", "1 ", "-1", "17", "99", "016", "01", "1.5", "0x1", "1e1", "+1", " ",
     {}, {"a": 1}, [], [1], True, False, 17, 100, -1, 1.5, 16.5, 1e20],
    ids=repr,
)
def test_a_bad_trusted_proxy_hops_refuses_at_render_naming_the_key(value, tmp_path):
    refused_naming(overlay(HOPS, value), "trustedProxyHops", tmp_path)


@pytest.mark.parametrize(
    "value,expected",
    [("", ""), (0, "0"), (1, "1"), (16, "16"), ("0", "0"), ("1", "1"), ("9", "9"),
     ("10", "10"), ("16", "16"), (2.0, "2")],
    ids=repr,
)
def test_a_good_trusted_proxy_hops_renders(value, expected, tmp_path):
    entry = hops_entry(rendered(overlay(HOPS, value), tmp_path))
    assert entry.get("value") == expected, entry


def test_a_null_trusted_proxy_hops_still_renders_the_empty_instruction(tmp_path):
    entry = hops_entry(rendered(overlay(HOPS, None), tmp_path))
    assert entry.get("value") in (None, ""), entry


def test_the_string_refusal_is_the_render_check_and_the_number_refusal_is_the_schema(tmp_path):
    """The two halves are separate gates: the schema types the value and bounds a
    number, the render check reads a string. Each must refuse by itself."""
    number = refused_naming(overlay(HOPS, 17), "trustedProxyHops", tmp_path)
    assert SCHEMA_WRAPPER in number, number
    string = refused_naming(overlay(HOPS, "17"), "trustedProxyHops", tmp_path)
    assert SCHEMA_WRAPPER not in string, string


# ── 2. the whole-number check on every numeric knob ──────────────────────────

# (dotted key, the env var it renders into)
ENV_KNOBS = [
    ("projectValidation.registryPollSeconds", "YADGAR_PROJECT_REGISTRY_POLL_SECONDS"),
    ("credentialCache.ttlSeconds", "YADGAR_CREDENTIAL_TTL_SECONDS"),
    ("rateLimit.timeoutMs", "YADGAR_RATE_LIMIT_TIMEOUT_MS"),
]
PORT_KNOBS = [
    ("task.port", "TASK_PORT"),
    ("iam.port", "IAM_PORT"),
    ("project.port", "PROJECT_PORT"),
]
BAD_WHOLE = [1.5, 0.5, -1, "-1", "1.5", "abc", "", "0123", "08", "1e3", "1" * 19, 1e18, 1e20,
             True, [], {}, None]


@pytest.mark.parametrize("key,var", ENV_KNOBS)
def test_an_env_knob_renders_a_values_file_number_without_an_exponent(key, var, tmp_path):
    env = deployment_env(rendered(overlay(key, 1000000), tmp_path))
    assert env[var] == "1000000", env


@pytest.mark.parametrize("key,var", [k for k in ENV_KNOBS if k[0] != "credentialCache.ttlSeconds"])
def test_an_env_knob_still_accepts_a_digit_string(key, var, tmp_path):
    # `credentialCache.ttlSeconds` is schema-typed integer, so a string is the
    # schema's refusal and not this check's.
    env = deployment_env(rendered(overlay(key, "30"), tmp_path))
    assert env[var] == "30", env


@pytest.mark.parametrize("key,var", ENV_KNOBS)
@pytest.mark.parametrize("value", BAD_WHOLE, ids=repr)
def test_an_env_knob_that_is_not_a_whole_number_refuses_naming_the_key(key, var, value, tmp_path):
    # `credentialCache.ttlSeconds` is schema-typed integer and `None` deletes a
    # required key: either way the refusal must still name the key.
    refused_naming(overlay(key, value), key.split(".")[-1], tmp_path)


@pytest.mark.parametrize("key,var", ENV_KNOBS)
def test_the_whole_number_ceiling_is_exact(key, var, tmp_path):
    # 10**17 is the largest power of ten a float64 holds exactly below the ceiling;
    # a string spells the 18-digit maximum, a number cannot.
    top = 10**17
    env = deployment_env(rendered(overlay(key, top), tmp_path))
    assert env[var] == str(top), env
    refused_naming(overlay(key, 10**18), key.split(".")[-1], tmp_path)
    if key != "credentialCache.ttlSeconds":
        top = "9" * 18
        env = deployment_env(rendered(overlay(key, top), tmp_path))
        assert env[var] == top, env
        refused_naming(overlay(key, "1" + "0" * 18), key, tmp_path)


@pytest.mark.parametrize("key,var", PORT_KNOBS)
def test_a_port_renders_both_ends_and_refuses_one_past_each(key, var, tmp_path):
    for value in (1, 65535, 50052.0, "443"):
        env = deployment_env(rendered(overlay(key, value), tmp_path))
        assert env[var] == str(int(value)), env
    for value in (0, 65536, "0", "65536", 1000000, -1, 1.5, "abc"):
        refused_naming(overlay(key, value), key, tmp_path)


def test_the_service_port_renders_in_the_service_and_the_route(tmp_path):
    stdout = rendered(overlay("service.port", 1000), tmp_path)
    (service,) = [o for o in objects(stdout) if o["kind"] == "Service"]
    assert service["spec"]["ports"][0]["port"] == 1000
    assert isinstance(service["spec"]["ports"][0]["port"], int)
    for value in (1, 65535):
        stdout = rendered(overlay("service.port", value), tmp_path)
        (service,) = [o for o in objects(stdout) if o["kind"] == "Service"]
        assert service["spec"]["ports"][0]["port"] == value
    for value in (0, 65536, 1.5, "abc", -1):
        refused_naming(overlay("service.port", value), "service.port", tmp_path)


# ── 3. replica counts, the grace period and the sleep ────────────────────────


def test_a_values_file_replica_count_renders_as_an_integer(tmp_path):
    stdout = rendered(overlay("replicaCount", 1000000), tmp_path)
    assert "replicas: 1000000\n" in stdout
    assert "1e+06" not in stdout
    assert deployment_env(stdout)["YADGAR_MAX_REPLICAS"] == "1000000"


def test_the_replica_count_ceiling_is_the_int32_field_and_both_ends_are_exact(tmp_path):
    stdout = rendered(overlay("replicaCount", INT32_MAX), tmp_path)
    assert f"replicas: {INT32_MAX}\n" in stdout
    refused_naming(overlay("replicaCount", INT32_MAX + 1), "replicaCount", tmp_path)
    refused_naming(overlay("replicaCount", str(INT32_MAX + 1)), "replicaCount", tmp_path)


@pytest.mark.parametrize("value", [1.5, -1, "abc", "", "0123", 1e20, True, [], "9" * 19, "1" + "0" * 18], ids=repr)
def test_a_replica_count_that_is_not_whole_refuses_naming_the_key(value, tmp_path):
    refused_naming(overlay("replicaCount", value), "replicaCount", tmp_path)


def test_zero_replicas_still_render(tmp_path):
    """No floor and no refusal of 0: both are pending rulings (yaadgaar 482)."""
    stdout = rendered(overlay("replicaCount", 0), tmp_path)
    assert "replicas: 0\n" in stdout
    body = overlay("autoscaling.minReplicas", 0, autoscaling=True)
    stdout = rendered(body, tmp_path, *KEDA)
    assert "minReplicaCount: 0\n" in stdout


def test_the_autoscaling_counts_render_as_integers_and_bound_both_ends(tmp_path):
    body = overlay("autoscaling.minReplicas", 1000000, autoscaling=True)
    body["autoscaling"]["maxReplicas"] = 2000000
    stdout = rendered(body, tmp_path, *KEDA)
    assert "minReplicaCount: 1000000\n" in stdout
    assert "maxReplicaCount: 2000000\n" in stdout
    assert deployment_env(stdout)["YADGAR_MAX_REPLICAS"] == "2000000"
    assert "1e+06" not in stdout and "2e+06" not in stdout
    for key in ("minReplicas", "maxReplicas"):
        top = overlay(f"autoscaling.{key}", INT32_MAX, autoscaling=True)
        assert rendered(top, tmp_path, *KEDA)
        over = overlay(f"autoscaling.{key}", INT32_MAX + 1, autoscaling=True)
        refused_naming(over, f"autoscaling.{key}", tmp_path, *KEDA)
        for value in (1.5, "abc", -1, ""):
            bad = overlay(f"autoscaling.{key}", value, autoscaling=True)
            refused_naming(bad, f"autoscaling.{key}", tmp_path, *KEDA)


def test_the_autoscaling_counts_are_not_read_while_autoscaling_is_off(tmp_path):
    """Only a rendered knob is checked: `maxReplicas` feeds `YADGAR_MAX_REPLICAS` only
    when autoscaling is on, so a bad one with autoscaling off changes nothing today."""
    body = overlay("autoscaling.maxReplicas", 1.5)
    assert rendered(body, tmp_path)


def test_a_zero_grace_period_and_sleep_still_mean_not_rendered(tmp_path):
    body = overlay("terminationGracePeriodSeconds", 0)
    body["preStopSleepSeconds"] = 0
    spec = deployment(rendered(body, tmp_path))["spec"]["template"]["spec"]
    assert "terminationGracePeriodSeconds" not in spec


# ── 4. the defaults are untouched ────────────────────────────────────────────


def test_the_chart_defaults_pass_every_check(tmp_path):
    result = helm("template", CHART_NAME, str(CHART), "-f", str(CHART / "ci" / "values.yaml"))
    assert result.returncode == 0, result.stderr
    assert yaml.safe_load(open(CHART / "values.yaml"))["replicaCount"] == 2


def test_the_grace_period_and_pre_stop_sleep_are_bounded_where_a_float_prints_plainly(tmp_path):
    """Not cast through `int64`: the chart-baseline gate cannot price either through it.
    999999 is the largest value helm prints without an exponent."""
    spec = deployment(rendered(overlay("terminationGracePeriodSeconds", 999999), tmp_path))["spec"]["template"]["spec"]
    assert spec["terminationGracePeriodSeconds"] == 999999
    stdout = rendered(overlay("preStopSleepSeconds", 999999), tmp_path)
    assert "seconds: 999999\n" in stdout
    for key in ("terminationGracePeriodSeconds", "preStopSleepSeconds"):
        for value in (1000000, 1.5, "abc", -1, "0123", 1e20, ""):
            refused_naming(overlay(key, value), key, tmp_path)


def test_an_eighteen_digit_replica_count_string_is_the_string_ceiling(tmp_path):
    """18 digits fit int64 and are refused only by the int32 bound; 19 overflow the cast
    to 0 and are refused by the whole-number check. Both name the key."""
    refused_naming(overlay("replicaCount", "9" * 18), "replicaCount", tmp_path)
    refused_naming(overlay("replicaCount", "9" * 19), "replicaCount", tmp_path)
    assert "replicas: 2147483647\n" in rendered(overlay("replicaCount", str(INT32_MAX)), tmp_path)


def test_the_topology_skew_is_bounded_where_a_float_prints_plainly(tmp_path):
    """Not cast through `int64`: the chart-baseline gate cannot read the skew through it.
    999999 is the largest value helm prints without an exponent."""
    def skew(value):
        body = overlay("topologySpread.maxSkew", value)
        body["topologySpread"]["enabled"] = True
        return body

    for value in (1, 999999):
        spec = deployment(rendered(skew(value), tmp_path))["spec"]["template"]["spec"]
        assert spec["topologySpreadConstraints"][0]["maxSkew"] == value
    for value in (0, "0", 1000000, 1.5, "abc", -1, "", "0123", 1e20):
        refused_naming(skew(value), "topologySpread.maxSkew", tmp_path)


def test_the_topology_skew_is_not_read_while_the_spread_is_off(tmp_path):
    body = overlay("topologySpread.maxSkew", 1.5)
    body["topologySpread"]["enabled"] = False
    assert rendered(body, tmp_path)
