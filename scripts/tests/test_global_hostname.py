"""THE ESTATE'S HOSTNAME IS ONE VALUE, `global.hostname` (ADR-0808).

This chart carries one of the five keys that hold the public hostname,
`gateway.hostname`, which the HTTPRoute matches on. It resolves in this order, in
`templates/_hostname.tpl`:

  1. `gateway.hostname`, when it is set (an explicit per-chart value wins);
  2. `global.hostname`, when `gateway.hostname` is empty;
  3. `gateway.yadgar.internal`, when neither is set — the value `values.yaml`
     shipped before this change, so a render with no hostname anywhere is the
     render it was.

THE THREE CASES ARE (a), (b) AND (c) BELOW, and each has a red case. Only (b) is
red on the chart before this change, because that chart never read `global`. (a)
and (c) were green there by construction, so their red cases are MUTATIONS: a copy
of the chart with `_hostname.tpl` rewritten to lose the property under test, which
the same check must then refuse.

The chart's defaults render the HTTPRoute (`gateway.enabled` is true), so every
case here renders the defaults with only the hostname keys changed.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
HELPER = "templates/_hostname.tpl"

BUILT_IN = "gateway.yadgar.internal"
GLOBAL = "yadgar.example.com"
LOCAL = "edge.local.example"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), the same wording as the sibling suites.
    assert binary, (
        "helm is not on PATH. This suite renders the chart — install helm rather "
        "than letting it report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def template(chart: Path, *arguments: str) -> str:
    result = helm("template", "gateway", str(chart), *arguments)
    assert result.returncode == 0, result.stderr
    return result.stdout


def route_hostnames(chart: Path, *arguments: str) -> list[str]:
    routes = [
        document
        for document in yaml.safe_load_all(template(chart, *arguments))
        if isinstance(document, dict) and document.get("kind") == "HTTPRoute"
    ]
    assert len(routes) == 1, f"expected one HTTPRoute, found {len(routes)}"
    return routes[0]["spec"]["hostnames"]


def chart_with(destination: Path, old: str, new: str) -> Path:
    """A copy of the chart with one string in `_hostname.tpl` replaced. Red cases only.

    The edit is asserted to have landed: a replace whose pattern no longer matches
    leaves the chart unchanged, and the red case would then prove nothing.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    target = copy / HELPER
    before = target.read_text()
    assert old in before, f"the red case's edit matched nothing in {HELPER}"
    target.write_text(before.replace(old, new))
    return copy


def no_hostname_anywhere(chart: Path) -> list[str]:
    return route_hostnames(chart)


def global_only(chart: Path) -> list[str]:
    return route_hostnames(chart, "--set", f"global.hostname={GLOBAL}")


def global_and_local(chart: Path) -> list[str]:
    return route_hostnames(
        chart,
        "--set", f"global.hostname={GLOBAL}",
        "--set", f"gateway.hostname={LOCAL}",
    )


# ── (a) no global, no local: the render this chart always produced ─────────────


def test_a_no_hostname_anywhere_renders_the_built_in_default():
    assert no_hostname_anywhere(CHART) == [BUILT_IN]


def test_a_red_a_changed_built_in_default_is_caught(tmp_path):
    mutant = chart_with(tmp_path, f'"{BUILT_IN}"', '"elsewhere.invalid"')
    assert no_hostname_anywhere(mutant) != [BUILT_IN]


def test_a_an_explicit_null_global_is_the_same_as_none(tmp_path):
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("global: null\n")
    assert route_hostnames(CHART, "-f", str(overlay)) == [BUILT_IN]


# ── (b) global set, local empty: the route matches the global ──────────────────


def test_b_global_hostname_reaches_the_route():
    assert global_only(CHART) == [GLOBAL]


def test_b_global_hostname_leaves_no_trace_of_the_built_in_default():
    assert BUILT_IN not in template(CHART, "--set", f"global.hostname={GLOBAL}")


def test_b_red_a_chart_that_ignores_global_is_caught(tmp_path):
    mutant = chart_with(tmp_path, '(get $global "hostname")', '""')
    assert global_only(mutant) != [GLOBAL]


# ── (c) local and global both set: the local key wins ──────────────────────────


def test_c_an_explicit_local_key_wins_over_global():
    assert global_and_local(CHART) == [LOCAL]


def test_c_red_a_chart_that_prefers_global_is_caught(tmp_path):
    mutant = chart_with(
        tmp_path,
        '.local | default (get $global "hostname")',
        '(get $global "hostname") | default .local',
    )
    assert global_and_local(mutant) != [LOCAL]
