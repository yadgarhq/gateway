"""THE SCALED OBJECT THIS CHART RENDERS, and what keeps its group one with the check.

THE COUNTERPART OF `test_render_checks.py`, AND THE SPLIT IS THE REFERENCE'S. In
`yadgarhq/iam-db` the render-check harness is one file and the gates that read the
chart's own rendered objects are another (`test_mariadb.py`); this file is that
second half, copied from it (ADR-0679) with the MariaDB CR replaced by the
ScaledObject and the engine-contract gates — which have no counterpart here —
dropped rather than reimagined.

WHAT IT CARRIES THAT `test_render_checks.py` CANNOT. Two things, and both are about
this chart rather than about the construction:

  - THE DEFAULT RENDER'S OBJECT COUNT, against a literal. The render-check harness
    asserts only that the defaults render no object of a CHECKED group — the half
    that belongs to the check. The other half, that the default render is otherwise
    UNCHANGED by this whole change, is a count, and it lives here.
  - THE ONE SOURCE FOR THE GROUP-AND-VERSION STRING. The string is a literal in
    `templates/render-checks.yaml`, because the harness reads the invocation's
    arguments off the template, and it is recorded a second time in `values.yaml`
    beside the toggle. Two files hold it and this is the gate that keeps them one.

EVERY NUMBER HERE IS A LITERAL. A number derived from the thing under test agrees
with whatever that thing happens to be and detects nothing.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import yaml

from test_render_checks import (
    CHART,
    CHART_NAME,
    EXPECTED_CHECKS,
    REPO,
    TOGGLE_ON,
    declared_checks,
    objects,
    render,
)

# ── THE NUMBERS, WRITTEN DOWN ────────────────────────────────────────────────

# What this chart renders at its OWN defaults, and asserted UNCHANGED by the render
# check — `templates/render-checks.yaml` renders no object of its own, which is what
# this count is the evidence for.
EXPECTED_DEFAULT_OBJECTS = 6
EXPECTED_DEFAULT_KINDS = {
    "ConfigMap": 1,
    "Deployment": 1,
    "HTTPRoute": 1,
    "PodDisruptionBudget": 1,
    "Service": 1,
    "ServiceAccount": 1,
}

# The same set plus the ScaledObject, once `autoscaling.enabled` is true.
EXPECTED_OBJECTS_WITH_THE_SCALED_OBJECT = EXPECTED_DEFAULT_OBJECTS + 1

KEDA_API_VERSION = "keda.sh/v1alpha1"
KEDA_KIND = "ScaledObject"

# The group-and-version string the render check names, recorded in `values.yaml`
# beside the toggle so an operator upgrade that moved the version turns the check red
# rather than silently weakening it.
RECORDED_GROUP_PATH = ("autoscaling", "keda", "apiVersion")

API_VERSIONS_FOR_THE_SCALED_OBJECT = ("--api-versions", KEDA_API_VERSION)


def chart_values(chart: Path = CHART) -> dict:
    """`values.yaml` parsed. Used ONLY where the values file is itself the subject."""
    return yaml.safe_load((chart / "values.yaml").read_text())


def render_with_the_scaled_object(chart: Path = CHART):
    """The render with `autoscaling.enabled` true, which is the only one that has one.

    IT PASSES `--api-versions`, and it has to: the render check behind the same
    toggle refuses a render that does not name the operator's group, which is the
    whole point of that check. `test_render_checks.py` is where THAT is exercised.
    """
    return render(chart, *TOGGLE_ON, *API_VERSIONS_FOR_THE_SCALED_OBJECT)


def scaled_objects(rendered: list[dict]) -> list[dict]:
    """Every KEDA ScaledObject in a render. PURE."""
    return [
        document
        for document in rendered
        if document.get("apiVersion") == KEDA_API_VERSION
        and document.get("kind") == KEDA_KIND
    ]


# ── THE GATES ────────────────────────────────────────────────────────────────


def test_the_default_render_is_unchanged_and_creates_no_scaled_object():
    """The toggle defaults FALSE, so an adopter with no KEDA still installs.

    ASSERTED AS AN EQUALITY AGAINST ZERO AND AGAINST A LITERAL OBJECT COUNT, not as a
    skip. A pass that would also report a pass on one ScaledObject is not a gate, and
    the count is what catches the other direction — a template added here that renders
    something at the defaults. `templates/render-checks.yaml` is such a template and
    renders nothing, and this count is where that is asserted rather than assumed.
    `test_turning_the_toggle_on_reddens_the_zero_and_the_count` is the red case that
    makes both numbers falsifiable.
    """
    defaults = render(CHART)
    assert defaults.returncode == 0, defaults.stderr
    rendered = objects(defaults.stdout)

    assert scaled_objects(rendered) == [], (
        "the chart rendered a ScaledObject at its DEFAULTS, so it now requires KEDA's "
        "CRD on every cluster it installs on"
    )

    kinds: dict[str, int] = {}
    for document in rendered:
        kinds[document["kind"]] = kinds.get(document["kind"], 0) + 1
    assert kinds == EXPECTED_DEFAULT_KINDS, (
        f"the default render is {kinds}, expected {EXPECTED_DEFAULT_KINDS} — the "
        f"objects this chart rendered before the render check existed"
    )
    assert len(rendered) == EXPECTED_DEFAULT_OBJECTS, (
        f"the default render holds {len(rendered)} objects, expected "
        f"{EXPECTED_DEFAULT_OBJECTS}"
    )


def test_turning_the_toggle_on_reddens_the_zero_and_the_count():
    """THE RED CASE for the two numbers above, constructed rather than described.

    Without it both assertions above are satisfied by a chart that renders no
    ScaledObject under ANY values — including an `autoscaling.enabled` the template
    forgot to read, which is the defect a default-false toggle is most likely to hide.
    """
    with_the_scaled_object = render_with_the_scaled_object()
    assert with_the_scaled_object.returncode == 0, with_the_scaled_object.stderr
    rendered = objects(with_the_scaled_object.stdout)

    assert len(scaled_objects(rendered)) == 1, (
        "turning `autoscaling.enabled` on rendered no ScaledObject, so the zero above "
        "is a zero the chart reports under every values file and is no evidence"
    )
    assert len(rendered) == EXPECTED_OBJECTS_WITH_THE_SCALED_OBJECT, (
        f"the render with the toggle on holds {len(rendered)} objects, expected "
        f"{EXPECTED_OBJECTS_WITH_THE_SCALED_OBJECT}"
    )


def test_the_render_check_names_the_group_the_values_file_records():
    """ONE SOURCE FOR THE OPERATOR STRING, asserted across the two files that hold it.

    The group-and-version string is READ OFF the operator and RECORDED IN THE VALUES
    FILE beside the check that uses it, so an operator upgrade that moved the version
    turns the check red rather than silently weakening it. The check itself must pass
    a LITERAL — `test_render_checks.py` reads the invocation's arguments off the
    template — so the string exists in two places and this is the gate that keeps
    them one.

    COPIED FROM `yadgarhq/iam-db`'s
    `test_mariadb.py::test_the_render_check_names_the_group_the_values_file_records`
    (ADR-0679), with `database.mariadbOperator.apiVersion` replaced by this chart's
    own recorded path.
    """
    recorded = chart_values()
    for key in RECORDED_GROUP_PATH:
        recorded = recorded[key]

    declared = declared_checks(CHART)
    assert recorded in declared, (
        f"values.yaml records {recorded} as KEDA's group and the chart's checks ask "
        f"for {sorted(declared)}; the two disagree, so the recorded string is "
        f"documentation rather than the thing under test"
    )
    assert declared[recorded] == EXPECTED_CHECKS[recorded], declared[recorded]


def test_the_scaled_object_is_the_group_the_check_guards():
    """The object rendered and the group checked are the same group.

    A check naming a group no rendered object belongs to refuses installs for a
    prerequisite this chart does not actually need, and — the direction that matters
    — the ScaledObject's own group going unchecked is the apply-time `no matches for
    kind` the check exists to turn into a render-time refusal.

    SCOPED TO THE SCALED OBJECT, NEVER A CENSUS OF EVERY RENDERED GROUP. The census
    form would demand a check for every CRD-backed group this chart renders, and
    `gateway.enabled` is the one toggle in this estate that is true by default — so
    the only way to green a census is a Gateway API check behind a default-true
    toggle, which would refuse every offline render in the estate. The rule is about
    the toggle's DEFAULT, not about the API group.
    """
    rendered = objects(render_with_the_scaled_object().stdout)
    (scaled_object,) = scaled_objects(rendered)
    declared = declared_checks(CHART)

    assert scaled_object["apiVersion"] in declared, (
        f"the ScaledObject is {scaled_object['apiVersion']} and the chart's checks ask "
        f"for {sorted(declared)} — an object whose group no check guards fails at "
        f"APPLY naming a kind instead of at render naming an operator"
    )


def test_the_suite_reads_the_chart_this_repository_ships():
    """The paths, asserted rather than assumed — a suite reading elsewhere proves nothing."""
    assert CHART == REPO / "chart", CHART
    assert (CHART / "Chart.yaml").exists(), CHART
    assert yaml.safe_load((CHART / "Chart.yaml").read_text())["name"] == CHART_NAME
