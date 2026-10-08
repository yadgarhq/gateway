"""THE CLOSED KEY SET, `values.schema.json` (ledger 990, ADR-0847, ADR-0850).

WHAT THIS FILE IS NOT. `test_render_checks.py` and `test_autoscaling.py` assert
what `autoscaling.enabled` is READ AS, once it is read. This file asserts which
KEYS are read AT ALL: every block `chart/values.yaml` declares is now closed, so
a typo under any of them is refused BY NAME at render, rather than merged into
the values tree and silently never read. ADR-0847 draws the line between the
two files: TYPES, toggle SHAPES and `required` stay in `render-checks.yaml`;
this file closes KEY SETS and nothing else. A value written at the wrong SHAPE
— a string where a block belongs, a non-bool on a toggle — PASSES this schema
and is the other file's refusal to make; the two cases below prove it rather
than assert it from the two files' names alone.

THREE PATHS STAY OPEN (`OPEN` below) and are asserted bare `{}`, never typed:
`global` (Helm's reserved key, ADR-0722), `resources`
(`corev1.ResourceRequirements`, re-typed nowhere in this chart) and
`rollingUpdate` (`appsv1.RollingUpdateDeployment`, same reason). TWO EXTRAS
(`EXTRAS` below) are declared though `values.yaml` never states them, because a
template reads them anyway: `image.digest` (`templates/deployment.yaml`, D65/
D61) and `networkPolicy.scrapeFrom.namespace` (`templates/networkpolicy.yaml`).
ONE PAIR PREDATES THIS CLOSURE (`RETAINED` below) and is excluded from the
EXTRAS accounting rather than folded into it: `toolsPoll` /
`toolsPoll.intervalSeconds`, which override `chart/config/gateway.yaml` and
which `values.yaml` deliberately never states at all (ADR-0569, one source per
knob) — the schema's own `$comment` carries the full reasoning.

THREE MORE ARE EXCLUDED THE SAME WAY, FOR THE OPPOSITE REASON (`REQUIRED_NO_DEFAULT`
below, ledger 965, 1278, ADR-0845): `task.tls.enabled`, `iam.tls.enabled` and
`project.tls.enabled` are declared `type: boolean` and `required` in the schema
and ABSENT from `values.yaml`, on purpose — a dial's TLS switch has no chart
default and no binary default either (ADR-0569), so `values.yaml` ships no
value for any of the three and every consumer must set one explicitly. These are
not EXTRAS: EXTRAS is "a template reads this leaf though `values.yaml` never
states it"; these three are "this leaf exists, is required, and `values.yaml`
is the ONE place guaranteed never to supply it". Folding them into EXTRAS would
make the EXTRAS test pass without saying why these three are schema-only, which
is the exact blindness `test_every_schema_extra_is_exactly_the_declared_set`
exists to refuse.

THE STRUCTURAL TESTS BELOW ARE PURE — no helm, no subprocess — and are the ones
the module's four required mutations are checked against: delete root
`additionalProperties`, delete `global`, delete one extra, close one open map.
Each mutation is its own test, built on a FRESH read of the real file so one
mutated copy cannot bleed into the next assertion.

THE RENDER TESTS use `helm template`, reusing `CHART`, `render` and `helm` from
`test_render_checks.py` rather than re-deriving the chart path or the binary
lookup a second time.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from test_render_checks import CHART, helm, render

SCHEMA = CHART / "values.schema.json"
VALUES = CHART / "values.yaml"

# Paths whose schema node MUST be the bare `{}` an open map is. See the
# module docstring and the schema's own `$comment` for why each is open.
OPEN = ("global", "resources", "rollingUpdate")

# Leaves a template reads that `values.yaml` never states (§2 step 2's
# "read-but-undeclared keys"), declared here as closed-block leaves rather
# than left as open maps.
EXTRAS = ("image.digest", "networkPolicy.scrapeFrom.namespace")

# Declared leaves that predate this closure, excluded from the EXTRAS
# accounting below because they were never derived from a template grep —
# `toolsPoll` overrides a document `values.yaml` deliberately never states a
# key for (ADR-0569).
RETAINED = ("toolsPoll", "toolsPoll.intervalSeconds")

# Required, with no chart default (ADR-0845, ledger 965, 1278): each dial's
# TLS switch. Excluded from the EXTRAS accounting for the opposite reason
# RETAINED is — see the module docstring.
REQUIRED_NO_DEFAULT = ("task.tls.enabled", "iam.tls.enabled", "project.tls.enabled")

KEDA = ("--api-versions", "keda.sh/v1alpha1")


# ── READERS, PURE ─────────────────────────────────────────────────────────


def load_schema() -> dict:
    return json.loads(SCHEMA.read_text())


def load_values() -> dict:
    return yaml.safe_load(VALUES.read_text())


def schema_paths(schema: dict, prefix: str = "") -> set[str]:
    """Every dotted path declared under some `properties` key, anywhere. PURE."""
    paths: set[str] = set()
    for key, node in schema.get("properties", {}).items():
        path = f"{prefix}.{key}" if prefix else key
        paths.add(path)
        if isinstance(node, dict):
            paths |= schema_paths(node, path)
    return paths


def values_paths(values: dict, prefix: str = "", open_paths: tuple[str, ...] = OPEN) -> set[str]:
    """Every dotted path `values.yaml` itself states, PURE.

    MIRRORS `gen_schema.py`'s OWN RECURSION: an open path's children are never
    visited, because the schema does not declare them either — an empty dict
    counts as a stated path with no children, exactly as `networkPolicy.
    scrapeFrom` does today.
    """
    paths: set[str] = set()
    for key, value in values.items():
        path = f"{prefix}.{key}" if prefix else key
        paths.add(path)
        if isinstance(value, dict) and value and path not in open_paths:
            paths |= values_paths(value, path, open_paths)
    return paths


def schema_node(schema: dict, path: str):
    """The node at a dotted path, or `None` if any step is undeclared. PURE."""
    cursor = schema
    for step in path.split("."):
        cursor = cursor.get("properties", {}).get(step)
        if cursor is None:
            return None
    return cursor


def open_paths_failures(schema: dict) -> list[str]:
    """Every `OPEN` path that is not the bare, unconstrained `{}` an open map
    is — the real gate `test_the_open_paths_are_exactly_bare` asserts, reused
    here so the mutation tests below call the actual check rather than a
    weaker stand-in for it.
    """
    failures = []
    for path in OPEN:
        node = schema_node(schema, path)
        if node != {}:
            failures.append(f"{path} is declared as {node!r}, not the bare {{}} an open map is")
    return failures


def nodes_with_properties(schema: dict, prefix: str = ""):
    """Yield (path, node) for every node in the tree carrying `properties`.

    `prefix` is `""` for the root itself, so a root-level offender prints as
    `(root)` rather than an empty string nobody can read as a path.
    """
    if "properties" in schema:
        yield prefix, schema
        for key, node in schema["properties"].items():
            if isinstance(node, dict):
                yield from nodes_with_properties(node, f"{prefix}.{key}" if prefix else key)


def closure_offenders(schema: dict) -> list[str]:
    return [
        path or "(root)"
        for path, node in nodes_with_properties(schema)
        if node.get("additionalProperties") is not False
    ]


def extras_found(schema: dict, values: dict) -> set[str]:
    return (
        schema_paths(schema)
        - values_paths(values)
        - {"global"}
        - set(RETAINED)
        - set(REQUIRED_NO_DEFAULT)
    )


def overlay(body, destination: Path) -> Path:
    """One values overlay, WRITTEN AS A WHOLE FILE. See `test_render_checks.py`'s
    `shape_overlay` for why: appending onto a sibling key can nest a value under
    the wrong parent and silently test a different shape than the one named.
    """
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(body if isinstance(body, str) else yaml.safe_dump(body))
    return path


def render_with_overlay(chart: Path, body, destination: Path, *extra_args: str):
    path = overlay(body, destination)
    return render(chart, "-f", str(path), *extra_args)


# ── STRUCTURAL TESTS, PURE ───────────────────────────────────────────────


def test_every_node_with_properties_is_closed():
    """`additionalProperties: false` wherever `properties` appears, root included.

    THE RED CASE for this is `test_mutation_deleting_root_additional_properties_
    reddens_the_closure_check` below — a fresh schema read, not this one mutated
    in place, so the mutation cannot leak into a later assertion.
    """
    offenders = closure_offenders(load_schema())
    assert offenders == [], (
        f"{offenders} carries `properties` with no `additionalProperties: false` "
        f"— an adopter's typo under it is accepted rather than refused"
    )


def test_the_open_paths_are_exactly_bare():
    """`global`, `resources` and `rollingUpdate` are `{}` — open, untyped, unchecked.

    NOT merely "has no `additionalProperties`": a node like `{"type": "object"}`
    would pass a laxer check and still be a TYPED open map, which is not what
    this chart ships for any of the three.
    """
    failures = open_paths_failures(load_schema())
    assert failures == [], "\n".join(failures)


def test_every_values_yaml_leaf_is_declared():
    """Every path `values.yaml` itself states is declared somewhere in the schema.

    THE DIRECTION THAT MATTERS MOST: a key `values.yaml` ships with no matching
    schema entry is refused by the chart's OWN defaults the moment somebody
    rewrites it, which is a worse failure than a typo ever is.
    """
    declared = schema_paths(load_schema())
    stated = values_paths(load_values())
    missing = sorted(stated - declared)
    assert missing == [], (
        f"chart/values.yaml states {missing} and the schema declares none of "
        f"them — an adopter writing the CORRECT key would be refused by it"
    )


def test_every_schema_extra_is_exactly_the_declared_set():
    """Schema paths beyond values.yaml, `global` and the retained pair == EXTRAS.

    BOTH DIRECTIONS AT ONCE: a path missing from EXTRAS that the schema still
    declares is undocumented (and untested below); a path in EXTRAS the schema
    no longer declares is stale documentation for a key nothing refuses.
    """
    found = extras_found(load_schema(), load_values())
    assert found == set(EXTRAS), (
        f"found {sorted(found)}, EXTRAS says {sorted(EXTRAS)} — a path declared "
        f"with no template reading it, or a template read with nothing "
        f"declared, is a typo in one of the two"
    )


# ── THE FOUR MUTATIONS (preamble: "mutation-check the key assertion") ──────


def test_mutation_deleting_root_additional_properties_reddens_the_closure_check():
    schema = load_schema()
    del schema["additionalProperties"]
    assert closure_offenders(schema) == ["(root)"]


def test_mutation_deleting_global_reddens_the_open_path_check():
    schema = load_schema()
    del schema["properties"]["global"]
    assert open_paths_failures(schema) != []


def test_mutation_deleting_an_extra_reddens_the_extras_check():
    schema = load_schema()
    del schema["properties"]["image"]["properties"]["digest"]
    found = extras_found(schema, load_values())
    assert found != set(EXTRAS)
    assert "image.digest" not in found


def test_mutation_closing_an_open_map_reddens_the_open_path_check():
    schema = load_schema()
    schema["properties"]["resources"] = {"properties": {}, "additionalProperties": False}
    assert open_paths_failures(schema) != []


def test_mutation_reopening_autoscaling_lets_the_root_level_typo_through(tmp_path):
    """THE RENDER-LEVEL MUTATION CHECK for the red cases below.

    The four Python mutations above prove the STRUCTURAL tests are falsifiable.
    This one proves the RENDER-based red case
    (`test_a_typo_under_autoscaling_is_refused_by_name`) actually depends on
    THIS schema's closure and not on some other guard reaching the key first:
    with `autoscaling` reopened, the exact same typo renders clean.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    schema = json.loads((copy / "values.schema.json").read_text())
    schema["properties"]["autoscaling"]["additionalProperties"] = True
    (copy / "values.schema.json").write_text(json.dumps(schema))

    result = render_with_overlay(copy, {"autoscaling": {"enabeld": True}}, tmp_path / "reopened")
    assert result.returncode == 0, (
        f"reopening `autoscaling` and the red case below STILL refused, so that "
        f"case is not exercising this schema's closure: {result.stderr}"
    )


# ── RED: A TYPO UNDER A CLOSED BLOCK IS REFUSED BY NAME ────────────────────


def test_a_root_typo_is_refused_by_name(tmp_path):
    result = render_with_overlay(CHART, {"autoscalng": {"enabled": True}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert "autoscalng" in result.stderr, result.stderr


def test_a_typo_under_autoscaling_is_refused_by_name(tmp_path):
    result = render_with_overlay(CHART, {"autoscaling": {"enabeld": True}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert "enabeld" in result.stderr, result.stderr


def test_a_typo_two_levels_down_is_refused_by_name(tmp_path):
    result = render_with_overlay(
        CHART, {"networkPolicy": {"scrapeFrom": {"namespac": "x"}}}, tmp_path
    )
    assert result.returncode != 0, result.stdout
    assert "namespac" in result.stderr, result.stderr


def test_helm_lint_strict_also_refuses_the_root_typo(tmp_path):
    """The same schema applies in `helm lint --strict`, which the `helm-lint`
    pre-commit hook runs — a schema that only `helm template` enforced would
    leave that hook blind to the very typo this file exists to catch.
    """
    path = overlay({"autoscalng": {"enabled": True}}, tmp_path)
    result = helm("lint", "--strict", str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    assert "autoscalng" in (result.stdout + result.stderr)


# ── GREEN: THE WRONG SHAPE PASSES THIS SCHEMA (ADR-0847 draws the line) ────


def test_a_quoted_toggle_passes_this_schema_and_is_the_render_checks_refusal(tmp_path):
    """`autoscaling.enabled: "false"` is a SHAPE fault, not a KEY fault.

    Ledger 1135 (`render-checks.yaml`'s own `kindIs "bool"` arm) is what refuses
    it. This schema declares no `type` on the leaf (ADR-0847) and must not be
    what is doing the refusing — the second assertion is the discriminator: a
    schema-shaped refusal reads `additional propert`, and this one must not.
    """
    result = render_with_overlay(CHART, {"autoscaling": {"enabled": "false"}}, tmp_path, *KEDA)
    assert result.returncode != 0, (
        "autoscaling.enabled: \"false\" rendered clean — render-checks.yaml's "
        "kindIs \"bool\" arm (ledger 1135) should have refused it"
    )
    assert "must be true or false" in result.stderr, result.stderr
    assert "additional propert" not in result.stderr.lower(), (
        f"the refusal names an additional property, so THIS schema caught it "
        f"rather than the render check — types do not belong here: {result.stderr}"
    )


def test_a_block_scalar_passes_this_schema_and_is_refused_downstream(tmp_path):
    """`autoscaling: "x"` is a BLOCK written as a scalar — also not this
    schema's job. §3.2 declares a block as `{"properties": ..., "additional
    Properties": false}` with NO `type`, so JSON Schema's `properties` keyword
    does not even apply to a non-object instance and this file passes it
    through whole; the refusal is `render-checks.yaml`'s own `kindIs "map"` arm.
    """
    result = render_with_overlay(CHART, 'autoscaling: "x"\n', tmp_path, *KEDA)
    assert result.returncode != 0, result.stdout
    assert "must be a map" in result.stderr, result.stderr
    assert "additional propert" not in result.stderr.lower(), result.stderr


def test_a_deleted_key_passes_this_schema_and_is_the_absent_sentence(tmp_path):
    """`autoscaling:` with no value is helm deleting a null-valued declared key —
    absent, not present-and-wrong — so this schema (which never sees the key at
    all) has nothing to refuse; `render-checks.yaml`'s `hasKey` arm does.
    """
    result = render_with_overlay(CHART, "autoscaling:\n", tmp_path)
    assert result.returncode != 0, result.stdout
    assert "is absent from the values" in result.stderr, result.stderr
    assert "additional propert" not in result.stderr.lower(), result.stderr


# ── GREEN: AN OPEN MAP TAKES ANY SHAPE UNDERNEATH ──────────────────────────


DEFAULT_OBJECT_COUNT = 6


def test_open_resources_takes_an_unknown_shape(tmp_path):
    result = render_with_overlay(CHART, {"resources": {"foo": {"bar": 1}}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT


def test_open_global_takes_an_unknown_key(tmp_path):
    result = render_with_overlay(CHART, {"global": {"whatever": 1}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT


def test_open_rolling_update_takes_an_unknown_key(tmp_path):
    result = render_with_overlay(CHART, {"rollingUpdate": {"partition": 1}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT


# ── GREEN: THE EXTRAS AND THE RETAINED TYPED LEAF ──────────────────────────


def test_the_image_digest_extra_is_accepted(tmp_path):
    result = render_with_overlay(
        CHART, {"image": {"digest": "sha256:" + "a" * 64}}, tmp_path
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT


def test_typed_network_policy_client_objects_still_render(tmp_path):
    """`networkPolicy.clients`' items KEEP their typed-object shape (module
    docstring: this chart's `from` peers differ from every sibling's name list),
    so a real peer object must still pass whole, not merely the key `clients`.
    """
    result = render_with_overlay(
        CHART,
        {
            "networkPolicy": {
                "enabled": True,
                "clients": [
                    {
                        "namespaceSelector": {"matchLabels": {"a": "b"}},
                        "podSelector": {"matchLabels": {"c": "d"}},
                    }
                ],
            }
        },
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT + 1


def test_an_untyped_leaf_takes_a_cli_override(tmp_path):
    result = render(CHART, "--set-string", "replicaCount=2")
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT


def test_the_retained_typed_leaf_still_refuses_its_own_minimum(tmp_path):
    """`toolsPoll.intervalSeconds` PREDATES this closure and keeps its own
    `integer, minimum 1` (§3.3) — one of the typed nodes that predate this
    closure (see the schema's `$comment`), because a wrong type here reaches
    `rotate::GatewayDocument::tools_poll_interval` at BOOT rather than at
    render. This schema's closure elsewhere must not have disturbed it.

    ASSERTS THE KEY, NEVER HELM'S SENTENCE: helm 3.18.4 prints `Must be
    greater than or equal to 1`; 3.20.2 and 4.3.0 print `minimum: got 0,
    want 1`. Both name `intervalSeconds`; neither shares a word with the
    other, so `intervalSeconds` is the only assertion stable across them.
    """
    result = render_with_overlay(CHART, {"toolsPoll": {"intervalSeconds": 0}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert "intervalSeconds" in result.stderr, result.stderr


# ── RENDER-NEUTRALITY (ADR-0645): THE LIVE SOURCES THIS SCHEMA MUST NOT BREAK ──


def test_the_default_render_is_unchanged():
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT


def test_the_argocd_gateway_section_still_renders(tmp_path):
    """A FROZEN COPY of that section as read on 2026-10-03; it does not track
    the other repository. The live gate for argocd and parent inputs is the
    parent chart's suite plus the K-9 valuesObject sweep before each pin bump.
    """
    body = {
        "adminBootstrap": {"tokenSecret": "admin-bootstrap-token"},
        "autoscaling": {"enabled": True},
        "gateway": {"enabled": True},
        "global": {"hostname": "gateway.yadgar.internal"},
        "iam": {"tls": {"enabled": True}},
        "networkPolicy": {
            "enabled": True,
            "clients": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "envoy-gateway-system"}
                    },
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "envoy",
                            "gateway.envoyproxy.io/owning-gateway-name": "edge",
                            "gateway.envoyproxy.io/owning-gateway-namespace": "yadgar",
                        }
                    },
                }
            ],
            "scrapeFrom": {"namespace": "observability"},
        },
        "project": {"tls": {"enabled": True}},
        "sourceAddress": {"trustedProxyHops": ""},
        "task": {"tls": {"enabled": True}},
    }
    result = render_with_overlay(CHART, body, tmp_path, *KEDA)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT + 2  # ScaledObject + NetworkPolicy


def test_the_parent_example_gateway_section_still_renders(tmp_path):
    """A FROZEN COPY of that section as read on 2026-10-03; it does not track
    the other repository. The live gate for argocd and parent inputs is the
    parent chart's suite plus the K-9 valuesObject sweep before each pin bump.
    """
    body = {
        "global": {"hostname": ""},
        "adminBootstrap": {"tokenSecret": "admin-bootstrap-token"},
        "autoscaling": {"enabled": True},
    }
    result = render_with_overlay(CHART, body, tmp_path, *KEDA)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("\nkind: ") == DEFAULT_OBJECT_COUNT + 1  # ScaledObject


def test_the_suite_reads_the_schema_this_repository_ships():
    assert SCHEMA.exists(), SCHEMA
    schema = load_schema()
    assert schema["title"] == "yadgar/gateway", schema["title"]
    assert schema["additionalProperties"] is False
