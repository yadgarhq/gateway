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
`valkey` and `valkey.tls` used to be here too, for the B-V3E expand, when
`values.yaml` declared no `valkey` block at all; B-V3 stated one
(`caSecret`/`caSecretKey`), so both paths are now ordinary stated paths rather
than template-reads-but-values.yaml-does-not.
ONE PAIR PREDATES THIS CLOSURE (`RETAINED` below) and is excluded from the
EXTRAS accounting rather than folded into it: `toolsPoll` /
`toolsPoll.intervalSeconds`, which override `chart/config/gateway.yaml` and
which `values.yaml` deliberately never states at all (ADR-0569, one source per
knob) — the schema's own `$comment` carries the full reasoning.

FIVE MORE ARE EXCLUDED THE SAME WAY, FOR THE OPPOSITE REASON (`REQUIRED_NO_DEFAULT`
below, ledger 965, 1278, ADR-0845): `task.tls.enabled`, `iam.tls.enabled`,
`project.tls.enabled`, `nats.tls.enabled` (B-N3) and, since B-V3,
`valkey.tls.enabled` are declared `type: boolean` and `required` in the schema
and ABSENT from `values.yaml`, on purpose — a dial's TLS switch has no chart
default and no binary default either (ADR-0569), so `values.yaml` ships no
value for any of the five and every consumer must set one explicitly. These are
not EXTRAS: EXTRAS is "a template reads this leaf though `values.yaml` never
states it"; these five are "this leaf exists, is required, and `values.yaml`
is the ONE place guaranteed never to supply it". Folding them into EXTRAS would
make the EXTRAS test pass without saying why these five are schema-only, which
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

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
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
EXTRAS = (
    "image.digest",
    "networkPolicy.scrapeFrom.namespace",
)

# Declared leaves that predate this closure, excluded from the EXTRAS
# accounting below because they were never derived from a template grep —
# `toolsPoll` overrides a document `values.yaml` deliberately never states a
# key for (ADR-0569).
RETAINED = ("toolsPoll", "toolsPoll.intervalSeconds")

# Required, with no chart default (ADR-0845, ledger 965, 1278): each dial's
# TLS switch. Excluded from the EXTRAS accounting for the opposite reason
# RETAINED is — see the module docstring.
REQUIRED_NO_DEFAULT = (
    "task.tls.enabled",
    "iam.tls.enabled",
    "project.tls.enabled",
    "nats.tls.enabled",
    "valkey.tls.enabled",
)

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


# ── THE CENSUS: NO type / enum / default / required ANYWHERE UNLESS LISTED ───
#
# ADR-0847 keeps `type`, `enum` and `default` out of this schema; ADR-0845 and
# ADR-1006 put a few back on purpose. The spot checks above pin SPECIFIC
# leaves. They do not stop a new `type`, `enum`, `default` or `required` landing
# on any OTHER node, nor an `enum` riding in on a leaf that is already typed. The
# census walks EVERY node and compares it with two data tables, so a deliberate
# schema change must edit the table in the same PR (yaadgaar 327).
#
# `TYPED_ON_PURPOSE` maps each leaf path that carries keywords to the exact node
# it must equal; every other leaf must be `{}`. `BLOCKS_ON_PURPOSE` maps each
# block path that carries keywords besides `properties` and
# `additionalProperties` to those keywords; every other block carries none. The
# ROOT is the block path `""`. Prose keys (`description`, `$comment`, `$schema`,
# `title`) are ignored: they decide nothing. `default` and `enum` are refused
# everywhere, also inside a nested sub-schema (`anyOf`, `items`), with no table
# to excuse them (ADR-0705: a consequential knob carries no default, and a
# schema `default` is a second source for the chart default).
# The tables are data so ADR-0705's REQUIRED list (yaadgaar 336) can extend them.
#
# UNDELIBERATE? (yaadgaar 327): the entries below carry a `type`, `items` or
# `minimum` that no ADR, ruling or yaadgaar task cited by this chart covers, and
# ADR-0847 says a schema holds no types. The schema's own `$comment` says only
# that they "predate" the closure. They are pinned here as shipped, not deleted:
# `networkPolicy` and `networkPolicy.scrapeFrom` (`type: object`),
# `networkPolicy.enabled` (`boolean`), `networkPolicy.clients` (`array` of
# `object`), `networkPolicy.scrapeFrom.namespace` (`string`), `toolsPoll`
# (`object`) and `toolsPoll.intervalSeconds` (`integer`, `minimum: 1`), plus the
# bare `type: object` on the blocks `valkey`, `valkey.tls` and `nats.tls`.
# ADR-0845 (TLS switches), ADR-0925 / ADR-0569 / ADR-1006 (timeouts and cache TTL)
# and ADR-0520 / yaadgaar 513 (`sourceAddress.trustedProxyHops`) cover the rest.
# A ruling to keep or strip an undeliberate entry edits this table in the PR.

TYPED_ON_PURPOSE: dict[str, dict[str, Any]] = {
    "task.requestTimeoutSeconds": {"type": "integer", "minimum": 14, "maximum": 18},
    "task.tls.enabled": {"type": "boolean"},
    "iam.requestTimeoutSeconds": {"type": "integer", "minimum": 14, "maximum": 59},
    "iam.tls.enabled": {"type": "boolean"},
    "project.requestTimeoutSeconds": {"type": "integer", "minimum": 14, "maximum": 59},
    "project.tls.enabled": {"type": "boolean"},
    "credentialCache.ttlSeconds": {"type": "integer"},
    "nats.tls.enabled": {"type": "boolean"},
    "valkey.tls.enabled": {"type": "boolean"},
    "server.limits.headerReadTimeoutSeconds": {"type": "integer", "minimum": 1, "maximum": 60},
    "sourceAddress.trustedProxyHops": {"anyOf": [{"type": "null"}, {"type": "integer", "minimum": 0, "maximum": 16}, {"type": "string"}]},
    "adminBootstrap.refusePreMintedUserId": {"type": "boolean"},
    "networkPolicy.enabled": {"type": "boolean"},
    "networkPolicy.clients": {"type": "array", "items": {"type": "object", "description": "One NetworkPolicyPeer. Selectors written in ONE entry are an AND; the same two written as two entries are an OR and admit far more."}},
    "networkPolicy.scrapeFrom.namespace": {"type": "string"},
    "toolsPoll.intervalSeconds": {"type": "integer", "minimum": 1},
}

BLOCKS_ON_PURPOSE: dict[str, dict[str, Any]] = {
    "task": {"required": ["requestTimeoutSeconds"]},
    "task.tls": {"required": ["enabled"]},
    "iam": {"required": ["requestTimeoutSeconds"]},
    "iam.tls": {"required": ["enabled"]},
    "project": {"required": ["requestTimeoutSeconds"]},
    "project.tls": {"required": ["enabled"]},
    "credentialCache": {"required": ["ttlSeconds"]},
    "nats.tls": {"type": "object", "required": ["enabled"]},
    "valkey": {"type": "object"},
    "valkey.tls": {"type": "object", "required": ["enabled"]},
    "server.limits": {"required": ["headerReadTimeoutSeconds"]},
    "adminBootstrap": {"required": ["refusePreMintedUserId"]},
    "networkPolicy": {"type": "object"},
    "networkPolicy.scrapeFrom": {"type": "object"},
    "toolsPoll": {"type": "object"},
}

BOUNDED_LEAF = "server.limits.headerReadTimeoutSeconds"
CENSUS_PROSE = frozenset({"description", "$comment", "$schema", "title"})
CENSUS_STRUCTURE = frozenset({"properties", "additionalProperties"})


def _census_keywords(node: dict[str, Any], skip: frozenset[str]) -> dict[str, Any]:
    kept = {key: value for key, value in node.items() if key not in skip}
    if "required" in kept:
        kept["required"] = sorted(kept["required"])
    return kept


def _nested_refusals(node: Any, where: str) -> list[str]:
    """`default` or `enum` anywhere inside a keyword's value (`anyOf`, `items`,
    ...). A `properties` map is walked by the caller, so its keys are not
    keywords here. PURE."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("default", "enum"):
                found.append(f"{where}: carries a nested `{key}`")
            elif key != "properties":
                found.extend(_nested_refusals(value, where))
    elif isinstance(node, list):
        for item in node:
            found.extend(_nested_refusals(item, where))
    return found


def census_failures(
    schema: dict[str, Any],
    typed: dict[str, dict[str, Any]] | None = None,
    blocks: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Every node whose keywords differ from the tables above. PURE."""
    typed = TYPED_ON_PURPOSE if typed is None else typed
    blocks = BLOCKS_ON_PURPOSE if blocks is None else blocks
    failures: list[str] = []
    seen_leaves: set[str] = set()
    seen_blocks: set[str] = set()

    def walk(node: dict[str, Any], path: str) -> None:
        where = path or "<root>"
        if "default" in node:
            failures.append(f"{where}: carries a `default`")
        if "enum" in node:
            failures.append(f"{where}: carries an `enum`")
        failures.extend(
            _nested_refusals({k: v for k, v in node.items() if k not in ("default", "enum")}, where)
        )
        if "properties" in node:
            seen_blocks.add(path)
            expected = _census_keywords(blocks.get(path, {}), frozenset())
            actual = _census_keywords(node, CENSUS_PROSE | CENSUS_STRUCTURE)
            if actual != expected:
                failures.append(f"{where}: block keywords {actual} != {expected}")
            for key, child in node["properties"].items():
                walk(child, f"{path}.{key}" if path else key)
        else:
            seen_leaves.add(path)
            expected = _census_keywords(typed.get(path, {}), frozenset())
            actual = _census_keywords(node, CENSUS_PROSE)
            if actual != expected:
                failures.append(f"{where}: leaf {actual} != {expected}")

    walk(schema, "")
    for path in sorted(set(typed) - seen_leaves):
        failures.append(f"{path}: TYPED_ON_PURPOSE names a leaf the schema does not have")
    for path in sorted(set(blocks) - seen_blocks):
        failures.append(f"{path or '<root>'}: BLOCKS_ON_PURPOSE names a block the schema does not have")
    return failures


def a_census_untyped_leaf(schema: dict[str, Any]) -> str:
    """The first leaf path (sorted) that no table excuses. PURE."""
    leaves: list[str] = []

    def walk(node: dict[str, Any], path: str) -> None:
        if "properties" in node:
            for key, child in node["properties"].items():
                walk(child, f"{path}.{key}" if path else key)
        elif path not in TYPED_ON_PURPOSE and node == {}:
            leaves.append(path)

    walk(schema, "")
    return sorted(leaves)[0]


def census_node(schema: dict[str, Any], path: str) -> dict[str, Any]:
    node = schema
    for step in path.split(".") if path else []:
        node = node["properties"][step]
    return node


def test_the_census_is_clean_on_the_shipped_schema() -> None:
    assert census_failures(load_schema()) == []


def test_the_census_tables_name_only_nodes_that_carry_keywords() -> None:
    assert all(TYPED_ON_PURPOSE.values()), "an empty TYPED_ON_PURPOSE entry excuses nothing"
    assert all(BLOCKS_ON_PURPOSE.values()), "an empty BLOCKS_ON_PURPOSE entry excuses nothing"


def test_the_census_ignores_prose() -> None:
    mutated = copy.deepcopy(load_schema())
    mutated["$comment"] = "reworded"
    census_node(mutated, "task.tls.enabled")["description"] = "reworded"
    census_node(mutated, a_census_untyped_leaf(mutated))["description"] = "reworded"
    assert census_failures(mutated) == []


def census_mutations() -> dict[str, Any]:
    """Name -> mutator(schema) for every row of the red table. Each must redden."""

    def on_untyped(change: dict[str, Any]):
        def mutate(schema: dict[str, Any]) -> None:
            census_node(schema, a_census_untyped_leaf(schema)).update(change)

        return mutate

    def on_node(path: str, change: dict[str, Any]):
        def mutate(schema: dict[str, Any]) -> None:
            census_node(schema, path).update(change)

        return mutate

    def delete_key(path: str, key: str):
        def mutate(schema: dict[str, Any]) -> None:
            del census_node(schema, path)[key]

        return mutate

    def replace_node(path: str, node: dict[str, Any]):
        def mutate(schema: dict[str, Any]) -> None:
            parent, _, leaf = path.rpartition(".")
            census_node(schema, parent)["properties"][leaf] = node

        return mutate

    def drop_required(path: str, name: str):
        def mutate(schema: dict[str, Any]) -> None:
            census_node(schema, path)["required"].remove(name)

        return mutate

    def nested_in_any_of(path: str, index: int, change: dict[str, Any]):
        def mutate(schema: dict[str, Any]) -> None:
            census_node(schema, path)["anyOf"][index].update(change)

        return mutate

    def drop_any_of_branch(path: str, index: int):
        def mutate(schema: dict[str, Any]) -> None:
            del census_node(schema, path)["anyOf"][index]

        return mutate

    def nested_in_items(path: str, change: dict[str, Any]):
        def mutate(schema: dict[str, Any]) -> None:
            census_node(schema, path)["items"].update(change)

        return mutate

    return {
        # keyword added where the table lists none
        "type on an untyped leaf": on_untyped({"type": "string"}),
        "enum on an untyped leaf": on_untyped({"enum": ["a", "b"]}),
        "default on an untyped leaf": on_untyped({"default": "x"}),
        "required on an untyped leaf": on_untyped({"required": ["x"]}),
        "minimum on an untyped leaf": on_untyped({"minimum": 1}),
        # keyword riding on a leaf that is already typed on purpose
        "default on task.tls.enabled": on_node("task.tls.enabled", {"default": True}),
        "enum on task.tls.enabled": on_node("task.tls.enabled", {"enum": [True]}),
        "default on a bounded integer": on_node(BOUNDED_LEAF, {"default": 5}),
        "enum on a bounded integer": on_node(BOUNDED_LEAF, {"enum": [5]}),
        # a typed leaf drifts
        "bound raised": on_node(BOUNDED_LEAF, {"maximum": TYPED_ON_PURPOSE[BOUNDED_LEAF]["maximum"] + 1}),
        "bound lowered": on_node(BOUNDED_LEAF, {"minimum": TYPED_ON_PURPOSE[BOUNDED_LEAF]["minimum"] + 1}),
        "bound dropped": delete_key(BOUNDED_LEAF, "maximum"),
        "type changed": on_node(BOUNDED_LEAF, {"type": "number"}),
        # a typed leaf loses its keywords (the reverse direction)
        "task.tls.enabled loses its type": replace_node("task.tls.enabled", {}),
        "bounded integer loses its type": replace_node(BOUNDED_LEAF, {}),
        # blocks
        "type on a block that has none": on_node("task", {"type": "object"}),
        "enum on a block": on_node("task", {"enum": [{}]}),
        "default on a block": on_node("task", {"default": {}}),
        "extra required on a block": on_node("task.tls", {"required": ["enabled", "caSecret"]}),
        "required key dropped from a block": drop_required("task.tls", "enabled"),
        "required dropped from a block": delete_key("task.tls", "required"),
        # the multi-branch leaf: a keyword hidden inside `anyOf` still reddens
        "enum inside a trustedProxyHops branch": nested_in_any_of("sourceAddress.trustedProxyHops", 1, {"enum": [1, 2]}),
        "default inside a trustedProxyHops branch": nested_in_any_of("sourceAddress.trustedProxyHops", 1, {"default": 1}),
        "enum inside a trustedProxyHops string branch": nested_in_any_of("sourceAddress.trustedProxyHops", 2, {"enum": ["1"]}),
        "default inside a trustedProxyHops string branch": nested_in_any_of("sourceAddress.trustedProxyHops", 2, {"default": "1"}),
        "key inside the trustedProxyHops null branch": nested_in_any_of("sourceAddress.trustedProxyHops", 0, {"pattern": "x"}),
        "trustedProxyHops maximum raised": nested_in_any_of("sourceAddress.trustedProxyHops", 1, {"maximum": 17}),
        "trustedProxyHops null branch dropped": drop_any_of_branch("sourceAddress.trustedProxyHops", 0),
        "default on trustedProxyHops": on_node("sourceAddress.trustedProxyHops", {"default": 1}),
        "default inside networkPolicy.clients items": nested_in_items("networkPolicy.clients", {"default": {}}),
        "enum inside networkPolicy.clients items": nested_in_items("networkPolicy.clients", {"enum": [{}]}),
        # undeliberate entries are pinned: strip or retype one and the census reddens
        "networkPolicy.enabled loses its type": replace_node("networkPolicy.enabled", {}),
        "toolsPoll.intervalSeconds loses its minimum": delete_key("toolsPoll.intervalSeconds", "minimum"),
        "credentialCache.ttlSeconds gains a bound": on_node("credentialCache.ttlSeconds", {"minimum": 1}),
        "valkey loses its type": delete_key("valkey", "type"),
        "nats.tls loses its type": delete_key("nats.tls", "type"),
        "iam.requestTimeoutSeconds bound raised": on_node("iam.requestTimeoutSeconds", {"maximum": 60}),
        "task.requestTimeoutSeconds bound raised": on_node("task.requestTimeoutSeconds", {"maximum": 19}),
        "refusePreMintedUserId loses its type": replace_node("adminBootstrap.refusePreMintedUserId", {}),
        "required dropped from server.limits": delete_key("server.limits", "required"),
        "required key dropped from credentialCache": drop_required("credentialCache", "ttlSeconds"),
        "required dropped from nats.tls": drop_required("nats.tls", "enabled"),
        # root
        "type on the root": on_node("", {"type": "object"}),
        "default on the root": on_node("", {"default": {}}),
        "required on the root": on_node("", {"required": ["tls"]}),
    }


@pytest.mark.parametrize("name", sorted(census_mutations()))
def test_the_census_reddens_on(name: str) -> None:
    mutated = copy.deepcopy(load_schema())
    census_mutations()[name](mutated)
    assert census_failures(mutated) != [], name


def test_a_stale_typed_entry_reddens_the_census() -> None:
    typed = {**TYPED_ON_PURPOSE, "no.such.leaf": {"type": "string"}}
    assert census_failures(load_schema(), typed=typed) != []


def test_a_stale_block_entry_reddens_the_census() -> None:
    blocks = {**BLOCKS_ON_PURPOSE, "no.such.block": {"required": ["x"]}}
    assert census_failures(load_schema(), blocks=blocks) != []


def test_a_typed_table_missing_an_entry_reddens_the_census() -> None:
    typed = {path: node for path, node in TYPED_ON_PURPOSE.items() if path != "task.tls.enabled"}
    assert census_failures(load_schema(), typed=typed) != []


def test_a_block_table_missing_an_entry_reddens_the_census() -> None:
    blocks = {path: node for path, node in BLOCKS_ON_PURPOSE.items() if path != "task.tls"}
    assert census_failures(load_schema(), blocks=blocks) != []
