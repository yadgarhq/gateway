"""THE EDGE'S INGRESS ALLOW-LIST: who may reach this module, and on which ports.

WHAT THIS SUITE IS FOR, AND WHY IT IS NOT A CENSUS. Every gate below asserts a
REFERENCE between two objects the SAME RENDER produces — the policy's
`podSelector` against the pod labels the Deployment stamps, the policy's serving
port against the `containerPort` the Deployment declares — and only then asserts
how many of each it examined. A count is the denominator of a reference
assertion here, never the assertion itself. Counting objects is the failure this
estate has shipped repeatedly: a selector that matches nothing renders an object,
so a census stays green while the reference is broken.

THE MATCHERS ARE COPIED, NOT RE-DERIVED (ADR-0679). `from_less_rules`,
`policy_ports` and `rules_admitting` are `yadgarhq/platform`'s
`scripts/tests/test_shared_infrastructure.py` verbatim, docstrings included,
because they were written and reviewed for exactly this question. Re-deriving a
hardened matcher is what ADR-0679 forbids, and the one that matters most here is
`from_less_rules`: `not rule.get("from")` rather than `"from" not in rule`, so
`from: []` is seen as the allow-all it is.

WHY THIS CHART CARRIES A POLICY AT ALL, GIVEN ADR-0685. That decision placed
this estate's own copy of the edge allow-list in the repository that declares the
`Gateway` object its selector is derived from, and that copy is untouched. What
this chart adds is ADR-0685's own recorded viable alternative — a `from` supplied
by values, so the template carries no ingress-implementation literal. The
template's header states it at length.

THE RENDERS. R1 is the chart's shipped `values.yaml`, where `networkPolicy.enabled`
is false and this template renders NOTHING. R2 is R1 with an adopter's policy
values layered on: a peer for the serving port and a namespace for the scrape.
R3 is R2 with whatever a red case needs stated explicitly.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"

# ── WHAT THIS CHART'S POLICY ADMITS, WRITTEN DOWN ────────────────────────────
# Counts are LITERALS for the reason every expected number in this estate is
# one: a number derived from the render agrees with whatever the render happens
# to be.
EXPECTED_INGRESS_RULES = 2  # the serving port, and the scrape
POLICY_NAME = "gateway-ingress"

# The serving port, and the metrics port. Both are asserted against the
# Deployment the SAME RENDER produces rather than trusted from here: `SERVING`
# against its `containerPort`, `METRICS` against its `METRICS_LISTEN`.
SERVING_PORT = 8080
METRICS_PORT = 9090

# ── THE PORTS ADMITTED FROM EVERY SOURCE, WRITTEN DOWN ───────────────────────
# An ingress rule with no `from` matches ALL sources — every namespace, and
# whatever else the CNI presents to the pod (ADR-0664). THIS POLICY CARRIES NO
# SUCH RULE ON ANY PORT.
#
# AN EMPTY EXPECTATION DOES NOT MAKE THIS VACUOUS. Two red cases below construct
# the non-empty path — one cuts the `from` out of the serving rule, one supplies
# `from: []` through values — and each asserts this census would go red on it.
# `set()` is the strongest form this gate takes, not the absence of one.
#
# THIS IS WHAT THE PEER GATE CANNOT SEE. A rule carrying no `from` contributes
# no peers, so a peer census reports the same sources it always did while the
# port stands open to the cluster.
EXPECTED_ALLOW_ALL_PORTS: set[int] = set()

# The namespace the scrape rule must name, and the label it must select on.
# A SENTINEL the template could not plausibly contain, so a template that
# hardcoded `observability` — or any other real namespace — fails here instead
# of agreeing with a fixture that had copied it.
SENTINEL_SCRAPE_NAMESPACE = "sentinel-scrape-namespace-1999"
NAMESPACE_LABEL = "kubernetes.io/metadata.name"

# The adopter's policy values, as `chart/values.yaml`'s own comment writes them.
# The peer's two selectors sit in ONE entry, which means AND.
ADOPTER_POLICY_VALUES = f"""
networkPolicy:
  enabled: true
  clients:
    - namespaceSelector:
        matchLabels:
          {NAMESPACE_LABEL}: envoy-gateway-system
      podSelector:
        matchLabels:
          app.kubernetes.io/name: envoy
          gateway.envoyproxy.io/owning-gateway-name: edge
          gateway.envoyproxy.io/owning-gateway-namespace: yadgar
  scrapeFrom:
    namespace: {SENTINEL_SCRAPE_NAMESPACE}
"""

# The peer that entry names, read back out of the render. Written here rather
# than parsed out of the string above, so a gate cannot agree with its own input.
EXPECTED_SERVING_PEER = {
    "namespaceSelector": {"matchLabels": {NAMESPACE_LABEL: "envoy-gateway-system"}},
    "podSelector": {
        "matchLabels": {
            "app.kubernetes.io/name": "envoy",
            "gateway.envoyproxy.io/owning-gateway-name": "edge",
            "gateway.envoyproxy.io/owning-gateway-namespace": "yadgar",
        }
    },
}


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why. Same wording as `yadgarhq/platform`'s
    # suites, which made the same decision for the same reason.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def template(chart: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "gateway", str(chart), *arguments)


def documents(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def render(chart: Path, *arguments: str) -> list[dict]:
    result = template(chart, *arguments)
    assert result.returncode == 0, result.stderr
    return documents(result.stdout)


def defaults_render(chart: Path = CHART) -> list[dict]:
    """R1 — the chart's shipped values, bare."""
    return render(chart)


def values_file(destination: Path, body: str) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body)
    return destination


def policy_render(tmp_path: Path, chart: Path = CHART, body: str | None = None):
    """R2 — the shipped values with an adopter's policy block layered on."""
    overlay = values_file(
        tmp_path / "policy-values.yaml",
        ADOPTER_POLICY_VALUES if body is None else body,
    )
    return render(chart, "-f", str(overlay))


def of_kind(rendered: list[dict], kind: str) -> list[dict]:
    return [document for document in rendered if document.get("kind") == kind]


def by_name(rendered: list[dict], kind: str, name: str) -> dict:
    found = [
        document
        for document in of_kind(rendered, kind)
        if document["metadata"]["name"] == name
    ]
    assert len(found) == 1, (
        f"expected exactly one {kind} named {name}, found {len(found)} of "
        f"{[document['metadata']['name'] for document in of_kind(rendered, kind)]}"
    )
    return found[0]


def pod_labels(workload: dict) -> dict:
    return workload["spec"]["template"]["metadata"]["labels"]


def container_ports(workload: dict) -> set[int]:
    """Every `containerPort` the workload's containers declare. PURE."""
    return {
        port["containerPort"]
        for container in workload["spec"]["template"]["spec"]["containers"]
        for port in container.get("ports") or []
    }


def environment(workload: dict) -> dict[str, str]:
    """The first container's environment, by name. PURE."""
    container = workload["spec"]["template"]["spec"]["containers"][0]
    return {
        entry["name"]: entry.get("value", "")
        for entry in container.get("env") or []
        if "name" in entry
    }


# ── THE THREE MATCHERS, COPIED FROM `yadgarhq/platform` (ADR-0679) ───────────
# `scripts/tests/test_shared_infrastructure.py`, verbatim. ADR-0679 forbids
# re-deriving a hardened matcher, and these three were written and reviewed for
# exactly the question this file asks.


def from_less_rules(policy: dict) -> list[dict]:
    """Every ingress rule that names NO source, i.e. every rule admitting all of them. PURE.

    `not rule.get("from")` rather than `"from" not in rule`, and the difference is
    the whole gate. A rule carrying `from: []` is the SAME allow-all to the API
    server as a rule carrying no `from` key at all — ADR-0664 read it off the
    OpenAPI description compiled into the kubectl binary: "If this field is empty or
    missing, this rule matches all sources". The empty-list shape is also the one a
    values override or a `range` over an empty list produces, so a predicate keyed
    on the missing KEY would miss the shape most likely to arrive.
    """
    return [rule for rule in policy["spec"]["ingress"] if not rule.get("from")]


def policy_ports(policy: dict) -> set[int]:
    return {
        port["port"]
        for rule in policy["spec"]["ingress"]
        for port in rule.get("ports", [])
    }


def rules_admitting(policy: dict, port: int) -> list[dict]:
    """Every ingress rule of `policy` that names `port`. PURE.

    RETURNS THE LIST RATHER THAN THE RULE, and the caller asserts its length. A
    helper that returned "the" rule would have to pick one when a policy names the
    same port twice — two rules on one port are an OR, so a second one widens what
    is admitted while the first still reads correctly — and it would have to raise
    or return `None` when there are none, which is the shape that lets a caller
    written as `for rule in ...:` pass over an empty list in silence.
    """
    return [
        rule
        for rule in policy["spec"]["ingress"]
        if any(named["port"] == port for named in rule.get("ports", []))
    ]


def without_the_serving_from(text: str) -> str:
    """`templates/networkpolicy.yaml` with the serving rule's `from` cut out.

    THE RESULT IS THE SHAPE ADR-0664 EXISTS TO REFUSE — a bare `- ports:` on the
    serving port, admitting every source in the cluster — reached PAST the `fail`
    guard, which sees a non-empty `clients` list and lets the render through.
    That is what makes this red case different from the guard's own: the guard
    proves the empty-list path refuses, and this proves the census would catch a
    from-less rule that reached the object anyway.

    Written as an index walk from the rule's own comment heading rather than as a
    `str.replace` of the whole block, because a replace whose pattern drifts
    returns the text UNCHANGED and `chart_with`'s tripwire would then be the only
    thing standing between this red case and a silent pass. `str.index` raises
    instead, naming the anchor that moved.
    """
    heading = text.index("# THE CALLERS, ON THE SERVING PORT")
    start = text.index("      from:\n", heading)
    end = text.index("    {{- if .Values.networkPolicy.scrapeFrom.namespace }}", start)
    return text[:start] + text[end:]


def with_an_empty_serving_from(text: str) -> str:
    """The same rule with `from: []` in place of its peers — the OTHER allow-all shape.

    ADR-0664 rules the two equivalent to the API server, and `from_less_rules`
    sees both. This case proves the SECOND one is seen, because a predicate keyed
    on the missing key would pass over it while the port stood open.
    """
    heading = text.index("# THE CALLERS, ON THE SERVING PORT")
    start = text.index("      from:\n", heading)
    end = text.index("    {{- if .Values.networkPolicy.scrapeFrom.namespace }}", start)
    return text[:start] + "      from: []\n" + text[end:]


def with_a_moved_pod_label(text: str) -> str:
    """`templates/deployment.yaml` stamping a label the policy does not select."""
    return text.replace(
        "      labels:\n        app: {{ .Chart.Name }}\n",
        "      labels:\n        app: {{ .Chart.Name }}-moved\n",
        1,
    )


def chart_with(destination: Path, relative: str, edit) -> Path:
    """A throwaway copy of the chart with one template rewritten. Red cases only.

    THE EDIT IS ASSERTED TO HAVE LANDED, and that is not ceremony. A `str.replace`
    whose pattern no longer matches the template returns the text UNCHANGED, so the
    red case would render the real chart, find the reference intact and report a
    pass — a red case that silently stopped constructing anything. Every caller
    below reaches this through one function so the tripwire cannot be forgotten in
    one of them.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    target = copy / relative
    before = target.read_text()
    after = edit(before)
    assert after != before, (
        f"the red case's edit to {relative} changed nothing, so it is "
        f"constructing no counter-example at all"
    )
    target.write_text(after)
    return copy


# ── THE SHIPPED DEFAULTS ─────────────────────────────────────────────────────


def test_the_defaults_render_no_policy():
    """R1 — `networkPolicy.enabled` is false, so nothing here reaches a cluster.

    THE DENOMINATOR IS PRINTED. A render that quietly stopped producing objects
    at all would satisfy "no NetworkPolicy" for the wrong reason, so the total is
    reported beside the zero.
    """
    rendered = defaults_render()
    policies = of_kind(rendered, "NetworkPolicy")
    print(
        f"[defaults gate] {len(rendered)} object(s) rendered at the chart's "
        f"shipped values, {len(policies)} of them NetworkPolicy"
    )
    assert rendered, "the chart's defaults rendered nothing at all"
    assert policies == [], (
        f"the chart's shipped values rendered {len(policies)} NetworkPolicy "
        f"object(s). `networkPolicy.enabled` defaults false on asymmetric cost: "
        f"a wrong policy on an enforcing CNI is an outage"
    )


def test_the_shipped_values_name_no_client():
    """`clients` ships EMPTY, and that is measured rather than a placeholder.

    A default naming the ingress implementation's data plane would put an
    ingress-implementation literal in a module chart, which is the coupling
    ADR-0685 placed this estate's own copy elsewhere to avoid.
    """
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    policy_values = values["networkPolicy"]
    assert policy_values["enabled"] is False, policy_values["enabled"]
    assert policy_values["clients"] == [], policy_values["clients"]
    assert policy_values["scrapeFrom"] == {}, policy_values["scrapeFrom"]


# ── THE POLICY'S REFERENCES TO THE WORKLOAD IT PROTECTS ──────────────────────


def test_the_policy_selects_the_pods_this_chart_renders(tmp_path):
    """THE SELECTOR AND THE POD LABELS COME FROM ONE RENDER, so a typo cannot hide.

    A `podSelector` that matches no pod is accepted by the API server, listed by
    `kubectl get netpol` and printed in full by `kubectl describe`. It reads
    exactly like a working policy while protecting nothing, and this estate has no
    control that refuses one (ADR-0685). Comparing it with the labels the SAME
    render stamps is the control this file can offer.
    """
    rendered = policy_render(tmp_path)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)
    deployment = by_name(rendered, "Deployment", "gateway")

    selector = policy["spec"]["podSelector"]["matchLabels"]
    labels = pod_labels(deployment)
    print(
        f"[selector gate] {POLICY_NAME} selects {selector}; the Deployment "
        f"stamps {labels} on its pods"
    )
    assert selector, "the policy's podSelector is empty, which selects EVERY pod"
    assert selector.items() <= labels.items(), (
        f"the policy selects {selector} and the pods carry {labels}, so this "
        f"policy governs no pod in this release"
    )


def test_the_serving_rule_names_the_port_the_container_listens_on(tmp_path):
    """THE POLICY'S PORT IS THE CONTAINER'S PORT, read off the same render.

    A NetworkPolicy port is the packet's DESTINATION port, so it must follow
    `containerPort` and `LISTEN` rather than `service.port`. The two happen to be
    the same number today; a Service that translated them would make the
    difference decide the rule, and a literal restating the value it checks would
    certify whatever the author believed.
    """
    rendered = policy_render(tmp_path)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)
    deployment = by_name(rendered, "Deployment", "gateway")

    declared = container_ports(deployment)
    admitted = policy_ports(policy)
    print(
        f"[port gate] the Deployment declares containerPort(s) {sorted(declared)}; "
        f"{POLICY_NAME} admits {sorted(admitted)}"
    )
    assert declared, "the Deployment declares no containerPort at all"
    assert SERVING_PORT in declared, (
        f"the container no longer declares {SERVING_PORT}; it declares "
        f"{sorted(declared)}. Move the policy's serving rule with it"
    )
    assert SERVING_PORT in admitted, (
        f"{POLICY_NAME} does not admit the serving port {SERVING_PORT}, so every "
        f"external call through the edge is dropped. It admits {sorted(admitted)}"
    )

    # THE METRICS PORT IS NOT A `containerPort` AND THAT CHANGES NOTHING — the
    # process listens on it either way, from `METRICS_LISTEN`. So it is checked
    # against the environment the same render sets rather than against the
    # declared ports.
    listen = environment(deployment)["METRICS_LISTEN"]
    assert listen.endswith(f":{METRICS_PORT}"), (
        f"`METRICS_LISTEN` is {listen!r}, so the policy's metrics rule names a "
        f"port nothing serves"
    )
    assert METRICS_PORT in admitted, sorted(admitted)


# ── WHO IS ADMITTED, AND THE ALLOW-ALL CENSUS ────────────────────────────────


def assert_serving_rule_admits_only(rules: list[dict], peer: dict) -> None:
    """The serving gate's whole assertion, factored so a red case can call it.

    IT TAKES THE RULES RATHER THAN THE POLICY, and that is what makes the
    empty-lookup red case below possible: that case hands this an EMPTY list —
    the shape a lookup that found nothing produces — and demands it still go red.
    A gate written inline as `for rule in rules_admitting(...)` could not be
    tested that way, and would pass over an empty list in silence.
    """
    assert len(rules) == 1, (
        f"expected exactly ONE ingress rule naming port {SERVING_PORT}, found "
        f"{len(rules)}: {rules}. Zero means the serving port is DENIED to "
        f"everything and every external call through the edge times out; more "
        f"than one is an OR, so a second rule widens what is admitted while the "
        f"first still reads correctly"
    )
    peers = rules[0]["from"]
    assert len(peers) == 1, (
        f"the serving rule names {len(peers)} peers and each is an OR with the "
        f"others, so any one of them admits traffic on its own: {peers}"
    )
    assert peers[0] == peer, (
        f"the serving rule admits {peers[0]}, not {peer}. BOTH SELECTORS MUST "
        f"SIT IN ONE ENTRY: written as two entries they are an OR admitting "
        f"'any pod in that namespace' OR 'any pod anywhere with those labels', "
        f"which reads as correct and is far broader than intended"
    )


def test_the_serving_rule_admits_only_the_peer_the_values_named(tmp_path):
    """THE PEER IS READ BACK OUT OF THE RENDER, key for key.

    The census below says no rule admits everybody. That is not the same claim as
    this one: a rule could name a `from` and still admit sources nobody meant, by
    splitting one AND into two ORs or by dropping a label from the selector.
    """
    rendered = policy_render(tmp_path)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)
    rules = policy["spec"]["ingress"]
    admitting = rules_admitting(policy, SERVING_PORT)

    print(
        f"[serving-rule gate] {POLICY_NAME}: {len(rules)} ingress rule(s) "
        f"examined, {len(admitting)} naming port {SERVING_PORT}, "
        f"{len(from_less_rules(policy))} naming no source at all; ports "
        f"admitted overall: {sorted(policy_ports(policy))}"
    )

    assert len(rules) == EXPECTED_INGRESS_RULES, (
        f"expected {EXPECTED_INGRESS_RULES} ingress rules — the serving port and "
        f"the scrape — found {len(rules)}"
    )
    assert admitting and admitting[0] not in from_less_rules(policy), (
        f"the rule admitting port {SERVING_PORT} names NO source, so it admits "
        f"every pod in every namespace (ADR-0664). `from_less_rules` is the "
        f"hardened predicate for that and it sees `from: []` as well as a "
        f"missing key"
    )
    assert_serving_rule_admits_only(admitting, EXPECTED_SERVING_PEER)


def test_the_scrape_rule_admits_the_namespace_named_and_no_other(tmp_path):
    """THE SCRAPE NAMESPACE IS A SENTINEL, PASSED IN AND READ BACK OUT.

    A value the template could not plausibly contain, so a template that
    hardcoded `observability` fails here instead of agreeing with a fixture that
    had copied it. The metrics port serves without authentication, so ADR-0770
    governs this rule: scoped to one named namespace, never open to the cluster.
    """
    rendered = policy_render(tmp_path)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)
    admitting = rules_admitting(policy, METRICS_PORT)

    print(
        f"[scrape-rule gate] {len(admitting)} rule(s) name port {METRICS_PORT} "
        f"of {len(policy['spec']['ingress'])} examined"
    )
    assert len(admitting) == 1, admitting
    peers = admitting[0]["from"]
    assert len(peers) == 1, peers
    assert set(peers[0]) == {"namespaceSelector"}, (
        f"the scrape peer carries {sorted(peers[0])}; a `podSelector` beside the "
        f"`namespaceSelector` NARROWS this peer to named pods and would drop the "
        f"scrape, and an `ipBlock` in a peer of its own WIDENS it to a CIDR"
    )
    assert peers[0]["namespaceSelector"]["matchLabels"] == {
        NAMESPACE_LABEL: SENTINEL_SCRAPE_NAMESPACE
    }, peers[0]


def test_the_scrape_rule_is_absent_until_a_namespace_is_named(tmp_path):
    """No scrape source named renders NO rule for the metrics port at all.

    A bare install exposes the metrics port to nobody rather than to a guessed
    namespace — and, because a policy denies every port it does not name, the
    metrics port is denied rather than merely unmentioned.
    """
    rendered = policy_render(
        tmp_path,
        body=ADOPTER_POLICY_VALUES.split("  scrapeFrom:")[0],
    )
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)
    admitted = policy_ports(policy)
    print(
        f"[scrape-absence gate] with no scrape namespace named, "
        f"{POLICY_NAME} admits {sorted(admitted)} across "
        f"{len(policy['spec']['ingress'])} rule(s)"
    )
    assert admitted == {SERVING_PORT}, admitted


def test_the_policy_admits_from_every_source_only_where_written_down(tmp_path):
    """NO RULE ADMITS EVERYBODY, and the expectation is `set()`.

    An ingress rule with no `from` matches ALL sources (ADR-0664). This is the
    census that says so, and the two red cases below construct the non-empty path
    so the empty expectation is not a claim nothing could falsify.
    """
    rendered = policy_render(tmp_path)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)
    rules = policy["spec"]["ingress"]
    allow_all = from_less_rules(policy)
    admitted = {port["port"] for rule in allow_all for port in rule.get("ports", [])}

    print(
        f"[allow-all census] {POLICY_NAME}: {len(rules)} ingress rule(s) "
        f"examined, {len(allow_all)} naming no source; ports open to every "
        f"source: {sorted(admitted)}"
    )
    assert rules, "the policy carries no ingress rules at all, which denies every port"
    assert admitted == EXPECTED_ALLOW_ALL_PORTS, (
        f"{sorted(admitted)} is admitted from EVERY source in the cluster. An "
        f"empty or missing `from` is not a narrower scope — it is the widest "
        f"there is (ADR-0664)"
    )


# ── THE RED CASES ────────────────────────────────────────────────────────────


def test_enabling_the_policy_with_no_client_refuses_the_render(tmp_path):
    """ADR-0664's GUARD: the chart refuses rather than emitting an allow-all.

    `fail` aborts the WHOLE render, not this one template, which is the point —
    the day a shared values block turns policies on across every module, this
    chart's Application refuses to sync until the list names a peer.
    """
    overlay = values_file(
        tmp_path / "empty-clients.yaml",
        "networkPolicy:\n  enabled: true\n  clients: []\n",
    )
    result = template(CHART, "-f", str(overlay))
    print(f"[guard red case] helm exited {result.returncode}")
    assert result.returncode != 0, (
        "the chart rendered with `networkPolicy.enabled: true` and an empty "
        "`clients`, so ADR-0664's guard is not firing"
    )
    assert (
        "networkPolicy.enabled is true but networkPolicy.clients names no "
        "ingress source" in result.stderr
    ), result.stderr
    # THE REFUSAL STATES THE ALLOW-ALL SEMANTICS, which ADR-0664 requires: the
    # corrected rule is read where it is tripped rather than only in a comment.
    assert "matching ALL sources" in result.stderr, result.stderr
    assert "ADR-0664" in result.stderr, result.stderr


def test_a_blank_entry_beside_no_other_reaches_the_refusal(tmp_path):
    """`compact` BEFORE THE EMPTINESS TEST, and this is what it buys.

    A list holding one EMPTY peer is truthy to a bare `not` guard, and would
    render `from: [{}]` — a peer selecting nothing, which the API server accepts.
    `compact` drops it so the refusal is reached instead.
    """
    overlay = values_file(
        tmp_path / "blank-client.yaml",
        "networkPolicy:\n  enabled: true\n  clients:\n    - {}\n",
    )
    result = template(CHART, "-f", str(overlay))
    assert result.returncode != 0, (
        "a `clients` list holding one EMPTY peer rendered, so the guard's "
        "`compact` is not running before the emptiness test"
    )
    assert "names no ingress source" in result.stderr, result.stderr


def test_a_client_list_of_workload_names_is_refused_by_the_schema(tmp_path):
    """THE PASTE HAZARD, AND THE ONE THING THAT MAKES IT LOUD.

    Every sibling module chart's `networkPolicy.clients` holds workload NAMES.
    Pasted here, a name renders `from: ["iam"]` — valid YAML that helm emits
    happily and only the API server rejects, so the failure would be silent until
    apply. `chart/values.schema.json` types the entries as objects, which turns
    it into a refusal naming the key at render time.

    THE PHRASING IS NOT ASSERTED, ONLY WHAT THE MESSAGE NAMES. helm 3.18.4 says
    `networkPolicy.clients.0: Invalid type. Expected: object, given: string` and
    helm 4.3.0 says `at '/networkPolicy/clients/0': got string, want object` —
    both measured. Pinning either sentence would redden this suite on the OTHER
    helm, and this gate's claim is that the refusal names the key and the type it
    wanted, not which of two sentences the renderer chose.
    """
    overlay = values_file(
        tmp_path / "names.yaml",
        "networkPolicy:\n  enabled: true\n  clients:\n    - iam\n",
    )
    result = template(CHART, "-f", str(overlay))
    print(f"[schema red case] helm exited {result.returncode}")
    assert result.returncode != 0, (
        "a list of workload NAMES was accepted, so the schema does not type "
        "this chart's `clients` entries"
    )
    assert "schema" in result.stderr, result.stderr
    assert "clients" in result.stderr, result.stderr
    assert "object" in result.stderr, result.stderr
    assert "string" in result.stderr, result.stderr


def test_a_from_less_rule_added_to_the_policy_reddens_the_allow_all_census(tmp_path):
    """THE CONSTRUCTED RED CASE: a from-less rule that reaches the rendered object.

    The `from` block is cut out of the serving rule, leaving a bare `- ports:` —
    the allow-all ADR-0664 exists to refuse, reached PAST the guard, which sees a
    non-empty `clients` list and lets the render through. Both gates must go red:
    the peer gate above, and the allow-all census whose expectation is `set()`.
    """
    copy = chart_with(
        tmp_path, "templates/networkpolicy.yaml", without_the_serving_from
    )
    rendered = policy_render(tmp_path, chart=copy)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)

    admitting = rules_admitting(policy, SERVING_PORT)
    assert len(admitting) == 1, admitting
    assert admitting[0] in from_less_rules(policy), (
        "the red case cut the `from` out of the serving rule and "
        "`from_less_rules` did not see the result, so it is constructing nothing"
    )

    # The peer gate goes red, and the message is asserted rather than the
    # exception alone — a gate reddening for the WRONG reason would pass a bare
    # check.
    try:
        assert_serving_rule_admits_only(admitting, EXPECTED_SERVING_PEER)
    except (AssertionError, KeyError) as failure:
        assert isinstance(failure, KeyError) and failure.args[0] == "from", (
            f"expected the gate to fail reaching the absent `from`, got {failure!r}"
        )
    else:
        raise AssertionError(
            "the serving rule lost its `from` and the gate passed, so the gate "
            "does not check that the rule names a source at all"
        )

    # And the census that owns "admits everybody" goes red on the same render.
    admitted = {port["port"] for rule in from_less_rules(policy) for port in rule["ports"]}
    assert admitted == {SERVING_PORT}, admitted
    assert admitted != EXPECTED_ALLOW_ALL_PORTS, (
        "the serving rule was returned to admitting every source and the "
        "allow-all census would still have passed"
    )


def test_a_from_written_as_an_empty_list_is_seen_too(tmp_path):
    """THE OTHER ALLOW-ALL SHAPE, and the reason the matcher is copied rather than written.

    `from: []` is the SAME allow-all to the API server as a missing `from`. A
    predicate keyed on the missing KEY passes over it while the port stands open
    to every namespace — which is why ADR-0679 sends this file to
    `yadgarhq/platform`'s `from_less_rules` rather than to a fresh one.
    """
    copy = chart_with(
        tmp_path, "templates/networkpolicy.yaml", with_an_empty_serving_from
    )
    rendered = policy_render(tmp_path, chart=copy)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)

    admitting = rules_admitting(policy, SERVING_PORT)
    assert len(admitting) == 1, admitting
    assert admitting[0]["from"] == [], admitting[0]
    assert admitting[0] in from_less_rules(policy), (
        "`from: []` was NOT seen as an allow-all, so the matcher is keyed on the "
        "missing key rather than on emptiness"
    )

    admitted = {port["port"] for rule in from_less_rules(policy) for port in rule["ports"]}
    assert admitted != EXPECTED_ALLOW_ALL_PORTS, admitted


def test_the_serving_gate_reddens_when_its_own_lookup_finds_nothing(tmp_path):
    """THE GATE'S OWN RED CASE: a census that examines nothing must not pass.

    This mutates the TEST rather than the chart. `assert_serving_rule_admits_only`
    is handed the empty list — precisely what `rules_admitting` returns if the
    port constant is wrong, if the rule is deleted outright, or if the render
    stops producing the policy — and must go red rather than finding no
    counter-example among zero rules and reporting a pass.

    Asserting the COUNT before reading the rule is what closes that, and this
    case is what proves the count assertion is actually there.
    """
    rendered = policy_render(tmp_path)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)

    # The lookup that finds nothing is a REAL one: no rule names this port.
    absent = rules_admitting(policy, 9999)
    print(
        f"[vacuity red case] a lookup for port 9999 returned {len(absent)} "
        f"rule(s) of {len(policy['spec']['ingress'])} examined"
    )
    assert absent == [], f"9999 was expected to name no rule, got {absent}"

    try:
        assert_serving_rule_admits_only(absent, EXPECTED_SERVING_PEER)
    except AssertionError as failure:
        assert "expected exactly ONE ingress rule" in str(failure), (
            f"the gate reddened on an empty lookup for the wrong reason: {failure}"
        )
    else:
        raise AssertionError(
            "the serving gate passed over an EMPTY rule list, so it asserts a "
            "property of every rule it found while finding none — the vacuous "
            "census this suite exists to not ship"
        )


def test_a_moved_pod_label_reddens_the_selector_gate(tmp_path):
    """The Deployment stamps a label the policy does not select, and the gate says so."""
    copy = chart_with(tmp_path, "templates/deployment.yaml", with_a_moved_pod_label)
    rendered = policy_render(tmp_path, chart=copy)
    policy = by_name(rendered, "NetworkPolicy", POLICY_NAME)
    deployment = by_name(rendered, "Deployment", "gateway")

    selector = policy["spec"]["podSelector"]["matchLabels"]
    labels = pod_labels(deployment)
    assert not selector.items() <= labels.items(), (
        f"the pods were relabelled to {labels} and the policy still selects "
        f"{selector} — the selector gate would not have noticed"
    )
