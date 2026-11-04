"""PROSE THAT COUNTS THE GATEWAY'S PEERS MUST NOT SAY "TWO" OR "BOTH" (yaadgaar #596).

The gateway dials THREE gRPC upstreams (`task`, `iam`, `project`) and verifies FIVE
peers (those three, NATS and Valkey): `deployment.yaml` mounts one CA bundle per
peer, and the client leaf is presented when any of the five has TLS on. The prose
was written when there were two gRPC upstreams. "Both upstreams" and "the CA
bundles `iam` and `task` are verified against" survived the later peers because
nothing reads a comment. The `deployment.yaml` and `values.yaml` comments RENDER
into the manifest an operator diffs, so a stale count there reaches the person
deciding what to enable.

The check is deliberately narrow: it covers the files #596 and #615 named. It is a
regression pin for those sentences and not a claim about every file in the repo.
Comment markers and line wraps are removed first, so a phrase split across two
comment lines is still found.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

FILES = [
    "Cargo.toml",
    "README.md",
    "chart/templates/deployment.yaml",
    "chart/values.yaml",
    "scripts/tests/test_adr_0845_tls_required.py",
    "src/boot/wiring.rs",
    "src/http/tests.rs",
    "src/main.rs",
    "src/rotate.rs",
    "src/upstream/tests.rs",
    "src/upstream/tls.rs",
    "tests/assembly.rs",
    "tests/boot_message.rs",
    "tests/iam_tls.rs",
    "tests/support/mod.rs",
    "tests/upstream_absence.rs",
]

# A count of gRPC upstreams that is not three. One optional word may sit between,
# so "two gRPC upstreams" matches. "both" also covers hops and dials, and "two"
# also covers dials, but "two hops" does not: README.md says "the two hops
# above" for task and iam, which is
# true where it stands (the registry hop is the third).
COUNT = re.compile(
    r"\b(?:both\s+(?:\w+\s+)?(?:upstreams?|hops|dials)|two\s+(?:\w+\s+)?(?:upstreams?|dials))\b",
    re.IGNORECASE,
)
# History is allowed: "once served two upstreams, now five peers" says what WAS true.
HISTORY = re.compile(r"\b(?:once|used to|until|formerly|originally)\b[^.]{0,40}$", re.IGNORECASE)
# The CA bundles verify five peers, not the first two.
CA_PAIR = re.compile(
    r"CA bundles[^.]{0,40}\biam`? and `?task\b|CA bundles[^.]{0,40}\btask`? and `?iam\b",
    re.IGNORECASE,
)
MARKER = re.compile(r"^\s*(?://[!/]?|#)\s?")


def prose(name: str) -> str:
    lines = (MARKER.sub("", line) for line in (REPO / name).read_text().splitlines())
    return re.sub(r"\s+", " ", " ".join(lines))


def count_hits(text: str) -> list[str]:
    return [
        m.group(0)
        for m in COUNT.finditer(text)
        if not HISTORY.search(text[max(0, m.start() - 60) : m.start()])
    ]


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("the two gRPC upstreams", True),
        ("both upstreams cleartext", True),
        ("because both hops are cleartext", True),
        ("both dials are lazy", True),
        ("after the two dials resolve", True),
        ("this once served two upstreams, now five peers", False),
        ("it used to dial both hops", False),
        ("all three upstreams and every dial", False),
    ],
)
def test_count_matcher(text: str, flagged: bool) -> None:
    """The matcher itself: it catches a qualified count and spares history."""
    assert bool(count_hits(text)) is flagged


@pytest.mark.parametrize("name", FILES)
def test_no_two_upstream_count(name: str) -> None:
    hits = count_hits(prose(name))
    assert not hits, f"{name} counts the upstreams as two: {hits}. There are three gRPC upstreams."


@pytest.mark.parametrize("name", ["README.md", "src/rotate.rs"])
def test_ca_bundles_are_not_only_iam_and_task(name: str) -> None:
    hits = [m.group(0) for m in CA_PAIR.finditer(prose(name))]
    assert not hits, f"{name} says the CA bundles verify only iam and task: {hits}. They verify five peers."


def test_readme_names_the_five_peers_whose_bundles_are_verified() -> None:
    """`CA_PAIR` misses a list that drops `project`, NATS or Valkey. Assert the set."""
    (listed,) = re.findall(r"CA bundles it verifies (.+?) against", prose("README.md"))
    peers = {p.strip("` ").lower() for p in re.split(r",| and ", listed) if p.strip("` ")}
    assert peers == {"task", "iam", "project", "nats", "valkey"}, listed


def test_deployment_mounts_five_ca_bundles() -> None:
    """The count the prose now states: one CA volume per peer, five peers."""
    text = (REPO / "chart/templates/deployment.yaml").read_text()
    mounts = set(re.findall(r"^\s+- name: (\w+)-ca\n\s+mountPath: /var/run/config/\1-ca\n", text, re.M))
    assert mounts == {"task", "iam", "project", "nats", "valkey"}
