"""THE EDGE'S ROUTE AND ITS BACKEND ARE NEVER PRUNED BY ARGO CD (ADR-0851, yaadgaar #297).

ADR-0851 puts `argocd.argoproj.io/sync-options: Prune=false` on every chart-owned
object whose loss takes the edge down. Max ruled that this chart's HTTPRoute and
Service are two of them: the HTTPRoute is the edge's only route to this gateway,
and the Service is that route's backend. A render that drops either one (a
values key renamed, `gateway.enabled` flipped, a template deleted) must leave
the live object in place for a person to delete by hand, rather than let a sync
with pruning on take MCP off the edge.

Each object is asserted on its own, so a mutant that removes the annotation from
one and keeps it on the other is caught. The Service is also asserted with the
route turned off, because the Service renders whether or not the route does.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
KEY = "argocd.argoproj.io/sync-options"
VALUE = "Prune=false"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), the same wording as the sibling suites.
    assert binary, (
        "helm is not on PATH. This suite renders the chart — install helm rather "
        "than letting it report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def rendered(*arguments: str) -> list[dict]:
    result = helm(
        "template", "gateway", str(CHART), "-f", str(CHART / "ci" / "values.yaml"), *arguments
    )
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if isinstance(d, dict)]


def one(documents: list[dict], kind: str) -> dict:
    found = [d for d in documents if d.get("kind") == kind]
    assert len(found) == 1, f"expected one {kind}, found {len(found)}"
    return found[0]


def sync_options(document: dict) -> str | None:
    return ((document.get("metadata") or {}).get("annotations") or {}).get(KEY)


def test_the_httproute_carries_prune_false() -> None:
    assert sync_options(one(rendered(), "HTTPRoute")) == VALUE


def test_the_service_carries_prune_false() -> None:
    assert sync_options(one(rendered(), "Service")) == VALUE


def test_the_service_carries_prune_false_with_the_route_off() -> None:
    documents = rendered("--set", "gateway.enabled=false")
    assert not [d for d in documents if d.get("kind") == "HTTPRoute"]
    assert sync_options(one(documents, "Service")) == VALUE
