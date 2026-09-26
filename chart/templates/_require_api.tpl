{{/*
THE RENDER CHECK: an apply-time `no matches for kind` turned into a render-time
refusal that names the prerequisite.

COPIED FROM `yadgarhq/iam-db`'s `chart/templates/_require_api.tpl` (ADR-0679: a
matcher a sibling has hardened is copied, never re-derived), which took it in turn
from `yadgarhq/platform`. Two things differ from either and both are deliberate —
the template's NAME and the prefix of the message it fails with. Helm template names
are GLOBAL across a chart tree: the parent renders every module chart together in ONE
namespace, so one name shared between every chart that copies this partial would
leave ONE definition's body rendering for every caller, silently, with nothing in any
one repository's own suite able to see it.

SO THE NAMES MUST STAY PAIRWISE DISTINCT ACROSS THE ASSEMBLED TREE, and nothing in
THIS repository can assert that — a chart rendered alone has no sibling to collide
with. The measurement behind this paragraph is recorded in LEDGER TASK 1063, which
also carries the obligation on the parent's suite: the only place distinctness can be
asserted. So a reader today follows this pointer and lands somewhere real.

THE MEASUREMENT IS NOT RESTATED HERE, and that is the rule rather than an omission.
A version-pinned measurement written into a comment is a claim no suite re-runs, so
nothing goes red the day it stops being true while the prose still reads as evidence.

A TOGGLE GATES A RESOURCE; IT DOES NOT DIAGNOSE A MISSING PREREQUISITE. A toggle set
true on a cluster with no KEDA renders cleanly and then fails at apply with `no
matches for kind ScaledObject`, half-way through an install, naming a kind rather
than an operator somebody has to go and install. This partial is what makes the
refusal happen before anything is applied, with the operator's name in it.

WHAT IT PROVES, AND WHAT IT DOES NOT. `.Capabilities.APIVersions.Has` answers "is
this API registered on the target". It NEVER answers "is a controller running". A
cluster carrying KEDA's CRDs with no KEDA operator pod renders, installs, and then
leaves the ScaledObject sitting there unreconciled while the Deployment beside it
keeps whatever replica count it was applied with. The controller half is the
preflight Job `yadgarhq/platform` carries, and this chart does not carry one.

IT MAY ONLY EVER BE CALLED FROM BEHIND A DEFAULT-FALSE TOGGLE. `Has` is false for
every API group outside helm's built-in list whenever there is no cluster and no
`--api-versions`, so a check reachable at a chart's defaults refuses every offline
render — `helm lint --strict`, the shared `helm lint and render` hook, and every bare
`helm template` in the estate's suites. `autoscaling.enabled` defaults false, which
is what makes this legal here. `gateway.enabled` is the one toggle in this estate
that is true by default, and that is why no check sits behind it.

CALL IT WITH A DICT:

  {{- include "gateway.require-api" (dict
        "context"    $
        "apiVersion" "keda.sh/v1alpha1"
        "operator"   "KEDA"
        "toggle"     "autoscaling.enabled") }}
*/}}
{{- define "gateway.require-api" -}}
{{- $context := .context -}}
{{- if not ($context.Capabilities.APIVersions.Has .apiVersion) -}}
{{- fail (printf (join "" (list
      "gateway: this render needs the API %s, which %s provides, and the target does not have it. "
      "%s is true, and that is what asked for it. Install %s in the target cluster, or set %s false. "
      "If you are rendering offline: helm does not populate .Capabilities.APIVersions with "
      "CRD-backed groups from anywhere but a live cluster, so pass --api-versions %s to render this."))
      .apiVersion .operator .toggle .operator .toggle .apiVersion) -}}
{{- end -}}
{{- end -}}
