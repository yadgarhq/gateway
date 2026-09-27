{{/*
THE ESTATE'S PUBLIC HOSTNAME, RESOLVED IN ONE PLACE (ADR-0808).

An adopter states the hostname once, as `global.hostname` in the parent chart.
Helm hands `global` to every subchart, so this chart reads it without any
plumbing. `gateway.hostname`, which the HTTPRoute matches on, resolves in this
order:

  1. `gateway.hostname`, when it is set: an explicit per-chart value still wins;
  2. `global.hostname`, when `gateway.hostname` is empty;
  3. `gateway.yadgar.internal`, when neither is set. That is the value
     `values.yaml` shipped before ADR-0808, so a render with no hostname
     anywhere is byte-identical to the render before it.

`gateway.hostname` defaults to empty in `values.yaml` because a non-empty default
cannot be told apart from a value somebody set, and step 1 would then always win.

`global` MAY BE ABSENT OR NULL. This chart rendered on its own has no `global`
unless the caller passes one, and `global: null` in an overlay removes it; both
fall through to step 3.

The same order is written in `yadgarhq/platform`'s and `yadgarhq/iam`'s
`_hostname.tpl`. The name carries this chart's prefix because helm template names
are global across the parent's whole tree, and the three must not collide.

  {{ include "gateway.hostname" (dict "local" .Values.gateway.hostname "context" $) }}
*/}}
{{- define "gateway.hostname" -}}
{{- $global := .context.Values.global | default dict -}}
{{- .local | default (get $global "hostname") | default "gateway.yadgar.internal" -}}
{{- end -}}
