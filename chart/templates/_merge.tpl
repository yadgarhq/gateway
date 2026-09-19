{{- /*
A DEEP MERGE THIS CHART OWNS, rather than sprig's `mergeOverwrite`.

`gateway.deepMerge` takes `base` and `over` as dicts and returns the merged
document as YAML text. A key present in both and holding a map in both recurses;
anything else the `over` side states REPLACES what `base` says. So an adopter
states one leaf and inherits the rest of the document, which is ADR-0721's whole
point — a whole-document replacement would make them restate every knob and stop
receiving upstream's improvements to it.

A SECOND COPY OF `yadgarhq/config`'s `config.deepMerge`, BY DECISION. ADR-0740
moved this document into this chart and says ADR-0721's per-leaf merge semantics
do NOT change, so the semantics had to come with it. There is no chart library in
this estate to share a partial through, and inventing one to hold fourteen lines
would be a new mechanism where a copy will do. The copy is behaviourally
identical on purpose — divergence here would mean one knob merging differently
depending on which repository renders it.

WHY NOT `mergeOverwrite`, WHICH IS ONE LINE. Its behaviour for a zero, a `false`
and an empty string is mergo's notion of an "empty" value rather than helm's
documented contract, and the adopter's own helm — or Argo's bundled one — is what
decides which mergo this chart gets. This document's one leaf refuses zero at the
schema, so nothing here would notice today; the second gateway-only knob might be
a `false` that MEANS false, and a merge that read it as unset would hand an
installation upstream's value while the operator reads their own.

THE ROUND TRIP IS PER NESTING LEVEL, and it is what `include` costs: a named
template returns a string, so the recursive call is re-parsed by `fromYaml`. An
integer survives it — a values file reaches helm through `sigs.k8s.io/yaml` as a
float64, and `intervalSeconds: 600.0` is a ConfigMap `serde_norway` refuses for a
`u64`, which is why `values.schema.json` types the leaf as an integer.

THIS FILE RENDERS NOTHING. A template whose name starts with `_` emits no
manifest.
*/ -}}
{{- define "gateway.deepMerge" -}}
{{- $out := dict -}}
{{- range $key, $value := .base }}
{{-   $out = set $out $key $value }}
{{- end }}
{{- range $key, $value := .over }}
{{-   if and (hasKey $out $key) (kindIs "map" (index $out $key)) (kindIs "map" $value) }}
{{-     $out = set $out $key (fromYaml (include "gateway.deepMerge" (dict "base" (index $out $key) "over" $value))) }}
{{-   else }}
{{-     $out = set $out $key $value }}
{{-   end }}
{{- end }}
{{- toYaml $out -}}
{{- end -}}
