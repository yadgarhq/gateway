{{/*
THE BROWSER ORIGIN THIS GATEWAY ADMITS, DERIVED FROM THE ESTATE'S HOSTNAME
(yaadgaar #294, ADR-0808). Not CORS: the value feeds the binary's Origin check.
`YADGAR_ALLOWED_ORIGINS` resolves in this order:

  1. `cors.allowedOrigins`, when it is set: an explicit value still wins;
  2. `https://` + `global.hostname`, when `cors.allowedOrigins` is empty. NO
     PORT, as in iam's enrolment URL: the edge listener answers on 443. A
     deployment whose browsers use another port (kind's 18443) sets step 1;
  3. EMPTY, when neither is set: no browser origin is admitted. That is the
     value shipped before this change, so a render with no hostname anywhere
     renders the value it rendered before.

Step 2 reads `global.hostname` and NOT `gateway.hostname` (`_hostname.tpl`):
the ruling derives the origin from the estate's one hostname, and the route's
built-in fallback `gateway.yadgar.internal` must never open an origin nobody
stated. The binary checks the result at boot (`src/origin.rs`).

`global` MAY BE ABSENT OR NULL, as in `_hostname.tpl`; both fall through to 3.

  {{ include "gateway.allowedOrigins" (dict "local" .Values.cors.allowedOrigins "context" $) }}
*/}}
{{- define "gateway.allowedOrigins" -}}
{{- $global := .context.Values.global | default dict -}}
{{- $hostname := get $global "hostname" -}}
{{- if .local -}}
{{- .local -}}
{{- else if $hostname -}}
{{- printf "https://%s" $hostname -}}
{{- end -}}
{{- end -}}

{{/*
THE DEVELOPMENT SWITCH FOR http:// ORIGINS, as "1" or "0" (yaadgaar #294).
`cors.allowHttpOrigins` must be the bare word true or false (ADR-0797): a
string "false" is truthy in a template and would turn cleartext origins ON.
The check lives HERE, in the include the Deployment calls, so it runs before
any raw template error can (ADR-0850).

  {{ include "gateway.allowHttpOrigins" .Values.cors }}
*/}}
{{- define "gateway.allowHttpOrigins" -}}
{{- if not (and (kindIs "map" .) (hasKey . "allowHttpOrigins") (kindIs "bool" .allowHttpOrigins)) -}}
{{- $found := "absent" -}}
{{- if and (kindIs "map" .) (hasKey . "allowHttpOrigins") -}}
{{- $found = toJson .allowHttpOrigins -}}
{{- end -}}
{{- fail (printf "gateway: `cors.allowHttpOrigins` must be true or false and is %s. It is the development switch that admits http:// browser origins, and a string such as \"false\" would read as on. Write the bare word `false` (shipped) or, in development only, `true`." $found) -}}
{{- end -}}
{{- ternary "1" "0" .allowHttpOrigins -}}
{{- end -}}
