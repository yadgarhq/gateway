{{/*
THE BROWSER ORIGIN THIS GATEWAY ADMITS, DERIVED FROM THE ESTATE'S HOSTNAME
(yaadgaar #294, ADR-0808). Not CORS: the value feeds the binary's Origin check.
`YADGAR_ALLOWED_ORIGINS` resolves in this order:

  0. `cors.enabled: false` (yaadgaar #582, ruled by Max 2026-11-05): EMPTY, no
     browser origin, whatever `global.hostname` says. It is the off switch the
     derived origin otherwise lacks. `false` beside a non-empty
     `cors.allowedOrigins` is contradictory and is REFUSED, naming both keys:
     silently dropping a list somebody wrote is a mistake nobody sees. The
     shipped value is `true`, so steps 1 to 3 are the render before #582;
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
stated. The binary checks the result at boot (`src/origin.rs`). A wildcard
`global.hostname` is refused HERE, naming the key, in step 2 only: the binary
would refuse the derived `https://*...` anyway, but as a crash-loop on rollout.

`global` MAY BE ABSENT OR NULL, as in `_hostname.tpl`; both fall through to 3.

`cors.enabled` must be the bare word true or false (ADR-0797), checked HERE for
the reason `gateway.allowHttpOrigins` below is: a string "false" is truthy in a
template and would leave the origin open. The schema refuses a string first;
this check also refuses an absent or null key, which reads as neither on nor off.

  {{ include "gateway.allowedOrigins" (dict "local" .Values.cors.allowedOrigins "context" $) }}
*/}}
{{- define "gateway.allowedOrigins" -}}
{{- $global := .context.Values.global | default dict -}}
{{- $hostname := get $global "hostname" -}}
{{- $cors := .context.Values.cors -}}
{{- if not (and (kindIs "map" $cors) (hasKey $cors "enabled") (kindIs "bool" $cors.enabled)) -}}
{{- $found := "absent" -}}
{{- if and (kindIs "map" $cors) (hasKey $cors "enabled") -}}
{{- $found = toJson $cors.enabled -}}
{{- end -}}
{{- fail (printf "gateway: `cors.enabled` must be true or false and is %s. It is the off switch for every browser origin, and a string such as \"false\" would read as on. Write the bare word `true` (shipped) or `false`." $found) -}}
{{- end -}}
{{- if not $cors.enabled -}}
{{- if .local -}}
{{- fail (printf "gateway: `cors.enabled` is false, which admits no browser origin, and `cors.allowedOrigins` is %s, which admits some. The two contradict each other. Set `cors.allowedOrigins` to \"\" to admit none, or set `cors.enabled` to true to admit the list." (toJson .local)) -}}
{{- end -}}
{{- else if .local -}}
{{- .local -}}
{{- else if $hostname -}}
{{- if contains "*" (toString $hostname) -}}
{{- fail (printf "gateway: `global.hostname` is %s, a wildcard, and the browser origin derived from it would be one too. The gateway refuses a wildcard origin at boot. Set `cors.allowedOrigins` to each browser origin in full, or set `global.hostname` to one name." (toJson $hostname)) -}}
{{- end -}}
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
