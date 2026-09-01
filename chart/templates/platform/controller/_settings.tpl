{{/* What the chart decided at install time and no document carries: the controller renders with it. The file
     /etc/aisolate/settings.yaml, carried by the controller's pod template (aisolate.dev/settings), which the
     backend cannot write: its Role writes ConfigMaps. */}}
{{- define "aisolate.controllerSettings" -}}
{{- /* Every peer the pods reach names its port; ingressFrom reaches the pods' own. */ -}}
{{- with .Values.platform.identity.egress }}{{ $_ := required "platform.identity.egress.port is required" .port }}{{ end -}}
{{- with .Values.platform.egress.dns }}{{ $_ := required "platform.egress.dns.port is required" .port }}{{ end -}}
{{- range $host, $peer := .Values.platform.egress.hosts }}{{ $_ := required (printf "platform.egress.hosts.%s.port is required" $host) $peer.port }}{{ end -}}
aisolate:
  controller:
    namespace: {{ .Release.Namespace }}
    ingress:
      host: {{ .Values.platform.ingress.host | quote }}
      className: {{ .Values.platform.ingress.className | quote }}
      publicUrl: {{ .Values.platform.ingress.publicUrl | quote }}
    images:
      airlock: {{ include "aisolate.image" (dict "imageRoot" .Values.platform.airlock.image "context" $) }}
      toolServer: {{ include "aisolate.image" (dict "imageRoot" .Values.platform.toolServer.image "context" $) }}
      pullPolicy: {{ .Values.platform.airlock.image.pullPolicy }}
      allowTags: {{ .Values.allowTags }}
    identity:
      issuerUri: {{ .Values.platform.identity.issuerUri | quote }}
      jwkSetUri: {{ .Values.platform.identity.jwkSetUri | quote }}
      rolesClaim: {{ .Values.platform.identity.rolesClaim | quote }}
      egress:
{{ include "aisolate.peer" .Values.platform.identity.egress | indent 8 }}
    egress:
      dns:
{{ include "aisolate.peer" .Values.platform.egress.dns | indent 8 }}
      ingressFrom:
{{ include "aisolate.peer" .Values.platform.egress.ingressFrom | indent 8 }}
      {{- /* Bracketed like the peers' label keys: Spring keeps a host's dots only in brackets. */}}
      hosts:
{{- range $host, $peer := .Values.platform.egress.hosts }}
        "[{{ $host }}]":
{{ include "aisolate.peer" $peer | indent 10 }}
{{- else }} {}
{{- end }}
    airlockPods:
      replicas: {{ .Values.platform.airlock.replicas }}
      runtimeClassName: {{ .Values.platform.airlock.runtimeClassName | quote }}
    corsAllowedOrigins: {{ .Values.platform.airlock.corsAllowedOrigins | quote }}
    observability:
      otlpEndpoint: {{ .Values.platform.observability.otlpEndpoint | quote }}
    {{- /* No backend headless: the airlock pods keep their stdout lines alone, and no airlock's code can be fetched. */}}
    code:
      url: {{ ternary "" (printf "http://backend.%s.svc:8085/v1/code" .Release.Namespace) .Values.headless | quote }}
    audit:
      url: {{ ternary "" (printf "http://backend.%s.svc:8085/v1/audit/events" .Release.Namespace) .Values.headless | quote }}
      failClosed: {{ .Values.platform.audit.failClosed }}
      stdout: {{ .Values.platform.audit.stdout }}
    resources:
      airlock: {{ toJson .Values.platform.airlock.resources }}
      toolServer: {{ toJson .Values.platform.toolServer.resources }}
{{- end -}}
