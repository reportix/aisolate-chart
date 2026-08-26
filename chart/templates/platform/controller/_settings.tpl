{{/* What the chart decided at install time and no document carries: the controller renders with it. The file
     /etc/aisolate/settings.yaml, carried by the controller's pod template (aisolate.dev/settings), which the
     backend cannot write: its Role writes ConfigMaps. */}}
{{- define "aisolate.controllerSettings" -}}
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
