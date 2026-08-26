{{/*
An image reference: by digest (sha256: and 64 hex digits), or by tag when allowTags is on; anything else fails
the render.
{{ include "aisolate.image" (dict "imageRoot" .Values.platform.controller.image "context" $) }}
*/}}
{{- define "aisolate.image" -}}
{{- $ctx := .context -}}
{{- if and .imageRoot.digest (not (regexMatch "^sha256:[a-f0-9]{64}$" .imageRoot.digest)) -}}
{{ fail (printf "image %s: digest %q is not sha256: and 64 hex digits" .imageRoot.repository .imageRoot.digest) }}
{{- end -}}
{{- if or .imageRoot.digest $ctx.Values.allowTags -}}
{{ include "common.images.image" (dict "imageRoot" .imageRoot "global" $ctx.Values.global "chart" $ctx.Chart) }}
{{- else -}}
{{ fail (printf "image %s needs a digest (allowTags=false: a tag-only image never ships)" .imageRoot.repository) }}
{{- end -}}
{{- end -}}

{{/* The pull Secrets of the chart's own pods: the global ones and every image's. */}}
{{- define "aisolate.imagePullSecrets" -}}
{{- include "common.images.renderPullSecrets" (dict "images" (list
    .Values.platform.controller.image
    .Values.platform.backend.image
    .Values.persistence.postgres.image
  ) "context" $) -}}
{{- end -}}

{{/* The backend database's password: the existing Secret's on an upgrade, else a new random one. Kept on the
     root context, so the Secret and both pods' checksum agree within one render. */}}
{{- define "aisolate.dbPassword" -}}
{{- if not (hasKey . "aisolateDbPassword") -}}
{{- $data := (lookup "v1" "Secret" .Release.Namespace "db").data | default dict -}}
{{- $_ := set . "aisolateDbPassword" (ternary (index $data "password" | default "" | b64dec) (randAlphaNum 32) (hasKey $data "password")) -}}
{{- end -}}
{{- index . "aisolateDbPassword" -}}
{{- end -}}

{{/* The audit ingest key (headless=false): the existing Secret's on an upgrade, else a new random one, kept on the
     root context like the database's password. The controller derives each airlock's ingest token from it, the
     backend checks a line's token against it. */}}
{{- define "aisolate.auditIngestKey" -}}
{{- if not (hasKey . "aisolateAuditIngestKey") -}}
{{- $data := (lookup "v1" "Secret" .Release.Namespace "audit-ingest").data | default dict -}}
{{- $_ := set . "aisolateAuditIngestKey" (ternary (index $data "key" | default "" | b64dec) (randAlphaNum 48) (hasKey $data "key")) -}}
{{- end -}}
{{- index . "aisolateAuditIngestKey" -}}
{{- end -}}

{{/* Rolls the controller and the backend together when the ingest key changes: both must hold the same one; an
     existingSecret is the installer's to rotate, and the chart cannot read it. */}}
{{- define "aisolate.auditIngestKeyChecksum" -}}
{{- if not .Values.platform.audit.existingSecret -}}
checksum/audit-ingest-key: {{ include "aisolate.auditIngestKey" . | sha256sum | trunc 12 | quote }}
{{- end -}}
{{- end -}}

{{/* The pod-template annotation that rolls the database and the backend together when the password changes; an
     existingSecret is the installer's to rotate, and the chart cannot read it. */}}
{{- define "aisolate.dbPasswordChecksum" -}}
{{- if not .Values.persistence.postgres.existingSecret -}}
checksum/db-password: {{ include "aisolate.dbPassword" . | sha256sum | trunc 12 | quote }}
{{- end -}}
{{- end -}}

{{/* The scheme every public host is served on: the release's. */}}
{{- define "aisolate.scheme" -}}
{{- (urlParse .Values.platform.ingress.publicUrl).scheme -}}
{{- end -}}

{{/* The restricted Pod Security Standard, for every AIsolate container. */}}
{{- define "aisolate.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}
{{- define "aisolate.podSecurity" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* An Ingress's annotations: the chart's nginx ones (plus .extra), under platform.ingress.annotations. */}}
{{- define "aisolate.ingressAnnotations" -}}
{{- $nginx := dict "nginx.ingress.kubernetes.io/proxy-read-timeout" "600" "nginx.ingress.kubernetes.io/proxy-buffering" "off" -}}
{{- toYaml (merge (dict) .context.Values.platform.ingress.annotations (.extra | default dict) $nginx) -}}
{{- end -}}

{{/* An Ingress's TLS, with platform.ingress.tls: the Secret <name>-tls for its host. */}}
{{- define "aisolate.ingressTls" -}}
{{- if .context.Values.platform.ingress.tls }}
tls:
  - hosts:
      - {{ .host | quote }}
    secretName: {{ .name }}-tls
{{- end }}
{{- end -}}

{{/* One host's Ingress: everything under / to the component's Service. */}}
{{- define "aisolate.ingress" -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ .name }}
  namespace: {{ .context.Release.Namespace }}
  annotations:
    {{- include "aisolate.ingressAnnotations" (dict "extra" (.annotations | default (dict "nginx.ingress.kubernetes.io/proxy-body-size" "16m")) "context" .context) | nindent 4 }}
spec:
  ingressClassName: {{ .context.Values.platform.ingress.className }}
  {{- include "aisolate.ingressTls" . | nindent 2 }}
  rules:
    - host: {{ .host }}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: {{ .name }}
                port:
                  number: {{ .port }}
{{- end -}}
