{{/*
An image reference: by digest (sha256: and 64 hex digits), or by tag when allowTags is on; anything else fails
the render. The tag is the chart's appVersion when empty, the registry is global.imageRegistry when that is set.
{{ include "aisolate.image" (dict "imageRoot" .Values.platform.controller.image "context" $) }}
*/}}
{{- define "aisolate.image" -}}
{{- $r := .imageRoot -}}
{{- if and $r.digest (not (regexMatch "^sha256:[a-f0-9]{64}$" $r.digest)) -}}
{{ fail (printf "image %s: digest %q is not sha256: and 64 hex digits" $r.repository $r.digest) }}
{{- end -}}
{{- if not (or $r.digest .context.Values.allowTags) -}}
{{ fail (printf "image %s needs a digest (allowTags=false: a tag-only image never ships)" $r.repository) }}
{{- end -}}
{{- $registry := .context.Values.global.imageRegistry | default $r.registry -}}
{{- if $registry }}{{ $registry }}/{{ end }}{{ $r.repository }}{{ if $r.digest }}@{{ $r.digest }}{{ else }}:{{ $r.tag | default .context.Chart.AppVersion }}{{ end -}}
{{- end -}}

{{/* The pull Secrets of the chart's own pods: global.imagePullSecrets, names or {name: …} entries. */}}
{{- define "aisolate.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets -}}
imagePullSecrets:
{{- range . }}
  - name: {{ if kindIs "map" . }}{{ .name }}{{ else }}{{ . }}{{ end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* The keys the chart generates, each kept across upgrades: the existing Secret's on an upgrade, else a new random one. Kept
     on the root context, so the Secret and every pod's checksum agree within one render. .name: db (the backend database's
     password), audit (the ingest key: the controller derives each airlock's token from it, the backend checks it) or
     credentials (what the backend seals typed API keys and passwords with). */}}
{{- define "aisolate.generated" -}}
{{- $r := index (dict
    "db" (dict "secret" "db" "key" "password" "length" 32)
    "audit" (dict "secret" "audit-ingest" "key" "key" "length" 48)
    "credentials" (dict "secret" "credentials-key" "key" "key" "length" 64)) .name -}}
{{- $id := print "aisolateGenerated" .name -}}
{{- if not (hasKey .root $id) -}}
{{- $data := (lookup "v1" "Secret" .root.Release.Namespace $r.secret).data | default dict -}}
{{- $_ := set .root $id (ternary (index $data $r.key | default "" | b64dec) (randAlphaNum (int $r.length)) (hasKey $data $r.key)) -}}
{{- end -}}
{{- index .root $id -}}
{{- end -}}

{{/* The pod-template annotation that rolls a pod when a generated key changes. An existingSecret is the installer's to rotate,
     and the chart cannot read it: no annotation then (.existing is that value). */}}
{{- define "aisolate.rollOn" -}}
{{- if not .existing -}}
checksum/{{ index (dict "db" "db-password" "audit" "audit-ingest-key" "credentials" "credentials-key") .name }}: {{ include "aisolate.generated" . | sha256sum | trunc 12 | quote }}
{{- end -}}
{{- end -}}

{{/* The identity providers: the values, or with platform.keycloak.enabled the chart's Keycloak: the users realm for the
     pods, the operators realm for the backend, the keys from its in-cluster Service. A value that is set wins; a
     provider set by its issuer takes no default for its keys or its peer. */}}
{{- define "aisolate.keycloakRealm" -}}
{{- include "aisolate.scheme" .context }}://{{ .context.Values.platform.keycloak.host }}/realms/{{ .realm }}
{{- end -}}
{{- define "aisolate.keycloakJwks" -}}
http://keycloak.{{ .context.Release.Namespace }}.svc:8080/realms/{{ .realm }}/protocol/openid-connect/certs
{{- end -}}
{{- define "aisolate.keycloakPeer" -}}
namespaceSelector:
  kubernetes.io/metadata.name: {{ .Release.Namespace | quote }}
podSelector:
  app: keycloak
port: 8080
{{- end -}}
{{- define "aisolate.identity.issuerUri" -}}
{{- if .Values.platform.identity.issuerUri }}{{ .Values.platform.identity.issuerUri }}
{{- else if .Values.platform.keycloak.enabled }}{{ include "aisolate.keycloakRealm" (dict "realm" .Values.platform.keycloak.realms.users.name "context" $) }}
{{- else }}{{ fail "platform.identity.issuerUri is required unless platform.keycloak.enabled" }}{{ end -}}
{{- end -}}
{{- define "aisolate.identity.jwkSetUri" -}}
{{- if .Values.platform.identity.jwkSetUri }}{{ .Values.platform.identity.jwkSetUri }}
{{- else if and .Values.platform.keycloak.enabled (not .Values.platform.identity.issuerUri) }}{{ include "aisolate.keycloakJwks" (dict "realm" .Values.platform.keycloak.realms.users.name "context" $) }}{{ end -}}
{{- end -}}
{{- define "aisolate.identity.egress" -}}
{{- if .Values.platform.identity.egress }}{{ toYaml .Values.platform.identity.egress }}
{{- else if and .Values.platform.keycloak.enabled (not .Values.platform.identity.issuerUri) }}{{ include "aisolate.keycloakPeer" . }}
{{- else }}{}{{ end -}}
{{- end -}}
{{- define "aisolate.identity.operators.issuerUri" -}}
{{- if .Values.platform.identity.operators.issuerUri }}{{ .Values.platform.identity.operators.issuerUri }}
{{- else if .Values.platform.keycloak.enabled }}{{ include "aisolate.keycloakRealm" (dict "realm" .Values.platform.keycloak.realms.operators.name "context" $) }}{{ end -}}
{{- end -}}
{{/* The backend's keys: the operators' provider's when it has one of its own, else the shared provider's. */}}
{{- define "aisolate.identity.operators.jwkSetUri" -}}
{{- if .Values.platform.identity.operators.issuerUri }}{{ .Values.platform.identity.operators.jwkSetUri }}
{{- else if .Values.platform.keycloak.enabled }}{{ include "aisolate.keycloakJwks" (dict "realm" .Values.platform.keycloak.realms.operators.name "context" $) }}
{{- else }}{{ include "aisolate.identity.jwkSetUri" . }}{{ end -}}
{{- end -}}
{{- define "aisolate.identity.operators.egress" -}}
{{- if .Values.platform.identity.operators.egress }}{{ toYaml .Values.platform.identity.operators.egress }}
{{- else if and .Values.platform.keycloak.enabled (not .Values.platform.identity.operators.issuerUri) }}{{ include "aisolate.keycloakPeer" . }}
{{- else }}{{ include "aisolate.identity.egress" . }}{{ end -}}
{{- end -}}

{{/* Keycloak's passwords (platform.keycloak.enabled), by key: the existing Secret's on an upgrade, else a new random
     one, kept on the root context like the database's password. admin-password bootstraps Keycloak (and is the demo
     admin's); <user>-password is each demo user's. */}}
{{- define "aisolate.keycloakSecret" -}}
{{- $ctx := .context -}}
{{- if not (hasKey $ctx "aisolateKeycloakSecret") -}}
{{- $_ := set $ctx "aisolateKeycloakSecret" ((lookup "v1" "Secret" $ctx.Release.Namespace "keycloak").data | default dict) -}}
{{- end -}}
{{- $data := $ctx.aisolateKeycloakSecret -}}
{{- if not (hasKey $data .key) -}}{{- $_ := set $data .key (randAlphaNum 32 | b64enc) -}}{{- end -}}
{{- index $data .key | b64dec -}}
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

{{/* The ingress rule of a pod serving /actuator/prometheus: a scraper in any namespace, by the fixed label
     aisolate.dev/scraper=true, on the management port 9464 alone, which no Service exposes. The controller
     renders the same rule on the airlock and tool server pods. */}}
{{- define "aisolate.scraperIngress" -}}
- from:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          aisolate.dev/scraper: "true"
  ports:
    - port: 9464
      protocol: TCP
{{- end -}}

{{/* A values peer map as one NetworkPolicyPeer list entry: selectors under matchLabels, or an ipBlock. */}}
{{- define "aisolate.policyPeer" -}}
{{- if .cidr }}
- ipBlock:
    cidr: {{ .cidr | quote }}
{{- else }}
-
  {{- if .namespaceSelector }}
  namespaceSelector:
    matchLabels: {{ toJson .namespaceSelector }}
  {{- end }}
  {{- if .podSelector }}
  podSelector:
    matchLabels: {{ toJson .podSelector }}
  {{- end }}
{{- end }}
{{- end -}}

{{/* The egress rule to the cluster DNS, port 53 over UDP and TCP. */}}
{{- define "aisolate.dnsEgress" -}}
- to:
{{ include "aisolate.policyPeer" .Values.platform.egress.dns | indent 4 }}
  ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
{{- end -}}

{{/* The egress rule to the Kubernetes API server: its ports, at its cidr when set. Without a cidr the rule names
     no peer, since CNIs disagree on whether an ipBlock matches a node-hosted API server (Cilium does not). */}}
{{- define "aisolate.apiServerEgress" -}}
- ports:
  {{- range .Values.platform.egress.apiServer.ports }}
    - port: {{ . }}
      protocol: TCP
  {{- end }}
  {{- with .Values.platform.egress.apiServer.cidr }}
  to:
    - ipBlock:
        cidr: {{ . | quote }}
  {{- end }}
{{- end -}}

{{/* The way out to an address: HTTPS to a public one, never to a private, loopback or link-local range. */}}
{{- define "aisolate.publicEgress" -}}
- to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
          - 100.64.0.0/10
          - 127.0.0.0/8
          - 169.254.0.0/16
  ports:
    - port: 443
      protocol: TCP
{{- end -}}

{{/* A ClusterIP Service: the pods labelled .selector, on .ports (port, which is also the targetPort; optional name and protocol). */}}
{{- define "aisolate.service" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ .name }}
  namespace: {{ .context.Release.Namespace }}
spec:
  selector:
    {{- toYaml .selector | nindent 4 }}
  ports:
    {{- range .ports }}
    - {{ with .name }}name: {{ . }}
      {{ end }}port: {{ .port }}
      targetPort: {{ .port }}
      {{- with .protocol }}
      protocol: {{ . }}
      {{- end }}
    {{- end }}
{{- end -}}

{{/* A PersistentVolumeClaim of one component, on the cluster's default StorageClass unless one is named. */}}
{{- define "aisolate.pvc" -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ .name }}
  namespace: {{ .context.Release.Namespace }}
  labels:
    app: {{ .name }}
spec:
  accessModes: [ReadWriteOnce]
  {{- with .storageClass }}
  storageClassName: {{ . | quote }}
  {{- end }}
  resources:
    requests:
      storage: {{ .size | quote }}
{{- end -}}

{{/* A Next.js pod behind an Ingress on 3000 with no ServiceAccount token: the AIsolate UI and the sample chat. */}}
{{- define "aisolate.web" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .name }}
  namespace: {{ .context.Release.Namespace }}
  labels:
    app: {{ .name }}
spec:
  replicas: {{ .replicas }}
  selector:
    matchLabels:
      app: {{ .name }}
  template:
    metadata:
      labels:
        app: {{ .name }}
    spec:
      {{- include "aisolate.scheduling" .context | nindent 6 }}
      automountServiceAccountToken: false
      {{- include "aisolate.imagePullSecrets" .context | nindent 6 }}
      {{- with .hostAliases }}
      hostAliases:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        runAsUser: 1000   # the image's `node` user; runAsNonRoot needs the number to verify
        {{- include "aisolate.podSecurity" .context | nindent 8 }}
      containers:
        - name: {{ .name }}
          image: {{ include "aisolate.image" (dict "imageRoot" .image "context" .context) }}
          imagePullPolicy: {{ .image.pullPolicy }}
          ports:
            - name: http
              containerPort: 3000
          readinessProbe:
            httpGet:
              path: /
              port: 3000
            periodSeconds: 5
          {{- with .resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          securityContext:
            {{- include "aisolate.containerSecurity" .context | nindent 12 }}
          volumeMounts:
            - name: cache
              mountPath: {{ .cache }}
      volumes:
        - name: cache
          emptyDir: {}
{{- end -}}

{{/* The ingress rule from the ingress controller (platform.egress.ingressFrom) to one port. */}}
{{- define "aisolate.ingressControllerIngress" -}}
- from:
{{ include "aisolate.policyPeer" .context.Values.platform.egress.ingressFrom | indent 4 }}
  ports:
    - port: {{ .port }}
      protocol: TCP
{{- end -}}

{{/* A NetworkPolicy peer map for the controller's settings: label keys hold dots, and Spring's map
     binding splits a dotted key unless it is bracketed, so every key is written as "[key]". */}}
{{- define "aisolate.peer" -}}
{{- $peer := . -}}
{{- /* What no policy would bound fails the render; the controller checks the same at start. */ -}}
{{- if and $peer.cidr (or $peer.namespaceSelector $peer.podSelector) }}{{ fail "a peer is a cidr or selectors, not both" }}{{ end -}}
{{- if and $peer.cidr (lt (int (regexReplaceAll "^[^/]*/?" $peer.cidr "")) 8) }}{{ fail (printf "the cidr %s is too wide: /8 or longer" $peer.cidr) }}{{ end -}}
{{- if $peer.cidr }}
cidr: {{ $peer.cidr | quote }}
{{- end }}
{{- if $peer.namespaceSelector }}
namespaceSelector:
{{- range $k, $v := $peer.namespaceSelector }}
  "[{{ $k }}]": {{ $v | quote }}
{{- end }}
{{- end }}
{{- if $peer.podSelector }}
podSelector:
{{- range $k, $v := $peer.podSelector }}
  "[{{ $k }}]": {{ $v | quote }}
{{- end }}
{{- end }}
{{- if $peer.port }}
port: {{ $peer.port }}
{{- end }}
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

{{/* Where every pod of the release runs (platform.scheduling): the chart's Deployments and the helm test take it here,
     the controller the same from its settings for the pods it renders. */}}
{{- define "aisolate.scheduling" -}}
{{- with .Values.platform.scheduling.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.platform.scheduling.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
