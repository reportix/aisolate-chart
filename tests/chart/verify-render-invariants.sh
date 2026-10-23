#!/usr/bin/env bash
# What the charts must always and never render, beyond the goldens: lint, what headless and
# headless=false contain, the routes, the restricted Pod Security Standard, no ServiceAccount
# tokens, the proxy's peers, the OTLP endpoint, the scraper's reach, the backend's and the controller's rights
# and the digest rule.
set -euo pipefail
source "$(dirname "$0")/common.sh"
values=$TEST_DIR/values
fail() { echo "FAIL: $*" >&2; exit 1; }
count() { yq -N "select(.kind == \"$1\") | .metadata.name" | grep -c . || true; }
render_with() { helm template t chart --namespace aisolate "$@"; }
restricted='select(.kind == "Deployment") | select((.spec.template.spec.securityContext.runAsNonRoot != true) or (.spec.template.spec.securityContext.seccompProfile.type != "RuntimeDefault") or ([.spec.template.spec.containers[] | select((.securityContext.allowPrivilegeEscalation != false) or ((.securityContext.capabilities.drop // []) | contains(["ALL"]) | not))] | length > 0)) | .metadata.name'

echo "== render invariants"
helm lint chart --values "$values/ui.yaml" >/dev/null || fail "helm lint (headless=false)"
helm lint chart --values "$values/headless.yaml" >/dev/null || fail "helm lint (headless)"

prod=$(render_with --values "$values/headless.yaml")
ui=$(render_with --values "$values/ui.yaml")
chat=$(render_with --values "$values/chat.yaml")
kc=$(render_with --values "$values/keycloak.yaml")

echo "headless (default): exactly the controller and the release-level objects"
[ "$(echo "$prod" | count Deployment)" = 1 ] || fail "headless renders $(echo "$prod" | count Deployment) Deployments, expected the controller only"
[ "$(echo "$prod" | count Namespace)" = 0 ] || fail "headless renders a Namespace"
echo "$prod" | yq -N 'select(.kind == "NetworkPolicy") | .metadata.name' | grep -x default-deny >/dev/null || fail "headless lacks default-deny"
echo "$prod" | yq -N 'select(.kind == "Service") | .metadata.name' | grep -x aisolate >/dev/null || fail "headless lacks the aisolate Service"
echo "$prod" | yq -N 'select(.kind == "Deployment") | .metadata.name' | grep -x ui >/dev/null && fail "headless renders the AIsolate UI"
echo "$prod" | grep -q "aisolate/backend" && fail "headless mentions the backend image: it comes with the AIsolate UI only"

echo "headless=false: the AIsolate UI on top"
[ "$(echo "$ui" | count Deployment)" = 4 ] || fail "headless=false renders $(echo "$ui" | count Deployment) Deployments, expected 4 (controller, backend, ui, db)"
echo "$ui" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[0].image' | grep -q "aisolate/backend" || fail "the backend Deployment does not run the backend image"
echo "$ui" | yq -N 'select(.kind == "Deployment") | .metadata.name' | grep -x ui >/dev/null || fail "headless=false lacks the AIsolate UI"
for pod in backend ui db; do
  echo "$ui" | yq -N "select(.kind == \"NetworkPolicy\" and .spec.podSelector.matchLabels.app == \"$pod\") | .metadata.name" | grep . >/dev/null || fail "no NetworkPolicy opens the $pod pod inside the default-deny"
done
[ "$(echo "$ui" | count Namespace)" = 0 ] || fail "headless=false renders a Namespace: the AIsolate UI shares aisolate"
for doc in "$prod" "$ui" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "Deployment" and .metadata.namespace != "aisolate") | .metadata.name' | grep . >/dev/null && fail "a Deployment outside aisolate"
  echo "$doc" | yq -N "$restricted" | grep . && fail "the Deployments above do not pass the restricted Pod Security Standard aisolate enforces"
  echo "$doc" | yq -N 'select(.kind == "Deployment" and .metadata.name != "aisolate-controller") | .spec.template.spec.containers[].env[]?.name' | grep -E -x 'AISOLATE_(OLLAMA_URL|TOOL_SERVER_URL|CONTEXT_PREPARATOR_DB_URL)' >/dev/null && fail "a Deployment names a model or tool server: only the pods talk to them"
done

echo "no policy of the chart's pods opens everything (helm test's own aside); the UI reaches nothing"
for doc in "$prod" "$ui" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name != "aisolate-test") | select([.spec.ingress[]?, .spec.egress[]?] | any_c(tag == "!!map" and length == 0)) | .metadata.name' | grep . && fail "the policies above admit or let out everything"
done
[ "$(echo "$ui" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "ui") | .spec.egress | length')" = 0 ] || fail "the UI may reach something: every API call is the browser's"
ingress_ports() { yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$1\") | .spec.ingress[].ports[].port" | sort -n | tr '\n' ' '; }
[ "$(echo "$ui" | ingress_ports backend)" = "8080 8085 9464 " ] || fail "the backend admits more than the ingress controller on 8080, the airlock and tool server pods on 8085 and the scraper on 9464: $(echo "$ui" | ingress_ports backend)"
ingest_from=$(echo "$ui" | yq -N -o json -I0 'select(.kind == "NetworkPolicy" and .metadata.name == "backend") | .spec.ingress[] | select(.ports[].port == 8085) | .from')
[ "$ingest_from" = '[{"podSelector":{"matchLabels":{"aisolate.dev/role":"airlock"}}},{"podSelector":{"matchLabels":{"aisolate.dev/role":"tool-server"}}}]' ] || fail "the backend's ingest port admits more than the airlock and tool server pods: $ingest_from"
echo "$ui" | yq -N 'select(.kind == "Ingress") | .spec.rules[].http.paths[].backend.service.port | (.number, .name)' | grep -x -E '8085|ingest' >/dev/null && fail "an Ingress routes to the ingest port: only the pods hand audit lines over and fetch their code"
[ "$(echo "$ui" | ingress_ports ui)" = "3000 " ] || fail "the UI admits more than the ingress controller on 3000: $(echo "$ui" | ingress_ports ui)"
egress_ports() { yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$1\") | .spec.egress[].ports[].port" | sort -n -u | tr '\n' ' '; }
[ "$(echo "$prod" | egress_ports aisolate-controller)" = "53 443 6443 8443 " ] || fail "the controller reaches more than the DNS and the API server: $(echo "$prod" | egress_ports aisolate-controller)"
[ "$(echo "$ui" | egress_ports backend)" = "53 443 5432 6443 8443 9090 16686 " ] || fail "the backend reaches more than the DNS, its database, the identity provider, the trace store, Prometheus and the API server: $(echo "$ui" | egress_ports backend)"
narrowed=$(render_with --values "$values/ui.yaml" --set platform.egress.apiServer.cidr=192.0.2.10/32)
for policy in aisolate-controller backend; do
  to=$(echo "$narrowed" | yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$policy\") | .spec.egress[] | select(.ports[].port == 6443) | .to[].ipBlock.cidr")
  [ "$to" = 192.0.2.10/32 ] || fail "platform.egress.apiServer.cidr does not narrow the $policy's way to the API server: '$to'"
done
[ "$(yq -N 'select(.platform.egress.apiServer.cidr != null) | .platform.egress.apiServer.cidr' chart/examples/example-values.yaml)" != "" ] || fail "the production example leaves the API server at any address"

echo "headless=false: only the backend reaches the database, which reaches nothing, by a generated password"
db_policy=$(echo "$ui" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "db")' | yq -o json -I0 '[.spec.ingress, .spec.egress]')
[ "$db_policy" = '[[{"from":[{"podSelector":{"matchLabels":{"app":"backend"}}}],"ports":[{"port":5432,"protocol":"TCP"}]}],[]]' ] || fail "the db policy admits more than the backend on 5432, or lets the database out: $db_policy"
echo "$ui" | yq -N 'select(.kind == "Deployment") | .spec.template.spec.containers[].env[]? | select(.name | test("PASSWORD")) | select(.value != null) | .name' | grep . && fail "a password above is a literal, not the db Secret"
[ "$(echo "$ui" | yq -N 'select(.kind == "Secret" and .metadata.name == "db") | .data.password | @base64d | length')" = 32 ] || fail "the db Secret's password is not 32 generated characters"
[ "$(echo "$ui" | yq -N 'select(.kind == "Deployment" and (.metadata.name == "db" or .metadata.name == "backend")) | .spec.template.metadata.annotations["checksum/db-password"]' | sort -u | grep -c .)" = 1 ] || fail "the db and the backend pods do not roll on the same password"
own=$(render_with --values "$values/ui.yaml" --set persistence.postgres.existingSecret=my-db)
echo "$own" | yq -N 'select(.kind == "Secret" and .metadata.name == "db") | .metadata.name' | grep . >/dev/null && fail "with existingSecret the chart still renders its own db Secret"
[ "$(echo "$own" | yq -N 'select(.kind == "Deployment") | .spec.template.spec.containers[].env[]? | select(.name | test("PASSWORD")) | .valueFrom.secretKeyRef.name' | sort -u)" = my-db ] || fail "with existingSecret the db and the backend do not read it"

echo "headless=false: with platform.audit.existingSecret the controller and the backend read the installer's Secret, and the chart renders no ingest key of its own"
audit=$(render_with --values "$values/ui.yaml" --set platform.audit.existingSecret=my-audit)
audit_env='select(.kind == "Deployment" and (.metadata.name == "aisolate-controller" or .metadata.name == "backend")) | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_AUDIT_INGEST_KEY" or .name == "AISOLATE_CONTROLLER_AUDIT_INGESTKEY")'
echo "$audit" | yq -N 'select(.kind == "Secret" and .metadata.name == "audit-ingest") | .metadata.name' | grep . >/dev/null && fail "with platform.audit.existingSecret the chart still renders its own audit-ingest Secret"
echo "$audit" | yq -N 'select(.kind == "Deployment") | select(.spec.template.metadata.annotations["checksum/audit-ingest-key"] != null) | .metadata.name' | grep . >/dev/null && fail "with platform.audit.existingSecret a Deployment still rolls on a checksum of an ingest key the chart cannot read"
[ "$(echo "$audit" | yq -N "$audit_env | .valueFrom.secretKeyRef.name" | tr '\n' ' ')" = "my-audit my-audit " ] || fail "with platform.audit.existingSecret the controller and the backend do not both read it: $(echo "$audit" | yq -N "$audit_env | .valueFrom.secretKeyRef.name" | tr '\n' ' ')"
[ "$(echo "$audit" | yq -N "$audit_env | .valueFrom.secretKeyRef.key" | sort -u)" = key ] || fail "with platform.audit.existingSecret the ingest key is not read from the key 'key' of the Secret"

echo "headless=false: the backend alone reads a generated credentials key; with platform.credentials.existingSecret the installer's; headless has none"
[ "$(echo "$ui" | yq -N 'select(.kind == "Secret" and .metadata.name == "credentials-key") | .data.key | @base64d | length')" = 64 ] || fail "the credentials-key Secret's key is not 64 generated characters"
[ "$(echo "$ui" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_CREDENTIALS_KEY") | .valueFrom.secretKeyRef | .name + "/" + .key')" = "credentials-key/key" ] || fail "the backend does not read the credentials key from the Secret"
echo "$ui" | yq -N 'select(.kind == "Deployment" and .metadata.name == "aisolate-controller") | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_CREDENTIALS_KEY") | .name' | grep . >/dev/null && fail "the controller reads the credentials key it must not hold"
[ "$(echo "$ui" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.metadata.annotations["checksum/credentials-key"] | select(. != null)' | grep -c .)" = 1 ] || fail "the backend does not roll on the credentials key"
creds=$(render_with --values "$values/ui.yaml" --set platform.credentials.existingSecret=my-creds)
echo "$creds" | yq -N 'select(.kind == "Secret" and .metadata.name == "credentials-key") | .metadata.name' | grep . >/dev/null && fail "with platform.credentials.existingSecret the chart still renders its own credentials-key Secret"
echo "$creds" | yq -N 'select(.kind == "Deployment") | select(.spec.template.metadata.annotations["checksum/credentials-key"] != null) | .metadata.name' | grep . >/dev/null && fail "with platform.credentials.existingSecret the backend still rolls on a checksum of a key the chart cannot read"
[ "$(echo "$creds" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_CREDENTIALS_KEY") | .valueFrom.secretKeyRef.name')" = my-creds ] || fail "with platform.credentials.existingSecret the backend does not read it"
echo "$prod" | yq -N 'select(.kind == "Secret" and .metadata.name == "credentials-key") | .metadata.name' | grep . >/dev/null && fail "headless renders a credentials key nobody uses"

echo "headless=false: the database keeps its data on the PersistentVolumeClaim db, of the cluster's default class unless named"
[ "$(echo "$ui" | yq -N 'select(.kind == "Deployment" and .metadata.name == "db") | .spec.template.spec.volumes[] | select(.name == "data") | .persistentVolumeClaim.claimName')" = db ] || fail "the database's data is not on the PersistentVolumeClaim db"
[ "$(echo "$ui" | yq -N 'select(.kind == "PersistentVolumeClaim" and .metadata.name == "db") | .spec.storageClassName == null')" = true ] || fail "an empty storageClass names a class instead of leaving the cluster's default"
[ "$(render_with --values "$values/ui.yaml" --set persistence.postgres.storage.storageClass=fast | yq -N 'select(.kind == "PersistentVolumeClaim") | .spec.storageClassName')" = fast ] || fail "persistence.postgres.storage.storageClass does not reach the claim"

echo "the release host's /.well-known/ is the pods' in both modes; the backend validates the operators' issuer when set, else the users'"
for doc in "$prod" "$ui"; do
  echo "$doc" | yq -N 'select(.kind == "Ingress" and .metadata.name == "aisolate") | .spec.rules[].http.paths[] | select(.path == "/.well-known/") | .backend.service.name' | grep -x aisolate >/dev/null || fail "the release host's /.well-known/ does not go to the pods"
done
issuer() { echo "$1" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_ISSUER_URI") | .value'; }
[ "$(issuer "$ui")" = https://idp-ops.example.com/realms/aisolate ] || fail "the backend does not validate the operators' issuer"
[ "$(issuer "$(render_with --values "$values/ui.yaml" --set platform.identity.operators.issuerUri=)")" = https://idp.example.com/realms/customer ] || fail "without operators the backend does not validate the users' issuer"
jwks() { echo "$1" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[].env[]? | select(.name == "SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWKSETURI") | .value'; }
users_jwks=https://idp.example.com/realms/customer/protocol/openid-connect/certs
[ -z "$(jwks "$(render_with --values "$values/ui.yaml" --set platform.identity.jwkSetUri=$users_jwks)")" ] || fail "with the operators' own issuer the backend takes the users' JWKS"
[ "$(jwks "$(render_with --values "$values/ui.yaml" --set platform.identity.operators.issuerUri= --set platform.identity.jwkSetUri=$users_jwks)")" = $users_jwks ] || fail "with a shared issuer the backend does not take its JWKS"
err=$(render_with --values "$values/ui.yaml" --set platform.identity.operators.egress.cidr=10.0.0.1/32 2>&1 >/dev/null) && fail "the chart rendered the operators' egress without a port"
echo "$err" | grep -q "platform.identity.operators.egress.port is required" || fail "the render failed, but not on the operators' egress port: $err"

echo "discovery reaches the discovery pods; an airlock's chat path is longer and wins"
for doc in "$prod" "$ui" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "Ingress" and .metadata.name == "aisolate") | .spec.rules[].http.paths[] | select(.path == "/v1/spaces/" and .pathType == "Prefix") | .backend.service.name' | grep -x aisolate >/dev/null || fail "the release Ingress lacks the Prefix route for one airlock's discovery"
done

echo "the release Service carries every user's token: it selects the discovery pods alone, never a pod running an airlock's code"
for doc in "$prod" "$ui" "$chat" "$kc"; do
  selector=$(echo "$doc" | yq -N -o json -I0 'select(.kind == "Service" and .metadata.name == "aisolate") | .spec.selector')
  [ "$selector" = '{"aisolate.dev/role":"discovery"}' ] || fail "the aisolate Service selects $selector, not the discovery pods alone"
done

echo "with platform.ingress.tls every Ingress serves its host from <name>-tls, and platform.ingress.annotations reach every Ingress"
tls=$(render_with --values "$values/ui.yaml" --set platform.ingress.tls=true --set 'platform.ingress.annotations.cert-manager\.io/cluster-issuer=ca' | yq -N 'select(.kind == "Ingress") | .metadata.name + " " + .spec.tls[0].secretName + " " + (.spec.tls[0].hosts[0] == .spec.rules[0].host | tostring) + " " + .metadata.annotations["cert-manager.io/cluster-issuer"]' | sort | tr '\n' ',')
[ "$tls" = "aisolate aisolate-tls true ca,backend backend-tls true ca,ui ui-tls true ca," ] || fail "an Ingress lacks its TLS or the annotations: $tls"

echo "no route ever points at port 8081"
for doc in "$prod" "$ui" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "Ingress") | .spec.rules[].http.paths[].backend.service.port.number' | grep -x 8081 >/dev/null && fail "an Ingress targets 8081"
done

echo "every Deployment but the controller and the backend mounts no ServiceAccount token"
for doc in "$prod" "$ui" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "Deployment" and .metadata.name != "aisolate-controller" and .metadata.name != "backend") | .spec.template.spec.automountServiceAccountToken' | grep -v '^false$' | grep . >/dev/null && fail "a Deployment mounts a token"
done

echo "headless with an egress proxy and a cidr ingress peer renders, the proxy's DNS peer as a real peer, a CONNECT route to its domains alone"
proxy=$(render_with --values "$values/headless.yaml" --set 'platform.egress.proxy.domains[0]=idp.example.com' --set platform.egress.proxy.image.digest=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --set platform.egress.ingressFrom.cidr=10.0.0.0/8 --set platform.egress.ingressFrom.namespaceSelector=null) || fail "headless with a proxy and a cidr ingress peer does not render"
echo "$proxy" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "egress-proxy") | .spec.egress[0].to[0].namespaceSelector.matchLabels."kubernetes.io/metadata.name"' | grep -x kube-system >/dev/null || fail "the proxy policy's DNS peer is not a namespaceSelector.matchLabels peer"
echo "$proxy" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "egress-proxy") | .spec.egress[0].to[0].port' | grep -v '^null$' | grep . >/dev/null && fail "the proxy policy's DNS peer carries a bare port"
echo "$proxy" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "egress-proxy")' | grep -q "aisolate.dev/scraper" && fail "the egress proxy's policy admits the scraper: it serves no metrics"
envoy=$(echo "$proxy" | yq -N 'select(.kind == "Deployment" and .metadata.name == "egress-proxy") | .spec.template.metadata.annotations["aisolate.dev/envoy-yaml"]')
vhosts='.static_resources.listeners[].filter_chains[].filters[].typed_config.route_config.virtual_hosts[]'
[ "$(echo "$envoy" | yq -N "[$vhosts | select(.routes | any_c(.route != null)) | .domains[]] | join(\" \")")" = "idp.example.com:443" ] || fail "the proxy lets out more than CONNECT idp.example.com:443: a name not on its domains has a route"
echo "$envoy" | yq -N "$vhosts | select(.name == \"refused\") | .routes[] | select(.direct_response.status != 403)" | grep . && fail "the proxy's catch-all does more than refuse with a 403"

echo "the controller's settings carry the OTLP endpoint only when it is set"
otlp() { yq -N 'select(.kind == "Deployment" and .metadata.name == "aisolate-controller") | .spec.template.metadata.annotations["aisolate.dev/settings"]' | yq -N '.aisolate.controller.observability.otlpEndpoint'; }
[ "$(echo "$prod" | otlp)" = "" ] || fail "headless renders an OTLP endpoint nobody set: $(echo "$prod" | otlp)"
[ "$(render_with --values "$values/observability.yaml" | otlp)" = "http://otel-collector.monitoring.svc:4318" ] || fail "the settings lack the OTLP endpoint observability.yaml sets"

echo "a scraper, by its fixed label in any namespace, reaches the pods that serve metrics on the management port alone, and no other"
scraper='.spec.ingress[]? | select(.from[].podSelector.matchLabels["aisolate.dev/scraper"] == "true") | select(.from[].namespaceSelector | tag == "!!map") | select(.from[].namespaceSelector | length == 0) | .ports[].port'
scraper_port() { yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$1\") | $scraper"; }
[ "$(echo "$prod" | scraper_port aisolate-controller)" = 9464 ] || fail "the controller's policy does not admit the scraper on 9464 alone: $(echo "$prod" | scraper_port aisolate-controller)"
[ "$(echo "$ui" | scraper_port backend)" = 9464 ] || fail "the backend's policy does not admit the scraper on 9464 alone: $(echo "$ui" | scraper_port backend)"

echo "the management port (9464) is on no Service and no Ingress; the kubelet probes it"
for doc in "$prod" "$ui" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "Service") | .spec.ports[] | (.port, .targetPort)' | grep -x -E '9464|management' >/dev/null && fail "a Service exposes the management port"
  echo "$doc" | yq -N 'select(.kind == "Ingress") | .spec.rules[].http.paths[].backend.service.port | (.number, .name)' | grep -x -E '9464|management' >/dev/null && fail "an Ingress routes to the management port"
done
echo "$ui" | yq -N 'select(.kind == "Deployment" and (.metadata.name == "aisolate-controller" or .metadata.name == "backend")) | .spec.template.spec.containers[0] | (.readinessProbe.httpGet.port, .livenessProbe.httpGet.port)' | grep -v -x management >/dev/null && fail "a probe of the controller or the backend is not on the management port"
for policy in db ui default-deny; do
  echo "$ui" | yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$policy\")" | grep -q "aisolate.dev/scraper" && fail "the $policy policy admits the scraper: it serves no metrics"
done

echo "every container of the chart's Deployments has a read-only root and runs an image by digest"
for doc in "$ui" "$proxy" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.securityContext.readOnlyRootFilesystem != true) | .name' | grep . && fail "the containers above write their root filesystem"
  echo "$doc" | yq -N 'select(.kind == "Deployment") | .spec.template.spec.containers[].image' | grep -v '@sha256:' && fail "the images above ship without a digest"
done

echo "every Deployment's container takes its resources from the values"
sized=$(render_with --values "$values/ui.yaml" --set 'platform.egress.proxy.domains[0]=idp.example.com' --set platform.egress.proxy.image.digest=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --set platform.controller.resources.requests.cpu=1m --set platform.backend.resources.requests.cpu=1m --set platform.frontend.resources.requests.cpu=1m \
  --set platform.chat.enabled=true --set platform.chat.image.digest=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --set platform.chat.resources.requests.cpu=1m \
  --set platform.keycloak.enabled=true --set platform.keycloak.resources.requests.cpu=1m \
  --set platform.egress.proxy.resources.requests.cpu=1m --set persistence.postgres.resources.requests.cpu=1m)
echo "$sized" | yq -N 'select(.kind == "Deployment") | select(.spec.template.spec.containers[0].resources.requests.cpu != "1m") | .metadata.name' | grep . && fail "the Deployments above ignore their resources value"

echo "a digest that is not sha256: and 64 hex digits is refused"
err=$(render_with --values "$values/headless.yaml" --set platform.controller.image.digest=sha256:aa 2>&1 >/dev/null) && fail "the chart rendered a short digest"
echo "$err" | grep -q "is not sha256: and 64 hex digits" || fail "the render failed, but not on the digest format: $err"

echo "without allowTags a tag-only image is refused, with or without the AIsolate UI"
err=$(render_with 2>&1 >/dev/null) && fail "the chart rendered without digests"
echo "$err" | grep -q "needs a digest" || fail "the render failed, but not on the digest rule: $err"
err=$(render_with --values "$values/headless.yaml" --set headless=false 2>&1 >/dev/null) && fail "the AIsolate UI rendered without digests"
echo "$err" | grep -q "needs a digest" || fail "the AIsolate UI's render failed, but not on the digest rule: $err"

echo "an egress peer with an open cidr, a cidr next to selectors or no port is refused"
err=$(render_with --values "$values/headless.yaml" --set 'platform.egress.hosts.db\.example\.com.cidr=0.0.0.0/0' --set 'platform.egress.hosts.db\.example\.com.port=5432' 2>&1 >/dev/null) && fail "the chart rendered a 0.0.0.0/0 peer"
echo "$err" | grep -q "too wide" || fail "the render failed, but not on the cidr width: $err"
err=$(render_with --values "$values/headless.yaml" --set 'platform.egress.hosts.db\.example\.com.cidr=10.0.0.1/32' 2>&1 >/dev/null) && fail "the chart rendered a peer without a port"
echo "$err" | grep -q "port is required" || fail "the render failed, but not on the port: $err"
err=$(render_with --values "$values/headless.yaml" --set 'platform.egress.hosts.db\.example\.com.cidr=10.0.0.1/32' --set 'platform.egress.hosts.db\.example\.com.port=5432' --set 'platform.egress.hosts.db\.example\.com.podSelector.app=db' 2>&1 >/dev/null) && fail "the chart rendered a cidr next to selectors"
echo "$err" | grep -q "not both" || fail "the render failed, but not on cidr-or-selectors: $err"

echo "headless=false: the backend may clear what it applied (its DELETE /v1/spaces), and writes no ConfigMap: the pods fetch their code from it"
role='select(.kind == "Role" and .metadata.name == "backend-apply") | .rules[]'
echo "$ui" | yq -N "$role | select(.resources[] == \"configmaps\") | .verbs[]" | grep . && fail "the backend may write ConfigMaps: the code no longer travels as one"
echo "$ui" | yq -N "$role | select(.resources[] == \"pods\") | .verbs[]" | grep -x list >/dev/null || fail "the backend cannot list pods to wait for them"
echo "$ui" | yq -N "$role | select(.resources[] == \"pods\") | .verbs[]" | grep -x -E 'delete|create|update|patch' >/dev/null && fail "the backend may write pods: read-only, the controller owns them"

echo "headless=false: the backend creates and deletes the airlocks' Secrets and never reads them"
secret_verbs=$(echo "$ui" | yq -N "$role | select(.resources | any_c(test(\"^(secrets|[*])\$\"))) | .verbs[]" | sort | tr '\n' ' ')
[ "$secret_verbs" = "create delete " ] || fail "the backend's Secret verbs are '$secret_verbs', expected create and delete only: get, list, watch, patch and update return the data"

echo "the controller's settings and the proxy's config are in no ConfigMap"
for doc in "$ui" "$proxy" "$chat" "$kc"; do
  echo "$doc" | yq -N 'select(.kind == "Deployment" and (.metadata.name == "aisolate-controller" or .metadata.name == "egress-proxy")) | .spec.template.spec.volumes[] | select(.configMap) | .name' | grep . && fail "the volumes above are ConfigMaps"
done
echo "$ui" | yq -N 'select(.kind == "ConfigMap") | .metadata.name' | grep . && fail "the chart renders the ConfigMaps above"

echo "the controller watches the three kinds and writes their status; nothing of an airlock is versioned"
controller_verbs() { echo "$prod" | yq -N "select(.kind == \"Role\" and .metadata.name == \"aisolate-controller\") | .rules[] | select(.resources[] == \"$1\") | .verbs[]" | sort | tr '\n' ' '; }
echo "$prod" | yq -N 'select(.kind == "Role") | .rules[].resources[]' | grep -q airlockversions && fail "a Role still names airlockversions"
for kind in globals spaces airlocks; do
  [ "$(controller_verbs $kind)" = "get list watch " ] || fail "the controller cannot get, list and watch $kind"
  [ "$(controller_verbs $kind/status)" = "get patch update " ] || fail "the controller cannot write the $kind' status"
done

echo "headless=false: the backend applies the Global as it applies a space"
[ "$(echo "$ui" | yq -N "$role | select(.resources[] == \"globals\") | .verbs[]" | sort | tr '\n' ' ')" = "create delete get list patch update " ] || fail "the backend cannot apply the Global"

echo "headless=false: the controller and the backend share one generated audit ingest key; headless has none"
[ "$(echo "$ui" | yq -N 'select(.kind == "Secret" and .metadata.name == "audit-ingest") | .data.key | @base64d | length')" = 48 ] || fail "the audit-ingest Secret's key is not 48 generated characters"
[ "$(echo "$ui" | yq -N 'select(.kind == "Deployment" and (.metadata.name == "aisolate-controller" or .metadata.name == "backend")) | .spec.template.metadata.annotations["checksum/audit-ingest-key"]' | sort -u | grep -c .)" = 1 ] || fail "the controller and the backend do not roll on the same ingest key"
echo "$prod" | yq -N 'select(.kind == "Secret" and .metadata.name == "audit-ingest") | .metadata.name' | grep . >/dev/null && fail "headless renders an ingest key nobody checks"
audit_url() { yq -N 'select(.kind == "Deployment" and .metadata.name == "aisolate-controller") | .spec.template.metadata.annotations["aisolate.dev/settings"]' | yq -N '.aisolate.controller.audit.url'; }
[ "$(echo "$ui" | audit_url)" = "http://backend.aisolate.svc:8085/v1/audit/events" ] || fail "headless=false does not point the airlock pods at the backend's ingest: $(echo "$ui" | audit_url)"
[ "$(echo "$prod" | audit_url)" = "" ] || fail "headless points the airlock pods at a backend it has not: $(echo "$prod" | audit_url)"
code_url() { yq -N 'select(.kind == "Deployment" and .metadata.name == "aisolate-controller") | .spec.template.metadata.annotations["aisolate.dev/settings"]' | yq -N '.aisolate.controller.code.url'; }
[ "$(echo "$ui" | code_url)" = "http://backend.aisolate.svc:8085/v1/code" ] || fail "headless=false does not point the pods at the backend's code: $(echo "$ui" | code_url)"
[ "$(echo "$prod" | code_url)" = "" ] || fail "headless points the pods at a backend it has not: $(echo "$prod" | code_url)"

echo "headless=false: an artifact of any size reaches the backend unless the operator sets platform.backend.maxArtifactSize"
api_ingress() { yq -N 'select(.kind == "Ingress" and .metadata.name == "backend") | .metadata.annotations["nginx.ingress.kubernetes.io/'"$1"'"]'; }
[ "$(echo "$ui" | api_ingress proxy-body-size)" = 0 ] || fail "the API host's Ingress caps the body: $(echo "$ui" | api_ingress proxy-body-size)"
[ "$(echo "$ui" | api_ingress proxy-request-buffering)" = off ] || fail "the API host's Ingress spools uploads to the ingress controller's disk"
[ "$(echo "$ui" | yq -N 'select(.kind == "Ingress" and .metadata.name == "ui") | .metadata.annotations["nginx.ingress.kubernetes.io/proxy-body-size"]')" = 16m ] || fail "the UI host's body limit changed"
max_env() { yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[0].env[] | select(.name == "AISOLATE_MAX_ARTIFACT_SIZE") | .value'; }
[ -z "$(echo "$ui" | max_env)" ] || fail "the backend limits artifacts by default: $(echo "$ui" | max_env)"
[ "$(render_with --values "$values/ui.yaml" --set platform.backend.maxArtifactSize=500MB | max_env)" = 500MB ] || fail "platform.backend.maxArtifactSize does not reach the backend"

echo "headless=false: the backend reads the trace store only when one is named, through its peer on its port alone"
trace_env() { yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[0].env[] | select(.name == "AISOLATE_TRACING_QUERY_URL") | .value'; }
trace_rule() { yq -N -o json -I0 'select(.kind == "NetworkPolicy" and .metadata.name == "backend") | .spec.egress[] | select(.ports[0].port == 16686)'; }
[ "$(echo "$ui" | trace_env)" = "http://jaeger.monitoring.svc:16686" ] || fail "platform.tracing.queryUrl does not reach the backend"
[ "$(echo "$ui" | trace_rule | jq -c '[.to[].podSelector.matchLabels.app, (.ports | length)]')" = '["jaeger",1]' ] || fail "the backend does not reach the trace store through its peer on its port alone"
no_trace=$(render_with --values "$values/ui.yaml" --set platform.tracing.queryUrl=)
[ -z "$(echo "$no_trace" | trace_env)$(echo "$no_trace" | trace_rule)" ] || fail "an empty tracing.queryUrl still configures a trace store"
err=$(render_with --values "$values/ui.yaml" --set platform.tracing.egress=null 2>&1 >/dev/null) && fail "a tracing.queryUrl without its peer rendered"
echo "$err" | grep -q "platform.tracing.egress" || fail "a tracing.queryUrl without its peer failed, but not on the peer: $err"

echo "headless=false: the backend asks Prometheus only when it is named, through its peer on its port alone"
metrics_env() { yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[0].env[] | select(.name == "AISOLATE_METRICS_QUERY_URL") | .value'; }
metrics_rule() { yq -N -o json -I0 'select(.kind == "NetworkPolicy" and .metadata.name == "backend") | .spec.egress[] | select(.ports[0].port == 9090)'; }
[ "$(echo "$ui" | metrics_env)" = "http://prometheus.monitoring.svc:9090" ] || fail "platform.metrics.queryUrl does not reach the backend"
[ "$(echo "$ui" | metrics_rule | jq -c '[.to[].podSelector.matchLabels.app, (.ports | length)]')" = '["prometheus",1]' ] || fail "the backend does not reach Prometheus through its peer on its port alone"
no_metrics=$(render_with --values "$values/ui.yaml" --set platform.metrics.queryUrl=)
[ -z "$(echo "$no_metrics" | metrics_env)$(echo "$no_metrics" | metrics_rule)" ] || fail "an empty metrics.queryUrl still configures Prometheus"
err=$(render_with --values "$values/ui.yaml" --set platform.metrics.egress=null 2>&1 >/dev/null) && fail "a metrics.queryUrl without its peer rendered"
echo "$err" | grep -q "platform.metrics.egress" || fail "a metrics.queryUrl without its peer failed, but not on the peer: $err"

echo "the example dashboard is Grafana JSON over Prometheus alone, one data source variable"
jq -e '([.panels[].datasource.type] | unique) == ["prometheus"] and ([.templating.list[] | select(.type == "datasource") | .query] == ["prometheus"])' chart/examples/grafana-dashboard.json >/dev/null \
  || fail "chart/examples/grafana-dashboard.json reads more than Prometheus"

echo "platform.chat.enabled: the sample chat on its own host, with or without the AIsolate UI; it reaches the DNS and the ingress controller alone"
[ "$(echo "$chat" | count Deployment)" = 2 ] || fail "headless with the chat renders $(echo "$chat" | count Deployment) Deployments, expected 2 (controller, chat)"
echo "$ui" | yq -N 'select(.metadata.name == "chat") | .kind' | grep . && fail "headless=false installs the chat unasked"
for kind in Deployment Service Ingress NetworkPolicy; do
  echo "$chat" | yq -N "select(.kind == \"$kind\" and .metadata.name == \"chat\") | .metadata.name" | grep -x chat >/dev/null || fail "the chat has no $kind"
done
[ "$(echo "$chat" | yq -N 'select(.kind == "Ingress" and .metadata.name == "chat") | .spec.rules[0].host')" = chat.example.com ] || fail "the chat's Ingress does not serve platform.chat.host"
[ "$(echo "$chat" | ingress_ports chat)" = "3000 " ] || fail "the chat admits more than the ingress controller on 3000: $(echo "$chat" | ingress_ports chat)"
[ "$(echo "$chat" | egress_ports chat)" = "53 80 443 " ] || fail "the chat reaches more than the DNS and the ingress controller: $(echo "$chat" | egress_ports chat)"
chat_peer() { yq -N -o json -I0 "select(.kind == \"NetworkPolicy\" and .metadata.name == \"chat\") | $1"; }
[ "$(echo "$chat" | chat_peer '.spec.egress[] | select(.ports[].port == 443) | .to')" = "$(echo "$chat" | chat_peer '.spec.ingress[0].from')" ] || fail "the chat's way out is not the ingress controller it is reached through"
echo "$chat" | yq -N 'select(.kind == "Deployment" and .metadata.name == "chat") | .spec.template.spec.hostAliases' | grep -v '^null$' | grep . && fail "the chat pod carries host entries nobody set"
aliased=$(render_with --values "$values/chat.yaml" --set 'platform.chat.hostAliases[0].ip=10.96.0.10' --set 'platform.chat.hostAliases[0].hostnames={aisolate.example.com,idp.example.com}' | yq -N -o json -I0 'select(.kind == "Deployment" and .metadata.name == "chat") | .spec.template.spec.hostAliases')
[ "$aliased" = '[{"hostnames":["aisolate.example.com","idp.example.com"],"ip":"10.96.0.10"}]' ] || fail "platform.chat.hostAliases does not reach the chat pod: $aliased"

echo "platform.keycloak.enabled: a Keycloak of the chart's own with the two realms; the pods take its users realm, the backend its operators realm, unless a provider is named"
[ "$(echo "$kc" | count Deployment)" = 6 ] || fail "headless=false with the chat and Keycloak renders $(echo "$kc" | count Deployment) Deployments, expected 6"
echo "$ui" | yq -N 'select(.metadata.name == "keycloak") | .kind' | grep . && fail "headless=false installs Keycloak unasked"
for kind in Deployment Service Ingress NetworkPolicy PersistentVolumeClaim Secret; do
  echo "$kc" | yq -N "select(.kind == \"$kind\" and .metadata.name == \"keycloak\") | .metadata.name" | grep -x keycloak >/dev/null || fail "Keycloak has no $kind"
done
[ "$(echo "$kc" | yq -N 'select(.kind == "Ingress" and .metadata.name == "keycloak") | .spec.rules[0].host')" = keycloak.example.com ] || fail "Keycloak's Ingress does not serve platform.keycloak.host"
[ "$(echo "$kc" | ingress_ports keycloak)" = "8080 8080 " ] || fail "Keycloak admits more than the ingress controller and the pods on 8080: $(echo "$kc" | ingress_ports keycloak)"
[ "$(echo "$kc" | egress_ports keycloak)" = "53 " ] || fail "Keycloak reaches more than the DNS: $(echo "$kc" | egress_ports keycloak)"
kc_from=$(echo "$kc" | yq -N -o json -I0 'select(.kind == "NetworkPolicy" and .metadata.name == "keycloak") | .spec.ingress[1].from')
[ "$kc_from" = '[{"podSelector":{"matchLabels":{"app":"backend"}}},{"podSelector":{"matchExpressions":[{"key":"aisolate.dev/role","operator":"In","values":["airlock","tool-server","discovery"]}]}}]' ] || fail "Keycloak's in-cluster peers are not the backend and the airlock, tool server and discovery pods: $kc_from"
settings_identity() { yq -N 'select(.kind == "Deployment" and .metadata.name == "aisolate-controller") | .spec.template.metadata.annotations["aisolate.dev/settings"]' | yq -N -o json -I0 '.aisolate.controller.identity'; }
[ "$(echo "$kc" | settings_identity | jq -r '.issuerUri + " " + .jwkSetUri + " " + .egress.podSelector["[app]"] + " " + (.egress.port | tostring)')" = "https://keycloak.example.com/realms/acme http://keycloak.aisolate.svc:8080/realms/acme/protocol/openid-connect/certs keycloak 8080" ] \
  || fail "the pods do not take the users realm of the chart's Keycloak, its in-cluster keys and its peer: $(echo "$kc" | settings_identity)"
[ "$(issuer "$kc")" = https://keycloak.example.com/realms/aisolate ] || fail "the backend does not take the operators realm of the chart's Keycloak: $(issuer "$kc")"
[ "$(jwks "$kc")" = http://keycloak.aisolate.svc:8080/realms/aisolate/protocol/openid-connect/certs ] || fail "the backend does not fetch the operators realm's keys in-cluster: $(jwks "$kc")"
[ "$(echo "$kc" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "backend") | .spec.egress[] | select(.ports[].port == 8080) | .to[].podSelector.matchLabels.app')" = keycloak ] || fail "the backend's policy does not reach Keycloak on 8080"
named=$(render_with --values "$values/keycloak.yaml" --set platform.identity.issuerUri=https://idp.example.com/realms/customer --set platform.identity.operators.issuerUri=https://idp-ops.example.com/realms/aisolate)
[ "$(echo "$named" | settings_identity | jq -r '.issuerUri + " " + (.jwkSetUri // "") + " " + (.egress | length | tostring)')" = "https://idp.example.com/realms/customer  0" ] || fail "a named users' provider does not win over the chart's Keycloak: $(echo "$named" | settings_identity)"
[ "$(issuer "$named") $(jwks "$named")" = "https://idp-ops.example.com/realms/aisolate " ] || fail "a named operators' provider does not win over the chart's Keycloak: $(issuer "$named") $(jwks "$named")"
err=$(render_with --values "$values/headless.yaml" --set platform.identity.issuerUri= 2>&1 >/dev/null) && fail "the chart rendered without any identity provider"
echo "$err" | grep -q "platform.identity.issuerUri is required" || fail "the render failed, but not on the missing identity provider: $err"
echo "$kc" | yq -N 'select(.kind == "Deployment" and .metadata.name == "keycloak") | .spec.template.spec.containers[0].env[] | select(.name | test("PASSWORD")) | .value' | grep -v '^null$' | grep . && fail "a Keycloak password is a literal in the pod"
realm() { yq -N "select(.kind == \"ConfigMap\" and .metadata.name == \"keycloak-realms\") | .data[\"realm-$1.json\"]"; }
for r in operators users; do echo "$kc" | realm $r | jq -e . >/dev/null || fail "the $r realm is not valid JSON after tpl"; done
[ "$(echo "$kc" | realm operators | jq -r '.realm + " " + ([.users[].username] | join(",")) + " " + ([.users[].credentials[].value] | unique | join(","))')" = 'aisolate admin,developer,auditor ${ADMIN_PASSWORD},${AUDITOR_PASSWORD},${DEVELOPER_PASSWORD}' ] || fail "the operators realm's demo users or their password placeholder are off: $(echo "$kc" | realm operators | jq -c '[.realm, [.users[].username]]')"
[ "$(echo "$kc" | realm users | jq -r '.realm + " " + ([.clients[].clientId] | join(",")) + " " + (.clients[0].redirectUris[0]) + " " + ([.users[].username] | join(","))')" = "acme aisolate-chat https://chat.example.com/* jane,john,auditor" ] || fail "the users realm's chat client or demo users are off: $(echo "$kc" | realm users | jq -c '[.realm, [.clients[].clientId], [.users[].username]]')"
[ "$(echo "$kc" | realm users | jq -r '.components["org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"][] | select(.providerId == "trusted-hosts") | .config["trusted-hosts"][0]')" = chat.example.com ] || fail "the users realm does not trust the chat's host for registration"
[ "$(echo "$kc" | realm operators | jq -r '.clients[] | select(.clientId == "aisolate-ui") | .redirectUris[0]')" = "https://ui.example.com/*" ] || fail "aisolate-ui does not redirect to the UI's host"
quiet=$(render_with --values "$values/keycloak.yaml" --set platform.keycloak.demoUsers=false)
[ "$(echo "$quiet" | realm operators | jq '.users | length') $(echo "$quiet" | realm users | jq '.users | length')" = "0 0" ] || fail "demoUsers=false still imports users"
echo "$quiet" | yq -N 'select(.kind == "Deployment" and .metadata.name == "keycloak") | .spec.template.spec.containers[0].env[].name' | grep -x -E 'JANE_PASSWORD|DEVELOPER_PASSWORD' && fail "demoUsers=false still hands the demo passwords to the pod"
[ "$(echo "$kc" | yq -N 'select(.kind == "Deployment" and .metadata.name == "keycloak") | .spec.template.spec.containers[0].env[] | select(.name == "JANE_PASSWORD") | .valueFrom.secretKeyRef.key')" = jane-password ] || fail "jane's password does not come from the key jane-password"
[ "$(echo "$kc" | yq -N 'select(.kind == "Secret" and .metadata.name == "keycloak") | .data | keys | sort | join(",")')" = "admin-password,auditor-password,developer-password,jane-password,john-password" ] || fail "the Secret keycloak lacks a demo user's key"
[ "$(echo "$kc" | yq -N 'select(.kind == "Deployment" and .metadata.name == "keycloak") | .spec.template.spec.initContainers[0].command[2]')" = "/opt/keycloak/bin/kc.sh build --db=dev-file --health-enabled=true && cp -r /opt/keycloak/lib/quarkus/. /build/" ] || fail "the init container does not build the server for the chart's options"
own=$(render_with --values "$values/keycloak.yaml" --set platform.keycloak.existingSecret=my-keycloak)
echo "$own" | yq -N 'select(.kind == "Secret" and .metadata.name == "keycloak") | .metadata.name' | grep . && fail "platform.keycloak.existingSecret still generates the Secret keycloak"
[ "$(echo "$own" | yq -N 'select(.kind == "Deployment" and .metadata.name == "keycloak") | .spec.template.spec.containers[0].env[] | select(.name == "KC_BOOTSTRAP_ADMIN_PASSWORD") | .valueFrom.secretKeyRef.name')" = my-keycloak ] || fail "the admin password does not come from platform.keycloak.existingSecret"

echo "render checks passed"
