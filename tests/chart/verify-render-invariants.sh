#!/usr/bin/env bash
# What no render may ever say, beyond the two goldens. A golden says what a render is, and a regenerated one blesses any
# change; these fail on a weakened guarantee whatever the golden says: the network, the pods, the Secrets, the Roles, the
# controller's settings, the image digests, and the variants and refusals no golden covers (--set).
set -euo pipefail
source "$(dirname "$0")/common.sh"
values=$TEST_DIR/values
fail() { echo "FAIL: $*" >&2; exit 1; }
count() { yq -N "select(.kind == \"$1\") | .metadata.name" | grep -c . || true; }
render_with() { helm template t chart --namespace aisolate --values "$TEST_DIR/digests.yaml" "$@"; }
digest() { echo "sha256:$(printf '%064d' 0 | tr 0 "$1")"; }
settings() { yq -N 'select(.kind == "Deployment" and .metadata.name == "aisolate-controller") | .spec.template.metadata.annotations["aisolate.dev/settings"]'; }
restricted='select(.kind == "Deployment") | select((.spec.template.spec.securityContext.runAsNonRoot != true) or (.spec.template.spec.securityContext.seccompProfile.type != "RuntimeDefault") or ([.spec.template.spec.containers[] | select((.securityContext.allowPrivilegeEscalation != false) or ((.securityContext.capabilities.drop // []) | contains(["ALL"]) | not))] | length > 0)) | .metadata.name'

echo "== render invariants"
helm lint chart --values "$TEST_DIR/digests.yaml" --values "$values/headless.yaml" >/dev/null || fail "helm lint (headless)"
helm lint chart --values "$TEST_DIR/digests.yaml" --values "$values/full.yaml" >/dev/null || fail "helm lint (everything on)"

# prod: the default install, full: everything on (the goldens' two); ui: the AIsolate UI alone, with a provider of its
# own for the dashboard and the CLI.
prod=$(render_with --values "$values/headless.yaml")
full=$(render_with --values "$values/full.yaml")
ui_args=(--values "$values/headless.yaml" --set headless=false --set "platform.backend.image.digest=$(digest d)" --set "platform.frontend.image.digest=$(digest e)" --set platform.identity.operators.issuerUri=https://idp-ops.example.com/realms/aisolate)
ui=$(render_with "${ui_args[@]}")

echo "network: default-deny, no policy opens everything (helm test's own aside), a policy opens every Deployment's pods"
for doc in "$prod" "$ui" "$full"; do
  echo "$doc" | yq -N 'select(.kind == "NetworkPolicy") | .metadata.name' | grep -x default-deny >/dev/null || fail "no default-deny"
  echo "$doc" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name != "aisolate-test") | select([.spec.ingress[]?, .spec.egress[]?] | any_c(tag == "!!map" and length == 0)) | .metadata.name' | grep . && fail "the policies above admit or let out everything"
  echo "$doc" | yq ea -o json -I0 '[.]' | jq -r '[.[] | select(.kind == "NetworkPolicy") | (.spec.podSelector.matchLabels // {}) | select(. != {})] as $sel | .[] | select(.kind == "Deployment") | .metadata.name as $n | .spec.template.metadata.labels as $l | select([$sel[] | select(to_entries | all($l[.key] == .value))] | length == 0) | $n' | grep . && fail "no NetworkPolicy opens the Deployments above"
done

echo "every Deployment: in the release namespace, restricted, a read-only root, an image by digest, no ServiceAccount token (the controller and the backend aside), no model or tool server of its own"
for doc in "$prod" "$full"; do
  echo "$doc" | yq -N 'select(.kind == "Deployment" and .metadata.namespace != "aisolate") | .metadata.name' | grep . >/dev/null && fail "a Deployment outside aisolate"
  echo "$doc" | yq -N "$restricted" | grep . && fail "the Deployments above do not pass the restricted Pod Security Standard aisolate enforces"
  echo "$doc" | yq -N 'select(.kind == "Deployment" and .metadata.name != "aisolate-controller") | .spec.template.spec.containers[].env[]?.name' | grep -E -x 'AISOLATE_(OLLAMA_URL|TOOL_SERVER_URL|CONTEXT_PREPARATOR_DB_URL)' >/dev/null && fail "a Deployment names a model or tool server: only the pods talk to them"
  echo "$doc" | yq -N 'select(.kind == "Deployment" and .metadata.name != "aisolate-controller" and .metadata.name != "backend") | .spec.template.spec.automountServiceAccountToken' | grep -v '^false$' | grep . >/dev/null && fail "a Deployment mounts a token"
  echo "$doc" | yq -N 'select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.securityContext.readOnlyRootFilesystem != true) | .name' | grep . && fail "the containers above write their root filesystem"
  echo "$doc" | yq -N 'select(.kind == "Deployment") | .spec.template.spec | (.containers[], .initContainers[]?) | .image' | grep -v '@sha256:' && fail "the images above ship without a digest"
done

echo "peers: the UI reaches nothing; the backend admits the ingress controller, the scraper and, on its ingest port, the airlock and tool server pods; the controller reaches the DNS and the API server"
[ "$(echo "$full" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "ui") | .spec.egress | length')" = 0 ] || fail "the UI may reach something: every API call is the browser's"
ingress_ports() { yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$1\") | .spec.ingress[].ports[].port" | sort -n | tr '\n' ' '; }
egress_ports() { yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$1\") | .spec.egress[].ports[].port" | sort -n -u | tr '\n' ' '; }
[ "$(echo "$full" | ingress_ports backend)" = "8080 8085 9464 " ] || fail "the backend admits more than the ingress controller on 8080, the airlock and tool server pods on 8085 and the scraper on 9464: $(echo "$full" | ingress_ports backend)"
ingest_from=$(echo "$full" | yq -N -o json -I0 'select(.kind == "NetworkPolicy" and .metadata.name == "backend") | .spec.ingress[] | select(.ports[].port == 8085) | .from')
[ "$ingest_from" = '[{"podSelector":{"matchLabels":{"aisolate.dev/role":"airlock"}}},{"podSelector":{"matchLabels":{"aisolate.dev/role":"tool-server"}}}]' ] || fail "the backend's ingest port admits more than the airlock and tool server pods: $ingest_from"
[ "$(echo "$full" | ingress_ports ui)" = "3000 " ] || fail "the UI admits more than the ingress controller on 3000: $(echo "$full" | ingress_ports ui)"
[ "$(echo "$prod" | egress_ports aisolate-controller)" = "53 443 6443 8443 " ] || fail "the controller reaches more than the DNS and the API server: $(echo "$prod" | egress_ports aisolate-controller)"
[ "$(echo "$full" | egress_ports backend)" = "53 443 5432 6443 8080 8443 9090 16686 " ] || fail "the backend reaches more than the DNS, its database, the identity provider, the trace store, Prometheus and the API server: $(echo "$full" | egress_ports backend)"
for policy in aisolate-controller backend; do
  to=$(echo "$full" | yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$policy\") | .spec.egress[] | select(.ports[].port == 6443) | .to[].ipBlock.cidr")
  [ "$to" = 10.0.0.1/32 ] || fail "platform.egress.apiServer.cidr does not narrow the $policy's way to the API server: '$to'"
done
[ "$(yq -N 'select(.platform.egress.apiServer.cidr != null) | .platform.egress.apiServer.cidr' chart/examples/example-values.yaml)" != "" ] || fail "the production example leaves the API server at any address"
render_with --values chart/examples/example-values.yaml >/dev/null || fail "the production example does not render"
public='10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16 443 1'
public_rule() { yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$1\") | .spec.egress[] | select(.to[0].ipBlock.cidr == \"0.0.0.0/0\") | (.to[0].ipBlock.except | join(\",\")) + \" \" + (.ports[0].port | tostring) + \" \" + (.ports | length | tostring)"; }
[ "$(echo "$ui" | public_rule backend)" = "$public" ] || fail "the backend's way to an identity provider outside the cluster is not HTTPS to a public address alone: $(echo "$ui" | public_rule backend)"
[ "$(echo "$full" | public_rule egress-proxy)" = "$public" ] || fail "the proxy's way out is not HTTPS to a public address alone: $(echo "$full" | public_rule egress-proxy)"

echo "exposure: no Ingress routes to a port the design keeps inside (8081 tool servers, 8085 ingest, 9464 management), no Service exposes the management port, the release Service selects the discovery pods alone"
for doc in "$prod" "$full"; do
  echo "$doc" | yq -N 'select(.kind == "Ingress") | .spec.rules[].http.paths[].backend.service.port | (.number, .name)' | grep -x -E '8081|8085|ingest|9464|management' >/dev/null && fail "an Ingress routes to a port the design keeps inside the namespace"
  echo "$doc" | yq -N 'select(.kind == "Service") | .spec.ports[] | (.port, .targetPort)' | grep -x -E '9464|management' >/dev/null && fail "a Service exposes the management port"
  selector=$(echo "$doc" | yq -N -o json -I0 'select(.kind == "Service" and .metadata.name == "aisolate") | .spec.selector')
  [ "$selector" = '{"aisolate.dev/role":"discovery"}' ] || fail "the aisolate Service selects $selector, not the discovery pods alone"
done
tls=$(echo "$full" | yq -N 'select(.kind == "Ingress") | .metadata.name + " " + .spec.tls[0].secretName + " " + (.spec.tls[0].hosts[0] == .spec.rules[0].host | tostring) + " " + .metadata.annotations["cert-manager.io/cluster-issuer"]' | sort | tr '\n' ',')
[ "$tls" = "aisolate aisolate-tls true ca,backend backend-tls true ca,chat chat-tls true ca,keycloak keycloak-tls true ca,ui ui-tls true ca," ] || fail "an Ingress lacks its TLS or the annotations: $tls"

echo "a scraper, by its fixed label in any namespace, reaches the pods that serve metrics on the management port alone, and no other"
scraper='.spec.ingress[]? | select(.from[].podSelector.matchLabels["aisolate.dev/scraper"] == "true") | select(.from[].namespaceSelector | tag == "!!map") | select(.from[].namespaceSelector | length == 0) | .ports[].port'
scraper_port() { yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$1\") | $scraper"; }
[ "$(echo "$prod" | scraper_port aisolate-controller)" = 9464 ] || fail "the controller's policy does not admit the scraper on 9464 alone: $(echo "$prod" | scraper_port aisolate-controller)"
[ "$(echo "$full" | scraper_port backend)" = 9464 ] || fail "the backend's policy does not admit the scraper on 9464 alone: $(echo "$full" | scraper_port backend)"
for policy in $(echo "$full" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name != "aisolate-controller" and .metadata.name != "backend") | .metadata.name'); do
  echo "$full" | yq -N "select(.kind == \"NetworkPolicy\" and .metadata.name == \"$policy\")" | grep -q "aisolate.dev/scraper" && fail "the $policy policy admits the scraper: it serves no metrics"
done

echo "the egress proxy: a cidr ingress peer renders, its DNS peer is a real peer, CONNECT to its domains alone and a 403 for the rest"
cidr=$(render_with --values "$values/full.yaml" --set platform.egress.ingressFrom.cidr=10.0.0.0/8 --set platform.egress.ingressFrom.namespaceSelector=null) || fail "a cidr ingress peer does not render"
echo "$cidr" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "egress-proxy") | .spec.egress[0].to[0].namespaceSelector.matchLabels."kubernetes.io/metadata.name"' | grep -x kube-system >/dev/null || fail "the proxy policy's DNS peer is not a namespaceSelector.matchLabels peer"
echo "$cidr" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "egress-proxy") | .spec.egress[0].to[0].port' | grep -v '^null$' | grep . >/dev/null && fail "the proxy policy's DNS peer carries a bare port"
envoy=$(echo "$cidr" | yq -N 'select(.kind == "Deployment" and .metadata.name == "egress-proxy") | .spec.template.metadata.annotations["aisolate.dev/envoy-yaml"]')
vhosts='.static_resources.listeners[].filter_chains[].filters[].typed_config.route_config.virtual_hosts[]'
[ "$(echo "$envoy" | yq -N "[$vhosts | select(.routes | any_c(.route != null)) | .domains[]] | join(\" \")")" = "idp.example.com:443" ] || fail "the proxy lets out more than CONNECT idp.example.com:443: a name not on its domains has a route"
echo "$envoy" | yq -N "$vhosts | select(.name == \"refused\") | .routes[] | select(.direct_response.status != 403)" | grep . && fail "the proxy's catch-all does more than refuse with a 403"

echo "the controller's settings and the proxy's config are in no ConfigMap; the settings carry what the chart decided: the OTLP endpoint only when set, the audit and code URLs only with the UI, the identity provider's peer, the placement"
for doc in "$prod" "$full"; do
  echo "$doc" | yq -N 'select(.kind == "Deployment" and (.metadata.name == "aisolate-controller" or .metadata.name == "egress-proxy")) | .spec.template.spec.volumes[] | select(.configMap) | .name' | grep . && fail "the volumes above are ConfigMaps"
done
for doc in "$prod" "$ui"; do echo "$doc" | yq -N 'select(.kind == "ConfigMap") | .metadata.name' | grep . && fail "the chart renders the ConfigMaps above"; done
[ "$(echo "$prod" | settings | yq -N '.aisolate.controller.observability.otlpEndpoint')" = "" ] || fail "headless renders an OTLP endpoint nobody set"
[ "$(echo "$full" | settings | yq -N '.aisolate.controller.observability.otlpEndpoint')" = "http://otel-collector.monitoring.svc:4318" ] || fail "the settings lack the OTLP endpoint full.yaml sets"
[ "$(echo "$full" | settings | yq -N '.aisolate.controller.audit.url')" = "http://backend.aisolate.svc:8085/v1/audit/events" ] || fail "headless=false does not point the airlock pods at the backend's ingest: $(echo "$full" | settings | yq -N '.aisolate.controller.audit.url')"
[ "$(echo "$prod" | settings | yq -N '.aisolate.controller.audit.url')" = "" ] || fail "headless points the airlock pods at a backend it has not: $(echo "$prod" | settings | yq -N '.aisolate.controller.audit.url')"
[ "$(echo "$full" | settings | yq -N '.aisolate.controller.code.url')" = "http://backend.aisolate.svc:8085/v1/code" ] || fail "headless=false does not point the pods at the backend's code: $(echo "$full" | settings | yq -N '.aisolate.controller.code.url')"
[ "$(echo "$prod" | settings | yq -N '.aisolate.controller.code.url')" = "" ] || fail "headless points the pods at a backend it has not: $(echo "$prod" | settings | yq -N '.aisolate.controller.code.url')"
[ "$(echo "$full" | settings | yq -N -o json -I0 '.aisolate.controller.scheduling | [.nodeSelector, .tolerations]' | jq -S -c .)" = '[{"pool":"robot"},[{"effect":"NoSchedule","key":"pool","operator":"Equal","value":"robot"}]]' ] || fail "the controller's settings do not carry the placement for the pods it renders"
[ "$(echo "$prod" | settings | yq -N -o json -I0 '.aisolate.controller.scheduling | [.nodeSelector, .tolerations]' | jq -S -c .)" = '[{},[]]' ] || fail "the controller's settings carry a placement nobody set"
placement() { yq -N -o json -I0 "select(.kind == \"$1\") | {\"n\": .spec${2-.template.spec}.nodeSelector, \"t\": .spec${2-.template.spec}.tolerations}" | jq -S -c '[.n, .t]' | sort -u; }
unplaced=$(render_with --values "$values/full.yaml" --set platform.scheduling.nodeSelector=null --set platform.scheduling.tolerations=null)
for doc in "$prod" "$unplaced"; do
  [ "$(echo "$doc" | placement Deployment)" = "[null,null]" ] && [ "$(echo "$doc" | placement Pod '')" = "[null,null]" ] || fail "a Deployment or the helm test pod carries a placement nobody set: $(echo "$doc" | placement Deployment) $(echo "$doc" | placement Pod '')"
done
settings_identity() { settings | yq -N -o json -I0 '.aisolate.controller.identity'; }
[ "$(echo "$full" | settings_identity | jq -r '.issuerUri + " " + .jwkSetUri + " " + .egress.podSelector["[app]"] + " " + (.egress.port | tostring)')" = "https://keycloak.example.com/realms/acme http://keycloak.aisolate.svc:8080/realms/acme/protocol/openid-connect/certs keycloak 8080" ] \
  || fail "the pods do not take the users realm of the chart's Keycloak, its in-cluster keys and its peer: $(echo "$full" | settings_identity)"

echo "Roles: the backend writes no ConfigMap and no pod, creates and deletes the airlocks' Secrets and never reads them, applies the three kinds; the controller watches the three kinds and writes their status, and nothing of an airlock is versioned"
role='select(.kind == "Role" and .metadata.name == "backend-apply") | .rules[]'
echo "$full" | yq -N "$role | select(.resources[] == \"configmaps\") | .verbs[]" | grep . && fail "the backend may write ConfigMaps: the code no longer travels as one"
echo "$full" | yq -N "$role | select(.resources[] == \"pods\") | .verbs[]" | grep -x list >/dev/null || fail "the backend cannot list pods to wait for them"
echo "$full" | yq -N "$role | select(.resources[] == \"pods\") | .verbs[]" | grep -x -E 'delete|create|update|patch' >/dev/null && fail "the backend may write pods: read-only, the controller owns them"
secret_verbs=$(echo "$full" | yq -N "$role | select(.resources | any_c(test(\"^(secrets|[*])\$\"))) | .verbs[]" | sort | tr '\n' ' ')
[ "$secret_verbs" = "create delete " ] || fail "the backend's Secret verbs are '$secret_verbs', expected create and delete only: get, list, watch, patch and update return the data"
[ "$(echo "$full" | yq -N "$role | select(.resources[] == \"globals\") | .verbs[]" | sort | tr '\n' ' ')" = "create delete get list patch update " ] || fail "the backend cannot apply the Global"
controller_verbs() { echo "$prod" | yq -N "select(.kind == \"Role\" and .metadata.name == \"aisolate-controller\") | .rules[] | select(.resources[] == \"$1\") | .verbs[]" | sort | tr '\n' ' '; }
echo "$prod" | yq -N 'select(.kind == "Role") | .rules[].resources[]' | grep -q airlockversions && fail "a Role still names airlockversions"
for kind in globals spaces airlocks; do
  [ "$(controller_verbs $kind)" = "get list watch " ] || fail "the controller cannot get, list and watch $kind"
  [ "$(controller_verbs $kind/status)" = "get patch update " ] || fail "the controller cannot write the $kind' status"
done

echo "generated Secrets: long, one checksum on the pods that share one, no password is a literal, the backend alone holds the credentials key, the headless install generates none"
secret_len() { echo "$full" | yq -N "select(.kind == \"Secret\" and .metadata.name == \"$1\") | .data.$2 | @base64d | length"; }
[ "$(secret_len db password)" = 32 ] || fail "the db Secret's password is not 32 generated characters"
[ "$(secret_len audit-ingest key)" = 48 ] || fail "the audit-ingest Secret's key is not 48 generated characters"
[ "$(secret_len credentials-key key)" = 64 ] || fail "the credentials-key Secret's key is not 64 generated characters"
rolls() { echo "$full" | yq -N "select(.kind == \"Deployment\" and ($2)) | .spec.template.metadata.annotations[\"checksum/$1\"] | select(. != null)" | sort | uniq -c | awk '{print $1}'; }
[ "$(rolls db-password '.metadata.name == "db" or .metadata.name == "backend"')" = 2 ] || fail "the db and the backend pods do not roll on the same password"
[ "$(rolls audit-ingest-key '.metadata.name == "aisolate-controller" or .metadata.name == "backend"')" = 2 ] || fail "the controller and the backend do not roll on the same ingest key"
[ "$(rolls credentials-key '.metadata.name == "backend"')" = 1 ] || fail "the backend does not roll on the credentials key"
echo "$full" | yq -N 'select(.kind == "Deployment") | .spec.template.spec.containers[].env[]? | select(.name | test("PASSWORD")) | select(.value != null) | .name' | grep . && fail "a password above is a literal, not a Secret"
[ "$(echo "$full" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_CREDENTIALS_KEY") | .valueFrom.secretKeyRef | .name + "/" + .key')" = "credentials-key/key" ] || fail "the backend does not read the credentials key from the Secret"
echo "$full" | yq -N 'select(.kind == "Deployment" and .metadata.name == "aisolate-controller") | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_CREDENTIALS_KEY") | .name' | grep . >/dev/null && fail "the controller reads the credentials key it must not hold"
for generated in db audit-ingest credentials-key; do
  echo "$prod" | yq -N "select(.kind == \"Secret\" and .metadata.name == \"$generated\") | .metadata.name" | grep . >/dev/null && fail "headless renders the Secret $generated nobody uses"
done
db_policy=$(echo "$full" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "db")' | yq -o json -I0 '[.spec.ingress, .spec.egress]')
[ "$db_policy" = '[[{"from":[{"podSelector":{"matchLabels":{"app":"backend"}}}],"ports":[{"port":5432,"protocol":"TCP"}]}],[]]' ] || fail "the db policy admits more than the backend on 5432, or lets the database out: $db_policy"

echo "an installer's existingSecret replaces the generated one: the chart renders none of its own, no pod rolls on a checksum of a key it cannot read, the pods read the installer's"
own_secret() { # parameter, generated Secret, checksum annotation (none: empty), env names read, "readers:Secret/key" expected
  local own
  own=$(render_with --values "$values/full.yaml" --set "$1=mine")
  echo "$own" | yq -N "select(.kind == \"Secret\" and .metadata.name == \"$2\") | .metadata.name" | grep . >/dev/null && fail "with $1 the chart still renders its own $2 Secret"
  if [ -n "$3" ]; then
    echo "$own" | yq -N "select(.kind == \"Deployment\") | select(.spec.template.metadata.annotations[\"checksum/$3\"] != null) | .metadata.name" | grep . >/dev/null && fail "with $1 a Deployment still rolls on a checksum of a key the chart cannot read"
  fi
  [ "$(echo "$own" | yq -N "select(.kind == \"Deployment\") | .spec.template.spec.containers[].env[]? | select(.name | test(\"$4\")) | .valueFrom.secretKeyRef | .name + \"/\" + .key" | sort | uniq -c | awk '{print $1 ":" $2}' | tr '\n' ' ')" = "$5" ] || fail "with $1 the pods do not read the installer's Secret from the right keys"
}
own_secret persistence.postgres.existingSecret db db-password '^(POSTGRES|AISOLATE_DB)_PASSWORD$' "2:mine/password "
own_secret platform.audit.existingSecret audit-ingest audit-ingest-key '^AISOLATE_(AUDIT_INGEST_KEY|CONTROLLER_AUDIT_INGESTKEY)$' "2:mine/key "
own_secret platform.credentials.existingSecret credentials-key credentials-key '^AISOLATE_CREDENTIALS_KEY$' "1:mine/key "
own_secret platform.keycloak.existingSecret keycloak "" '^(KC_BOOTSTRAP_ADMIN|ADMIN|DEVELOPER|AUDITOR|JANE|JOHN)_PASSWORD$' "2:mine/admin-password 1:mine/auditor-password 1:mine/developer-password 1:mine/jane-password 1:mine/john-password "

echo "the backend validates the operators' issuer when it has one, else the users'; its keys follow the issuer; the chart's Keycloak is the default, a named provider wins"
issuer() { echo "$1" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[].env[]? | select(.name == "AISOLATE_ISSUER_URI") | .value'; }
jwks() { echo "$1" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[].env[]? | select(.name == "SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWKSETURI") | .value'; }
[ "$(issuer "$ui")" = https://idp-ops.example.com/realms/aisolate ] || fail "the backend does not validate the operators' issuer"
[ "$(issuer "$(render_with "${ui_args[@]}" --set platform.identity.operators.issuerUri=)")" = https://idp.example.com/realms/customer ] || fail "without operators the backend does not validate the users' issuer"
users_jwks=https://idp.example.com/realms/customer/protocol/openid-connect/certs
[ -z "$(jwks "$(render_with "${ui_args[@]}" --set platform.identity.jwkSetUri=$users_jwks)")" ] || fail "with the operators' own issuer the backend takes the users' JWKS"
[ "$(jwks "$(render_with "${ui_args[@]}" --set platform.identity.operators.issuerUri= --set platform.identity.jwkSetUri=$users_jwks)")" = $users_jwks ] || fail "with a shared issuer the backend does not take its JWKS"
err=$(render_with "${ui_args[@]}" --set platform.identity.operators.egress.cidr=10.0.0.1/32 2>&1 >/dev/null) && fail "the chart rendered the operators' egress without a port"
echo "$err" | grep -q "platform.identity.operators.egress.port is required" || fail "the render failed, but not on the operators' egress port: $err"
[ "$(issuer "$full")" = https://keycloak.example.com/realms/aisolate ] || fail "the backend does not take the operators realm of the chart's Keycloak: $(issuer "$full")"
[ "$(jwks "$full")" = http://keycloak.aisolate.svc:8080/realms/aisolate/protocol/openid-connect/certs ] || fail "the backend does not fetch the operators realm's keys in-cluster: $(jwks "$full")"
named=$(render_with --values "$values/full.yaml" --set platform.identity.issuerUri=https://idp.example.com/realms/customer --set platform.identity.operators.issuerUri=https://idp-ops.example.com/realms/aisolate)
[ "$(echo "$named" | settings_identity | jq -r '.issuerUri + " " + (.jwkSetUri // "") + " " + (.egress | length | tostring)')" = "https://idp.example.com/realms/customer  0" ] || fail "a named users' provider does not win over the chart's Keycloak: $(echo "$named" | settings_identity)"
[ "$(issuer "$named") $(jwks "$named")" = "https://idp-ops.example.com/realms/aisolate " ] || fail "a named operators' provider does not win over the chart's Keycloak: $(issuer "$named") $(jwks "$named")"
err=$(render_with --values "$values/headless.yaml" --set platform.identity.issuerUri= 2>&1 >/dev/null) && fail "the chart rendered without any identity provider"
echo "$err" | grep -q "platform.identity.issuerUri is required" || fail "the render failed, but not on the missing identity provider: $err"

echo "Keycloak: reached by the ingress controller, the backend and the pods alone, reaches the DNS alone; a realm names no password, its redirects and its registration are the UI's and the chat's hosts; demoUsers=false imports none"
[ "$(echo "$full" | ingress_ports keycloak)" = "8080 8080 " ] || fail "Keycloak admits more than the ingress controller and the pods on 8080: $(echo "$full" | ingress_ports keycloak)"
[ "$(echo "$full" | egress_ports keycloak)" = "53 " ] || fail "Keycloak reaches more than the DNS: $(echo "$full" | egress_ports keycloak)"
kc_from=$(echo "$full" | yq -N -o json -I0 'select(.kind == "NetworkPolicy" and .metadata.name == "keycloak") | .spec.ingress[1].from')
[ "$kc_from" = '[{"podSelector":{"matchLabels":{"app":"backend"}}},{"podSelector":{"matchExpressions":[{"key":"aisolate.dev/role","operator":"In","values":["airlock","tool-server","discovery"]}]}}]' ] || fail "Keycloak's in-cluster peers are not the backend and the airlock, tool server and discovery pods: $kc_from"
[ "$(echo "$full" | yq -N 'select(.kind == "NetworkPolicy" and .metadata.name == "backend") | .spec.egress[] | select(.ports[].port == 8080) | .to[].podSelector.matchLabels.app')" = keycloak ] || fail "the backend's policy does not reach Keycloak on 8080"
realm() { yq -N "select(.kind == \"ConfigMap\" and .metadata.name == \"keycloak-realms\") | .data[\"realm-$1.json\"]"; }
for r in operators users; do
  echo "$full" | realm $r | jq -e . >/dev/null || fail "the $r realm is not valid JSON after tpl"
  [ "$(echo "$full" | realm $r | jq -r '[.users[].credentials[].value | select(test("^\\$\\{[A-Z]+_PASSWORD\\}$") | not)] | length')" = 0 ] || fail "a user of the $r realm has a password that is not a placeholder"
done
[ "$(echo "$full" | realm users | jq -r '.clients[0].redirectUris[0] + " " + (.components["org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"][] | select(.providerId == "trusted-hosts") | .config["trusted-hosts"][0])')" = "https://chat.example.com/* chat.example.com" ] || fail "the users realm does not redirect to the chat's host or trust it for registration"
[ "$(echo "$full" | realm operators | jq -r '.clients[] | select(.clientId == "aisolate-ui") | .redirectUris[0]')" = "https://ui.example.com/*" ] || fail "aisolate-ui does not redirect to the UI's host"
quiet=$(render_with --values "$values/full.yaml" --set platform.keycloak.demoUsers=false)
[ "$(echo "$quiet" | realm operators | jq '.users | length') $(echo "$quiet" | realm users | jq '.users | length')" = "0 0" ] || fail "demoUsers=false still imports users"
echo "$quiet" | yq -N 'select(.kind == "Deployment" and .metadata.name == "keycloak") | .spec.template.spec.containers[0].env[].name' | grep -x -E 'JANE_PASSWORD|DEVELOPER_PASSWORD' && fail "demoUsers=false still hands the demo passwords to the pod"

echo "Monitoring: the backend reads the trace store and Prometheus only when they are named, each through its peer on its port alone; the sample chat renders without the UI and reaches the DNS and the ingress controller alone"
for store in "tracing jaeger 16686" "metrics prometheus 9090"; do
  set -- $store
  name=$1 app=$2 port=$3 var=AISOLATE_$(echo "$1" | tr a-z A-Z)_QUERY_URL
  backend_env() { yq -N "select(.kind == \"Deployment\" and .metadata.name == \"backend\") | .spec.template.spec.containers[0].env[] | select(.name == \"$var\") | .value"; }
  rule() { yq -N -o json -I0 "select(.kind == \"NetworkPolicy\" and .metadata.name == \"backend\") | .spec.egress[] | select(.ports[0].port == $port)"; }
  [ "$(echo "$full" | rule | jq -c '[.to[].podSelector.matchLabels.app, (.ports | length)]')" = "[\"$app\",1]" ] || fail "the backend does not reach $name's store through its peer on its port alone"
  unnamed=$(render_with --values "$values/full.yaml" --set "platform.$name.queryUrl=")
  [ -z "$(echo "$unnamed" | backend_env)$(echo "$unnamed" | rule)" ] || fail "an empty $name.queryUrl still configures a store"
  err=$(render_with --values "$values/full.yaml" --set "platform.$name.egress=null" 2>&1 >/dev/null) && fail "a $name.queryUrl without its peer rendered"
  echo "$err" | grep -q "platform.$name.egress" || fail "a $name.queryUrl without its peer failed, but not on the peer: $err"
done
chat_alone=$(render_with --values "$values/headless.yaml" --set platform.chat.enabled=true --set "platform.chat.image.digest=$(digest f)")
[ "$(echo "$chat_alone" | count Deployment)" = 2 ] || fail "headless with the chat renders $(echo "$chat_alone" | count Deployment) Deployments, expected 2 (controller, chat)"
echo "$chat_alone" | yq -N 'select(.kind == "Deployment" and .metadata.name == "chat") | .spec.template.spec.hostAliases' | grep -v '^null$' | grep . && fail "the chat pod carries host entries nobody set"
[ "$(echo "$full" | ingress_ports chat)" = "3000 " ] || fail "the chat admits more than the ingress controller on 3000: $(echo "$full" | ingress_ports chat)"
[ "$(echo "$full" | egress_ports chat)" = "53 80 443 " ] || fail "the chat reaches more than the DNS and the ingress controller: $(echo "$full" | egress_ports chat)"
chat_peer() { yq -N -o json -I0 "select(.kind == \"NetworkPolicy\" and .metadata.name == \"chat\") | $1"; }
[ "$(echo "$full" | chat_peer '.spec.egress[] | select(.ports[].port == 443) | .to')" = "$(echo "$full" | chat_peer '.spec.ingress[0].from')" ] || fail "the chat's way out is not the ingress controller it is reached through"

echo "the AIsolate UI alone installs no chat, no Keycloak, no artifact limit, no trace store, and keeps the database on the cluster's default class; the example dashboard reads Prometheus alone"
echo "$ui" | yq -N 'select(.metadata.name == "chat" or .metadata.name == "keycloak") | .kind' | grep . && fail "headless=false installs the chat or Keycloak unasked"
[ -z "$(echo "$ui" | yq -N 'select(.kind == "Deployment" and .metadata.name == "backend") | .spec.template.spec.containers[0].env[] | select(.name == "AISOLATE_MAX_ARTIFACT_SIZE" or .name == "AISOLATE_TRACING_QUERY_URL" or .name == "AISOLATE_METRICS_QUERY_URL") | .name')" ] || fail "the backend limits artifacts or reads a store nobody named"
[ "$(echo "$ui" | yq -N 'select(.kind == "PersistentVolumeClaim" and .metadata.name == "db") | .spec.storageClassName == null')" = true ] || fail "an empty storageClass names a class instead of leaving the cluster's default"
jq -e '([.panels[].datasource.type] | unique) == ["prometheus"] and ([.templating.list[] | select(.type == "datasource") | .query] == ["prometheus"])' chart/examples/grafana-dashboard.json >/dev/null \
  || fail "chart/examples/grafana-dashboard.json reads more than Prometheus"

echo "images: a digest that is not sha256: and 64 hex digits, a tag without allowTags and an open or half-named egress peer are refused; global.imageRegistry reaches every image"
err=$(render_with --values "$values/headless.yaml" --set platform.controller.image.digest=sha256:aa 2>&1 >/dev/null) && fail "the chart rendered a short digest"
echo "$err" | grep -q "is not sha256: and 64 hex digits" || fail "the render failed, but not on the digest format: $err"
# Each clears a digest itself: scripts/pin-release.sh fills the chart's own.
err=$(render_with --values "$values/headless.yaml" --set platform.controller.image.digest= 2>&1 >/dev/null) && fail "the chart rendered the controller with its digest cleared"
echo "$err" | grep -q "aisolate/controller needs a digest" || fail "the render failed, but not on the controller's cleared digest: $err"
err=$(render_with "${ui_args[@]}" --set platform.backend.image.digest= 2>&1 >/dev/null) && fail "the AIsolate UI rendered the backend with its digest cleared"
echo "$err" | grep -q "aisolate/backend needs a digest" || fail "the AIsolate UI's render failed, but not on the backend's cleared digest: $err"
err=$(render_with --values "$values/headless.yaml" --set 'platform.egress.hosts.db\.example\.com.cidr=0.0.0.0/0' --set 'platform.egress.hosts.db\.example\.com.port=5432' 2>&1 >/dev/null) && fail "the chart rendered a 0.0.0.0/0 peer"
echo "$err" | grep -q "too wide" || fail "the render failed, but not on the cidr width: $err"
err=$(render_with --values "$values/headless.yaml" --set 'platform.egress.hosts.db\.example\.com.cidr=10.0.0.1/32' 2>&1 >/dev/null) && fail "the chart rendered a peer without a port"
echo "$err" | grep -q "port is required" || fail "the render failed, but not on the port: $err"
err=$(render_with --values "$values/headless.yaml" --set 'platform.egress.hosts.db\.example\.com.cidr=10.0.0.1/32' --set 'platform.egress.hosts.db\.example\.com.port=5432' --set 'platform.egress.hosts.db\.example\.com.podSelector.app=db' 2>&1 >/dev/null) && fail "the chart rendered a cidr next to selectors"
echo "$err" | grep -q "not both" || fail "the render failed, but not on cidr-or-selectors: $err"
registry=$(render_with --values "$values/full.yaml" --set global.imageRegistry=registry.example.com)
echo "$registry" | yq -N 'select(.kind == "Deployment" or .kind == "Pod") | (.spec.template.spec // .spec) | (.containers[], .initContainers[]?) | .image' | grep -v '^registry.example.com/' && fail "the images above ignore global.imageRegistry"
echo "$registry" | settings | yq -N '.aisolate.controller.images | (.airlock, .toolServer, .airlockPython, .toolServerPython)' | grep -v '^registry.example.com/' && fail "the pod images the controller renders ignore global.imageRegistry"

echo "render checks passed"
