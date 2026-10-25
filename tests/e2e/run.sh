#!/usr/bin/env bash
# The chart end to end on a cluster: installs it from this tree with tag-only images (allowTags), the chart's own
# Keycloak as the users' identity provider and a stub model server, applies one Space and one Airlock (the company-hr
# template's documents without their code: a headless install runs airlocks without code only), runs helm test, then
# asks the airlock a question through the ingress as the realm's user john and expects the stub's reply as JSON.
# One line per step; the first FAIL prints the step's output with the pods, events and logs, and exits 1.
# Needs helm, kubectl 1.31 or newer (wait --for=create), curl and jq, and for the kind cluster Docker 28 or newer and
# kind; bash 3.2 will do.
#   --context <ctx>          an existing cluster instead of the kind cluster aisolate-e2e on this Docker (created, or
#                            reused when it exists, and deleted at the end). The run changes that cluster: it applies
#                            the chart's CRDs server-side, installs ingress-nginx when absent (its namespace,
#                            ClusterRoles, IngressClass and admission webhook stay), labels the namespace restricted,
#                            upgrades a release aisolate there and loads no images: give it a namespace you own on a
#                            cluster that can pull them
#   --images <prefix>:<tag>  the AIsolate images, <prefix>/<app>:<tag>; default aisolate:local, built on this Docker.
#                            kind gets them loaded, pulled first when missing (never the tag local), and needs no pull
#                            Secret
#   --namespace <ns>         default aisolate-e2e; on a given context, deleted at the end if this run created it
#   --keep                   delete nothing, to look around
set -euo pipefail

usage() { echo "usage: $0 [--context <ctx>] [--images <prefix>:<tag>] [--namespace <ns>] [--keep]" >&2; exit 2; }
root=$(cd "$(dirname "$0")/../.." && pwd)
cluster=aisolate-e2e ctx="" images=aisolate:local ns=aisolate-e2e keep=false
while [ $# -gt 0 ]; do
  case $1 in
    --context) ctx=${2:?$1 needs a value}; shift 2 ;;
    --images) images=${2:?$1 needs a value}; shift 2 ;;
    --namespace) ns=${2:?$1 needs a value}; shift 2 ;;
    --keep) keep=true; shift ;;
    *) usage ;;
  esac
done
prefix=${images%:*} tag=${images##*:}
case $tag in "$images" | "" | */*) usage ;; esac   # no tag: a registry's port would pass for one
tools="helm kubectl curl jq"
[ -n "$ctx" ] || tools="$tools docker kind"
for tool in $tools; do command -v "$tool" >/dev/null || { echo "$0 needs $tool" >&2; exit 2; }; done
# The stub's one reply, passed on as written: no digit, so the airlock grounds no figure and asks the model once.
answer="Hello from the stub model."
host=aisolate.example.com keycloak=keycloak.aisolate.example.com   # the chart's default hosts
# ingress-nginx, which the chart's defaults name (class nginx, its namespace); its last release. NodePort: no cloud
# load balancer, the run reaches it through a port-forward.
ingress_nginx=https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.15.1/deploy/static/provider/baremetal/deploy.yaml
tmp=$(mktemp -d)
own=false
if [ -z "$ctx" ]; then
  own=true ctx=kind-$cluster
  export KUBECONFIG=$tmp/kubeconfig   # the kind cluster stays out of ~/.kube/config
fi
k() { kubectl --context "$ctx" "$@"; }

cleanup() {
  if $keep; then
    if $own; then echo "kept: kind export kubeconfig --name $cluster"; else echo "kept: namespace $ns on $ctx"; fi
  elif $own; then
    kind delete cluster --name "$cluster" >/dev/null 2>&1 \
      || echo "warning: the kind cluster $cluster is left: kind delete cluster --name $cluster" >&2
  elif [ -f "$tmp/created-namespace" ]; then
    k delete namespace "$ns" --wait=false >/dev/null 2>&1 || echo "warning: the namespace $ns on $ctx is left" >&2
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

diagnose() {
  local n pod c
  # The containers that restarted: their logs before the restart say why.
  local restarted='(.status.initContainerStatuses // []) + (.status.containerStatuses // [])
    | .[] | select(.restartCount > 0) | .name'
  set +e
  echo "--- the cluster at the failure"
  k get pods -A -o wide
  k -n "$ns" get spaces,airlocks -o yaml
  for n in "$ns" ingress-nginx; do
    k -n "$n" get events --sort-by=.lastTimestamp | tail -n 25
    for pod in $(k -n "$n" get pods -o name); do
      echo "--- logs $n/$pod"
      k -n "$n" logs "$pod" --all-containers --prefix --tail=100
      for c in $(k -n "$n" get "$pod" -o json | jq -r "$restarted"); do
        echo "--- logs $n/$pod, container $c before its last restart"
        k -n "$n" logs "$pod" -c "$c" --previous --tail=100
      done
    done
  done
}

# <title> <function>: one PASS or FAIL line. The function runs in a subshell with errexit, which a `||` around it
# would switch off; its output is shown only when it fails.
step() {
  local title=$1 start=$SECONDS rc
  shift
  set +e
  ( set -e; "$@" ) >"$tmp/step.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" = 0 ]; then echo "PASS $title ($((SECONDS - start))s)"; return 0; fi
  echo "FAIL $title ($((SECONDS - start))s)"
  cat "$tmp/step.log"
  diagnose
  exit 1
}

create_cluster() {
  kind get clusters 2>/dev/null | grep -x "$cluster" >/dev/null || kind create cluster --name "$cluster" --wait 120s
  kind get kubeconfig --name "$cluster" >"$KUBECONFIG"
}

# The two images an airlock without code runs: the controller, and the airlock image of its pod and the discovery pods.
# Saved for the node's platform alone: kind load docker-image imports every platform a pulled image's index lists,
# most of which the containerd image store never fetched, and fails.
load_images() {
  local app image platform
  platform=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
  for app in controller airlock; do
    image=$prefix/$app:$tag
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      [ "$tag" != local ] || { echo "no image $image: build the images first (README.md, End-to-end test)"; return 1; }
      docker pull "$image"
    fi
    docker save --platform "$platform" -o "$tmp/image.tar" "$image"
    kind load image-archive "$tmp/image.tar" --name "$cluster"
  done
}

install_ingress() {
  k -n ingress-nginx get service ingress-nginx-controller >/dev/null 2>&1 || k apply -f "$ingress_nginx"
  k -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=300s
}

prepare_namespace() {
  if ! k get namespace "$ns" >/dev/null 2>&1; then
    k create namespace "$ns"
    touch "$tmp/created-namespace"
  fi
  k label namespace "$ns" pod-security.kubernetes.io/enforce=restricted --overwrite
  k apply --server-side --force-conflicts -f "$root/chart/crds"   # helm installs crds/ on the first install only
}

# Ollama's API as the airlock calls it, without a model: POST /api/chat, not streamed, the same reply to every request.
# Restricted like the release's pods; only the airlock pods reach it, through the namespace's default-deny.
deploy_stub() {
  k -n "$ns" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: llm-stub}
data:
  default.conf: |
    server {
      listen 8080;
      default_type application/json;
      location / {
        return 200 '{"model":"stub","created_at":"2026-01-01T00:00:00Z","message":{"role":"assistant","content":"$answer"},"done":true,"done_reason":"stop","total_duration":1,"load_duration":1,"prompt_eval_count":1,"prompt_eval_duration":1,"eval_count":1,"eval_duration":1}';
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: llm-stub}
spec:
  selector: {matchLabels: {app: llm-stub}}
  template:
    metadata: {labels: {app: llm-stub}}
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 101, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: nginx
          image: nginxinc/nginx-unprivileged:1.31.5-alpine-slim@sha256:736aa11ab9f9c320825722e411661c64559881e15e77f37137eef168ebe9515c
          ports: [{containerPort: 8080}]
          securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
          volumeMounts: [{name: conf, mountPath: /etc/nginx/conf.d}]
      volumes: [{name: conf, configMap: {name: llm-stub}}]
---
apiVersion: v1
kind: Service
metadata: {name: llm-stub}
spec:
  selector: {app: llm-stub}
  ports: [{port: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: llm-stub}
spec:
  podSelector: {matchLabels: {app: llm-stub}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {aisolate.dev/role: airlock}}}]
      ports: [{port: 8080}]
EOF
  k -n "$ns" rollout status deployment/llm-stub --timeout=120s
}

# Headless, with the chart's Keycloak and its demo users, over plain http (no TLS: the endpoints discovery names are
# http too); the stub is the one model host the airlock pods may reach.
install_chart() {
  local sets=() pair
  for pair in controller:controller airlock:airlock toolServer:tool-server airlockPython:airlock-python \
    toolServerPython:tool-server-python; do
    sets+=(--set "platform.${pair%%:*}.image.registry=" --set "platform.${pair%%:*}.image.repository=$prefix/${pair#*:}"
      --set "platform.${pair%%:*}.image.tag=$tag")
  done
  helm upgrade --install aisolate "$root/chart" --kube-context "$ctx" -n "$ns" --wait --timeout 10m "${sets[@]}" -f - <<EOF
allowTags: true
platform:
  ingress: {publicUrl: "http://$host"}
  keycloak: {enabled: true, demoUsers: true}
  egress:
    hosts:
      llm-stub.$ns.svc: {namespaceSelector: {kubernetes.io/metadata.name: $ns}, podSelector: {app: llm-stub}, port: 8080}
EOF
}

# The company-hr template's space and airlock (docs/documents.md in the app repository) without its code, answering
# with the stub; john (realm role employee) may ask it.
deploy_airlock() {
  k -n "$ns" apply -f - <<EOF
apiVersion: aisolate.dev/v1
kind: Space
metadata: {name: hr-space}
spec:
  displayName: hr-space
  description: "The employment contracts of Acme's people."
  access: {roles: [ceo]}
  llms:
    - {id: stub, provider: ollama, url: "http://llm-stub.$ns.svc:8080", model: stub}
---
apiVersion: aisolate.dev/v1
kind: Airlock
metadata: {name: hr-contracts}
spec:
  space: hr-space
  displayName: HR contracts
  description: "Employment contracts: position, pay, working time, notice and confidentiality."
  access: {roles: [employee], callers: ["*"]}
  llm: stub
  prompt: >-
    You are the Acme contracts assistant. Answer only from the employment contract passages provided to you;
    when no passage answers, reply exactly: I don't know.
EOF
  k -n "$ns" wait --for=create deployment/aisolate-discovery --timeout=120s
  k -n "$ns" rollout status deployment/aisolate-discovery --timeout=300s
  k -n "$ns" wait --for=jsonpath='{.status.phase}'=Ready airlock/hr-contracts --timeout=300s
  k -n "$ns" wait --for=condition=Ready pod -l aisolate.dev/airlock=hr-contracts --timeout=60s
}

run_helm_test() {
  helm test aisolate --kube-context "$ctx" -n "$ns" --timeout 5m
}

# As a chat client does: a token from Keycloak, the airlock's endpoint from discovery, one question; every host through
# one port-forward to the ingress controller, so the release's Ingresses and network policies are on the path.
ask_airlock() {
  local port="" password token endpoint="" code
  # kubectl itself in the background, not k() in a subshell: $! must be the forward that the kill ends, which outlives
  # the run under --keep and --context.
  kubectl --context "$ctx" -n ingress-nginx port-forward service/ingress-nginx-controller 0:80 >"$tmp/forward" 2>&1 &
  forward=$!
  trap 'kill "$forward" 2>/dev/null' EXIT
  for _ in $(seq 1 30); do
    port=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$tmp/forward")
    [ -n "$port" ] && break
    sleep 1
  done
  [ -n "$port" ] || { cat "$tmp/forward"; return 1; }
  # Every host through the forward; no request waits more than a minute.
  through_ingress() { curl --max-time 60 --connect-to "::127.0.0.1:$port" "$@"; }
  password=$(k -n "$ns" get secret keycloak -o go-template='{{index .data "john-password" | base64decode}}')
  token=$(through_ingress -sSf "http://$keycloak/realms/acme/protocol/openid-connect/token" -d grant_type=password \
    -d client_id=aisolate-chat -d username=john --data-urlencode "password=$password" -d scope=openid | jq -er .access_token)
  # The discovery pods read the airlocks from a mounted ConfigMap, which the kubelet refreshes within about a minute.
  for _ in $(seq 1 40); do
    endpoint=$(through_ingress -sf "http://$host/v1/airlocks" -H "Authorization: Bearer $token" \
      | jq -r '.[] | select(.id == "hr-contracts") | .endpoint') && [ -n "$endpoint" ] && break
    sleep 3
  done
  echo "discovery: hr-contracts at $endpoint"
  [ "$endpoint" = "http://$host/v1/spaces/hr-space/airlocks/hr-contracts/chat" ]
  # The ingress controller routes to a new airlock pod seconds after it is ready: a request without a token gets 401 then.
  for _ in $(seq 1 20); do
    code=$(through_ingress -s -o /dev/null -w '%{http_code}' -X POST "$endpoint" -H 'Content-Type: application/json' -d '{}') \
      || true
    [ "$code" = 401 ] && break
    sleep 3
  done
  code=$(through_ingress -sS -o "$tmp/answer.json" -w '%{http_code}' "$endpoint" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"message":"What is my notice period?"}')
  echo "answer ($code): $(cat "$tmp/answer.json")"
  [ "$code" = 200 ] && [ "$(jq -r .answer "$tmp/answer.json")" = "$answer" ]
}

if $own; then
  if kind get clusters 2>/dev/null | grep -x "$cluster" >/dev/null; then
    echo "note: this run reuses the kind cluster $cluster$($keep || echo ", and deletes it at the end")"
  fi
  step "kind cluster $cluster" create_cluster
  step "images $prefix/controller:$tag and $prefix/airlock:$tag loaded" load_images
fi
step "ingress-nginx" install_ingress
step "namespace $ns (restricted) and the CRDs" prepare_namespace
step "stub model server" deploy_stub
step "chart installed: the controller and Keycloak ready" install_chart
step "Space hr-space and Airlock hr-contracts: the discovery and airlock pods ready" deploy_airlock
step "helm test" run_helm_test
step "john asks hr-contracts through the ingress: the model's reply as JSON" ask_airlock
echo "PASS e2e (${SECONDS}s)"
