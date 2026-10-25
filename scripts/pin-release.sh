#!/usr/bin/env bash
# Pins the chart to an AIsolate release: its images by their digests on their registry, appVersion, and
# the CRDs of the release's tag, so the chart installs exactly what that release built. The chart's version
# is the release MR's to bump; tag stays empty, it only counts with allowTags.
# Usage: scripts/pin-release.sh <appVersion> [--dry-run]    (bash 3.2, yq, curl; git and tar for the CRDs)
set -euo pipefail
cd "$(dirname "$0")/.."

app_repo=git@ssh.gitlab.reportix.com:aisolate/aisolate.git
images="controller airlock toolServer airlockPython toolServerPython backend"
# ponytail: the UI and the chat bake their deployment's URLs in at build, so an installer builds them and they stay
# optional until they are published generically; then make them required.
optional="frontend chat"
# Accepting the index types pins a multi-arch image by its index, not by one platform's manifest.
accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

version=${1:-} dry_run=${2:-}
[[ $# -le 2 && $version =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ && ( -z $dry_run || $dry_run == --dry-run ) ]] \
  || { echo "usage: $0 <appVersion> [--dry-run]" >&2; exit 2; }

keys=() digests=() missing=()
for key in $images $optional; do
  image=$(k=$key yq '.platform[strenv(k)].image | .registry + "/" + .repository' chart/values.yaml)
  url="https://${image%%/*}/v2/${image#*/}/manifests/$version"
  # ponytail: anonymous HEAD, which docker-public answers today; add the Bearer token flow if it starts asking.
  headers=$(curl -sSI -H "Accept: $accept" "$url" | tr -d '\r') || true
  # The last status line: a proxy's CONNECT answer comes first.
  status=$(awk '/^HTTP\// { s = $2 } END { print s }' <<<"$headers")
  digest=$(awk 'tolower($1) == "docker-content-digest:" { print $2 }' <<<"$headers")
  echo "$url ${status:-no-answer} ${digest:--}"
  if [[ $status == 200 && $digest =~ ^sha256:[a-f0-9]{64}$ ]]; then
    keys+=("$key"); digests+=("$digest")
  elif [[ " $optional " == *" $key "* ]]; then
    echo "WARN: $image:$version is not published (HTTP ${status:-no answer}); platform.$key.image.digest stays empty" >&2
    keys+=("$key"); digests+=("")
  else
    missing+=("$image:$version (HTTP ${status:-no answer})")
  fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "FAIL: ${#missing[@]} of the release's images have no manifest on their registry; nothing pinned:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi
if [[ $dry_run ]]; then
  echo "would write these digests to chart/values.yaml and appVersion \"$version\" to chart/Chart.yaml, and"
  echo "replace chart/crds/*.yaml with crds/*.yaml of $app_repo at $version"
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git archive --remote="$app_repo" "$version" crds | tar -x -C "$tmp"
crds=("$tmp"/crds/*.yaml)
[[ -e ${crds[0]} ]] || { echo "FAIL: $app_repo has no crds/*.yaml at $version" >&2; exit 1; }

# sed, not yq -i: yq drops values.yaml's blank lines and unfolds Chart.yaml's description.
sed_args=()
for i in "${!keys[@]}"; do
  sed_args+=(-e "/@param platform\.${keys[$i]}\.image\.digest /{n;s|^\( *digest:\).*|\1 ${digests[$i]:-\"\"}|;}")
done
sed "${sed_args[@]}" chart/values.yaml > "$tmp/values.yaml"
sed "s/^appVersion: .*/appVersion: \"$version\"/" chart/Chart.yaml > "$tmp/Chart.yaml"
# Read back before anything moves: a digest line that left its @param line fails here instead of shipping empty.
for i in "${!keys[@]}"; do
  [[ $(k=${keys[$i]} yq '.platform[strenv(k)].image.digest' "$tmp/values.yaml") == "${digests[$i]}" ]] \
    || { echo "FAIL: no digest line right under @param platform.${keys[$i]}.image.digest" >&2; exit 1; }
done
[[ $(yq '.appVersion' "$tmp/Chart.yaml") == "$version" ]] || { echo "FAIL: chart/Chart.yaml has no appVersion line" >&2; exit 1; }

mv "$tmp/values.yaml" chart/values.yaml
mv "$tmp/Chart.yaml" chart/Chart.yaml
rm -f chart/crds/*.yaml
mv "${crds[@]}" chart/crds/
echo "pinned $version; next: tests/chart/regenerate.sh (the parameter table shows the digests), then the release MR"
