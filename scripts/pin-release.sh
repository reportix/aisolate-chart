#!/usr/bin/env bash
# Pins the chart to an AIsolate release: its images by their digests on their registry, appVersion, and the CRDs
# of the release's tag, so the chart installs exactly what that release built. The chart's version is the release
# MR's to bump; tag stays empty, it only counts with allowTags. --check writes nothing and fails unless
# chart/values.yaml pins what the registry serves for chart/Chart.yaml's appVersion: CI runs it on release tags.
# Usage: scripts/pin-release.sh <appVersion> [--dry-run] | --check   (bash 3.2, yq, curl; git and tar for the CRDs)
set -euo pipefail
cd "$(dirname "$0")/.."

app_repo=git@ssh.gitlab.reportix.com:aisolate/aisolate.git
required="controller airlock toolServer airlockPython toolServerPython backend"
# Known limit: the UI and the chat bake their deployment's URLs in at build, so an installer builds them. They stay
# optional, with an empty registry by default, until they are published generically; then default their registry
# to docker-public.sonatype.reportix.com and make them required.
optional="frontend chat"
# Accepting the index types pins a multi-arch image by its index, not by one platform's manifest.
accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

if [[ $# == 1 && $1 == --check ]]; then mode=check version=$(yq '.appVersion' chart/Chart.yaml)
elif [[ $# == 1 || ( $# == 2 && $2 == --dry-run ) ]]; then mode=${2:-pin} version=$1
else mode= version=; fi
[[ $mode && $version =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]] || { echo "usage: $0 <appVersion> [--dry-run] | --check" >&2; exit 2; }

value() { k=$key yq ".platform[strenv(k)].image.$1" chart/values.yaml; }
keys=() digests=() failed=()
for key in $required $optional; do
  registry=$(value registry) repository=$(value repository) pinned=$(value digest) served= reason=
  image=${registry:+$registry/}$repository:$version
  if [[ -z $registry ]]; then
    reason="platform.$key.image.registry is empty"
  else
    url="https://$registry/v2/$repository/manifests/$version"
    # Known limit: anonymous HEAD, which docker-public answers today; add the Bearer token flow if it starts asking.
    headers=$(curl -sSI -H "Accept: $accept" "$url" | tr -d '\r') || true
    # The last status line: a proxy's CONNECT answer comes first.
    status=$(awk '/^HTTP\// { s = $2 } END { print s }' <<<"$headers")
    digest=$(awk 'tolower($1) == "docker-content-digest:" { print $2 }' <<<"$headers")
    echo "$url ${status:-no-answer} ${digest:--}"
    case $status in
      200) if [[ $digest =~ ^sha256:[a-f0-9]{64}$ ]]; then served=$digest; else reason="no sha256 digest (HTTP 200)"; fi ;;
      401|403) reason="registry refused anonymous access (HTTP $status)" ;;
      '') reason="no answer from $registry" ;;
      *) reason="no manifest (HTTP $status)" ;;
    esac
  fi
  case " $optional " in *" $key "*) opt=1 ;; *) opt= ;; esac
  if [[ $mode == check ]]; then
    # An optional image may stay empty; a digest it does carry must be the one served.
    if [[ $opt && -z $pinned ]]; then continue; fi
    if [[ -z $served ]]; then failed+=("$image: $reason")
    elif [[ $pinned != "$served" ]]; then failed+=("platform.$key.image.digest is ${pinned:-empty}, $image is $served"); fi
  elif [[ $served ]]; then
    keys+=("$key"); digests+=("$served")
  elif [[ $opt ]]; then
    echo "WARN: $image is not published: $reason; platform.$key.image.digest stays empty" >&2
    keys+=("$key"); digests+=("")
  else
    failed+=("$image: $reason")
  fi
done
if [[ ${#failed[@]} -gt 0 ]]; then
  if [[ $mode == check ]]; then echo "FAIL: chart/values.yaml does not pin what the registry serves for $version:" >&2
  else echo "FAIL: ${#failed[@]} of the release's images cannot be pinned; nothing written:" >&2; fi
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
if [[ $mode == check ]]; then echo "chart/values.yaml pins what the registry serves for $version"; exit 0; fi
if [[ $mode == --dry-run ]]; then
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
