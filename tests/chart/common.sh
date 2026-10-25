#!/usr/bin/env bash
# Shared by test.sh, regenerate.sh and verify-render-invariants.sh: the readme generator, the generated
# docs and the golden renders. Works from the repository root, under bash 3.2 and BSD or GNU tools.
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_DIR="$ROOT_DIR/tests/chart"
cd "$ROOT_DIR"

# The readme generator: a build of readme-generator-for-helm with the strict schema and the noReadme
# modifier, named by $README_GENERATOR_BIN. Without it the docs check is skipped and regenerate.sh stops.
readme_generator() {
  [ -n "${README_GENERATOR_BIN:-}" ] && echo "$README_GENERATOR_BIN"
}

# chart/README.md (its "## Parameters" section) and chart/values.schema.json, generated into <dir>.
# Returns 2 without a generator.
generate_docs() {
  local dir=$1 out bin
  bin=$(readme_generator) || return 2
  cp chart/README.md "$dir/README.md"
  out=$("$bin" --values chart/values.yaml --readme "$dir/README.md" --schema "$dir/values.schema.json" --strict 2>&1) \
    || { echo "$out" >&2; return 1; }
}

# One golden per scenario of tests/chart/values/, each rendered on top of digests.yaml.
render() {
  local dir=$1 values
  rm -rf "$dir" && mkdir -p "$dir"
  for values in tests/chart/values/*.yaml; do
    # The database password, the audit ingest key, the credentials key and Keycloak's passwords are random per render: the goldens keep their place, not their value.
    helm template aisolate chart --namespace aisolate --values tests/chart/digests.yaml --values "$values" \
      | yq '... comments="" | (select(.kind == "Secret" and .metadata.name == "db") | .data.password) = "generated"
          | (select(.kind == "Secret" and .metadata.name == "audit-ingest") | .data.key) = "generated"
          | (select(.kind == "Secret" and .metadata.name == "credentials-key") | .data.key) = "generated"
          | (select(.kind == "Secret" and .metadata.name == "keycloak") | .data[]) = "generated"
          | (select(.spec.template.metadata.annotations["checksum/credentials-key"] != null) | .spec.template.metadata.annotations["checksum/credentials-key"]) = "generated"
          | (select(.spec.template.metadata.annotations["checksum/audit-ingest-key"] != null) | .spec.template.metadata.annotations["checksum/audit-ingest-key"]) = "generated"
          | (select(.spec.template.metadata.annotations["checksum/db-password"] != null) | .spec.template.metadata.annotations["checksum/db-password"]) = "generated"' \
      > "$dir/$(basename "$values")"
  done
}
