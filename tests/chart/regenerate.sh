#!/usr/bin/env bash
# Rewrites what the chart tests compare against: chart/README.md, chart/values.schema.json and expected-results.
set -euo pipefail
source "$(dirname "$0")/common.sh"

docs=$(mktemp -d)
trap 'rm -rf "$docs"' EXIT
generate_docs "$docs" || { echo "README_GENERATOR_BIN is not set" >&2; exit 1; }
cp "$docs/README.md" chart/README.md
cp "$docs/values.schema.json" chart/values.schema.json
render "$TEST_DIR/expected-results"
echo "regenerated chart/README.md, chart/values.schema.json and tests/chart/expected-results"
