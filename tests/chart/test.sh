#!/usr/bin/env bash
# The chart's checks: every parameter documented, the docs current, the golden renders, the render invariants.
set -euo pipefail
source "$(dirname "$0")/common.sh"

"$TEST_DIR/verify-parameters-documented.sh"

echo "== docs: chart/README.md and chart/values.schema.json are generated from chart/values.yaml"
docs=$(mktemp -d)
trap 'rm -rf "$docs"' EXIT
generate_docs "$docs" && status=0 || status=$?
case $status in
  0) diff -u chart/README.md "$docs/README.md" && diff -u chart/values.schema.json "$docs/values.schema.json" \
       || { echo "FAIL: the docs are out of date: run tests/chart/regenerate.sh" >&2; exit 1; } ;;
  2) echo "   skipped: set README_GENERATOR_BIN to check them" ;;
  *) exit 1 ;;
esac

echo "== golden renders: tests/chart/expected-results"
render "$TEST_DIR/actual-results"
diff -ru "$TEST_DIR/expected-results" "$TEST_DIR/actual-results" \
  || { echo "FAIL: the render differs from expected-results; if intended, run tests/chart/regenerate.sh" >&2; exit 1; }

"$TEST_DIR/verify-render-invariants.sh"
echo "chart tests passed"
