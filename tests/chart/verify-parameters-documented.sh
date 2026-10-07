#!/usr/bin/env bash
# Cross-checks the chart's templates against its `## @param` annotations: every `.Values.X` a
# template reads must be documented, and every documented parameter must be used. The readme
# generator only ever sees values.yaml, so it cannot do this. Run from anywhere.
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
export LC_ALL=C

# Image blocks and .Values.global are handed over whole.
USED_PARAMETERS=$(grep -ohR '\.Values\.[.A-Za-z0-9_-]*' chart/templates | \
  sed -E 's/^\.Values\.//' | \
  grep -v -E '\.image(\.[A-Za-z]+)?$|^global$' | \
  sort -u)

# global.* is read by the Bitnami common helpers; common is the library chart's own values.
DOCUMENTED_PARAMETERS=$(grep -oh -E '@(param|extra)[[:space:]]+[.A-Za-z0-9_-]+' chart/values.yaml | \
  sed -E 's/^@(param|extra)[[:space:]]+//' | \
  grep -v -E '\.image(\.[A-Za-z]+)?$|^common$|^global\.(imageRegistry|imagePullSecrets)$' | \
  sort -u)

DOCUMENTED_UNUSED=$(comm -13 <(echo "$USED_PARAMETERS") <(echo "$DOCUMENTED_PARAMETERS"))
UNDOCUMENTED_USED=$(comm -23 <(echo "$USED_PARAMETERS") <(echo "$DOCUMENTED_PARAMETERS"))

if [ -n "${DOCUMENTED_UNUSED}" ] || [ -n "${UNDOCUMENTED_USED}" ]; then
  echo "***********"
  echo "The following parameters are documented but unused in the chart:"
  echo "$DOCUMENTED_UNUSED"
  echo "***********"
  echo "The following parameters are undocumented but used in the chart:"
  echo "$UNDOCUMENTED_USED"
  echo "***********"
  exit 1
fi
echo "All documented parameters are used in the chart"
echo "All parameters used in the chart are documented"
