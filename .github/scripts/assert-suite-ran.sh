#!/usr/bin/env bash
# Fails unless every Test function declared under DIR passed in the go test
# -json output JSON. A file count would accept a file the build tag excludes,
# or a suite where every test skips; a vacuous pass is a failure here.
set -euo pipefail
dir="$1"
json="$2"

expected=$(grep -rh '^func Test' --include='*_test.go' "${dir}" | sed -E 's/^func (Test[A-Za-z0-9_]*).*/\1/' | grep -vx TestMain | sort -u)
if [ -z "${expected}" ]; then
  echo "::error::no tests declared under ${dir}; this job would pass vacuously"
  exit 1
fi

passed=$(jq -r 'select(.Action=="pass" and (.Test // "") != "") | .Test' "${json}" | sort -u)
missing=0
for name in ${expected}; do
  if ! grep -qx "${name}" <<<"${passed}"; then
    echo "::error::test ${name} under ${dir} did not pass"
    missing=$((missing + 1))
  fi
done
echo "tests declared under ${dir}: $(wc -w <<<"${expected}"), missing: ${missing}"
[ "${missing}" -eq 0 ]
