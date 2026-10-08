#!/usr/bin/env bash
set -euo pipefail

# Gates the licences of the Go modules gauntlet imports -- what
# `go build ./...` actually ships, not build- or test-only tooling.
# Copied from birdcage's scripts/licence-check.sh, unchanged apart from
# the module path below and the second check at the end; kept host
# independent for the same reason birdcage's is.
#
# Two checks. go-licenses gives every linked package the licence of the
# nearest licence file above it and holds that to allow-licenses -- which
# covers vendored code that carries its own licence file. Then
# scripts/licence-check-bundled.py looks inside the same modules for what
# go-licenses cannot see (#64): vendored code with no licence file of its
# own, and files embedded with //go:embed. Each needs a recorded review
# under go-bundled-assets: in the policy file.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_FILE="${POLICY_FILE:-$SCRIPT_DIR/../supply-chain/licence-policy.yml}"
GO_LICENSES_VERSION="${GO_LICENSES_VERSION:-v2.0.1}"

if [ ! -f "$POLICY_FILE" ]; then
  echo "licence-check: policy file not found: $POLICY_FILE" >&2
  exit 1
fi

# Extract the allow-licenses list entries (lines "  - X" under that key,
# up to the next top-level key) straight out of the policy file. No yq:
# the file's shape is simple and fixed enough for awk/sed.
ALLOWED_LICENSES="$(awk '
  /^allow-licenses:/ { in_list=1; next }
  /^[^[:space:]]/ { in_list=0 }
  in_list && /^[[:space:]]*-[[:space:]]*/ {
    sub(/^[[:space:]]*-[[:space:]]*/, "")
    print
  }
' "$POLICY_FILE" | sed 's/[[:space:]]*$//' | paste -sd, -)"

# An empty list must fail loudly rather than silently allowing every
# licence: go-licenses treats a blank --allowed_licenses as "no
# restriction", so a policy file that lost its entries (or whose key name
# drifted from what this script parses) must not pass quietly.
if [ -z "$ALLOWED_LICENSES" ]; then
  echo "licence-check: no allow-licenses entries found in $POLICY_FILE -- refusing to run with an empty allow-list" >&2
  exit 1
fi

echo "licence-check: allowed licences: $ALLOWED_LICENSES"

# `go install pkg@version` ignores this module's go.mod, so on a host whose
# default Go is older than the module's it builds go-licenses with the old
# toolchain, which then cannot classify the newer standard library and
# fails. Build it with the toolchain this module selects instead.
GOTOOLCHAIN="$(go env GOVERSION)" go install "github.com/google/go-licenses/v2@${GO_LICENSES_VERSION}"

# Per-module exceptions: allow-dependencies-licenses entries, each
# "pkg:golang/<module>@<version>" with a comment giving the reason and a
# review date. Without this the policy file documented an exception that
# changed nothing. An entry holds for that exact version only: if the
# build list has the module at any other version, or not at all, the
# entry is stale and fails, so a bump puts the new version's licence in
# front of the owner again -- the same rule go-bundled-assets follows.
# The reason lives in a comment nothing can parse, so the whole entry is
# printed, comment and all, beside the module it excepts.
IGNORE_ARGS=(--ignore github.com/tomlawesome/gauntlet)
EXCEPTION_FAILED=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  purl="${line%%#*}"
  purl="$(printf '%s' "$purl" | sed 's/[[:space:]]*$//')"
  case "$purl" in
    pkg:golang/?*@?*) ;;
    *)
      echo "licence-check: allow-dependencies-licenses entry is not pkg:golang/<module>@<version>: $line" >&2
      EXCEPTION_FAILED=1
      continue
      ;;
  esac
  ref="${purl#pkg:golang/}"
  module="${ref%@*}"
  want="${ref##*@}"
  got="$(go list -m -f '{{.Version}}' "$module" 2>/dev/null || true)"
  if [ "$got" != "$want" ]; then
    echo "licence-check: stale allow-dependencies-licenses entry: the build has $module at ${got:-no version (not required)}, the entry names $want: $line" >&2
    EXCEPTION_FAILED=1
    continue
  fi
  # go-licenses matches --ignore as a plain string prefix of each package
  # path, so excepting example.com/foo would also pass example.com/foobar
  # and any module nested under example.com/foo/. Refuse an entry whose
  # path is a prefix of another module in the build: the exception must
  # cover the one module the owner reviewed and nothing else.
  others="$(go list -m -f '{{.Path}}' all | awk -v m="$module" 'index($0, m) == 1 && $0 != m')"
  if [ -n "$others" ]; then
    echo "licence-check: allow-dependencies-licenses entry for $module would also except $(printf '%s' "$others" | paste -sd, -): $line" >&2
    EXCEPTION_FAILED=1
    continue
  fi
  echo "licence-check: excepted $module@$want by allow-dependencies-licenses: $line"
  IGNORE_ARGS+=(--ignore "$module")
done < <(awk '
  /^allow-dependencies-licenses:/ { in_list=1; next }
  /^[^[:space:]]/ { in_list=0 }
  in_list && /^[[:space:]]*-[[:space:]]*/ {
    sub(/^[[:space:]]*-[[:space:]]*/, "")
    print
  }
' "$POLICY_FILE" | sed 's/[[:space:]]*$//')
if [ "$EXCEPTION_FAILED" -ne 0 ]; then
  exit 1
fi

# The first --ignore excludes only gauntlet's own module path from the
# check it runs against dependencies; it does not add gauntlet's own
# licence (Apache-2.0) to the allow-list above, and gauntlet's own
# licence is not thereby "allowed" for any dependency that happens to
# share it.
go-licenses check ./... \
  "${IGNORE_ARGS[@]}" \
  --allowed_licenses="$ALLOWED_LICENSES"

python3 "$SCRIPT_DIR/licence-check-bundled.py" "$POLICY_FILE" ./...
