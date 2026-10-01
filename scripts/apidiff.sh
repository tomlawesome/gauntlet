#!/usr/bin/env bash
set -euo pipefail

# Fails when the module's exported Go API has changed incompatibly since
# the last release tag (ADR-0002 decision 3, #22): a removed or renamed
# exported identifier, a changed signature, a removed struct field.
# Additive changes pass. The only way past a real break is a major
# version bump in VERSION.
#
# Usage: scripts/apidiff.sh [BASE_REF]
#   BASE_REF defaults to the newest v* tag reachable from HEAD.
#
# apidiff is golang.org/x/exp/cmd/apidiff, run with `go run` at a pinned
# pseudo-version so it never enters go.mod (approved for CI only, owner
# 2026-09-30). apidiff itself always exits 0; this script fails on any
# line of its -incompatible report instead.

APIDIFF_VERSION="${APIDIFF_VERSION:-v0.0.0-20260908205506-85c1c2202aba}"
APIDIFF="golang.org/x/exp/cmd/apidiff@${APIDIFF_VERSION}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

base="${1:-}"
if [ -z "$base" ]; then
  base="$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD 2>/dev/null)" || {
    echo "apidiff: no v* tag reachable from HEAD -- fetch tags, or pass a base ref" >&2
    exit 1
  }
fi
git rev-parse --verify --quiet "$base^{commit}" >/dev/null || {
  echo "apidiff: base ref '$base' not found" >&2
  exit 1
}

# A major version bump is the one sanctioned way to break the API.
major() { sed -E 's/^v?([0-9]+)\..*/\1/'; }
base_major="$(printf '%s\n' "$base" | major)"
new_major="$(tr -d '[:space:]' < VERSION | major)"
case "$base_major$new_major" in
  *[!0-9]*) base_major="" ;;
esac
if [ -n "$base_major" ] && [ "$new_major" -gt "$base_major" ]; then
  echo "apidiff: VERSION moves the major version ($base_major -> $new_major); incompatible changes are allowed."
  exit 0
fi

module="$(go list -m)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Same reason as licence-check.sh: build the tool with the toolchain
# this module selects, not an older default one.
export GOTOOLCHAIN="${GOTOOLCHAIN:-$(go env GOVERSION)}"

mkdir "$work/old"
git archive "$base" | tar -x -C "$work/old"
# apidiff loads a module from the directory holding its go.mod.
(cd "$work/old" && go run "$APIDIFF" -m -w "$work/old.api" "$module")
go run "$APIDIFF" -m -w "$work/new.api" "$module"

echo "apidiff: $module, $base -> working tree"
go run "$APIDIFF" -m "$work/old.api" "$work/new.api"
incompatible="$(go run "$APIDIFF" -m -incompatible "$work/old.api" "$work/new.api")"
if [ -n "$incompatible" ]; then
  echo
  echo "apidiff: FAIL -- incompatible changes since $base:" >&2
  printf '%s\n' "$incompatible" >&2
  echo "Keep the old identifier (deprecate it, ADR-0002), or bump the major version." >&2
  exit 1
fi
echo "apidiff: OK -- no incompatible changes since $base"
