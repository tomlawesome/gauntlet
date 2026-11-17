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
# apidiff is golang.org/x/exp/cmd/apidiff at a pinned pseudo-version
# (approved for CI only, owner 2026-09-30). It is built with `go install`
# from a temporary directory into a temporary GOBIN, so neither the tool
# nor its dependencies ever enter this module's go.mod or go.sum, and the
# binary is then run directly. apidiff itself always exits 0; this script
# fails on any line of its -incompatible report instead.
#
# The script also fails if go.mod or go.sum changed while it ran (#62): a
# stray go.sum line is easy to commit by accident. apidiff reads this
# module through `go list`, so GOFLAGS is forced to -mod=readonly here --
# with -mod=mod in the environment (a `go env -w GOFLAGS=-mod=mod` on the
# host) Go would otherwise be free to add lines to go.sum.

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

# Fingerprint go.mod and go.sum before anything runs a go command here.
sums() { cat go.mod go.sum 2>/dev/null | cksum; }
before="$(sums)"
untouched() {
  if [ "$(sums)" != "$before" ]; then
    echo "apidiff: FAIL -- go.mod or go.sum changed while this script ran:" >&2
    git status --short -- go.mod go.sum >&2 || true
    echo "Discard the change (git checkout -- go.mod go.sum) and report it on #62." >&2
    return 1
  fi
}

export GOFLAGS=-mod=readonly
module="$(go list -m)"
work="$(mktemp -d)"
# The check runs on every exit, so a run that fails part-way still
# reports a changed go.sum.
trap 'rc=$?; rm -rf "$work"; untouched || rc=1; exit "$rc"' EXIT

# Same reason as licence-check.sh: build the tool with the toolchain
# this module selects, not an older default one.
export GOTOOLCHAIN="${GOTOOLCHAIN:-$(go env GOVERSION)}"

# Outside the module: `go install pkg@version` ignores any go.mod, and
# running it from an empty directory makes that impossible to get wrong.
mkdir "$work/bin" "$work/tool"
(cd "$work/tool" && GOBIN="$work/bin" go install "$APIDIFF")
apidiff="$work/bin/apidiff"

mkdir "$work/old"
git archive "$base" | tar -x -C "$work/old"
# apidiff loads a module from the directory holding its go.mod.
(cd "$work/old" && "$apidiff" -m -w "$work/old.api" "$module")
"$apidiff" -m -w "$work/new.api" "$module"
untouched

echo "apidiff: $module, $base -> working tree"
"$apidiff" -m "$work/old.api" "$work/new.api"
incompatible="$("$apidiff" -m -incompatible "$work/old.api" "$work/new.api")"
if [ -n "$incompatible" ]; then
  echo
  echo "apidiff: FAIL -- incompatible changes since $base:" >&2
  printf '%s\n' "$incompatible" >&2
  echo "Keep the old identifier (deprecate it, ADR-0002), or bump the major version." >&2
  exit 1
fi
echo "apidiff: OK -- no incompatible changes since $base"
