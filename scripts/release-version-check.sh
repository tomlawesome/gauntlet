#!/usr/bin/env bash
set -euo pipefail

# Checks release:version needs before it is safe to cut a tag (refs #26):
#   1. VERSION is a strict three-part semantic version -- a loose glob
#      let non-semantic strings like "0.2.0.1" or "02.0.0" through, and
#      Go's module proxy refuses to fetch a protected tag shaped like
#      that once it exists.
#   2. VERSION sorts above every v* tag already cut, so a VERSION typed
#      too low can never be published (the proxy can't un-publish).
#   3. The commit being tagged is the current tip of dev, so an old
#      pipeline's release button can't tag a commit dev has moved past.
# Pure string logic, no network calls, so release-version-check_test.sh
# can feed it canned input offline.
#
# Usage:
#   release-version-check.sh VERSION REMOTE_TAGS DEV_SHA COMMIT_SHA
#
#   VERSION      contents of the VERSION file, e.g. "0.2.1"
#   REMOTE_TAGS  output of `git ls-remote --tags origin` (may be empty)
#   DEV_SHA      sha of origin/dev, e.g. from
#                `git ls-remote origin refs/heads/dev | cut -f1`
#   COMMIT_SHA   the commit being tagged, e.g. $CI_COMMIT_SHA
#
# On success prints "RELEASE_TAG=v<VERSION>" and exits 0.

if [ "$#" -ne 4 ]; then
  echo "usage: release-version-check.sh VERSION REMOTE_TAGS DEV_SHA COMMIT_SHA" >&2
  exit 1
fi

version="$1"
remote_tags="$2"
dev_sha="$3"
commit_sha="$4"

# 1. Strict semantic version: exactly three numeric, dot-separated parts.
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION holds '$version', not a semantic version (X.Y.Z)" >&2
  exit 1
fi
tag="v$version"

# Tags already cut, as plain "X.Y.Z" strings (leading "v" stripped).
existing_versions="$(printf '%s\n' "$remote_tags" \
  | grep -oE 'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  | sed -E 's#refs/tags/v##' || true)"

if printf '%s\n' "$existing_versions" | grep -qx "$version"; then
  echo "$tag already exists -- bump VERSION before cutting another release." >&2
  exit 1
fi

# 2. VERSION must sort above every tag already cut.
if [ -n "$existing_versions" ]; then
  highest="$(printf '%s\n%s\n' "$existing_versions" "$version" | sort -V | tail -1)"
  if [ "$highest" != "$version" ]; then
    echo "VERSION '$version' does not sort above the newest existing tag -- a lower or out-of-order version can never be withdrawn from the Go module proxy once published." >&2
    exit 1
  fi
fi

# 3. The commit being tagged must be the current tip of dev.
if [ "$commit_sha" != "$dev_sha" ]; then
  echo "commit $commit_sha is not the current tip of dev ($dev_sha) -- use the latest dev pipeline." >&2
  exit 1
fi

echo "RELEASE_TAG=$tag"
