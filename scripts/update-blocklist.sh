#!/usr/bin/env bash
set -euo pipefail

# Replaces the common-password list compiled into gauntlet
# (blocklist/embedded/, #52, ADR-0005) with a published one, as a
# release step (docs/releasing.md). It never builds or edits a list: it
# takes the exact files the blocklist pipeline signed and published,
# checks them the way an application would, and copies them in.
#
# Usage:
#   scripts/update-blocklist.sh                  # the newest published list
#   scripts/update-blocklist.sh --version 2026.11.01
#   scripts/update-blocklist.sh --gitlab         # from the GitLab registry instead
#   scripts/update-blocklist.sh --from DIR       # files already downloaded,
#                                                # e.g. blocklist:sign's artifact
#
# What it checks before copying anything:
#   - the SHA-256 beside the list matches, the list parses, and its
#     signature verifies against blocklist/keys/*.pub (`pwlist verify`);
#   - it was built within the last 90 days (scripts/blocklist-age-check.sh,
#     the same check release:version makes).
# Then it removes the placeholder, if it is still there, and runs the
# embedded-copy test. Committing the result is left to you.
#
# Where from: by default the public GitHub mirror's releases
# (pwned-top10k-current, or pwned-top10k-<version>), which need no
# login -- the same files applications fetch. --gitlab fetches the same
# signed files from the GitLab generic package registry, where they are
# published first; while the project is private that needs
# GAUNTLET_REGISTRY_TOKEN_FILE, a file holding a token with read_api,
# which is sent from a 0600 header file and never on the command line.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GITHUB_RELEASES="https://github.com/tomlawesome/gauntlet/releases/download"
GITLAB_REGISTRY="https://gitlab.tomlawson.io/api/v4/projects/56/packages/generic/pwned-top10k"
FILES=(top10k.txt top10k.txt.sha256 top10k.txt.sig)

version="current"
from=""
gitlab=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || { echo "update-blocklist: --version needs a value" >&2; exit 2; }
      version="$2"; shift 2 ;;
    --from)
      [ $# -ge 2 ] || { echo "update-blocklist: --from needs a directory" >&2; exit 2; }
      from="$2"; shift 2 ;;
    --gitlab)
      gitlab=1; shift ;;
    *)
      echo "usage: $0 [--version YYYY.MM.DD] [--gitlab] | --from DIR" >&2; exit 2 ;;
  esac
done
case "$version" in
  current | [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]) ;;
  *) echo "update-blocklist: --version must be YYYY.MM.DD or current" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/list"

if [ -n "$from" ]; then
  for f in "${FILES[@]}"; do
    cp "$from/$f" "$work/list/$f"
  done
else
  headers=()
  if [ -n "$gitlab" ]; then
    base="$GITLAB_REGISTRY/$version"
    if [ -n "${GAUNTLET_REGISTRY_TOKEN_FILE:-}" ]; then
      ( umask 077 && printf 'PRIVATE-TOKEN: %s\n' "$(tr -d '[:space:]' < "$GAUNTLET_REGISTRY_TOKEN_FILE")" > "$work/headers" )
      headers=(--header "@$work/headers")
    fi
  else
    base="$GITHUB_RELEASES/pwned-top10k-$version"
  fi
  for f in "${FILES[@]}"; do
    echo "update-blocklist: fetching $base/$f"
    # --proto-redir too: GitHub answers with a redirect to its download host.
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --max-filesize 2097152 "${headers[@]}" --output "$work/list/$f" "$base/$f"
  done
fi

go run ./cmd/pwlist verify --keys blocklist/keys --in "$work/list/top10k.txt"
scripts/blocklist-age-check.sh "$work/list"

cp "$work/list/top10k.txt" blocklist/embedded/top10k.txt
cp "$work/list/top10k.txt.sig" blocklist/embedded/top10k.txt.sig
rm -f blocklist/embedded/PLACEHOLDER
go test ./blocklist -run 'TestEmbeddedCopy|TestCommittedKeys' -count=1

built="$(sed -n 's/^# built: //p' blocklist/embedded/top10k.txt | head -n 1)"
echo
echo "update-blocklist: blocklist/embedded/ now holds the list built $built."
echo "Commit blocklist/embedded/ (and the placeholder's removal, the first time)."
