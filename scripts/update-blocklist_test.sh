#!/usr/bin/env bash
set -euo pipefail

# Exercises update-blocklist.sh's refusal to replace the embedded list
# with one built before it, and --force. It runs a copy of the script in
# a scratch tree under mktemp, with stand-ins for `go` and the age check
# (both covered elsewhere), so it never touches this repository's
# blocklist/embedded/ or the network. Run directly; exits non-zero on
# the first failure.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

tree="$WORK/tree"
mkdir -p "$tree/scripts" "$WORK/bin"
cp "$ROOT/scripts/update-blocklist.sh" "$tree/scripts/"
printf '#!/bin/sh\nexit 0\n' > "$tree/scripts/blocklist-age-check.sh"
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/go"
chmod +x "$tree/scripts/blocklist-age-check.sh" "$WORK/bin/go"
export PATH="$WORK/bin:$PATH"

# mk DIR BUILT: a list header with that built line, and the files beside
# it. Only the header matters to these cases.
mk() {
  mkdir -p "$1"
  printf '# format: gauntlet-pwned-top10k/1\n# built: %s\n' "$2" > "$1/top10k.txt"
  : > "$1/top10k.txt.sha256"
  : > "$1/top10k.txt.sig"
}

# embed BUILT: the scratch tree's embedded list, or the placeholder.
embed() {
  rm -rf "$tree/blocklist/embedded"
  mkdir -p "$tree/blocklist/embedded"
  if [ "$1" = placeholder ]; then
    echo placeholder > "$tree/blocklist/embedded/PLACEHOLDER"
  else
    mk "$tree/blocklist/embedded" "$1"
    rm "$tree/blocklist/embedded/top10k.txt.sha256"
  fi
}

embedded_built() { sed -n 's/^# built: //p' "$tree/blocklist/embedded/top10k.txt"; }

# expect pass|fail DESC WANT_EMBEDDED ARGS...: run the copy and check the
# outcome and which list is embedded afterwards.
expect() {
  want="$1" desc="$2" want_built="$3"
  shift 3
  if "$tree/scripts/update-blocklist.sh" "$@" > "$WORK/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ] || [ "$(embedded_built)" != "$want_built" ]; then
    echo "FAIL: $desc -- expected $want with $want_built embedded, got $got with $(embedded_built)" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
  echo "ok: $desc"
}

NEWER=2026-10-02T04:30:00Z
OLDER=2026-09-02T04:30:00Z
mk "$WORK/older" "$OLDER"
mk "$WORK/newer" "$NEWER"
mk "$WORK/same" "$NEWER"

embed "$NEWER"
expect fail "an older list is refused" "$NEWER" --from "$WORK/older"
grep -q 'refusing' "$WORK/out" || { echo "FAIL: the refusal does not say why" >&2; exit 1; }
expect pass "an older list with --force" "$OLDER" --force --from "$WORK/older"

embed "$OLDER"
expect pass "a newer list" "$NEWER" --from "$WORK/newer"
expect pass "the same list again" "$NEWER" --from "$WORK/same"

embed placeholder
expect pass "any list over the placeholder" "$OLDER" --from "$WORK/older"

echo "all update-blocklist cases passed"
