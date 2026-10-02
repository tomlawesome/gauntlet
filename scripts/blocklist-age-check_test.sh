#!/bin/sh
set -eu

# Exercises blocklist-age-check.sh: the placeholder (refused, except for
# v0.2.0), a missing list or
# signature, a bad header, the 90-day edge, a future date, and the date
# arithmetic against known epochs. POSIX sh, like the script, so it also
# runs on Alpine. Run directly; exits non-zero on the first failure.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/blocklist-age-check.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 2026-10-02T00:00:00Z
NOW=1790899200
DAY=86400
# Any version but 0.2.0, so the placeholder is refused below whatever
# the VERSION file says.
export RELEASE_VERSION=0.3.0

# mk DIR BUILT: a directory holding a list header with that built line,
# and a signature file. Only the header matters to this script.
mk() {
  rm -rf "$1"
  mkdir -p "$1"
  printf '# format: gauntlet-pwned-top10k/1\n# built: %s\n# count: 10000\n' "$2" > "$1/top10k.txt"
  : > "$1/top10k.txt.sig"
}

expect() {
  want="$1" desc="$2" dir="$3" now="$4"
  if NOW_EPOCH="$now" "$SCRIPT" "$dir" > "$WORK/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: $desc -- expected $want, got $got" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
  echo "ok: $desc"
}

d="$WORK/list"

mk "$d" 2026-09-22T00:00:00Z
expect pass "built 10 days ago" "$d" "$NOW"

mk "$d" 2026-07-04T00:00:00Z
expect pass "built exactly 90 days ago" "$d" "$NOW"
expect fail "90 days and one second" "$d" $((NOW + 1))

mk "$d" 2026-06-01T12:00:00Z
expect fail "built 122 days ago" "$d" "$NOW"

mk "$d" 2026-10-04T00:00:00Z
expect fail "built two days in the future" "$d" "$NOW"
mk "$d" 2026-10-02T23:00:00Z
expect pass "built 23 hours ahead (clock skew)" "$d" "$NOW"

mk "$d" 2026-10-02
expect fail "built without a time" "$d" "$NOW"
mk "$d" ""
expect fail "no built value" "$d" "$NOW"

mk "$d" 2026-09-22T00:00:00Z
rm "$d/top10k.txt.sig"
expect fail "no signature" "$d" "$NOW"
rm "$d/top10k.txt"
expect fail "no list" "$d" "$NOW"

mkdir -p "$WORK/placeholder"
echo "placeholder" > "$WORK/placeholder/PLACEHOLDER"
expect fail "the placeholder" "$WORK/placeholder" "$NOW"
mk "$WORK/placeholder" 2026-09-22T00:00:00Z
echo "placeholder" > "$WORK/placeholder/PLACEHOLDER"
expect fail "a list with the placeholder still beside it" "$WORK/placeholder" "$NOW"

# v0.2.0 alone may ship the bare placeholder (owner, 2026-10-02).
export RELEASE_VERSION=0.2.0
expect fail "a list with the placeholder beside it, at v0.2.0" "$WORK/placeholder" "$NOW"
rm -rf "$WORK/placeholder"
mkdir -p "$WORK/placeholder"
echo "placeholder" > "$WORK/placeholder/PLACEHOLDER"
expect pass "the placeholder at v0.2.0" "$WORK/placeholder" "$NOW"
mk "$d" 2026-06-01T12:00:00Z
expect fail "a stale list at v0.2.0" "$d" "$NOW"
for v in 0.2.1 0.3.0 0.1.0 1.0.0; do
  export RELEASE_VERSION="$v"
  expect fail "the placeholder at v$v" "$WORK/placeholder" "$NOW"
done
export RELEASE_VERSION=0.3.0

# The arithmetic itself, at a leap day, the epoch and past 2038 (where
# a 32-bit printf would overflow): each date is exactly its own age-0
# now.
for pair in "2000-02-29T12:34:56Z 951827696" "1970-01-01T00:00:00Z 0" "2100-03-01T00:00:00Z 4107542400"; do
  # shellcheck disable=SC2086 # split the pair into its two words
  set -- $pair
  mk "$d" "$1"
  expect pass "$1 is epoch $2" "$d" "$2"
  expect fail "two days before $1, it is in the future" "$d" $(($2 - 2 * DAY))
done

echo "all blocklist-age-check cases passed"
