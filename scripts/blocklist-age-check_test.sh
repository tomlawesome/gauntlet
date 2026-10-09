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

# refused_saying: a refusal for this reason, not just any refusal -- the
# exit status alone is the same whichever check fired.
refused_saying() {
  desc="$1" dir="$2" text="$3"
  expect fail "$desc" "$dir" "$NOW"
  grep -q -F "$text" "$WORK/out" || { echo "FAIL: $desc -- the refusal does not say '$text':" >&2; cat "$WORK/out" >&2; exit 1; }
}

mk "$d" 2026-09-22T00:00:00Z
rm "$d/top10k.txt.sig"
refused_saying "no signature, list present" "$d" "top10k.txt.sig is missing"
mk "$d" 2026-09-22T00:00:00Z
rm "$d/top10k.txt"
refused_saying "no list, signature present" "$d" "top10k.txt is missing"
rm "$d/top10k.txt.sig"
refused_saying "neither list nor signature" "$d" "top10k.txt is missing"

mkdir -p "$WORK/placeholder"
echo "placeholder" > "$WORK/placeholder/PLACEHOLDER"
refused_saying "the placeholder" "$WORK/placeholder" "holds the placeholder"
mk "$WORK/placeholder" 2026-09-22T00:00:00Z
echo "placeholder" > "$WORK/placeholder/PLACEHOLDER"
refused_saying "a list with the placeholder still beside it" "$WORK/placeholder" "holds the placeholder"

# v0.2.0's one-off allowance for the bare placeholder went when the
# first real list was embedded (#52): the version no longer matters.
rm -rf "$WORK/placeholder"
mkdir -p "$WORK/placeholder"
echo "placeholder" > "$WORK/placeholder/PLACEHOLDER"
for v in 0.2.0 0.3.0; do
  export RELEASE_VERSION="$v"
  expect fail "the placeholder at v$v" "$WORK/placeholder" "$NOW"
done
unset RELEASE_VERSION

# The arithmetic itself, at a leap day, the epoch, past 2038 (where a
# 32-bit printf would overflow) and the 15th of every month of 2026. A
# date "exactly its own age-0 now" is not enough on its own: the script
# allows a day of clock skew ahead and 90 days of age, so an epoch a
# day out either way would still pass at age 0. Each date is therefore
# pinned to the second from both sides, with no age allowance (age 0
# passes, one second later fails) and with only the one day's skew
# allowance (a day ahead passes, a day and a second ahead fails), and the
# age it reports at its own epoch is 0.
for pair in \
  "2000-02-29T12:34:56Z 951827696" \
  "1970-01-01T00:00:00Z 0" \
  "2100-03-01T00:00:00Z 4107542400" \
  "1999-12-31T23:59:59Z 946684799" \
  "2024-03-01T00:00:00Z 1709251200" \
  "2028-02-29T23:59:59Z 1835481599" \
  "2038-01-19T03:14:08Z 2147483648" \
  "2026-01-15T06:07:08Z 1768457228" \
  "2026-02-15T06:07:08Z 1771135628" \
  "2026-03-15T06:07:08Z 1773554828" \
  "2026-04-15T06:07:08Z 1776233228" \
  "2026-05-15T06:07:08Z 1778825228" \
  "2026-06-15T06:07:08Z 1781503628" \
  "2026-07-15T06:07:08Z 1784095628" \
  "2026-08-15T06:07:08Z 1786774028" \
  "2026-09-15T06:07:08Z 1789452428" \
  "2026-10-15T06:07:08Z 1792044428" \
  "2026-11-15T06:07:08Z 1794722828" \
  "2026-12-15T06:07:08Z 1797314828"; do
  # shellcheck disable=SC2086 # split the pair into its two words
  set -- $pair
  mk "$d" "$1"
  MAX_AGE_DAYS=0
  export MAX_AGE_DAYS
  expect pass "$1 is epoch $2 (not later)" "$d" "$2"
  expect fail "$1 is epoch $2 (not earlier)" "$d" $(($2 + 1))
  unset MAX_AGE_DAYS
  expect pass "$1 is a day ahead of epoch $2 - 86400" "$d" $(($2 - DAY))
  expect fail "$1 is more than a day ahead of epoch $2 - 86401" "$d" $(($2 - DAY - 1))
  expect pass "$1 at its own epoch reports 0 days" "$d" "$2"
  grep -q ', 0 days ago$' "$WORK/out" || { echo "FAIL: $1 at its own epoch did not report 0 days ago:" >&2; cat "$WORK/out" >&2; exit 1; }
done

echo "all blocklist-age-check cases passed"
