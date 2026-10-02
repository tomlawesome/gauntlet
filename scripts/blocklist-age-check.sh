#!/bin/sh
set -eu

# Refuses a release whose embedded common-password list (#52, ADR-0005)
# is missing, is still the placeholder, has no signature beside it, or
# was built more than 90 days ago. release:version runs it before it
# will tag; run it locally the same way.
#
# Usage: scripts/blocklist-age-check.sh [DIR]
#   DIR defaults to blocklist/embedded.
#   MAX_AGE_DAYS (default 90) and NOW_EPOCH (default: now) are for tests.
#
# POSIX sh and awk only: release:version runs on plain Alpine, which has
# busybox and no bash, GNU date or Go. The date arithmetic is Howard
# Hinnant's days-from-civil, so it needs no `date -d`, whose input
# formats differ between GNU and busybox.
#
# It checks age and presence only. That the list parses and its
# signature verifies against blocklist/keys is TestEmbeddedCopy's job,
# on every pipeline.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:-$ROOT/blocklist/embedded}"
MAX_AGE_DAYS="${MAX_AGE_DAYS:-90}"
NOW="${NOW_EPOCH:-$(date -u +%s)}"

fail() {
  echo "blocklist-age-check: $*" >&2
  exit 1
}

if [ -e "$DIR/PLACEHOLDER" ]; then
  fail "$DIR holds the placeholder, not a list. The first real list comes from the first signed run of the blocklist schedule; then run scripts/update-blocklist.sh (#52)."
fi
list="$DIR/top10k.txt"
[ -f "$list" ] || fail "$list is missing; run scripts/update-blocklist.sh"
[ -f "$list.sig" ] || fail "$list.sig is missing; run scripts/update-blocklist.sh"

built="$(sed -n 's/^# built: //p' "$list" | head -n 1)"
case "$built" in
  [0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9]Z) ;;
  *) fail "$list has no '# built: YYYY-MM-DDThh:mm:ssZ' header (got '$built')" ;;
esac

epoch="$(printf '%s\n' "$built" | awk '{
  y = substr($0, 1, 4) + 0; m = substr($0, 6, 2) + 0; d = substr($0, 9, 2) + 0
  H = substr($0, 12, 2) + 0; M = substr($0, 15, 2) + 0; S = substr($0, 18, 2) + 0
  if (m <= 2) y -= 1
  era = int(y / 400)
  yoe = y - era * 400
  mp = (m + 9) % 12
  doy = int((153 * mp + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  printf "%.0f\n", (era * 146097 + doe - 719468) * 86400 + H * 3600 + M * 60 + S
}')"

if [ $((epoch - NOW)) -gt 86400 ]; then
  fail "$list claims to be built at $built, more than a day in the future"
fi
age_days=$(((NOW - epoch) / 86400))
if [ $((NOW - epoch)) -gt $((MAX_AGE_DAYS * 86400)) ]; then
  fail "$list was built at $built, $age_days days ago -- over the $MAX_AGE_DAYS-day limit. Run scripts/update-blocklist.sh to take the newest published list."
fi
echo "blocklist-age-check: ok -- built $built, $age_days days ago"
