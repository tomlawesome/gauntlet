#!/bin/sh
# Copied from ai/agent-infra scripts/flake-check/flake-check.sh at commit
# 58d35a1. Changes go there first; this copy is replaced, not edited.
# Reads a project's flake log (docs/flakes.md) and fails the pipeline when the
# flake rule is broken: a flake with three sightings needs an issue and has to
# leave the merge gate for quarantine. Source of truth lives in agent-infra
# (scripts/flake-check/); each project copies it to scripts/ci/flake-check.sh and
# records the source path and agent-infra commit in the copy's header. Rules and
# log format: scripts/flake-check/SPEC.md (#30).
#
#   flake-check.sh [--quarantined FILE] [--threshold N] [--stale-days N]
#                  [--today YYYY-MM-DD] FLAKES_MD
#
# Defaults: threshold 3, stale-days 60, today from the clock. FILE lists the
# quarantined checks, one per line (blank lines and lines starting # ignored);
# a flake heading is quarantined when any listed line is a substring of it.
# Derive FILE from whatever actually skips the test (see README.md), never by
# hand beside it.
#
# A log bullet is a "- " line plus its indented continuation lines, joined with
# single spaces: a dated one is a sighting (four " · " fields), an undated one
# containing " · " is unparsed, any other is a note and ignored.
#
# Prints one finding per line, tab-separated: LEVEL, rule, heading (or -),
# detail. ERROR rules: unparsed, needs-issue, not-quarantined. WARN rules:
# stale, quarantined-unlogged. NOTE: quarantine-unchecked, then summary last.
# Exit 1 if any ERROR was printed, else 0. A missing or unreadable log, or an
# unknown option, is exit 2 with a message on stderr.
#
# Needs: POSIX sh and awk only (dash, busybox). Reads only; changes nothing.
#
# Healthy: a single NOTE line, "N flakes, M sightings, K at threshold", and
# exit 0; every flake at threshold has an issue link and is in the quarantine
# list.

usage="usage: flake-check.sh [--quarantined FILE] [--threshold N] [--stale-days N] [--today YYYY-MM-DD] FLAKES_MD"

quar=""
threshold=3
stale=60
today=""
file=""
nfile=0

while [ $# -gt 0 ]; do
  case "$1" in
    --quarantined|--threshold|--stale-days|--today)
      if [ $# -lt 2 ]; then echo "flake-check: $1 needs a value" >&2; echo "$usage" >&2; exit 2; fi
      case "$1" in
        --quarantined) quar=$2 ;;
        --threshold) threshold=$2 ;;
        --stale-days) stale=$2 ;;
        --today) today=$2 ;;
      esac
      shift 2 ;;
    -h|--help) echo "$usage"; exit 0 ;;
    --) shift; break ;;
    -?*) echo "flake-check: unknown option $1" >&2; echo "$usage" >&2; exit 2 ;;
    *) file=$1; nfile=$((nfile + 1)); shift ;;
  esac
done
while [ $# -gt 0 ]; do file=$1; nfile=$((nfile + 1)); shift; done

if [ "$nfile" -ne 1 ]; then echo "$usage" >&2; exit 2; fi

case "$threshold" in ''|*[!0-9]*) echo "flake-check: --threshold must be a whole number" >&2; exit 2 ;; esac
case "$stale" in ''|*[!0-9]*) echo "flake-check: --stale-days must be a whole number" >&2; exit 2 ;; esac
[ -n "$today" ] || today=$(date +%Y-%m-%d)
case "$today" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
  *) echo "flake-check: --today must be YYYY-MM-DD" >&2; exit 2 ;;
esac

if [ ! -f "$file" ] || [ ! -r "$file" ]; then
  echo "flake-check: cannot read $file" >&2
  exit 2
fi
if [ -n "$quar" ] && { [ ! -f "$quar" ] || [ ! -r "$quar" ]; }; then
  echo "flake-check: cannot read quarantine file $quar" >&2
  exit 2
fi

# The quarantine file name goes in through the environment, not -v, so that
# backslashes in it are not interpreted.
FLAKE_QUAR=$quar awk -v threshold="$threshold" -v stale="$stale" -v today="$today" '
# Days since a fixed epoch for a civil date (proleptic Gregorian).
function days(y, m, d,    yy, era, yoe, mp, doy, doe) {
    yy = y - (m <= 2)
    era = int(yy / 400)
    yoe = yy - era * 400
    mp = (m + 9) % 12
    doy = int((153 * mp + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    return era * 146097 + doe
}
function isodays(s) {
    return days(substr(s, 1, 4) + 0, substr(s, 6, 2) + 0, substr(s, 9, 2) + 0)
}
# True when s (YYYY-MM-DD) is a real calendar day.
function realdate(s,    y, m, d, dim) {
    y = substr(s, 1, 4) + 0; m = substr(s, 6, 2) + 0; d = substr(s, 9, 2) + 0
    if (m < 1 || m > 12 || d < 1) return 0
    dim = substr("312831303130313130313031", 2 * m - 1, 2) + 0
    if (m == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) dim = 29
    return d <= dim
}
function finding(level, rule, heading, detail) {
    gsub(/\t/, " ", heading)
    gsub(/\t/, " ", detail)
    printf "%s\t%s\t%s\t%s\n", level, rule, heading, detail
    if (level == "ERROR") errors++
}
BEGIN {
    quar = ENVIRON["FLAKE_QUAR"]
    todayn = isodays(today)
    nq = 0
    if (quar != "") {
        while ((getline line < quar) > 0) {
            gsub(/^[ \t\r]+/, "", line)
            gsub(/[ \t\r]+$/, "", line)
            if (line == "" || substr(line, 1, 1) == "#") continue
            q[++nq] = line
        }
        close(quar)
    }
    nh = 0
}
# A bullet is a "- " line plus the indented lines after it, joined with single
# spaces. Dated and with four or more " · " fields: a sighting. Undated but
# containing " · ": unparsed. Anything else is a note and is ignored.
function flush(    n, a, d, dn) {
    if (!inb) return
    inb = 0
    if (btext ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] · /) {
        n = split(btext, a, " · ")
        if (n >= 4 && realdate(substr(btext, 1, 10))) {
            d = substr(btext, 1, 10)
            dn = isodays(d)
            count[nh]++
            if (dn > newest[nh]) { newest[nh] = dn; newestd[nh] = d }
        } else {
            finding("ERROR", "unparsed", head[nh], bline)
        }
    } else if (index(btext, " · ") > 0) {
        finding("ERROR", "unparsed", head[nh], bline)
    }
}
{
    line = $0
    sub(/\r$/, "", line)
    if (inb && line ~ /^[ \t]/ && line ~ /[^ \t]/) {
        gsub(/^[ \t]+/, "", line)
        gsub(/[ \t]+$/, "", line)
        btext = btext " " line
        next
    }
    flush()
    if (substr(line, 1, 3) == "## ") {
        nh++
        head[nh] = substr(line, 4)
        count[nh] = 0
        newest[nh] = -1
        newestd[nh] = ""
        next
    }
    if (nh == 0) next
    if (substr(line, 1, 2) != "- ") next
    inb = 1
    bline = NR
    btext = substr(line, 3)
    gsub(/^[ \t]+/, "", btext)
    gsub(/[ \t]+$/, "", btext)
}
END {
    flush()
    sightings = 0; atthr = 0
    for (i = 1; i <= nh; i++) {
        h = head[i]
        sightings += count[i]
        hasissue = (h ~ /#[0-9]+/ || h ~ /\/issues\/[0-9]+/ || h ~ /\/work_items\/[0-9]+/)
        if (count[i] >= threshold) {
            atthr++
            if (!hasissue)
                finding("ERROR", "needs-issue", h, count[i] " sightings, no issue link in the heading")
            if (quar != "") {
                inq = 0
                for (j = 1; j <= nq; j++) if (index(h, q[j]) > 0) { inq = 1; break }
                if (!inq)
                    finding("ERROR", "not-quarantined", h, count[i] " sightings, matches no line of " quar)
            }
        }
        if (count[i] > 0 && todayn - newest[i] > stale)
            finding("WARN", "stale", h, "newest sighting " newestd[i] ", " (todayn - newest[i]) " days ago: fix it, delete the heading, or let the test back into the gate")
    }
    for (j = 1; j <= nq; j++) {
        found = 0
        for (i = 1; i <= nh; i++) if (index(head[i], q[j]) > 0) { found = 1; break }
        if (!found)
            finding("WARN", "quarantined-unlogged", "-", q[j] ": quarantined but matches no heading in the log")
    }
    if (quar == "")
        finding("NOTE", "quarantine-unchecked", "-", "--quarantined not given, so not-quarantined was not evaluated")
    finding("NOTE", "summary", "-", nh " flakes, " sightings " sightings, " atthr " at threshold")
    exit (errors > 0) ? 1 : 0
}' "$file"
