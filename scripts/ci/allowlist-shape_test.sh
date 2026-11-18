#!/bin/sh
# Shape test for .private-details-allow.toml (#121, item a): every
# [[allowlists]] table excuses exact values in named files, never a whole
# rule for whole files.
#
# A table must have targetRules, condition = "AND", paths, and a non-empty
# regexes list whose every entry begins ^ and ends $. A table with paths and
# no regexes is reported as such. A regex for a private, shared or public
# address must be exact; a family regex is allowed only when everything it
# matches is multicast (224/4), reserved (240/4), benchmark (198.18/15) or
# link-local (169.254/16). Failures print "<file>:<table line>: <why>".
#
# Self-tests run first on fixtures built at run time (a good table passes,
# each defect fails); fixture addresses are assembled from numbers.
#
# Run: sh scripts/ci/allowlist-shape_test.sh [<allowlist file>]
# Exit: 0 ok, 1 a failure. POSIX sh and awk; no TOML parser.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
TARGET=${1:-$ROOT/.private-details-allow.toml}

# check <file>: prints one line per problem, exits 0 when none.
check() {
    LC_ALL=C awk -v F="$1" -v R="$2" '
    function emit(s,   k) {
        if (cur == "" || t == 0) return
        k = cur
        n[t, k]++
        v[t, k, n[t, k]] = s
    }
    function scan(s,   i, c, j, str) {
        i = 1
        while (i <= length(s)) {
            c = substr(s, i, 1)
            if (depth == 0 && !started && match(substr(s, i), /^[ \t]*[A-Za-z]+[ \t]*=/)) {
                str = substr(s, i, RLENGTH)
                gsub(/[ \t=]/, "", str)
                cur = str; seen[t, cur] = 1; started = 1
                i += RLENGTH; continue
            }
            if (substr(s, i, 3) == "\047\047\047") {
                j = index(substr(s, i + 3), "\047\047\047")
                if (!j) return
                emit(substr(s, i + 3, j - 1)); i += j + 5; continue
            }
            if (c == "\047") {
                j = index(substr(s, i + 1), "\047")
                if (!j) return
                emit(substr(s, i + 1, j - 1)); i += j + 1; continue
            }
            if (c == "\"") {
                str = ""; j = i + 1
                while (j <= length(s) && substr(s, j, 1) != "\"") {
                    if (substr(s, j, 1) == "\\") { j++ }
                    str = str substr(s, j, 1); j++
                }
                emit(str); i = j + 1; continue
            }
            if (c == "[") depth++
            else if (c == "]") depth--
            else if (c == "#") return
            i++
        }
    }
    function bad(line, msg) { print F ":" line ": " msg; fails++ }
    function allowed(a, b) { return a >= 224 || (a == 169 && b == 254) || (a == 198 && (b == 18 || b == 19)) }
    function exact(re,   r) {
        r = re; sub(/^\^/, "", r); sub(/\$$/, "", r); gsub(/\\[.:]/, "", r)
        return r !~ /[][().*+?{}|^$\\]/
    }
    # a family regex: does it match any address outside the allowed ranges?
    function outside(re,   a, b, s, cd, k) {
        for (k = 1; k <= 6; k++) {
            cd = (k == 1) ? "0.0" : (k == 2) ? "0.1" : (k == 3) ? "0.5" : (k == 4) ? "1.1" : (k == 5) ? "200.254" : "255.255"
            for (a = 0; a < 256; a++) for (b = 0; b < 256; b++) {
                if (allowed(a, b)) continue
                s = a "." b "." cd
                if (s ~ re) return s
            }
        }
        return ""
    }
    { sub(/\r$/, "") }
    /^[ \t]*\[\[[ \t]*allowlists[ \t]*\]\][ \t]*(#.*)?$/ { t++; tl[t] = NR; depth = 0; started = 0; cur = ""; next }
    /^[ \t]*#/ { next }
    {
        if (depth == 0) started = 0
        scan($0)
        if (depth == 0) { started = 0; cur = "" }
    }
    END {
        if (t == 0) bad(1, "no [[allowlists]] table at all")
        for (i = 1; i <= t; i++) {
            L = tl[i]
            if (!seen[i, "targetRules"]) bad(L, "table has no targetRules")
            if (!seen[i, "condition"]) bad(L, "table has no condition")
            else if (n[i, "condition"] != 1 || v[i, "condition", 1] != "AND") bad(L, "condition is not \"AND\"")
            if (!seen[i, "paths"]) bad(L, "table has no paths")
            if (!seen[i, "regexes"]) {
                if (seen[i, "paths"]) bad(L, "paths without regexes (excuses whole files)")
                else bad(L, "table has no regexes")
            } else if (n[i, "regexes"] == 0) bad(L, "regexes is empty")
            v6 = 0
            for (j = 1; j <= n[i, "targetRules"]; j++) if (tolower(v[i, "targetRules", j]) ~ /ipv6/) v6 = 1
            for (j = 1; j <= n[i, "paths"]; j++) {
                pe = v[i, "paths", j]; pr = pe
                if (pe !~ /^\^/ || pe !~ /\$$/) { bad(L, "paths entry " j " is not anchored with ^ and $"); continue }
                sub(/^\^/, "", pr); sub(/\$$/, "", pr); gsub(/\\\./, ".", pr)
                q = pe; sub(/^\^/, "", q); sub(/\$$/, "", q); gsub(/\\\./, "", q)
                if (q !~ /^[A-Za-z0-9_\/-]+$/) { bad(L, "paths entry " j " is not an exact file path (only escaped dots, no regex metacharacters)"); continue }
                if (system("test -f \047" R "/" pr "\047") != 0) bad(L, "paths entry " j " names a file that does not exist")
            }
            for (j = 1; j <= n[i, "regexes"]; j++) {
                re = v[i, "regexes", j]
                if (re !~ /^\^/ || re !~ /\$$/) { bad(L, "regexes entry " j " is not anchored with ^ and $"); continue }
                if (exact(re)) continue
                if (v6) { bad(L, "regexes entry " j " is not exact in a table that targets an IPv6 rule"); continue }
                if ((s = outside(re)) != "") bad(L, "regexes entry " j " is a family regex that covers an address outside multicast, reserved, benchmark and link-local ranges")
            }
        }
        exit (fails ? 1 : 0)
    }' "$1"
}

# ---- self-tests --------------------------------------------------------------
TMP=$(mktemp -d "${TMPDIR:-/tmp}/allowlist-shape.XXXXXX") || exit 2
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' INT TERM

# rx <a> <b> <c> <d>: an exact anchored regex for a dotted quad.
rx() { printf "'''^%s\\\\.%s\\\\.%s\\\\.%s\$'''" "$1" "$2" "$3" "$4"; }

RE1=$(rx 10 0 0 5)
RE2=$(rx 192 168 1 1)
GOODREGEXES="regexes = [ $RE1, $RE2 ]"
FAMILY="'''^22[4-9]\\.[0-9.]+\$'''"

# mk <name> <body lines...>: one table in $TMP/<name>.toml
mk() {
    name=$1; shift
    {
        echo '# fixture'
        echo '[[allowlists]]'
        echo 'description = "x"'
        for l in "$@"; do printf '%s\n' "$l"; done
    } > "$TMP/$name.toml"
}
PATHS="paths = ['''^a\\.go\$''']"
: > "$TMP/a.go"; : > "$TMP/b.go"
TR6='targetRules = ["ipv6-address"]'
Z=$(printf "%s\\\\:%s" 2001 db8)
TR='targetRules = ["ip-address"]'
AND='condition = "AND"'

SELF_FAIL=0
expect_ok() {
    if out=$(check "$TMP/$1.toml" "$TMP"); then echo "PASS: self-test $1 accepted"
    else echo "FAIL: self-test $1 rejected: $out"; SELF_FAIL=1; fi
}
expect_bad() {
    if out=$(check "$TMP/$1.toml" "$TMP"); then echo "FAIL: self-test $1 accepted ($2)"; SELF_FAIL=1
    else
        case $out in
            *"$TMP/$1.toml:2: "*) echo "PASS: self-test $1 rejected" ;;
            *) echo "FAIL: self-test $1 rejected without naming the table line: $out"; SELF_FAIL=1 ;;
        esac
    fi
}

mk good "$TR" "$AND" "$PATHS" "$GOODREGEXES"
mk goodfam "$TR" "$AND" "$PATHS" "regexes = [ $RE1, $FAMILY, '''^169\\.254\\.[0-9.]+\$''', '''^198\\.(18|19)\\.[0-9.]+\$''' ]"
mk goodmulti "$TR" "$AND" "paths = [" "  '''^a\\.go\$'''," "  '''^b\\.go\$'''," "]" "regexes = [" "  $RE1," "  $RE2," "]"
mk notarget "$AND" "$PATHS" "$GOODREGEXES"
mk nocond "$TR" "$PATHS" "$GOODREGEXES"
mk orcond "$TR" 'condition = "OR"' "$PATHS" "$GOODREGEXES"
mk nopaths "$TR" "$AND" "$GOODREGEXES"
mk noregexes "$TR" "$AND" "$PATHS"
mk emptyregexes "$TR" "$AND" "$PATHS" "regexes = []"
mk noanchorstart "$TR" "$AND" "$PATHS" "regexes = ['''10\\.0\\.0\\.5\$''']"
mk noanchorend "$TR" "$AND" "$PATHS" "regexes = ['''^10\\.0\\.0\\.5''']"
mk privfam "$TR" "$AND" "$PATHS" "regexes = ['''^10\\.0\\.0\\.[0-9]+\$''']"
mk privfam2 "$TR" "$AND" "$PATHS" "regexes = ['''^192\\.168\\.[0-9.]+\$''']"
mk sharedfam "$TR" "$AND" "$PATHS" "regexes = ['''^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.[0-9.]+\$''']"
mk publicfam "$TR" "$AND" "$PATHS" "regexes = ['''^8\\.8\\.[0-9]+\\.[0-9]+\$''']"
mk widefam "$TR" "$AND" "$PATHS" "regexes = ['''^2[0-9][0-9]\\.[0-9.]+\$''']"
BARE=$(printf "%s.%s.%s.%s" 10 0 0 5); BARE="'''^${BARE}\$'''"
mk bareDots "$TR" "$AND" "$PATHS" "regexes = [$BARE]"
mk goodv6 "$TR6" "$AND" "$PATHS" "regexes = ['''^${Z}\\:1\$''']"
mk v6broad "$TR6" "$AND" "$PATHS" "regexes = ['''^${Z}\\:.*\$''']"
mk pathnoanchor "$TR" "$AND" "paths = ['''a\\.go\$''']" "$GOODREGEXES"
mk pathwild "$TR" "$AND" "paths = ['''^.*\\.go\$''']" "$GOODREGEXES"
mk pathdot "$TR" "$AND" "paths = ['''^a.go\$''']" "$GOODREGEXES"
mk pathmissing "$TR" "$AND" "paths = ['''^nope\\.go\$''']" "$GOODREGEXES"
# a second table that is bad: the failure must name that table's line
{ cat "$TMP/good.toml"; echo; echo '[[allowlists]]'; echo "$TR"; echo "$AND"; echo "$PATHS"; } > "$TMP/second.toml"

expect_ok good
expect_ok goodfam
expect_ok goodmulti
expect_ok goodv6
for d in notarget nocond orcond nopaths noregexes emptyregexes noanchorstart noanchorend \
    v6broad pathnoanchor pathwild pathdot pathmissing privfam privfam2 sharedfam publicfam widefam bareDots; do
    expect_bad "$d" "defect not caught"
done
out=$(check "$TMP/second.toml" "$TMP") && { echo "FAIL: self-test second accepted"; SELF_FAIL=1; } || {
    case $out in
        *"second.toml:9: "*) echo "PASS: self-test second names the bad table's line" ;;
        *) echo "FAIL: self-test second named the wrong line: $out"; SELF_FAIL=1 ;;
    esac
}

# ---- the real file -----------------------------------------------------------
REAL_FAIL=0
if [ ! -f "$TARGET" ]; then
    echo "FAIL: $TARGET not found"; REAL_FAIL=1
elif out=$(check "$TARGET" "$ROOT"); then
    echo "PASS: $TARGET has the required shape"
else
    printf '%s\n' "$out"
    echo "FAIL: $TARGET does not have the required shape"
    REAL_FAIL=1
fi

[ "$SELF_FAIL" -eq 0 ] && [ "$REAL_FAIL" -eq 0 ] && exit 0
exit 1
