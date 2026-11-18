#!/bin/sh
# Behavioural test for .private-details-allow.toml (#121, item a), modelled on
# agent-infra's scan-test.sh: it runs the pinned private-details scanner with
# the host's real rules over a throwaway copy of the tree.
#
#   1. the tree scans clean (the listed values still pass in their files);
#   2. for each file named in any table's paths, one appended address that is
#      in no table produces an ip-address finding naming that file;
#   3. each table's exact values, copied into a file not in any table's
#      paths, are found exactly as they are with no allowlist at all.
#
# The scanner is scan.sh at the ref the include of
# scripts/private-details/ci-template.yml pins in .gitlab-ci.yml, read with
# `git show` from the local agent-infra clone (never checked out or fetched).
# Rules: /etc/private-details/rules.toml; unreadable (or no gitleaks, or no
# agent-infra clone) prints SKIP and exits 0. The copy is `git archive HEAD`
# with the working tree's allowlist laid over it, so an edit can be tried
# before it is committed. Test addresses are assembled from numbers; the
# scanner's output is never printed, only counts and file names.
#
# Run: sh scripts/ci/allowlist-scan_test.sh   (KEEP=1 keeps the temp dir)
# Exit: 0 all pass or skipped, 1 a failure, 2 setup error. POSIX sh, awk, git.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RULES=${PRIVATE_DETAILS_RULES:-/etc/private-details/rules.toml}
AGENT_INFRA=${AGENT_INFRA_DIR:-$HOME/projects/agent-infra}
GL=${GITLEAKS:-gitleaks}

skip() { echo "SKIP: allowlist-scan_test: $*"; exit 0; }
setup() { echo "ERROR: allowlist-scan_test: $*" >&2; exit 2; }

[ -r "$RULES" ] || skip "rules file not readable ($RULES)"
command -v "$GL" > /dev/null 2>&1 || skip "gitleaks not found"
[ -d "$AGENT_INFRA/.git" ] || [ -f "$AGENT_INFRA/HEAD" ] || skip "no agent-infra clone at $AGENT_INFRA"

unset PRIVATE_DETAILS_RULES PRIVATE_DETAILS_ALLOWLIST PRIVATE_DETAILS_SINCE \
    PRIVATE_DETAILS_ALLOWLIST_ONLY CI_PROJECT_PATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE \
    GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL

WORK=$(mktemp -d "${TMPDIR:-/tmp}/allowlist-scan.XXXXXX") || setup "no temp dir"
cleanup() { [ -n "${KEEP:-}" ] || rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT TERM
GIT_CEILING_DIRECTORIES=$WORK
export GIT_CEILING_DIRECTORIES

# ---- the pinned scanner --------------------------------------------------------
REF=$(awk '
    /^[ \t]*-[ \t]*project:[ \t]*ai\/agent-infra/ { want = 1; ref = ""; next }
    want && /^[ \t]*ref:/ { ref = $2; next }
    want && /file:[ \t]*scripts\/private-details\/ci-template\.yml/ { print ref; exit }
    /^[ \t]*-[ \t]*project:/ { want = 0 }' "$ROOT/.gitlab-ci.yml")
case $REF in
    "" | *[!0-9a-f]*) setup "cannot read the private-details pin from .gitlab-ci.yml" ;;
esac
mkdir "$WORK/scanner" || setup "mkdir"
for f in scan.sh summary.tmpl; do
    git -C "$AGENT_INFRA" show "$REF:scripts/private-details/$f" > "$WORK/scanner/$f" 2> /dev/null ||
        skip "agent-infra clone has no $REF (not fetched, by design)"
done
SCAN=$WORK/scanner/scan.sh

# ---- the throwaway copy ----------------------------------------------------------
COPY=$WORK/tree
mkdir "$COPY" || setup "mkdir"
git -C "$ROOT" archive HEAD | tar -x -C "$COPY" || setup "git archive failed"
cp "$ROOT/.private-details-allow.toml" "$COPY/.private-details-allow.toml" || setup "no allowlist"
git -C "$COPY" init -q || setup "git init"
git -C "$COPY" config user.name Test
git -C "$COPY" config user.email test@example.com
git -C "$COPY" config commit.gpgsign false
git -C "$COPY" add -A && git -C "$COPY" commit -q --no-verify -m base || setup "base commit"
: > "$WORK/empty.toml"

# scan <allowlist> <mode...>: output in $WORK/out, status in $RC.
scan() {
    al=$1; shift
    RC=0
    (cd "$COPY" && PRIVATE_DETAILS_RULES=$RULES PRIVATE_DETAILS_ALLOWLIST=$al sh "$SCAN" "$@") \
        > "$WORK/out" 2> "$WORK/err" || RC=$?
}
# findings <file>: "<rule> <file>:<line>" per finding line of $WORK/out.
findings() { awk -v f="$1" '$1 == "private-details:" && index($3, f ":") == 1 { print $2, $3 }' "$WORK/out"; }
resetcopy() { git -C "$COPY" reset -q --hard HEAD; git -C "$COPY" clean -qfd; }

# ---- what the allowlist says -------------------------------------------------------
# Records: "P <table> <file>" for a literal paths entry, "V <table> <value>" for a
# literal (no metacharacter) regexes entry, "N <table> <entry>" for a path entry
# that is not a plain file name. A tolerant reader of the shape the shape test
# enforces; it does not judge the file.
awk '
    function emit(s,   r) {
        if (t == 0 || (cur != "paths" && cur != "regexes")) return
        r = s; sub(/^\^/, "", r); sub(/\$$/, "", r)
        q = r; gsub(/\\[.:]/, "", q)
        if (q ~ /[][().*+?{}|^$\\]/ || q == "") { if (cur == "paths") print "N", t, s; return }
        gsub(/\\\./, ".", r); gsub(/\\:/, ":", r)
        print (cur == "paths" ? "P" : "V"), t, r
    }
    function scan(s,   i, c, j, str) {
        i = 1
        while (i <= length(s)) {
            c = substr(s, i, 1)
            if (depth == 0 && !started && match(substr(s, i), /^[ \t]*[A-Za-z]+[ \t]*=/)) {
                str = substr(s, i, RLENGTH); gsub(/[ \t=]/, "", str)
                cur = str; started = 1; i += RLENGTH; continue
            }
            if (substr(s, i, 3) == "\047\047\047") {
                j = index(substr(s, i + 3), "\047\047\047"); if (!j) return
                emit(substr(s, i + 3, j - 1)); i += j + 5; continue
            }
            if (c == "\047") { j = index(substr(s, i + 1), "\047"); if (!j) return; emit(substr(s, i + 1, j - 1)); i += j + 1; continue }
            if (c == "\"") {
                str = ""; j = i + 1
                while (j <= length(s) && substr(s, j, 1) != "\"") { if (substr(s, j, 1) == "\\") j++; str = str substr(s, j, 1); j++ }
                emit(str); i = j + 1; continue
            }
            if (c == "[") depth++; else if (c == "]") depth--; else if (c == "#") return
            i++
        }
    }
    { sub(/\r$/, "") }
    /^[ \t]*\[\[[ \t]*allowlists[ \t]*\]\]/ { t++; depth = 0; started = 0; cur = ""; next }
    /^[ \t]*#/ { next }
    { if (depth == 0) started = 0; scan($0); if (depth == 0) { started = 0; cur = "" } }
' "$COPY/.private-details-allow.toml" > "$WORK/records"

awk '$1 == "P" { print $3 }' "$WORK/records" | sort -u > "$WORK/pfiles"
awk '$1 == "V" { print $2, $3 }' "$WORK/records" > "$WORK/values"

# ---- cases --------------------------------------------------------------------------
PASSES=0
FAILS=0
pass() { echo "PASS: $1"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

# An address in no table: assembled here from numbers, never written out.
A1=$((5 + 6)); A2=$((20 + 2)); A3=$((30 + 3)); A4=$((40 + 4))
NEWADDR="$A1.$A2.$A3.$A4"
if awk -v a="$NEWADDR" '$2 == a { f = 1 } END { exit !f }' "$WORK/values"; then
    A4=$((A4 + 100)); NEWADDR="$A1.$A2.$A3.$A4"
fi

# Case 1: the tree scans clean.
scan "$COPY/.private-details-allow.toml" history
if [ "$RC" -eq 0 ]; then pass "the tree scans clean"
else fail "the tree does not scan clean (exit $RC, $(grep -c '^private-details: [a-z]' "$WORK/out") finding line(s))"; fi

# Pick a file outside every table's paths for the control and for case 3.
OUTSIDE=$(git -C "$COPY" ls-files | while read -r f; do
    case $f in *.md | *.go) grep -qxF "$f" "$WORK/pfiles" || { echo "$f"; break; } ;; esac
done)
[ -n "$OUTSIDE" ] || setup "no file outside every table's paths"

# Control: the appended address is found where no table reaches.
resetcopy
printf '\n%s\n' "$NEWADDR" >> "$COPY/$OUTSIDE"
git -C "$COPY" add -A
scan "$COPY/.private-details-allow.toml" staged
if [ "$RC" -eq 1 ] && [ -n "$(findings "$OUTSIDE" | grep '^ip-address ')" ]; then pass "control: an address in no table is an ip-address finding in an unlisted file"
else fail "control: an address in no table was not found in an unlisted file (exit $RC); the test cannot prove anything"; fi
resetcopy

# Case 2: every listed file, one more address.
if [ ! -s "$WORK/pfiles" ]; then fail "no file is named in any table's paths"; fi
while read -r f; do
    [ -n "$f" ] || continue
    if [ ! -f "$COPY/$f" ]; then echo "NOTE: $f is listed in paths but is not in the tree"; continue; fi
    resetcopy
    printf '\n%s\n' "$NEWADDR" >> "$COPY/$f"
    git -C "$COPY" add -A
    scan "$COPY/.private-details-allow.toml" staged
    if [ "$RC" -eq 1 ] && [ -n "$(findings "$f" | grep '^ip-address ')" ]; then pass "appended address is an ip-address finding in $f"
    else fail "appended address passes (or is not named) in $f (exit $RC)"; fi
done < "$WORK/pfiles"
resetcopy

# Case 3: a table's values copied into an unlisted file are found as with no allowlist.
tables=$(awk '{ print $1 }' "$WORK/values" | sort -un)
if [ -z "$tables" ]; then fail "no table lists an exact value in regexes"; fi
for t in $tables; do
    awk -v t="$t" '$1 == t { print $2 }' "$WORK/values" > "$WORK/tv"
    nv=$(wc -l < "$WORK/tv")
    for al in "$WORK/empty.toml" "$COPY/.private-details-allow.toml"; do
        case $al in */empty.toml) FN=empty ;; *) FN=real ;; esac
        resetcopy
        { printf '\n'; cat "$WORK/tv"; } >> "$COPY/$OUTSIDE"
        git -C "$COPY" add -A
        scan "$al" staged
        findings "$OUTSIDE" | sort > "$WORK/f.$FN"
    done
    resetcopy
    nbase=$(wc -l < "$WORK/f.empty")
    if [ "$nbase" -eq 0 ]; then
        echo "NOTE: table $t: none of its $nv value(s) is a finding with no allowlist (centrally allowed); nothing to prove"
    elif cmp -s "$WORK/f.empty" "$WORK/f.real"; then
        pass "table $t: its $nv value(s) are all found in a file outside its paths ($nbase finding(s))"
    else
        fail "table $t: $((nbase - $(wc -l < "$WORK/f.real"))) of $nbase finding(s) vanish in a file outside its paths"
    fi
done

echo "allowlist-scan_test: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ] && exit 0
exit 1
