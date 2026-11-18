#!/bin/sh
# Tests scripts/quarantine-skip.sh (#121, #124): the quarantine names are
# printed as one anchored group, ^(TestA|TestB)$; a line that is not a
# top-level Go test name (`lint:go`, or a subtest such as `TestFoo/sub`)
# makes the script exit 1 naming the line number.
# The last section runs a throwaway Go package to prove the anchoring
# against `go test -skip`; it is skipped when `go` is not on PATH.
# Run: sh scripts/quarantine-skip_test.sh   (non-zero exit on any failure)

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/scripts/quarantine-skip.sh"
TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT INT TERM

FAILS=0
pass() { echo "ok: $1"; }
fail() { echo "FAIL: $1 -- $2" >&2; FAILS=$((FAILS + 1)); }

# Runs a copy of the script beside a quarantine.txt holding $1 (printf format
# string, so \n works). Sets OUT, ERR and RC.
run_script() {
  rm -rf "$TMP/s"; mkdir -p "$TMP/s/scripts"
  cp "$SRC" "$TMP/s/scripts/quarantine-skip.sh"
  printf "$1" > "$TMP/s/scripts/quarantine.txt"
  OUT=$(sh "$TMP/s/scripts/quarantine-skip.sh" 2>"$TMP/err"); RC=$?
  ERR=$(cat "$TMP/err")
}

expect_out() { # desc, file content, want stdout
  run_script "$2"
  if [ "$RC" -ne 0 ]; then fail "$1" "exit $RC, stderr: $ERR"
  elif [ "$OUT" != "$3" ]; then fail "$1" "got '$OUT', want '$3'"
  else pass "$1"; fi
}

expect_out "single name is grouped and anchored" 'TestFoo\n' '^(TestFoo)$'
expect_out "two names share one group" 'TestA\nTestB\n' '^(TestA|TestB)$'
expect_out "comments and blanks ignored between names" '# note\nTestA\n\n  # more\nTestB\n' '^(TestA|TestB)$'

# A subtest line is refused, naming its line number: `go test -skip` splits
# its pattern at `/` before it applies `|`, so a subtest cannot be listed.
run_script 'TestA\nTestFoo/sub\nTestB\n'
if [ "$RC" -ne 1 ]; then fail "subtest line exits 1" "exit $RC, stdout: '$OUT'"
else pass "subtest line exits 1"; fi
case "$ERR" in
  *"line 2"*) pass "subtest message names line number 2" ;;
  *) fail "subtest message names line number 2" "stderr: '$ERR'" ;;
esac
case "$ERR" in
  *TestFoo/sub*) pass "subtest message names the line text" ;;
  *) fail "subtest message names the line text" "stderr: '$ERR'" ;;
esac
[ -z "$OUT" ] && pass "subtest refusal prints nothing on stdout" \
  || fail "subtest refusal prints nothing on stdout" "stdout: '$OUT'"
expect_out "empty file prints nothing" '' ''
expect_out "comment-only file prints nothing" '# one\n\n   # two\n' ''

run_script 'TestA\nlint:go\nTestB\n'
if [ "$RC" -ne 1 ]; then fail "non-test-name line exits 1" "exit $RC"
else pass "non-test-name line exits 1"; fi
case "$ERR" in
  *lint:go*) pass "non-test-name message names the line text" ;;
  *) fail "non-test-name message names the line text" "stderr: '$ERR'" ;;
esac
case "$ERR" in
  *2*) pass "non-test-name message names line number 2" ;;
  *) fail "non-test-name message names line number 2" "stderr: '$ERR'" ;;
esac

run_script '# header\n\nlint:go\n'
case "$ERR" in
  *3*) [ "$RC" -eq 1 ] && pass "line number counts comments and blanks (3)" \
       || fail "line number counts comments and blanks (3)" "exit $RC" ;;
  *) fail "line number counts comments and blanks (3)" "exit $RC, stderr: '$ERR'" ;;
esac

# --- behavioural proof against go test -skip ---
if ! command -v go >/dev/null 2>&1; then
  echo "SKIP: go not on PATH; go test -skip proof not run"
else
  G="$TMP/g"; mkdir -p "$G"
  cat > "$G/go.mod" <<'GOMOD'
module throwaway

go 1.21
GOMOD
  cat > "$G/x_test.go" <<'GOSRC'
package throwaway

import "testing"

func TestFoo(t *testing.T)    {}
func TestFooBar(t *testing.T) {}
func TestBar(t *testing.T) {
	t.Run("sub", func(t *testing.T) {})
	t.Run("other", func(t *testing.T) {})
}
GOSRC
  rm -rf "$TMP/s"; mkdir -p "$TMP/s/scripts"
  cp "$SRC" "$TMP/s/scripts/quarantine-skip.sh"
  has() { printf '%s\n' "$RUN" | grep -Eq "^[[:space:]]*=== RUN[[:space:]]+$1\$"; }

  # One name: TestFoo is skipped, the prefix-sharing TestFooBar still runs.
  printf 'TestFoo\n' > "$TMP/s/scripts/quarantine.txt"
  PAT=$(sh "$TMP/s/scripts/quarantine-skip.sh" 2>"$TMP/err"); PRC=$?
  if [ "$PRC" -ne 0 ]; then
    fail "go: script runs on TestFoo" "exit $PRC: $(cat "$TMP/err")"
  else
    RUN=$(cd "$G" && go test -v -skip "$PAT" ./... 2>&1); GRC=$?
    [ "$GRC" -eq 0 ] || fail "go: go test -skip passes (one name)" "exit $GRC: $RUN"
    if has TestFoo; then fail "go: TestFoo is skipped" "it ran"; else pass "go: TestFoo is skipped"; fi
    if has TestFooBar; then pass "go: TestFooBar still runs"; else fail "go: TestFooBar still runs" "did not run"; fi
    if has TestBar; then pass "go: TestBar still runs"; else fail "go: TestBar still runs" "did not run"; fi
    if has 'TestBar/sub'; then pass "go: TestBar/sub still runs"; else fail "go: TestBar/sub still runs" "did not run"; fi
  fi

  # Two names: both are skipped, the rest still run.
  printf 'TestFoo\nTestBar\n' > "$TMP/s/scripts/quarantine.txt"
  PAT=$(sh "$TMP/s/scripts/quarantine-skip.sh" 2>"$TMP/err"); PRC=$?
  if [ "$PRC" -ne 0 ]; then
    fail "go: script runs on TestFoo and TestBar" "exit $PRC: $(cat "$TMP/err")"
  else
    RUN=$(cd "$G" && go test -v -skip "$PAT" ./... 2>&1); GRC=$?
    [ "$GRC" -eq 0 ] || fail "go: go test -skip passes (two names)" "exit $GRC: $RUN"
    if has TestFoo; then fail "go: two names: TestFoo is skipped" "it ran"; else pass "go: two names: TestFoo is skipped"; fi
    if has TestBar; then fail "go: two names: TestBar is skipped" "it ran"; else pass "go: two names: TestBar is skipped"; fi
    if has TestFooBar; then pass "go: two names: TestFooBar still runs"; else fail "go: two names: TestFooBar still runs" "did not run"; fi
  fi
fi

if [ "$FAILS" -ne 0 ]; then echo "$FAILS case(s) failed" >&2; exit 1; fi
echo "all passed"
