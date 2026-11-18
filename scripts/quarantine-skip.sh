#!/bin/sh
# Prints scripts/quarantine.txt as one regular expression for `go test -skip`.
# `-skip` matches each test name as an unanchored regexp, so a bare `TestFoo`
# would also skip `TestFooBar`. Each line must therefore be a top-level Go
# test name (`^Test[A-Za-z0-9_]*$`); the names are joined into one anchored
# group, so no escaping is needed for that character set:
#   TestFoo          -> ^(TestFoo)$
#   TestA, TestB     -> ^(TestA|TestB)$
# Comment and blank lines are ignored; an empty list prints nothing, and
# `-skip ""` skips nothing. Any other line is refused: the script names the
# line number on stderr and exits 1, so test:go fails rather than quietly
# quarantining nothing (e.g. `lint:go`).
# Subtests (`TestFoo/sub`) are refused too. `go test -skip` splits its
# pattern at each `/` before it applies `|`, so `^A$/^b$|^B$` reads as
# top level `^A$` and sub level `^b$|^B$`, and `B` would never be skipped.
# To quarantine a subtest, quarantine its parent. Used by test:go in
# .gitlab-ci.yml.
dir=$(dirname "$0")
n=0
out=
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  line=$(printf '%s\n' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  case "$line" in '' | '#'*) continue ;; esac
  if ! printf '%s\n' "$line" | grep -Eq '^Test[A-Za-z0-9_]*$'; then
    echo "quarantine-skip: quarantine.txt line $n: '$line' is not a top-level Go test name" >&2
    exit 1
  fi
  out=${out:+$out|}$line
done < "$dir/quarantine.txt"
[ -n "$out" ] && printf '^(%s)$\n' "$out"
exit 0
