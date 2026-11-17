#!/bin/sh
# Prints scripts/quarantine.txt as one regular expression for `go test -skip`:
# names joined with `|`, regexp characters escaped so `(` or `.` match
# literally. Prints nothing while the list is empty, and `-skip ""` skips
# nothing. Used by test:go in .gitlab-ci.yml.
dir=$(dirname "$0")
grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$dir/quarantine.txt" \
  | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[][\\.*+?(){}|^$]/\\&/g' \
  | paste -sd'|' -
