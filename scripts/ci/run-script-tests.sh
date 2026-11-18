#!/bin/sh
# Runs every scripts/*_test.sh and scripts/**/*_test.sh, each with the
# interpreter its shebang names, keeps going after a failure, prints one
# pass/fail line per file, then runs scripts/ci/job-rules_test.py. Exit 1 if
# anything failed. A new *_test.sh is picked up with no edit here (#123).
#
# Excluded, each with its reason:
#   scripts/ci/allowlist-scan_test.sh -- needs gitleaks and the private-details
#     runner's rules file (/etc/private-details/rules.toml); it is run by hand
#     on the host. Tracked by #123.
#
# job-rules_test.py needs python3, PyYAML and a clone of ai/agent-infra
# (AGENT_INFRA_DIR) holding the refs .gitlab-ci.yml pins.
# POSIX sh.

set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2

EXCLUDED="scripts/ci/allowlist-scan_test.sh"

fail=0
list=$(find scripts -name '*_test.sh' | LC_ALL=C sort)
[ -n "$list" ] || { echo "FAIL: no *_test.sh files found"; exit 1; }

for f in $list; do
  case " $EXCLUDED " in *" $f "*) echo "SKIP $f (excluded, see header)"; continue ;; esac
  interp=$(head -n 1 "$f" | sed -n 's/^#![[:space:]]*//p')
  case "$interp" in
    "") echo "FAIL $f (no shebang)"; fail=1; continue ;;
  esac
  # shellcheck disable=SC2086
  if $interp "$f" > /dev/null 2>&1; then
    echo "PASS $f"
  else
    echo "FAIL $f"
    # Re-run for the log so a failure can be read in the job output.
    $interp "$f" 2>&1 | tail -n 40 | sed 's/^/    /'
    fail=1
  fi
done

if python3 -I scripts/ci/job-rules_test.py > /dev/null 2>&1; then
  echo "PASS scripts/ci/job-rules_test.py"
else
  echo "FAIL scripts/ci/job-rules_test.py"
  python3 -I scripts/ci/job-rules_test.py 2>&1 | tail -n 40 | sed 's/^/    /'
  fail=1
fi

exit "$fail"
