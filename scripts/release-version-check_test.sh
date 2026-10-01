#!/usr/bin/env bash
set -euo pipefail

# Exercises release-version-check.sh against the cases refs #26 named: a
# non-semantic VERSION, a VERSION that sorts below an existing tag, a
# commit that isn't the tip of dev, and the good case that should pass.
# Run directly; exits non-zero on the first assertion that fails.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/release-version-check.sh"

DEV_SHA="aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
TAGS_V020="deadbeef00000000000000000000000000000000	refs/tags/v0.2.0"

assert_fail() {
  local desc="$1"; shift
  if "$SCRIPT" "$@" >/tmp/rvc_out 2>/tmp/rvc_err; then
    echo "FAIL: $desc -- expected failure, got success" >&2
    cat /tmp/rvc_out /tmp/rvc_err >&2
    exit 1
  fi
  echo "ok: $desc"
}

assert_pass() {
  local desc="$1" want="$2"; shift 2
  local got
  if ! got="$("$SCRIPT" "$@" 2>/tmp/rvc_err)"; then
    echo "FAIL: $desc -- expected success, got failure" >&2
    cat /tmp/rvc_err >&2
    exit 1
  fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: $desc -- got '$got', want '$want'" >&2
    exit 1
  fi
  echo "ok: $desc"
}

# Non-semantic VERSION is rejected.
assert_fail "non-semantic VERSION rejected" \
  "0.2.0.1" "$TAGS_V020" "$DEV_SHA" "$DEV_SHA"

# A zero-padded part is not a version Go will fetch.
assert_fail "zero-padded VERSION rejected" \
  "02.1.0" "$TAGS_V020" "$DEV_SHA" "$DEV_SHA"

# A VERSION below an existing tag is rejected.
assert_fail "out-of-order VERSION rejected" \
  "0.1.1" "$TAGS_V020" "$DEV_SHA" "$DEV_SHA"

# A VERSION equal to an existing tag is still "already exists".
assert_fail "existing tag rejected" \
  "0.2.0" "$TAGS_V020" "$DEV_SHA" "$DEV_SHA"

# A commit that is not the tip of dev is rejected.
assert_fail "non-tip commit rejected" \
  "0.2.1" "$TAGS_V020" "$DEV_SHA" "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"

# A VERSION above the existing tag, at the tip of dev, passes.
assert_pass "good case accepted" "RELEASE_TAG=v0.2.1" \
  "0.2.1" "$TAGS_V020" "$DEV_SHA" "$DEV_SHA"

echo "release-version-check_test.sh: all cases passed"
