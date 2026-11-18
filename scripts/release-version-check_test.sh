#!/usr/bin/env bash
set -euo pipefail

# Exercises release-version-check.sh against the cases refs #26 named: a
# non-semantic VERSION, a VERSION that sorts below an existing tag, a
# commit that isn't the tip of main (the release branch since #88; it
# was dev before), and the good case that should pass.
# Run directly; exits non-zero on the first assertion that fails.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/release-version-check.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MAIN_SHA="aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
# A commit dev has but main does not yet: what an old dev pipeline
# would offer.
DEV_ONLY_SHA="cccc3333cccc3333cccc3333cccc3333cccc3333"
TAGS_V020="deadbeef00000000000000000000000000000000	refs/tags/v0.2.0"

assert_fail() {
  local desc="$1"; shift
  if "$SCRIPT" "$@" >"$TMP/out" 2>"$TMP/err"; then
    echo "FAIL: $desc -- expected failure, got success" >&2
    cat "$TMP/out" "$TMP/err" >&2
    exit 1
  fi
  echo "ok: $desc"
}

# Like assert_fail, and the error must contain the given text.
assert_fail_says() {
  local desc="$1" want="$2"; shift 2
  if "$SCRIPT" "$@" >"$TMP/out" 2>"$TMP/err"; then
    echo "FAIL: $desc -- expected failure, got success" >&2
    cat "$TMP/out" "$TMP/err" >&2
    exit 1
  fi
  if ! grep -qF "$want" "$TMP/err"; then
    echo "FAIL: $desc -- error does not say '$want':" >&2
    cat "$TMP/err" >&2
    exit 1
  fi
  echo "ok: $desc"
}

assert_pass() {
  local desc="$1" want="$2"; shift 2
  local got
  if ! got="$("$SCRIPT" "$@" 2>"$TMP/err")"; then
    echo "FAIL: $desc -- expected success, got failure" >&2
    cat "$TMP/err" >&2
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
  "0.2.0.1" "$TAGS_V020" "$MAIN_SHA" "$MAIN_SHA"

# A zero-padded part is not a version Go will fetch.
assert_fail "zero-padded VERSION rejected" \
  "02.1.0" "$TAGS_V020" "$MAIN_SHA" "$MAIN_SHA"

# A VERSION below an existing tag is rejected.
assert_fail "out-of-order VERSION rejected" \
  "0.1.1" "$TAGS_V020" "$MAIN_SHA" "$MAIN_SHA"

# A VERSION equal to an existing tag is still "already exists".
assert_fail "existing tag rejected" \
  "0.2.0" "$TAGS_V020" "$MAIN_SHA" "$MAIN_SHA"

# A commit that is not the tip of main is rejected.
assert_fail "non-tip commit rejected" \
  "0.2.1" "$TAGS_V020" "$MAIN_SHA" "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"

# A commit only dev has is refused, and the message names main, so the
# releaser is sent to main's pipeline rather than dev's (#88).
assert_fail_says "dev-only commit refused, pointing at main" "not the current tip of main" \
  "0.2.1" "$TAGS_V020" "$MAIN_SHA" "$DEV_ONLY_SHA"

# A VERSION above the existing tag, at the tip of main, passes.
assert_pass "good case accepted" "RELEASE_TAG=v0.2.1" \
  "0.2.1" "$TAGS_V020" "$MAIN_SHA" "$MAIN_SHA"

# release-readiness (#122) passes "-" as MAIN_SHA to skip the tip check:
# there is no main tip to compare with before a promotion. Every other check
# still applies, and the four-argument contract stays.
assert_pass "'-' as MAIN_SHA skips the tip check" "RELEASE_TAG=v0.2.1" \
  "0.2.1" "$TAGS_V020" "-" "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
assert_pass "'-' as MAIN_SHA with no tags at all" "RELEASE_TAG=v0.1.0" \
  "0.1.0" "" "-" "$MAIN_SHA"
assert_fail "'-' as MAIN_SHA still rejects a non-semantic VERSION" \
  "1.2.beta" "$TAGS_V020" "-" "$MAIN_SHA"
assert_fail "'-' as MAIN_SHA still rejects an out-of-order VERSION" \
  "0.1.1" "$TAGS_V020" "-" "$MAIN_SHA"
assert_fail "'-' as MAIN_SHA still rejects an existing tag" \
  "0.2.0" "$TAGS_V020" "-" "$MAIN_SHA"
assert_fail "three arguments are still a usage error" \
  "0.2.1" "$TAGS_V020" "$MAIN_SHA"
assert_fail "five arguments are still a usage error" \
  "0.2.1" "$TAGS_V020" "$MAIN_SHA" "$MAIN_SHA" "-"

echo "release-version-check_test.sh: all cases passed"
