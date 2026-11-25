#!/bin/sh
# Exercises scripts/ci/config-check.sh (#121): modes `pins`, `env` and `tags`,
# against the real .gitlab-ci.yml and variants of it edited at run time.
# Prints one ok/FAIL line per case; exits non-zero if any case failed.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/config-check.sh"
REAL="$ROOT/.gitlab-ci.yml"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

FAILS=0
pass() { echo "ok: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

# run_cmd ARGS...: runs the script; sets RC and OUT (stdout and stderr).
run_cmd() {
  OUT="$(sh "$SCRIPT" "$@" 2>&1)"
  RC=$?
}

# expect_rc DESC WANT: asserts the last run_cmd exit code.
expect_rc() {
  if [ "$RC" -eq "$2" ]; then pass "$1"; else
    fail "$1 -- exit $RC, want $2"
    echo "$OUT" | sed 's/^/    | /'
  fi
}
# out_has DESC TEXT / out_lacks DESC TEXT: fixed-string checks on OUT.
out_has() {
  if printf '%s\n' "$OUT" | grep -qF -- "$2"; then pass "$1"; else fail "$1 -- output lacks '$2'"; fi
}
out_lacks() {
  if printf '%s\n' "$OUT" | grep -qF -- "$2"; then fail "$1 -- output contains '$2'"; else pass "$1"; fi
}
out_has_word() {
  if printf '%s\n' "$OUT" | grep -qw -- "$2"; then pass "$1"; else fail "$1 -- output lacks word '$2'"; fi
}
out_lacks_word() {
  if printf '%s\n' "$OUT" | grep -qw -- "$2"; then fail "$1 -- output names '$2'"; else pass "$1"; fi
}

if [ ! -f "$SCRIPT" ]; then
  echo "FAIL: $SCRIPT does not exist"
  echo "config-check_test.sh: 1 failed (script missing)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

# flip_ref TEMPLATE OUT: copy REAL to OUT with one hex digit of the include
# `ref:` (the line directly above `file: <TEMPLATE>`) changed.
flip_ref() {
  awk -v t="$1" '
    { l[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        if (l[i + 1] ~ ("file: " t "$") && match(l[i], /[0-9a-f]{40}/)) {
          c = substr(l[i], RSTART, 1); n = (c == "0") ? "1" : "0"
          l[i] = substr(l[i], 1, RSTART - 1) n substr(l[i], RSTART + 1)
        }
        print l[i]
      }
    }' "$REAL" >"$2"
}

# set_var VAR VALUE OUT: copy REAL with every `VAR:` variables line set to VALUE.
set_var() {
  awk -v v="$1" -v val="$2" '
    $0 ~ ("^ +" v ": ") { sub(v ": .*", v ": " val) }
    { print }' "$REAL" >"$3"
}

# job_vars JOB FILE: prints NAME=value for the job'"'"'s variables: block.
job_vars() {
  awk -v job="$1" '
    $0 == job ":" { injob = 1; next }
    injob && /^[^ #]/ { injob = 0 }
    injob && /^  variables:/ { inv = 1; next }
    injob && inv && /^  [^ ]/ { inv = 0 }
    injob && inv && /^    [A-Z_]+:/ {
      s = $0; sub(/^    /, "", s); k = s; sub(/:.*/, "", k)
      v = s; sub(/^[^:]*: */, "", v); sub(/ +#.*$/, "", v)
      print k "=" v
    }' "$2"
}

val_of() { job_vars "$1" "$REAL" | sed -n "s/^$2=//p"; }

PG_SHA="$(val_of publish-gate PUBLISH_GATE_SHA)"
PD_SHA="$(val_of private-details PRIVATE_DETAILS_SHA)"
if [ -z "$PG_SHA" ] || [ -z "$PD_SHA" ]; then
  echo "FAIL: fixture: cannot read the pinned SHAs from $REAL"
  exit 1
fi

RULES_PATH=/etc/private-details/rules.toml
KEY_PATH=/etc/gauntlet-publish-gate/key

# run_env JOB FILE [NAME=VALUE | -NAME]...: runs `env JOB FILE` in a clean
# environment built from FILE's variables for JOB, the fixed runner paths,
# then the given overrides (-NAME removes NAME).
run_env() {
  job="$1"; file="$2"; shift 2
  base="$TMP/envbase"
  job_vars "$job" "$file" >"$base"
  set --  "$@"
  overrides="$*"
  : "$overrides"
  # Build an env(1) argument list; later assignments win.
  args_file="$TMP/envargs"
  : >"$args_file"
  {
    cat "$base"
    printf 'PRIVATE_DETAILS_RULES=%s\n' "$RULES_PATH"
    if [ "$job" = publish-gate ]; then printf 'PUBLISH_GATE_SSH_KEY=%s\n' "$KEY_PATH"; fi
  } >"$args_file"
  unset_list=""
  for o in "$@"; do
    case "$o" in
      -*) unset_list="$unset_list ${o#-}" ;;
      *) printf '%s\n' "$o" >>"$args_file" ;;
    esac
  done
  # Remove the unset names from the base list.
  for n in $unset_list; do
    grep -v "^$n=" "$args_file" >"$args_file.n"; mv "$args_file.n" "$args_file"
  done
  # Assemble positional parameters from the file, one assignment per line.
  set --
  while IFS= read -r line; do set -- "$@" "$line"; done <"$args_file"
  OUT="$(env -i PATH="$PATH" "$@" sh "$SCRIPT" env "$job" "$file" 2>&1)"
  RC=$?
}

# ---------------------------------------------------------------------------
# pins
# ---------------------------------------------------------------------------

run_cmd pins "$REAL"
expect_rc "pins: real file passes" 0

(cd "$ROOT" && sh "$SCRIPT" pins >/dev/null 2>&1)
RC=$?
expect_rc "pins: default FILE is .gitlab-ci.yml in the current directory" 0

flip_ref scripts/publish-gate/ci-template.yml "$TMP/pg-ref.yml"
run_cmd pins "$TMP/pg-ref.yml"
expect_rc "pins: publish-gate include ref differs -> 1" 1
out_has "pins: names publish-gate" "publish-gate"
out_lacks_word "pins: does not name the other pair" "private-details"
out_lacks "pins: does not print the SHA" "$PG_SHA"

flip_ref scripts/private-details/ci-template.yml "$TMP/pd-ref.yml"
run_cmd pins "$TMP/pd-ref.yml"
expect_rc "pins: private-details include ref differs -> 1" 1
out_has "pins: names private-details" "private-details"
out_lacks_word "pins: does not name the other pair" "publish-gate"
out_lacks "pins: does not print the SHA" "$PD_SHA"

set_var PUBLISH_GATE_SHA "$(printf '%s' "$PG_SHA" | sed 's/^./0/; t; s/^./1/')" "$TMP/pg-var.yml"
# the sed above can leave the value unchanged when it already starts with 0
if [ "$(printf '%s' "$PG_SHA" | cut -c1)" = 0 ]; then
  set_var PUBLISH_GATE_SHA "1$(printf '%s' "$PG_SHA" | cut -c2-)" "$TMP/pg-var.yml"
fi
run_cmd pins "$TMP/pg-var.yml"
expect_rc "pins: PUBLISH_GATE_SHA differs from its include -> 1" 1
out_has "pins: names publish-gate" "publish-gate"

if [ "$(printf '%s' "$PD_SHA" | cut -c1)" = 0 ]; then d=1; else d=0; fi
set_var PRIVATE_DETAILS_SHA "$d$(printf '%s' "$PD_SHA" | cut -c2-)" "$TMP/pd-var.yml"
run_cmd pins "$TMP/pd-var.yml"
expect_rc "pins: PRIVATE_DETAILS_SHA differs from its include -> 1" 1
out_has "pins: names private-details" "private-details"
out_lacks_word "pins: does not name the other pair" "publish-gate"

sed '/^ *PUBLISH_GATE_SHA:/d' "$REAL" >"$TMP/pg-missing.yml"
run_cmd pins "$TMP/pg-missing.yml"
expect_rc "pins: PUBLISH_GATE_SHA line deleted -> 2" 2

sed '/^ *PRIVATE_DETAILS_SHA:/d' "$REAL" >"$TMP/pd-missing.yml"
run_cmd pins "$TMP/pd-missing.yml"
expect_rc "pins: PRIVATE_DETAILS_SHA line deleted -> 2" 2

awk '{ print } /^ +PUBLISH_GATE_SHA:/ { print }' "$REAL" >"$TMP/pg-dup.yml"
run_cmd pins "$TMP/pg-dup.yml"
expect_rc "pins: PUBLISH_GATE_SHA present twice -> 2" 2

awk '{ print } /^ +PRIVATE_DETAILS_SHA:/ { print }' "$REAL" >"$TMP/pd-dup.yml"
run_cmd pins "$TMP/pd-dup.yml"
expect_rc "pins: PRIVATE_DETAILS_SHA present twice -> 2" 2

# Not 40 lowercase hex: change the include and the variable together so the
# pair is equal and only the format is wrong.
upper="$(printf '%s' "$PG_SHA" | tr 'a-f' 'A-F')"
case "$upper" in "$PG_SHA") upper="" ;; esac
if [ -n "$upper" ]; then
  sed "s/$PG_SHA/$upper/g" "$REAL" >"$TMP/upper.yml"
  run_cmd pins "$TMP/upper.yml"
  expect_rc "pins: equal but uppercase hex -> 2" 2
fi
short="$(printf '%s' "$PG_SHA" | cut -c2-)"
sed "s/$PG_SHA/$short/g" "$REAL" >"$TMP/short.yml"
run_cmd pins "$TMP/short.yml"
expect_rc "pins: equal but 39 characters -> 2" 2

# ---------------------------------------------------------------------------
# env
# ---------------------------------------------------------------------------

BAD="zz-actual-marker-7"

run_env publish-gate "$REAL"
expect_rc "env publish-gate: environment built from the file passes" 0

run_env private-details "$REAL"
expect_rc "env private-details: environment built from the file passes" 0

# check_var JOB NAME: set NAME to a wrong value; only NAME may be named, and
# neither the expected nor the actual value may appear.
check_var() {
  job="$1"; name="$2"
  case "$name" in
    PUBLISH_GATE_SSH_KEY) expected="$KEY_PATH" ;;
    PRIVATE_DETAILS_RULES) expected="$RULES_PATH" ;;
    *) expected="$(val_of "$job" "$name")" ;;
  esac
  run_env "$job" "$REAL" "$name=$BAD"
  expect_rc "env $job: $name changed -> 1" 1
  out_has_word "env $job: $name is named" "$name"
  for other in $ALLNAMES; do
    [ "$other" = "$name" ] && continue
    out_lacks_word "env $job: $name changed, $other not named" "$other"
  done
  out_lacks "env $job: $name changed, actual value not printed" "$BAD"
  if [ -n "$expected" ]; then
    out_lacks "env $job: $name changed, expected value not printed" "$expected"
  fi
}

PG_EXACT="PUBLISH_GATE_SHA PUBLISH_REMOTE PUBLISH_AUTHOR_NAME PUBLISH_AUTHOR_EMAIL PUBLISH_GATE_SSH_KEY PRIVATE_DETAILS_RULES"
PG_FORBID="PRIVATE_DETAILS_SCAN GITLEAKS PUBLISH_REVIEWED_FILES PUBLISH_BRANCH PUBLISH_COMMIT"
PD_EXACT="PRIVATE_DETAILS_SHA PRIVATE_DETAILS_SINCE PRIVATE_DETAILS_RULES"
PD_FORBID="PRIVATE_DETAILS_ALLOWLIST PRIVATE_DETAILS_ALLOWLIST_ONLY GITLEAKS"

ALLNAMES="$PG_EXACT $PG_FORBID"
for v in $PG_EXACT $PG_FORBID; do check_var publish-gate "$v"; done
ALLNAMES="$PD_EXACT $PD_FORBID"
for v in $PD_EXACT $PD_FORBID; do check_var private-details "$v"; done

# A required variable that is absent also fails, by name.
run_env publish-gate "$REAL" -PUBLISH_REMOTE
expect_rc "env publish-gate: PUBLISH_REMOTE unset -> 1" 1
out_has_word "env publish-gate: names PUBLISH_REMOTE" PUBLISH_REMOTE

# Several at once: every failing name is listed.
run_env publish-gate "$REAL" "PUBLISH_REMOTE=$BAD" "PUBLISH_COMMIT=$BAD"
expect_rc "env publish-gate: two variables wrong -> 1" 1
out_has_word "env publish-gate: names PUBLISH_REMOTE" PUBLISH_REMOTE
out_has_word "env publish-gate: names PUBLISH_COMMIT" PUBLISH_COMMIT

# Documented run-time switches are not checked.
run_env publish-gate "$REAL" PUBLISH_DRY_RUN=1 PUBLISH_INIT_EXPECT=x PUBLISH_SCAN_TIMEOUT=60
expect_rc "env publish-gate: PUBLISH_DRY_RUN, _INIT_EXPECT, _SCAN_TIMEOUT allowed" 0

# Empty counts as unset for the forbidden variables.
for v in $PG_FORBID; do
  run_env publish-gate "$REAL" "$v="
  expect_rc "env publish-gate: $v set to empty passes" 0
done
for v in $PD_FORBID; do
  run_env private-details "$REAL" "$v="
  expect_rc "env private-details: $v set to empty passes" 0
done

# Exit 2: unknown job, unreadable file.
run_env no-such-job "$REAL"
expect_rc "env: unknown JOB -> 2" 2

run_env publish-gate "$TMP/does-not-exist.yml"
expect_rc "env: unreadable FILE -> 2" 2

# ---------------------------------------------------------------------------
# env renovate (P-RS1)
# ---------------------------------------------------------------------------

CI_API="https://gitlab.example.test/api/v4"
CI_PATH="example-group/example-project"
CI_DIR="/builds/example-group/example-project"

# run_renovate [NAME=VALUE | -NAME]...: runs `env renovate FILE` in a clean
# environment built from the renovate job's variables: (quotes stripped, the
# $CI_... references expanded to the fixed values above), then the overrides.
run_renovate() {
  rfile="$REAL"
  rargs="$TMP/renargs"
  job_vars renovate "$REAL" | sed -e 's/="\(.*\)"$/=\1/' \
    -e "s|\$CI_API_V4_URL|$CI_API|g" -e "s|\$CI_PROJECT_PATH|$CI_PATH|g" \
    -e "s|\$CI_PROJECT_DIR|$CI_DIR|g" >"$rargs"
  {
    printf 'CI_API_V4_URL=%s\nCI_PROJECT_PATH=%s\nCI_PROJECT_DIR=%s\n' "$CI_API" "$CI_PATH" "$CI_DIR"
    printf 'PRIVATE_DETAILS_RULES=%s\n' "$RULES_PATH"
  } >>"$rargs"
  for o in "$@"; do
    case "$o" in
      -*) grep -v "^${o#-}=" "$rargs" >"$rargs.n"; mv "$rargs.n" "$rargs" ;;
      *) grep -v "^${o%%=*}=" "$rargs" >"$rargs.n"; mv "$rargs.n" "$rargs"
         printf '%s\n' "$o" >>"$rargs" ;;
    esac
  done
  set --
  while IFS= read -r line; do set -- "$@" "$line"; done <"$rargs"
  OUT="$(env -i PATH="$PATH" "$@" sh "$SCRIPT" env renovate "$rfile" 2>&1)"
  RC=$?
}

REN_FILE="RENOVATE_PLATFORM RENOVATE_AUTODISCOVER RENOVATE_ONBOARDING RENOVATE_REQUIRE_CONFIG LOG_LEVEL GOPROXY GOPRIVATE"
REN_FORBID="RENOVATE_TOKEN GITHUB_COM_TOKEN HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY NODE_OPTIONS NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED RENOVATE_ADDITIONAL_CONFIG_FILE RENOVATE_CONFIG_FILE"

run_renovate
expect_rc "env renovate: environment built from the file passes" 0

# Each name the file sets (literally or via a $CI_ reference): changed -> 1,
# named, neither the actual nor the expected value printed; unset -> 1, named.
for v in $REN_FILE; do
  expected="$(job_vars renovate "$REAL" | sed -n "s/^$v=//p" | sed -e 's/^"\(.*\)"$/\1/')"
  run_renovate "$v=$BAD"
  expect_rc "env renovate: $v changed -> 1" 1
  out_has_word "env renovate: $v changed, named" "$v"
  out_lacks "env renovate: $v changed, actual value not printed" "$BAD"
  [ -n "$expected" ] && out_lacks "env renovate: $v changed, expected value not printed" "$expected"
  run_renovate "-$v"
  expect_rc "env renovate: $v unset -> 1" 1
  out_has_word "env renovate: $v unset, named" "$v"
done

# The control is the project setting, not this check: ENDPOINT and REPOSITORIES
# are no longer compared, so any value (or none) passes.
for v in RENOVATE_ENDPOINT RENOVATE_REPOSITORIES; do
  run_renovate "$v=https://example.invalid/api/v4"
  expect_rc "env renovate: passes with $v set" 0
  run_renovate "-$v"
  expect_rc "env renovate: passes with $v unset" 0
done

# Forbidden names fail when set to a value, pass when empty.
for v in $REN_FORBID; do
  run_renovate "$v=$BAD"
  expect_rc "env renovate: $v set -> 1" 1
  out_has_word "env renovate: $v set, named" "$v"
  out_lacks "env renovate: $v set, value not printed" "$BAD"
  run_renovate "$v="
  expect_rc "env renovate: $v set to empty passes" 0
done

# Prefix sweep: any other RENOVATE_ name fails.
for v in RENOVATE_HOST_RULES RENOVATE_CONFIG RENOVATE_X_FOO; do
  run_renovate "$v=$BAD"
  expect_rc "env renovate: $v set -> 1" 1
  out_has_word "env renovate: $v set, named" "$v"
  out_lacks "env renovate: $v set, value not printed" "$BAD"
done

# The two documented switches.
for val in extract lookup full ""; do
  run_renovate "RENOVATE_DRY_RUN=$val"
  expect_rc "env renovate: RENOVATE_DRY_RUN='$val' passes" 0
done
run_renovate RENOVATE_DRY_RUN=bogus
expect_rc "env renovate: RENOVATE_DRY_RUN=bogus -> 1" 1
out_has_word "env renovate: names RENOVATE_DRY_RUN" RENOVATE_DRY_RUN
out_lacks "env renovate: bogus value not printed" bogus
run_renovate RENOVATE_SECURITY_ONLY=true
expect_rc "env renovate: RENOVATE_SECURITY_ONLY=true passes" 0
run_renovate RENOVATE_SECURITY_ONLY=
expect_rc "env renovate: RENOVATE_SECURITY_ONLY empty passes" 0
run_renovate RENOVATE_SECURITY_ONLY=bogus
expect_rc "env renovate: RENOVATE_SECURITY_ONLY=bogus -> 1" 1
out_has_word "env renovate: names RENOVATE_SECURITY_ONLY" RENOVATE_SECURITY_ONLY

# The script's own text names the setting that is the real control.
if grep -qF "Minimum role to use pipeline variables" "$SCRIPT"; then
  pass "config-check.sh names the setting 'Minimum role to use pipeline variables'"
else
  fail "config-check.sh names the setting 'Minimum role to use pipeline variables'"
fi

# Usage text names the mode.
run_cmd
out_has "usage: names renovate" "renovate"

# ---------------------------------------------------------------------------
# tags
# ---------------------------------------------------------------------------

run_cmd tags "$REAL"
expect_rc "tags: real file passes" 0

(cd "$ROOT" && sh "$SCRIPT" tags >/dev/null 2>&1)
RC=$?
expect_rc "tags: default FILE is .gitlab-ci.yml in the current directory" 0

SIGN_LINE="$(awk '/^blocklist:sign:/ { j = 1; next } j && /^  tags: \[gauntlet-signing\]$/ { print NR; exit }' "$REAL")"
PUB_LINE="$(awk '/^blocklist:publish:/ { j = 1; next } j && /^  tags: \[gauntlet-publish\]$/ { print NR; exit }' "$REAL")"
DEF_LINE="$(awk '/^default:/ { j = 1; next } j && /^  tags: / { print NR; exit }' "$REAL")"
LINT_HDR="$(grep -n '^lint:go:' "$REAL" | cut -d: -f1)"
if [ -z "$SIGN_LINE" ] || [ -z "$PUB_LINE" ] || [ -z "$DEF_LINE" ] || [ -z "$LINT_HDR" ]; then
  fail "tags: fixture lines not found in $REAL"
else
  # Tag added to lint:go.
  awk '{ print } /^lint:go:/ { print "  tags: [gauntlet-signing]" }' "$REAL" >"$TMP/t-lint.yml"
  run_cmd tags "$TMP/t-lint.yml"
  expect_rc "tags: tag added to lint:go -> 1" 1
  out_has "tags: names the tag" "gauntlet-signing"
  out_has_word "tags: names the line" "$((LINT_HDR + 1))"

  # Tag removed from blocklist:sign.
  sed "${SIGN_LINE}d" "$REAL" >"$TMP/t-removed.yml"
  run_cmd tags "$TMP/t-removed.yml"
  expect_rc "tags: tag removed from blocklist:sign -> 1" 1
  out_has "tags: names the tag" "gauntlet-signing"

  # Tag shared with another tag on its own job.
  sed "${SIGN_LINE}s/.*/  tags: [gauntlet-signing, light]/" "$REAL" >"$TMP/t-extra.yml"
  run_cmd tags "$TMP/t-extra.yml"
  expect_rc "tags: [gauntlet-signing, light] -> 1" 1
  out_has "tags: names the tag" "gauntlet-signing"
  out_has_word "tags: names the line" "$SIGN_LINE"

  # Intended job with two tags lines.
  awk '{ print } /^blocklist:sign:/ { print "  tags: [gauntlet-signing]" }' "$REAL" >"$TMP/t-twice.yml"
  run_cmd tags "$TMP/t-twice.yml"
  expect_rc "tags: intended job has the tag line twice -> 1" 1
  out_has "tags: names the tag" "gauntlet-signing"

  # A variable in any tags line.
  awk '{ print } /^lint:go:/ { print "  tags: [$T]" }' "$REAL" >"$TMP/t-var.yml"
  run_cmd tags "$TMP/t-var.yml"
  expect_rc "tags: [\$T] on a job -> 1" 1
  out_has_word "tags: names the line" "$((LINT_HDR + 1))"

  # A !reference in a tags line.
  awk '{ print } /^lint:go:/ { print "  tags: !reference [.other, tags]" }' "$REAL" >"$TMP/t-ref.yml"
  run_cmd tags "$TMP/t-ref.yml"
  expect_rc "tags: !reference in a tags line -> 1" 1
  out_has_word "tags: names the line" "$((LINT_HDR + 1))"

  # default: naming a secret-holding tag.
  sed "${DEF_LINE}s/.*/  tags: [gauntlet-publish]/" "$REAL" >"$TMP/t-default.yml"
  run_cmd tags "$TMP/t-default.yml"
  expect_rc "tags: default: names gauntlet-publish -> 1" 1
  out_has "tags: names the tag" "gauntlet-publish"
  out_has_word "tags: names the line" "$DEF_LINE"

  # Hidden job with the tag.
  cp "$REAL" "$TMP/t-hidden.yml"
  printf '\n.hidden:\n  tags: [gauntlet-publish]\n' >>"$TMP/t-hidden.yml"
  hidden_line="$(wc -l <"$TMP/t-hidden.yml" | tr -d ' ')"
  run_cmd tags "$TMP/t-hidden.yml"
  expect_rc "tags: hidden .job: block with the tag -> 1" 1
  out_has "tags: names the tag" "gauntlet-publish"
  out_has_word "tags: names the line" "$hidden_line"

  # The longer tag must not be mistaken for its prefix: gauntlet-publish-gate
  # on blocklist:publish is wrong, naming the gate tag.
  sed "${PUB_LINE}s/.*/  tags: [gauntlet-publish-gate]/" "$REAL" >"$TMP/t-gate.yml"
  run_cmd tags "$TMP/t-gate.yml"
  expect_rc "tags: gauntlet-publish-gate on blocklist:publish -> 1" 1
  out_has "tags: names the tag" "gauntlet-publish-gate"

  # The renovate tag is held to its one job like the others.
  awk '{ print } /^lint:go:/ { print "  tags: [gauntlet-renovate]" }' "$REAL" >"$TMP/t-renovate.yml"
  run_cmd tags "$TMP/t-renovate.yml"
  expect_rc "tags: gauntlet-renovate added to lint:go -> 1" 1
  out_has "tags: names the tag" "gauntlet-renovate"
  out_has_word "tags: names the line" "$((LINT_HDR + 1))"

  # Dodges: a YAML anchor, a flow map, and the tag string on other lines.
  cp "$REAL" "$TMP/t-anchor.yml"
  printf '\n.t: &t [gauntlet-signing]\nother:\n  tags: *t\n' >>"$TMP/t-anchor.yml"
  run_cmd tags "$TMP/t-anchor.yml"
  expect_rc "tags: anchor holding the tag, used by tags: *t -> 1" 1
  out_has "tags: names the tag" "gauntlet-signing"

  awk '{ print } /^lint:go:/ { print "  tags: {a: [gauntlet-signing]}" }' "$REAL" >"$TMP/t-map.yml"
  run_cmd tags "$TMP/t-map.yml"
  expect_rc "tags: flow map holding the tag -> 1" 1
  out_has "tags: names the tag" "gauntlet-signing"

  awk '{ print } /^lint:go:/ { print "  extends: gauntlet-signing" }' "$REAL" >"$TMP/t-extends.yml"
  run_cmd tags "$TMP/t-extends.yml"
  expect_rc "tags: tag string in an extends: line -> 1" 1
  out_has "tags: names the tag" "gauntlet-signing"
  out_has_word "tags: names the line" "$((LINT_HDR + 1))"

  awk '{ print } /^lint:go:/ { print "  variables:"; print "    X: gauntlet-publish" }' "$REAL" >"$TMP/t-varval.yml"
  run_cmd tags "$TMP/t-varval.yml"
  expect_rc "tags: tag string as a variable value -> 1" 1
  out_has "tags: names the tag" "gauntlet-publish"

  # Comments are ignored.
  cp "$REAL" "$TMP/t-comment.yml"
  printf '# tags: [gauntlet-signing]\nlint:go-note:\n  # tags: [gauntlet-publish-gate]\n' >>"$TMP/t-comment.yml"
  # keep the file valid-looking: drop the extra job header again
  sed '/^lint:go-note:$/d' "$TMP/t-comment.yml" >"$TMP/t-comment2.yml"
  run_cmd tags "$TMP/t-comment2.yml"
  expect_rc "tags: tag only in comments passes" 0
fi

if [ "$FAILS" -gt 0 ]; then
  echo "config-check_test.sh: $FAILS case(s) failed"
  exit 1
fi
echo "config-check_test.sh: all cases passed"
