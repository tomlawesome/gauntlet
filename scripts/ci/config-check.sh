#!/bin/sh
# Checks the CI configuration against itself and against the job's
# environment (#121). POSIX sh and awk only: runs in the gitleaks Alpine
# image and on the host.
#
#   config-check.sh pins [FILE]
#     Each pinned agent-infra include `ref:` equals its job's SHA variable
#     (publish-gate: PUBLISH_GATE_SHA, private-details: PRIVATE_DETAILS_SHA),
#     and each is exactly 40 lowercase hex characters.
#   config-check.sh env JOB [FILE]
#     JOB's pinned inputs in the process environment equal the committed
#     values, the runner paths are the fixed ones, and the template's
#     undeclared inputs are unset or empty. A pipeline variable that
#     disagrees fails the job closed. JOB is publish-gate, private-details
#     or renovate. For renovate, any RENOVATE_ name the file does not set
#     fails except RENOVATE_DRY_RUN (extract, lookup or full) and
#     RENOVATE_SECURITY_ONLY (true), each of which may also be empty. That
#     is a tripwire for a mistaken owner variable, not the control. The
#     control is the project setting (Settings > CI/CD > Variables)
#     "Minimum role to use pipeline variables" = Owner (#138). No
#     script-level check can be the control, because the runner's own git
#     fetch and the image's BASH_ENV read the variables before this script
#     runs.
#   config-check.sh tags [FILE]
#     Each secret-holding runner tag appears on exactly one `tags:` line,
#     `  tags: [<tag>]` in its intended job, and no `tags:` line uses a
#     variable or !reference.
#
# FILE defaults to .gitlab-ci.yml. Output names variables, pairs, tags and
# line numbers only, never a value: a value may be a path, an address or a
# key. Exit 0 when every check holds, 1 when one fails, 2 on a usage error,
# an unreadable FILE or a configuration the check cannot read.
set -u

PROG=config-check
RULES_PATH=/etc/private-details/rules.toml
KEY_PATH=/etc/gauntlet-publish-gate/key

die2() { echo "$PROG: $*" >&2; exit 2; }

readable() {
  [ -f "$1" ] && [ -r "$1" ] || die2 "cannot read $1"
}

# job_vars JOB FILE: prints NAME=value for each entry of JOB's variables:
# block, with trailing comments and surrounding quotes removed.
job_vars() {
  awk -v job="$1" '
    /^[ \t]*#/ { next }
    /^[^ \t-]/ {
      k = $0; sub(/:( .*)?$/, "", k)
      injob = (k == job); inv = 0; next
    }
    injob && /^  variables:[ \t]*$/ { inv = 1; next }
    injob && inv && /^  [^ ]/ { inv = 0 }
    injob && inv && /^    [A-Za-z_][A-Za-z0-9_]*:/ {
      s = $0; sub(/^    /, "", s)
      k = s; sub(/:.*/, "", k)
      v = s; sub(/^[^:]*:[ \t]*/, "", v); sub(/[ \t]+#.*$/, "", v)
      sub(/[ \t]+$/, "", v)
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2)
      print k "=" v
    }' "$2"
}

# include_refs TEMPLATE FILE: prints the ref: of every include entry whose
# file: is TEMPLATE, one per line (an entry with no ref prints an empty line).
include_refs() {
  awk -v t="$1" '
    function done() { if (item && f == t) print r; item = 0; f = ""; r = "" }
    function kv(s,   k, v) {
      k = s; sub(/:.*/, "", k)
      v = s; sub(/^[^:]*:[ \t]*/, "", v); sub(/[ \t]+#.*$/, "", v)
      sub(/[ \t]+$/, "", v)
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2)
      if (k == "file") f = v
      if (k == "ref") r = v
    }
    /^[ \t]*#/ { next }
    /^[^ \t-]/ { done(); inc = ($0 ~ /^include:/); next }
    !inc { next }
    /^  - / { done(); item = 1; s = $0; sub(/^  - /, "", s); kv(s); next }
    item && /^    [a-z_]+:/ { s = $0; sub(/^    /, "", s); kv(s) }
    END { done() }' "$2"
}

is_sha() {
  [ "${#1}" -eq 40 ] || return 1
  case $1 in *[!0-9a-f]*) return 1 ;; esac
  return 0
}

# check_pair LABEL TEMPLATE JOB VAR FILE: sets PAIR_RC to 0, 1 or 2.
check_pair() {
  label="$1"; tmpl="$2"; job="$3"; var="$4"; file="$5"
  PAIR_RC=0
  refs="$(include_refs "$tmpl" "$file")"
  nref=0; ref=""
  if [ -n "$refs" ] || grep -q "file: *$tmpl" "$file"; then
    nref="$(printf '%s\n' "$refs" | wc -l | tr -d ' ')"
    ref="$refs"
  fi
  vals="$(job_vars "$job" "$file" | sed -n "s/^$var=//p")"
  nval=0
  [ -n "$vals" ] && nval="$(printf '%s\n' "$vals" | wc -l | tr -d ' ')"
  if [ "$nref" -ne 1 ]; then
    echo "$PROG: pins: $label: the include of its template appears $nref times, want 1" >&2
    PAIR_RC=2
  elif ! is_sha "$ref"; then
    echo "$PROG: pins: $label: the include ref is not 40 lowercase hex characters" >&2
    PAIR_RC=2
  fi
  if [ "$nval" -ne 1 ]; then
    echo "$PROG: pins: $label: $var appears $nval times in the job's variables, want 1" >&2
    PAIR_RC=2
  elif ! is_sha "$vals"; then
    echo "$PROG: pins: $label: $var is not 40 lowercase hex characters" >&2
    PAIR_RC=2
  fi
  if [ "$PAIR_RC" -eq 0 ] && [ "$ref" != "$vals" ]; then
    echo "$PROG: pins: $label: the include ref and $var differ; move them together" >&2
    PAIR_RC=1
  fi
}

do_pins() {
  file="${1:-.gitlab-ci.yml}"
  readable "$file"
  rc=0
  check_pair publish-gate scripts/publish-gate/ci-template.yml publish-gate PUBLISH_GATE_SHA "$file"
  [ "$PAIR_RC" -gt "$rc" ] && rc=$PAIR_RC
  check_pair private-details scripts/private-details/ci-template.yml private-details PRIVATE_DETAILS_SHA "$file"
  [ "$PAIR_RC" -gt "$rc" ] && rc=$PAIR_RC
  [ "$rc" -eq 0 ] && echo "$PROG: pins: ok"
  return "$rc"
}

# The value of the environment variable named $1 (a name from the fixed
# lists below, never input), and whether it is set.
env_val() { eval "ENV_VAL=\${$1-}"; eval "ENV_SET=\${$1+1}"; }

do_env() {
  job="${1:-}"; file="${2:-.gitlab-ci.yml}"
  case $job in
    publish-gate)
      from_file="PUBLISH_GATE_SHA PUBLISH_REMOTE PUBLISH_AUTHOR_NAME PUBLISH_AUTHOR_EMAIL"
      forbid="PRIVATE_DETAILS_SCAN GITLEAKS PUBLISH_REVIEWED_FILES PUBLISH_BRANCH PUBLISH_COMMIT" ;;
    private-details)
      from_file="PRIVATE_DETAILS_SHA PRIVATE_DETAILS_SINCE"
      forbid="PRIVATE_DETAILS_ALLOWLIST PRIVATE_DETAILS_ALLOWLIST_ONLY GITLEAKS" ;;
    renovate)
      from_file="RENOVATE_PLATFORM RENOVATE_AUTODISCOVER RENOVATE_ONBOARDING RENOVATE_REQUIRE_CONFIG LOG_LEVEL GOPROXY GOPRIVATE"
      forbid="RENOVATE_TOKEN GITHUB_COM_TOKEN HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY NODE_OPTIONS NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED RENOVATE_ADDITIONAL_CONFIG_FILE" ;;
    '') die2 "env: missing JOB (publish-gate, private-details or renovate)" ;;
    *) die2 "env: unknown JOB (want publish-gate, private-details or renovate)" ;;
  esac
  readable "$file"
  vars="$(job_vars "$job" "$file")"
  bad=""
  for name in $from_file; do
    n="$(printf '%s\n' "$vars" | grep -c "^$name=")"
    [ "$n" -eq 1 ] || die2 "env $job: $name appears $n times in the job's variables, want 1"
    want="$(printf '%s\n' "$vars" | sed -n "s/^$name=//p")"
    env_val "$name"
    if [ -z "$ENV_SET" ] || [ "$ENV_VAL" != "$want" ]; then bad="$bad $name"; fi
  done
  if [ "$job" = renovate ]; then
    env_val RENOVATE_DRY_RUN
    case $ENV_VAL in ''|extract|lookup|full) ;; *) bad="$bad RENOVATE_DRY_RUN" ;; esac
    env_val RENOVATE_SECURITY_ONLY
    case $ENV_VAL in ''|true) ;; *) bad="$bad RENOVATE_SECURITY_ONLY" ;; esac
    # Every other RENOVATE_ name is a setting a stray variable could add.
    # ENDPOINT, REPOSITORIES and CONFIG_FILE come from $CI_ values a
    # pipeline variable can override too, so comparing them proves nothing;
    # the project setting covers them. awk's ENVIRON gives names only, so a
    # value with a newline cannot fake one.
    known=" $from_file RENOVATE_ENDPOINT RENOVATE_REPOSITORIES RENOVATE_CONFIG_FILE $forbid RENOVATE_DRY_RUN RENOVATE_SECURITY_ONLY "
    for name in $(awk 'BEGIN { for (k in ENVIRON) if (k ~ /^RENOVATE_[A-Za-z0-9_]*$/) print k }'); do
      case $known in *" $name "*) ;; *) bad="$bad $name"; forbid="$forbid $name" ;; esac
    done
  else
    env_val PRIVATE_DETAILS_RULES
    if [ -z "$ENV_SET" ] || [ "$ENV_VAL" != "$RULES_PATH" ]; then bad="$bad PRIVATE_DETAILS_RULES"; fi
  fi
  if [ "$job" = publish-gate ]; then
    env_val PUBLISH_GATE_SSH_KEY
    if [ -z "$ENV_SET" ] || [ "$ENV_VAL" != "$KEY_PATH" ]; then bad="$bad PUBLISH_GATE_SSH_KEY"; fi
  fi
  for name in $forbid; do
    env_val "$name"
    [ -n "$ENV_VAL" ] && bad="$bad $name"
  done
  if [ -z "$bad" ]; then
    echo "$PROG: env $job: ok"
    return 0
  fi
  for name in $bad; do
    case $name in
      PUBLISH_GATE_SSH_KEY)
        echo "$PROG: env $job: $name is not the runner's key path: delete any CI/CD variable of that name, check the runner environment line (docs/releasing.md step 6)" >&2 ;;
      PRIVATE_DETAILS_RULES)
        echo "$PROG: env $job: $name is not the runner's mounted rules path" >&2 ;;
      RENOVATE_TOKEN|GITHUB_COM_TOKEN)
        echo "$PROG: env $job: $name arrives as a variable; delete that CI/CD variable (docs/releasing.md, Dependency updates, step 3)" >&2 ;;
      RENOVATE_DRY_RUN)
        echo "$PROG: env $job: $name is not extract, lookup, full or empty" >&2 ;;
      RENOVATE_SECURITY_ONLY)
        echo "$PROG: env $job: $name is not true or empty" >&2 ;;
      *)
        case " $forbid " in
          *" $name "*) echo "$PROG: env $job: $name is set; it must be unset or empty" >&2 ;;
          *) echo "$PROG: env $job: $name is unset or differs from the committed value" >&2 ;;
        esac ;;
    esac
  done
  echo "$PROG: env $job: a pipeline or CI/CD variable overrides a pinned input; refusing to run" >&2
  return 1
}

do_tags() {
  file="${1:-.gitlab-ci.yml}"
  readable "$file"
  awk -v prog="$PROG" '
    BEGIN {
      n = split("gauntlet-signing gauntlet-publish gauntlet-publish-gate gauntlet-renovate", tag, " ")
      want["gauntlet-signing"] = "blocklist:sign"
      want["gauntlet-publish"] = "blocklist:publish"
      want["gauntlet-publish-gate"] = "publish-gate"
      want["gauntlet-renovate"] = "renovate"
      for (i = 1; i <= n; i++) good[tag[i]] = 0
      bad = 0
    }
    function report(t, msg) {
      printf "%s: tags: line %d: %s%s\n", prog, NR, (t == "" ? "" : t ": "), msg > "/dev/stderr"
      bad = 1
    }
    function unquote(s) {
      gsub(/^[ \t]+|[ \t]+$/, "", s)
      if (s ~ /^".*"$/ || s ~ /^\047.*\047$/) s = substr(s, 2, length(s) - 2)
      return s
    }
    # check(t): t is one tag item from a tags: line at line NR.
    function check(t, exact) {
      if (!(t in want)) return
      if (exact && job == want[t]) { good[t]++; if (good[t] == 1) return
        report(t, "a second tags line in " want[t]); return }
      report(t, "may appear only as the line \"  tags: [" t "]\" in " want[t])
    }
    # scan(): every other occurrence of a tag as a whole word fails, so an
    # anchor, alias, map or other key cannot carry it. Allowed: a path
    # segment (/etc/<tag>) and double-quoted text on a list item (a script
    # line message); a tag reaches a job only through a tags: line.
    function scan(   s, i, t, p, rest, b, a) {
      s = $0
      if (s ~ /^[ \t]*- /) gsub(/"[^"]*"/, "\"\"", s)
      for (i = 1; i <= n; i++) {
        t = tag[i]; rest = s; p = 0
        while ((k = index(rest, t)) > 0) {
          b = (p + k > 1) ? substr(s, p + k - 1, 1) : ""
          a = substr(s, p + k + length(t), 1)
          if (b !~ /[A-Za-z0-9_\/-]/ && a !~ /[A-Za-z0-9_-]/) {
            report(t, "named outside its one \"  tags: [" t "]\" line in " want[t]); break
          }
          p += k; rest = substr(s, p + 1)
        }
      }
    }
    /^[ \t]*#/ { next }
    # Block-style items under a tags: key.
    inblock && $0 ~ /^[ \t]*- / && match($0, /^[ \t]*/) && RLENGTH > bind {
      s = $0; sub(/^[ \t]*- /, "", s); sub(/[ \t]+#.*$/, "", s)
      if (s ~ /\$|!reference/) report("", "tags item uses a variable or !reference")
      check(unquote(s), 0); next
    }
    { inblock = 0 }
    /^[^ \t-]/ { job = $0; sub(/:( .*)?$/, "", job) }
    /^[ \t]*tags:/ {
      match($0, /^[ \t]*/); ind = RLENGTH
      v = $0; sub(/^[ \t]*tags:[ \t]*/, "", v); sub(/[ \t]+#.*$/, "", v)
      if (v ~ /\$|!reference|\*|\{/) { report("", "tags line uses a variable, !reference, alias or map"); scan(); next }
      if (v == "") { inblock = 1; bind = ind; next }
      if (v ~ /^\[/ && v !~ /\]$/) { report("", "tags list not closed on its line"); next }
      exact = ($0 ~ /^  tags: \[[^],]*\]$/)
      if (v ~ /^\[/) { v = substr(v, 2, length(v) - 2) }
      m = split(v, item, ",")
      for (i = 1; i <= m; i++) check(unquote(item[i]), exact)
      next
    }
    { scan() }
    END {
      for (i = 1; i <= n; i++) if (good[tag[i]] != 1) {
        printf "%s: tags: %s: %s has %d \"  tags: [%s]\" lines, want 1\n", prog, tag[i], want[tag[i]], good[tag[i]], tag[i] > "/dev/stderr"
        bad = 1
      }
      if (!bad) print prog ": tags: ok"
      exit bad
    }' "$file"
}

mode="${1:-}"
[ $# -gt 0 ] && shift
case $mode in
  pins) [ $# -le 1 ] || die2 "usage: config-check.sh pins [FILE]"; do_pins "$@" ;;
  env) [ $# -ge 1 ] && [ $# -le 2 ] || die2 "usage: config-check.sh env JOB [FILE]"; do_env "$@" ;;
  tags) [ $# -le 1 ] || die2 "usage: config-check.sh tags [FILE]"; do_tags "$@" ;;
  *) die2 "usage: config-check.sh pins|env JOB|tags [FILE] (JOB: publish-gate, private-details or renovate)" ;;
esac
