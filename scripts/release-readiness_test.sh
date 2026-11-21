#!/usr/bin/env bash
set -euo pipefail

# Tests scripts/release-readiness.sh (gauntlet #122) against throwaway
# `git init` fixture repos. Offline; every fixture is under a mktemp dir that
# is removed on exit. Written from the issue and its design note alone.
#
# ---- The CLI contract under test ------------------------------------------
#
#   release-readiness.sh preview|main
#
#   The argument is the promotion leg: "preview" = dev -> preview,
#   "main" = preview -> main. No argument, or anything else: exit 2 with a
#   "usage" line on stderr.
#
#   The repository is the git work tree of the current directory (cwd). The
#   script runs its helpers from that repo's scripts/ directory:
#   scripts/release-version-check.sh (R2) and scripts/blocklist-age-check.sh
#   (R6), so a fixture can stub the latter. Tags are the local `v*` tags
#   (`git tag`), fed to release-version-check.sh in `git ls-remote --tags`
#   shape (<sha><TAB>refs/tags/v<X.Y.Z>); the MAIN_SHA argument is "-".
#
#   Refs, as env vars (no flags):
#     READINESS_SOURCE_REF  the branch being promoted. Default HEAD. Every
#                           file the checks read (VERSION, CHANGELOG.md,
#                           go.mod, docs/api/auth.yaml, docs/releasing.md,
#                           .gitlab-ci.yml, docs/releases/vX.Y.Z.md) is read
#                           from this ref with `git show`, not from the work
#                           tree. So on leg `main` the VERSION used is the
#                           source (preview) branch's.
#     READINESS_TARGET_REF  the branch promoted into. Default origin/<leg>.
#   R8's registry digest, no network in tests:
#     READINESS_IMAGE_DIGEST  the digest the registry currently serves for
#                           GOLANG_IMAGE's tag, e.g. sha256:<64 hex>. When
#                           unset the script looks it up itself (not tested).
#   The audit-issue check needs a GitLab token (GITLAB_TOKEN, a personal one,
#   used locally). With GITLAB_TOKEN unset, or in CI (CI_JOB_TOKEN set), the
#   script does not call the API and prints a line containing
#   "not checked here" that names the audit issue check.
#
#   Output (stdout and stderr together; tests read both):
#     "ok R<n>"                  a check passed
#     "FAIL R<n>: <what's wrong>" a check failed, followed on the next line by
#     "  do this: <hint>"        what to do about it (one per FAIL)
#     "WARN R8: <text>"          digest drift only; not a failure
#   Every check always runs. Exit 1 if any FAIL line was printed, else 0.
#
#   R1 record docs/releases/v<VERSION>.md, one `key: value` per line (other
#      lines, such as a title, are ignored):
#        version: <VERSION>
#        guide-blob: <git rev-parse SOURCE:docs/releasing.md>
#        guide-commit: <commit that last changed the guide>
#        step N: done: <ref> | step N: not-needed: <owner decision>
#                | step N: after-merge
#        Signed-off-by: Name          (name only, no email)
#      Steps are the top-level `N. ` numbered lines of docs/releasing.md
#      before its first `## ` heading; the record has exactly one line per
#      step, in order 1..N. A <ref>/<decision> that is empty, "TODO", or
#      still in angle brackets is placeholder text. Exactly one
#      Signed-off-by line, name only (an email fails R1). Its value must equal
#      the author name (%an) of the commit that last changed the record on the
#      source branch and the Signed-off-by trailer of that commit's message.
#   R8 compares the image's Go version (GOLANG_IMAGE in .gitlab-ci.yml, tag
#      before the @) with go.mod: the `toolchain goX.Y.Z` line if there is
#      one (exact), else the `go X.Y[.Z]` line's major.minor. A mismatch is a
#      FAIL; a digest differing from READINESS_IMAGE_DIGEST is only a WARN.
# ----------------------------------------------------------------------------

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/release-readiness.sh"
VERSION_CHECK="$ROOT/scripts/release-version-check.sh"

# Fixture repos must not pick up the host's global git config (commit hooks).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

DIGEST="sha256:$(printf 'a%.0s' $(seq 64))"
OTHER_DIGEST="sha256:$(printf 'b%.0s' $(seq 64))"
NAME="Agent Tester"
IDENT="$NAME <agent@example.invalid>"

pass=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; pass=$((pass + 1)); }

# ---- fixture ---------------------------------------------------------------
# build sets FX to the fixture dir. Knobs are F_* vars; defaults give a repo on
# which `release-readiness.sh preview` passes everything:
#   branch preview (target, tagged v0.1.0) and branch feature (HEAD, source)
#   carrying VERSION 0.2.0, the guide, and the signed record.
F_VERSION=0.2.0 F_API=0.2.0 F_CL=ok F_RETRACT='retract [v0.0.1, v0.0.5]'
F_GOMOD_TOOLCHAIN="" F_IMAGE=golang:1.27.4@$DIGEST F_BLOCK=ok F_DIVERGE=0
F_TAGS="v0.1.0" F_REC=ok F_STEPS="" F_SOB="$NAME" F_TRAILER="$NAME" F_SOB2=""
F_AUTHOR="$IDENT" F_STALE_GUIDE=0 F_REC_VERSION="" F_GUIDE_STEPS=3
F_GC="" F_GUIDE_NUMS="" F_REAL_GUIDE=0 F_NO_GUIDE=0 F_CI_MODE=""
n=0

reset_knobs() {
  F_VERSION=0.2.0 F_API=0.2.0 F_CL=ok F_RETRACT='retract [v0.0.1, v0.0.5]'
  F_GOMOD_TOOLCHAIN="" F_IMAGE=golang:1.27.4@$DIGEST F_BLOCK=ok F_DIVERGE=0
  F_TAGS="v0.1.0" F_REC=ok F_STEPS="" F_SOB="$NAME" F_TRAILER="$NAME" F_SOB2=""
  F_AUTHOR="$IDENT" F_STALE_GUIDE=0 F_REC_VERSION="" F_GUIDE_STEPS=3
  F_GC="" F_GUIDE_NUMS="" F_REAL_GUIDE=0 F_NO_GUIDE=0 F_CI_MODE=""
}

write_guide() {
  if [ "$F_REAL_GUIDE" = 1 ]; then cp "$ROOT/docs/releasing.md" docs/releasing.md; return; fi
  local nums="${F_GUIDE_NUMS:-$(seq "$F_GUIDE_STEPS" | tr "\n" " ")}"
  {
    echo "# Releasing"; echo; echo "Intro text."; echo
    local i
    for i in $nums; do
      echo "$i. Do thing $i."; echo "   More about thing $i."; echo
    done
    echo "## Elsewhere"; echo
    echo "1. A numbered list in a later section."
    echo "2. It is not a guide step."
  } > docs/releasing.md
}

write_changelog() {
  local v="$F_VERSION"
  case "$F_CL" in
    ok) printf '# Changelog\n\n## [Unreleased]\n\n## [%s] - 2026-11-18\n\n### Added\n\n- A thing (#1).\n\n## [0.1.0] - 2026-10-01\n\n- First.\n' "$v" ;;
    nosection) printf '# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-10-01\n\n- First.\n' ;;
    nodate) printf '# Changelog\n\n## [Unreleased]\n\n## [%s]\n\n### Added\n\n- A thing (#1).\n\n## [0.1.0] - 2026-10-01\n\n- First.\n' "$v" ;;
    noentries) printf '# Changelog\n\n## [Unreleased]\n\n## [%s] - 2026-11-18\n\n## [0.1.0] - 2026-10-01\n\n- First.\n' "$v" ;;
    unreleased) printf '# Changelog\n\n## [Unreleased]\n\n### Added\n\n- Pending (#2).\n\n## [%s] - 2026-11-18\n\n- A thing (#1).\n\n## [0.1.0] - 2026-10-01\n\n- First.\n' "$v" ;;
  esac > CHANGELOG.md
}

write_record() {
  mkdir -p docs/releases
  local blob commit rv="${F_REC_VERSION:-$F_VERSION}" steps
  blob="$(git rev-parse HEAD:docs/releasing.md 2>/dev/null || true)"
  commit="$(git log -1 --format=%H -- docs/releasing.md)"
  steps="$F_STEPS"
  [ "$steps" != none ] || steps=""
  [ "$F_STEPS" = none ] || :
  if [ -z "$steps" ] && [ "$F_STEPS" != none ]; then
    steps="step 1: done: issue #9 closed
step 2: not-needed: owner decision 2026-11-18
step 3: after-merge"
  fi
  {
    echo "# Release v$F_VERSION"; echo
    echo "version: $rv"
    echo "guide-blob: $blob"
    case "$F_GC" in
      "") echo "guide-commit: $commit" ;;
      missing) ;;
      *) echo "guide-commit: $F_GC" ;;
    esac
    printf '%s\n' "$steps"
    [ "$F_SOB" = none ] || echo "Signed-off-by: $F_SOB"
    [ -z "$F_SOB2" ] || echo "Signed-off-by: $F_SOB2"
  } > "docs/releases/v$F_VERSION.md"
}

build() {
  n=$((n + 1))
  local d
  d="$(mktemp -d "$TMP/fx.XXXXXX")"
  mkdir -p "$d/scripts" "$d/docs/api"
  cd "$d"
  git init -q -b preview
  git config user.name "Fixture"; git config user.email "fixture@example.invalid"
  git config commit.gpgsign false
  ln -s "$VERSION_CHECK" scripts/release-version-check.sh
  printf '#!/bin/sh\n[ "%s" = ok ]\n' "$F_BLOCK" > scripts/blocklist-age-check.sh
  chmod +x scripts/blocklist-age-check.sh
  echo "/scripts/" >> .git/info/exclude  # helpers are work-tree only
  # Base state, as on the target branch.
  echo 0.1.0 > VERSION
  printf 'openapi: 3.0.3\ninfo:\n  title: Auth\n  version: 0.1.0\n' > docs/api/auth.yaml
  F_VERSION=0.1.0 F_CL=ok write_changelog
  { echo "module example.invalid/auth"; echo; echo "go 1.27.0"
    [ -z "$F_GOMOD_TOOLCHAIN" ] || echo "toolchain $F_GOMOD_TOOLCHAIN"
    echo "$F_RETRACT"; } > go.mod
  case "$F_CI_MODE" in
    joblevel-first) printf 'build:\n  variables:\n    GOLANG_IMAGE: golang:1.99.0\n\nvariables:\n  GOLANG_IMAGE: %s\n' "$F_IMAGE" > .gitlab-ci.yml ;;
    joblevel-only) printf 'build:\n  variables:\n    GOLANG_IMAGE: %s\n' "$F_IMAGE" > .gitlab-ci.yml ;;
    *) printf 'variables:\n  GOLANG_IMAGE: %s\n' "$F_IMAGE" > .gitlab-ci.yml ;;
  esac
  write_guide
  git add -A; git commit -qm "base"
  local t
  for t in $F_TAGS; do git tag "$t"; done
  # Source branch: the release prep.
  git checkout -q -b feature
  echo "$F_VERSION" > VERSION
  printf 'openapi: 3.0.3\ninfo:\n  title: Auth\n  version: %s\n' "$F_API" > docs/api/auth.yaml
  write_changelog
  git add -A; git commit -qm "prepare release"
  if [ "$F_NO_GUIDE" = 1 ]; then git rm -q docs/releasing.md; git commit -qm "drop the guide"; fi
  if [ "$F_REC" != missing ]; then
    write_record
    git add -A
    if [ "$F_TRAILER" = none ]; then
      GIT_AUTHOR_NAME="${F_AUTHOR%% <*}" GIT_AUTHOR_EMAIL="$(echo "$F_AUTHOR" | sed 's/.*<\(.*\)>/\1/')" \
        git commit -qm "docs: release record"
    else
      GIT_AUTHOR_NAME="${F_AUTHOR%% <*}" GIT_AUTHOR_EMAIL="$(echo "$F_AUTHOR" | sed 's/.*<\(.*\)>/\1/')" \
        git commit -qm "docs: release record" --trailer "Signed-off-by: $F_TRAILER"
    fi
  fi
  if [ "$F_STALE_GUIDE" = 1 ]; then
    # Change the guide's bytes without touching its steps, so only the
    # guide-blob comparison can notice.
    echo "A note added after the record was written." >> docs/releasing.md
    git commit -qam "docs: change the guide"
  fi
  if [ "$F_DIVERGE" = 1 ]; then
    git checkout -q preview
    echo x > target-only.txt; git add -A; git commit -qm "target moved on"
    git checkout -q feature
  fi
  cd "$TMP"
  FX="$d"
}

# run LEG [VAR=value ...] -- runs the script in the fixture dir $FX; output
# to $TMP/out (both streams), exit code to $RC.
RC=0
run() {
  local leg="$1"; shift
  RC=0
  ( cd "${FX:?}" && env -u GITLAB_TOKEN -u CI_JOB_TOKEN \
      READINESS_TARGET_REF=preview READINESS_IMAGE_DIGEST="$DIGEST" "$@" \
      "$SCRIPT" "$leg" ) >"$TMP/out" 2>&1 || RC=$?
}

failed_set() { { grep -oE '^FAIL R[0-9]+' "$TMP/out" || true; } | sed 's/FAIL //' | sort | tr '\n' ' ' | sed 's/ $//'; }

# expect_only DESC "R1 R3" -- exit 1 with exactly those checks failed, each
# followed by a hint; "" means a clean pass (exit 0, no FAIL).
expect_only() {
  local desc="$1" want="$2" got
  got="$(failed_set)"
  if [ "$got" != "$want" ]; then
    echo "--- output:" >&2; cat "$TMP/out" >&2
    fail "$desc -- failed checks '$got', want '$want'"
  fi
  if [ -z "$want" ]; then
    [ "$RC" -eq 0 ] || { cat "$TMP/out" >&2; fail "$desc -- exit $RC, want 0"; }
  else
    [ "$RC" -eq 1 ] || { cat "$TMP/out" >&2; fail "$desc -- exit $RC, want 1"; }
    local nf nh
    nf="$(grep -cE '^FAIL R[0-9]+' "$TMP/out")"
    nh="$(grep -cE '^ +do this: .+' "$TMP/out")"
    [ "$nf" -eq "$nh" ] || { cat "$TMP/out" >&2; fail "$desc -- $nf FAIL lines but $nh 'do this' hints"; }
  fi
  ok "$desc"
}

# case DESC LEG "R.." -- builds a fixture from the current knobs, runs, checks.
case_() {
  build; run "$2"
  expect_only "$1" "$3"
  reset_knobs
}

# ---- cases -------------------------------------------------------------------

# Contract basics.
build
run preview
expect_only "good fixture passes every check on leg preview" ""
for r in R1 R2 R3 R4 R5 R6 R7 R8; do
  grep -qE "^ok $r\b" "$TMP/out" || { cat "$TMP/out" >&2; fail "good run does not report 'ok $r'"; }
done
ok "good run reports ok for R1..R8"
run main
expect_only "good fixture passes on leg main" ""
RC=0; ( cd "${FX:?}" && "$SCRIPT" ) >"$TMP/out" 2>&1 || RC=$?
[ "$RC" -eq 2 ] && grep -qi usage "$TMP/out" || fail "no argument: want exit 2 and a usage line, got $RC"
RC=0; ( cd "${FX:?}" && "$SCRIPT" dev ) >"$TMP/out" 2>&1 || RC=$?
[ "$RC" -eq 2 ] && grep -qi usage "$TMP/out" || fail "unknown leg: want exit 2 and a usage line, got $RC"
ok "bad or missing leg exits 2 with usage"

# R1 -- the release record.
F_REC=missing case_ "R1 fails when the record file is missing" preview "R1"
F_REC_VERSION=0.9.9 case_ "R1 fails when the record names another version" preview "R1"
F_STALE_GUIDE=1 case_ "R1 fails when guide-blob is stale (guide changed after the record)" preview "R1"
F_STEPS="step 1: done: issue #9 closed
step 3: after-merge" case_ "R1 fails when a step line is missing" preview "R1"
F_STEPS="step 1: done: issue #9 closed
step 2: not-needed: owner decision 2026-11-18
step 3: after-merge
step 4: after-merge" case_ "R1 fails on an extra step line" preview "R1"
F_STEPS="step 2: not-needed: owner decision 2026-11-18
step 1: done: issue #9 closed
step 3: after-merge" case_ "R1 fails when step lines are out of order" preview "R1"
F_GUIDE_STEPS=4 case_ "R1 fails when the guide has more steps than the record" preview "R1"
F_STEPS="step 1: done: TODO
step 2: not-needed: owner decision 2026-11-18
step 3: after-merge" case_ "R1 fails on placeholder evidence (TODO)" preview "R1"
F_STEPS="step 1: done: TODO
step 2: not-needed: <decision>
step 3: after-merge" case_ "R1 placeholder refusal reads as clean English (no doubled substitution)" preview "R1"
grep -qE '^FAIL R1: .*step 1: done has no real evidence(;|$)' "$TMP/out" || { cat "$TMP/out" >&2; fail "R1 done-placeholder message is not 'step 1: done has no real evidence'"; }
grep -qE '^FAIL R1: .*step 2: not-needed has no real owner decision(;|$)' "$TMP/out" || { cat "$TMP/out" >&2; fail "R1 not-needed-placeholder message is not 'step 2: not-needed has no real owner decision'"; }
ok "R1 placeholder message is clean: 'done has no real evidence', 'not-needed has no real owner decision'"
F_STEPS="step 1: done: <ref>
step 2: not-needed: owner decision 2026-11-18
step 3: after-merge" case_ "R1 fails on placeholder evidence (<ref>)" preview "R1"
F_STEPS="step 1: done:
step 2: not-needed: owner decision 2026-11-18
step 3: after-merge" case_ "R1 fails on empty evidence" preview "R1"
F_STEPS="step 1: done: issue #9 closed
step 2: not-needed:
step 3: after-merge" case_ "R1 fails on a not-needed with no owner decision" preview "R1"
F_STEPS="step 1: maybe
step 2: not-needed: owner decision 2026-11-18
step 3: after-merge" case_ "R1 fails on an unknown step status" preview "R1"
F_SOB="Someone Else" F_TRAILER="Someone Else" \
  case_ "R1 fails when Signed-off-by is not the commit author" preview "R1"
F_TRAILER="Someone Else" case_ "R1 fails when Signed-off-by differs from the commit trailer" preview "R1"
F_SOB=none case_ "R1 fails when there is no Signed-off-by line" preview "R1"
F_SOB="$IDENT" case_ "R1 fails when the Signed-off-by line carries an email (correct name plus email)" preview "R1"
F_SOB="$IDENT" F_TRAILER="$IDENT" case_ "R1 fails on a name-plus-email line even with a matching email trailer" preview "R1"
F_SOB="Someone Else <someone@example.invalid>" F_TRAILER="Someone Else <someone@example.invalid>" \
  case_ "R1 fails on a Signed-off-by email even when the name is not the author's" preview "R1"
grep -qE '^FAIL R1:.*carries an email' "$TMP/out" || { cat "$TMP/out" >&2; fail "email-only R1 refusal does not mention the email"; }
ok "R1 email refusal message mentions the email (name differs from author)"
F_SOB2="$NAME" case_ "R1 fails on more than one Signed-off-by line" preview "R1"
F_TRAILER=none case_ "R1 fails when the commit has no Signed-off-by trailer" preview "R1"

# expect_fails DESC "R2" -- the named checks failed (others may too).
expect_fails() {
  local desc="$1" want="$2" r
  [ "$RC" -eq 1 ] || { cat "$TMP/out" >&2; fail "$desc -- exit $RC, want 1"; }
  for r in $want; do
    grep -qE "^FAIL $r\b" "$TMP/out" || { cat "$TMP/out" >&2; fail "$desc -- no FAIL $r"; }
  done
  ok "$desc"
}

# R2 -- VERSION is strict semver, above every tag, not yet tagged.
F_VERSION=0.2 F_API=0.2 build; run preview; reset_knobs
expect_fails "R2 fails on a non-semver VERSION" "R2"
F_VERSION=0.0.9 F_API=0.0.9 case_ "R2 fails when VERSION is below an existing tag" preview "R2"
F_TAGS="v0.1.0 v0.2.0" case_ "R2 fails when VERSION is already tagged" preview "R2"
F_TAGS="v0.1.0 v0.3.0" case_ "R2 fails when a higher tag exists" preview "R2"

# R3 -- API spec version.
F_API=0.1.0 case_ "R3 fails when docs/api/auth.yaml info.version differs from VERSION" preview "R3"

# R4 -- changelog.
F_CL=nosection case_ "R4 fails with no [VERSION] section" preview "R4"
F_CL=nodate case_ "R4 fails when the [VERSION] section has no date" preview "R4"
F_CL=noentries case_ "R4 fails when the [VERSION] section is empty" preview "R4"
F_CL=unreleased case_ "R4 fails when [Unreleased] still has entries" preview "R4"

# R5 -- retract.
F_RETRACT="retract [v0.1.0, v0.2.5]" case_ "R5 fails when a retract range covers VERSION" preview "R5"
F_RETRACT="retract v0.2.0" case_ "R5 fails when a single retract names VERSION" preview "R5"

# R6 -- blocklist age.
F_BLOCK=fail case_ "R6 fails when blocklist-age-check.sh fails" preview "R6"

# R7 -- target must be an ancestor of source.
F_DIVERGE=1 case_ "R7 fails when the target has moved on (back-merge first)" preview "R7"
grep -qi 'back-merge' "$TMP/out" || fail "R7 hint does not say back-merge"
ok "R7 hint says back-merge"

# R8 -- image Go version vs go.mod; digest drift only warns.
F_IMAGE="golang:1.28.0@$DIGEST" case_ "R8 fails when the image minor differs from go.mod's go line" preview "R8"
F_GOMOD_TOOLCHAIN=go1.27.3 case_ "R8 fails when the image differs from go.mod's toolchain line" preview "R8"
F_GOMOD_TOOLCHAIN=go1.27.4 case_ "R8 passes when the image equals go.mod's toolchain line" preview ""
build; run preview READINESS_IMAGE_DIGEST="$OTHER_DIGEST"; reset_knobs
expect_only "R8 digest drift alone is not a failure (exit 0)" ""
grep -qE '^WARN R8' "$TMP/out" || { cat "$TMP/out" >&2; fail "digest drift prints no 'WARN R8' line"; }
ok "R8 digest drift prints a WARN line"
F_IMAGE="golang:1.28.0@$DIGEST" build; run preview READINESS_IMAGE_DIGEST="$OTHER_DIGEST"; reset_knobs
expect_only "R8 version mismatch still fails alongside drift" "R8"

# All failures in one run.
F_API=0.1.0 F_CL=nodate F_RETRACT="retract v0.2.0" F_BLOCK=fail F_DIVERGE=1 F_REC=missing \
  F_IMAGE="golang:1.28.0@$DIGEST" case_ "every failing check is listed in one run" preview "R1 R3 R4 R5 R6 R7 R8"

# Audit issue: not checkable without a personal token.
build; run preview; reset_knobs
grep -qi 'audit' "$TMP/out" && grep -q 'not checked here' "$TMP/out" \
  || { cat "$TMP/out" >&2; fail "token-less run does not print 'not checked here' for the audit issue"; }
ok "token-less run says the audit issue is 'not checked here'"
[ "$RC" -eq 0 ] || fail "an unchecked audit issue must not fail the run"
build; run preview CI_JOB_TOKEN=job-token-placeholder; reset_knobs
grep -q 'not checked here' "$TMP/out" && [ "$RC" -eq 0 ] \
  || { cat "$TMP/out" >&2; fail "CI run (job token) does not say 'not checked here' and pass"; }
ok "CI run says the audit issue is 'not checked here'"

# Leg main reads the source (preview) branch's files, not the work tree's: the
# work tree differs in every file a check reads, so any one read from HEAD
# fails (go.mod: R8's go line and R5's retract both differ, #131).
build
( cd "${FX:?}" && git checkout -q -b other && echo 9.9.9 > VERSION \
  && printf '# Changelog\n\n## [Unreleased]\n' > CHANGELOG.md \
  && printf 'openapi: 3.0.3\ninfo:\n  title: Auth\n  version: 9.9.9\n' > docs/api/auth.yaml \
  && printf 'module example.invalid/auth\n\ngo 1.99.0\nretract v0.2.0\n' > go.mod \
  && printf 'variables:\n  GOLANG_IMAGE: golang:1.99.0\n' > .gitlab-ci.yml \
  && git rm -q -r docs/releases docs/releasing.md \
  && git commit -qam "work tree differs in every file the checks read" )
run main READINESS_SOURCE_REF=feature
expect_only "leg main uses VERSION from the source ref, not the work tree" ""
run preview READINESS_SOURCE_REF=feature
expect_only "leg preview uses VERSION from the source ref too" ""
reset_knobs

# ---- review findings (#122): each case runs in its own subshell so one
# failure does not hide the others; the run exits 1 if any failed -----------
soft_fail=0
soft_pass=0
soft() { # soft NAME FUNC
  if ( "$2" ); then soft_pass=$((soft_pass + 1)); else soft_fail=$((soft_fail + 1)); echo "NEW CASE FAILED: $1" >&2; fi
}
need_out() { # need_out DESC REGEX
  grep -qE "$2" "$TMP/out" || { cat "$TMP/out" >&2; fail "$1 -- output lacks /$2/"; }
}
no_out() { # no_out DESC REGEX
  ! grep -qE "$2" "$TMP/out" || { cat "$TMP/out" >&2; fail "$1 -- output has /$2/"; }
}

# 1. The source ref is the branch, not a merge commit of the target into it.
t_src_branch_vs_merge() {
  F_DIVERGE=1 build
  ( cd "${FX:?}" && git checkout -q -b mr preview && git merge -q --no-edit feature )
  local branch merge
  branch="$(git -C "${FX:?}" rev-parse feature)"; merge="$(git -C "${FX:?}" rev-parse mr)"
  run preview READINESS_SOURCE_REF="$branch"
  expect_only "R7 fails when the branch sha lacks the target's tip" "R7"
  run preview READINESS_SOURCE_REF="$merge"
  expect_only "R7 passes against the merge commit (why CI must not use it)" ""
}
soft "R7 against the branch sha, not the merge commit" t_src_branch_vs_merge

# 2. guide-commit is informational; the field is still required.
t_gc_differs() { F_GC=0000000000000000000000000000000000000000 case_ "R1 passes when guide-commit differs from the real commit" preview ""; }
soft "guide-commit differing passes" t_gc_differs
t_gc_missing() { F_GC=missing case_ "R1 fails when the guide-commit line is missing" preview "R1"; }
soft "guide-commit missing fails" t_gc_missing

# 3. Guide step numbers run 1..N in order.
t_guide_gap() {
  F_GUIDE_NUMS="1 2 4" build; run preview
  expect_only "R1 fails when the guide's steps run 1,2,4" "R1"
  need_out "guide numbering hint" '^FAIL R1:.*guide.*(number|consecutive|1\.\.N|order)'
}
soft "guide steps 1,2,4" t_guide_gap
t_real_guide() {
  local g="$ROOT/docs/releasing.md" cnt nums want steps="" i
  nums="$(awk '/^## /{exit} /^[0-9]+\. /{sub(/\..*/, ""); print}' "$g" | tr '\n' ' ')"
  cnt="$(printf '%s' "$nums" | wc -w)"
  want="$(seq "$cnt" | tr '\n' ' ')"
  [ "$cnt" -ge 1 ] && [ "$nums" = "$want" ] || fail "the real docs/releasing.md steps are '$nums', not 1..N"
  for i in $(seq "$cnt"); do steps="$steps${steps:+
}step $i: after-merge"; done
  F_REAL_GUIDE=1 F_STEPS="$steps" case_ "R1 passes with $cnt step lines against the real docs/releasing.md" preview ""
}
soft "real guide step count" t_real_guide

# 4. No docs/releasing.md on the source: R1 fails, never an empty-blob pass.
t_no_guide() { F_NO_GUIDE=1 F_STEPS=none case_ "R1 fails when docs/releasing.md is missing on the source" preview "R1"; }
soft "missing guide" t_no_guide

# 5. An unresolvable source ref still ends in a FAIL list.
t_bad_ref() {
  build; run preview READINESS_SOURCE_REF=nonexistent
  [ "$RC" -eq 1 ] || { cat "$TMP/out" >&2; fail "bad ref: exit $RC, want 1"; }
  need_out "bad ref" '^FAIL.*nonexistent'
  need_out "bad ref hint" '^ +do this: .+'
  ok "unresolvable source ref prints a FAIL naming it and exits 1"
}
soft "bad source ref" t_bad_ref

# 6. More placeholders; an empty Signed-off-by.
t_ph() {
  local ph
  for ph in TBD tbd n/a N/A; do
    F_STEPS="step 1: done: $ph
step 2: not-needed: owner decision 2026-11-18
step 3: after-merge" case_ "R1 fails on placeholder evidence ($ph)" preview "R1"
  done
}
soft "placeholders" t_ph
t_empty_sob() { F_SOB="" F_TRAILER="" case_ "R1 fails on an empty Signed-off-by value" preview "R1"; }
soft "empty Signed-off-by" t_empty_sob

# 7. The audit check, with a stub glab and a personal token.
mkstub() { # mkstub NAME BODY
  mkdir -p "$TMP/stub/$1"; printf '#!/bin/sh\n%s\n' "$2" > "$TMP/stub/$1/glab"; chmod +x "$TMP/stub/$1/glab"
}
mkstub err 'echo "glab: 401 Unauthorized" >&2; exit 1'
mkstub open 'echo "[{\"iid\":7,\"state\":\"opened\",\"labels\":[\"security\"]}]"'
mkstub closed_v 'case "$*" in *milestone=v0.2.0*) echo "[{\"iid\":7,\"state\":\"closed\",\"labels\":[\"security\"]}]" ;; *) echo "[]" ;; esac'
mkstub closed_bare 'case "$*" in *milestone=0.2.0*) echo "[{\"iid\":7,\"state\":\"closed\",\"labels\":[\"security\"]}]" ;; *) echo "[]" ;; esac'
audit_run() { build; run preview GITLAB_TOKEN=token-placeholder PATH="$TMP/stub/$1:$PATH"; }
t_audit_err() {
  audit_run err
  [ "$RC" -eq 1 ] || { cat "$TMP/out" >&2; fail "glab error: exit $RC, want 1"; }
  need_out "glab error" '^FAIL audit: could not query GitLab'
  ok "a glab error prints 'FAIL audit: could not query GitLab'"
}
soft "audit glab error" t_audit_err
t_audit_open() {
  audit_run open
  [ "$RC" -eq 1 ] || { cat "$TMP/out" >&2; fail "open issue: exit $RC, want 1"; }
  need_out "open issue" '^FAIL audit'
  no_out "open issue" 'could not query'
  ok "an open security issue fails the audit check (not a query error)"
}
soft "audit open issue" t_audit_open
t_audit_closed() {
  audit_run closed_v
  expect_only "a closed security issue in milestone v0.2.0 passes" ""
  need_out "closed issue" '^ok audit'
}
soft "audit closed issue" t_audit_closed
t_audit_bare() {
  audit_run closed_bare
  [ "$RC" -eq 1 ] || { cat "$TMP/out" >&2; fail "bare milestone: exit $RC, want 1"; }
  need_out "bare milestone" '^FAIL audit'
  ok "a closed issue only in milestone '0.2.0' (no v) does not count"
}
soft "audit milestone v only" t_audit_bare

# 8. R8 reads GOLANG_IMAGE from the top-level variables: block only.
t_r8_joblevel_first() { F_CI_MODE=joblevel-first case_ "R8 ignores an earlier job-level GOLANG_IMAGE" preview ""; }
soft "R8 job-level override ignored" t_r8_joblevel_first
t_r8_joblevel_only() { F_CI_MODE=joblevel-only case_ "R8 fails when GOLANG_IMAGE is only set at job level" preview "R8"; }
soft "R8 job-level only fails" t_r8_joblevel_only

echo "review-finding cases: $soft_pass passed, $soft_fail failed"
[ "$soft_fail" -eq 0 ] || exit 1

echo "release-readiness_test.sh: $pass checks passed"
