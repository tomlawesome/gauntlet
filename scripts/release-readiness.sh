#!/usr/bin/env bash
set -euo pipefail

# The release-readiness check (#122): everything the repository and the
# registry can show before a promotion is opened, run in one pass. Every
# check runs, whatever the others say; the run ends with the full list, and
# each failure says what to do. The release_readiness CI job runs it first on
# every merge request into preview or main; run it the same way locally
# before opening one (docs/releasing.md, "Before a promotion").
#
# Usage: scripts/release-readiness.sh preview|main
#   preview  the leg dev -> preview
#   main     the leg preview -> main
#
# Run it inside the git work tree to check. Environment (no flags):
#   READINESS_SOURCE_REF    branch being promoted (default HEAD). Every file
#                           a check reads comes from this ref, not the work
#                           tree; the exception is the blocklist, which
#                           blocklist-age-check.sh reads from the work tree.
#   READINESS_TARGET_REF    branch promoted into (default origin/<leg>)
#   READINESS_IMAGE_DIGEST  the digest the registry serves for GOLANG_IMAGE's
#                           tag (sha256:<hex>). Unset: looked up with
#                           `docker buildx imagetools inspect` when docker is
#                           there, else not checked.
#   READINESS_PROJECT       GitLab project of the audit issue (ai/gauntlet)
#
# Output, one line per check: "ok R<n>", "FAIL R<n>: <what>" followed by
# "  do this: <hint>", or "WARN R8: <text>" (digest drift only). Exit 0 when
# nothing failed, 1 when a check failed, 2 on a usage error.
#
#   R1 the release record docs/releases/v<VERSION>.md is valid and signed
#   R2 VERSION is semver, above every tag, not yet tagged
#   R3 docs/api/auth.yaml info.version equals VERSION
#   R4 CHANGELOG has a dated [VERSION] section with entries, empty [Unreleased]
#   R5 no go.mod retract covers VERSION
#   R6 the embedded blocklist is fresh (scripts/blocklist-age-check.sh)
#   R7 the target is an ancestor of the source
#   R8 GOLANG_IMAGE's Go version equals go.mod's
# The audit issue (docs/releasing.md step 1) is checked only locally, with a
# personal GITLAB_TOKEN: the CI job token cannot read issues.

leg="${1:-}"
if [ "$#" -ne 1 ] || { [ "$leg" != preview ] && [ "$leg" != main ]; }; then
  echo "usage: release-readiness.sh preview|main" >&2
  exit 2
fi

root="$(git rev-parse --show-toplevel)"
cd "$root"
SRC="${READINESS_SOURCE_REF:-HEAD}"
TGT="${READINESS_TARGET_REF:-origin/$leg}"
nfail=0

ok() { echo "ok $1"; }
fail() { # fail Rn "what" "hint"
  echo "FAIL $1: $2"
  echo "  do this: $3"
  nfail=$((nfail + 1))
}
show() { git show "$SRC:$1" 2>/dev/null; }

# An unresolvable source ref cannot be checked at all: say so and stop, with
# the one FAIL, rather than letting every check trip over it.
if ! git rev-parse -q --verify "$SRC^{commit}" >/dev/null 2>&1; then
  fail READINESS "source ref '$SRC' does not resolve to a commit here" "give READINESS_SOURCE_REF a branch or sha that exists in this checkout (git fetch origin first), or run from the source branch"
  echo "$nfail check(s) failed"
  exit 1
fi

VERSION="$(show VERSION 2>/dev/null | tr -d '[:space:]' || true)"

# ver_le A B: A <= B in version order (a leading v is ignored).
ver_le() {
  local a="${1#v}" b="${2#v}"
  [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" = "$a" ]
}

# --- R1 the release record ----------------------------------------------
check_r1() {
  local rec="docs/releases/v$VERSION.md" text guide="" hint problems=()
  hint="write $rec from the template in docs/releasing.md (\"Before a promotion\"), commit it with git commit --trailer \"Signed-off-by: <Name>\", and rerun"
  if ! text="$(show "$rec")"; then
    fail R1 "no release record $rec on $SRC" "$hint"
    return
  fi
  local v blob gc nsteps=0 nums want
  v="$(printf '%s\n' "$text" | sed -n 's/^version:[[:space:]]*//p' | head -1)"
  [ "$v" = "$VERSION" ] || problems+=("version: is '$v', want '$VERSION'")
  blob="$(git rev-parse "$SRC:docs/releasing.md" 2>/dev/null || true)"
  # guide-commit is informational: required, not compared.
  gc="$(printf '%s\n' "$text" | sed -n 's/^guide-commit:[[:space:]]*//p' | head -1)"
  [ -n "$gc" ] || problems+=("no guide-commit: line")
  if [ -z "$blob" ] || ! guide="$(show docs/releasing.md)"; then
    problems+=("no docs/releasing.md on $SRC")
  else
    [ "$(printf '%s\n' "$text" | sed -n 's/^guide-blob:[[:space:]]*//p' | head -1)" = "$blob" ] \
      || problems+=("guide-blob is not the current docs/releasing.md ($blob): the guide changed, read it again")
    # The guide's steps: top-level "N. " lines before its first "## " heading,
    # numbered 1..N in order.
    nums="$(printf '%s\n' "$guide" | awk '/^## /{exit} /^[0-9]+\. /{sub(/\..*/, ""); print}' | tr '\n' ' ')"
    nsteps="$(printf '%s' "$nums" | wc -w)"
    want="$(seq "$nsteps" | tr '\n' ' ')"
    [ "$nums" = "$want" ] || problems+=("the guide's step numbers are '${nums% }', not consecutive 1..N in order: fix docs/releasing.md")
  fi
  local -a lines=()
  mapfile -t lines < <(printf '%s\n' "$text" | grep -E '^step ' || true)
  if [ "${#lines[@]}" -ne "$nsteps" ]; then
    problems+=("${#lines[@]} step lines, the guide has $nsteps steps")
  fi
  local i=0 l re='^step ([0-9]+): ([a-z-]+):?[[:space:]]*(.*)$'
  for l in "${lines[@]}"; do
    i=$((i + 1))
    if ! [[ "$l" =~ $re ]]; then problems+=("malformed step line '$l'"); continue; fi
    local num="${BASH_REMATCH[1]}" st="${BASH_REMATCH[2]}" rest="${BASH_REMATCH[3]}"
    [ "$num" -eq "$i" ] || problems+=("step line $i is for step $num (lines must be in order 1..N)")
    case "$st" in
      done | not-needed)
        if [ -z "$rest" ] || [[ "${rest^^}" == TODO* || "${rest^^}" == TBD* || "${rest^^}" == N/A* ]] || [[ "$rest" =~ \<[^\>]+\> ]]; then
          problems+=("step $num: $st has no real ${st/done/evidence}${st/not-needed/owner decision}")
        fi ;;
      after-merge) ;;
      *) problems+=("step $num: unknown status '$st'") ;;
    esac
  done

  # Signed-off-by: a name only, matching the author (%an) and trailer of the
  # commit that last changed the record. Name only because the shared
  # private-details commit check refuses emails in commit messages (as in
  # ai/orbit's readiness check).
  local -a sobs=()
  local sob rc author msg
  mapfile -t sobs < <(printf '%s\n' "$text" | grep -E '^Signed-off-by:' || true)
  sob="$(printf '%s\n' "${sobs[0]:-}" | sed 's/^Signed-off-by:[[:space:]]*//; s/[[:space:]]*$//')"
  rc="$(git log -1 --format=%H "$SRC" -- "$rec" || true)"
  author="$(git log -1 --format='%an' "$rc" 2>/dev/null || true)"
  msg="$(git log -1 --format=%B "$rc" 2>/dev/null || true)"
  if [ "${#sobs[@]}" -eq 0 ] || [ -z "$sob" ]; then
    problems+=("no Signed-off-by: line")
  elif [ "${#sobs[@]}" -gt 1 ]; then
    problems+=("${#sobs[@]} Signed-off-by: lines, want exactly one")
  elif [[ "$sob" == *"<"*">"* ]]; then
    problems+=("Signed-off-by '$sob' carries an email: give the name only")
  else
    [ "$sob" = "$author" ] || problems+=("Signed-off-by '$sob' is not the author of the commit that last changed the record ('$author')")
    printf '%s\n' "$msg" | grep -qxF "Signed-off-by: $sob" \
      || problems+=("that commit's message has no 'Signed-off-by: $sob' trailer (git commit --trailer \"Signed-off-by: $sob\")")
  fi

  if [ "${#problems[@]}" -eq 0 ]; then ok R1; return; fi
  local IFS=';'
  fail R1 "release record $rec: ${problems[*]}" "$hint"
}

# --- R2 version ----------------------------------------------------------
check_r2() {
  local tags out
  tags="$(git for-each-ref --format='%(objectname)%09%(refname)' 'refs/tags/v*')"
  if out="$("$root/scripts/release-version-check.sh" "$VERSION" "$tags" - "$(git rev-parse "$SRC^{commit}")" 2>&1)"; then
    ok R2
  else
    fail R2 "$(printf '%s' "$out" | tr '\n' ' ')" "fix VERSION on the source branch (strict X.Y.Z, above every v* tag); fetch tags if they look stale"
  fi
}

# --- R3 API spec version -------------------------------------------------
check_r3() {
  local av
  av="$(show docs/api/auth.yaml | awk '
    /^info:/ { inf = 1; next }
    /^[^ #]/ { inf = 0 }
    inf && /^  version:/ { v = $0; sub(/^  version:[ \t]*/, "", v); sub(/[ \t]*#.*$/, "", v); gsub(/"/, "", v); gsub(/\047/, "", v); print v; exit }' || true)"
  if [ -n "$VERSION" ] && [ "$av" = "$VERSION" ]; then ok R3
  else fail R3 "docs/api/auth.yaml info.version is '$av', VERSION is '$VERSION'" "set info.version in docs/api/auth.yaml to $VERSION"; fi
}

# --- R4 changelog --------------------------------------------------------
check_r4() {
  local cl problems=() sec unrel
  if ! cl="$(show CHANGELOG.md)"; then fail R4 "no CHANGELOG.md on $SRC" "add CHANGELOG.md with a [$VERSION] section"; return; fi
  # section NAME: its header line, then its body up to the next "## ".
  sec="$(printf '%s\n' "$cl" | awk -v h="## [$VERSION]" 'index($0, h) == 1 { f = 1; print "HEAD " $0; next } /^## / { f = 0 } f { print }')"
  if [ -z "$sec" ]; then
    problems+=("no '## [$VERSION]' section")
  else
    printf '%s\n' "$sec" | grep -qE '^HEAD ## \[[^]]*\] - [0-9]{4}-[0-9]{2}-[0-9]{2}' || problems+=("the [$VERSION] section has no date (## [$VERSION] - YYYY-MM-DD)")
    printf '%s\n' "$sec" | grep -v '^HEAD ' | grep -qE '^[[:space:]]*[-*] ' || problems+=("the [$VERSION] section has no entries")
  fi
  unrel="$(printf '%s\n' "$cl" | awk 'index($0, "## [Unreleased]") == 1 { f = 1; next } /^## / { f = 0 } f { print }')"
  printf '%s\n' "$unrel" | grep -qE '^[[:space:]]*[-*] ' && problems+=("[Unreleased] still has entries")
  if [ "${#problems[@]}" -eq 0 ]; then ok R4; return; fi
  local IFS=';'
  fail R4 "CHANGELOG.md: ${problems[*]}" "move the [Unreleased] entries under '## [$VERSION] - <date>' and leave [Unreleased] empty"
}

# --- R5 retract ----------------------------------------------------------
check_r5() {
  local gm lo hi hit=""
  gm="$(show go.mod || true)"
  while read -r lo hi; do
    [ -n "$lo" ] || continue
    [ -n "$hi" ] || hi="$lo"
    if ver_le "$lo" "$VERSION" && ver_le "$VERSION" "$hi"; then hit="$lo..$hi"; fi
  done < <(printf '%s\n' "$gm" | awk '
    { sub(/\/\/.*$/, "") }
    /^[ \t]*retract[ \t]*\(/ { blk = 1; next }
    blk && /^[ \t]*\)/ { blk = 0; next }
    blk || /^[ \t]*retract[ \t]/ { s = $0; sub(/^[ \t]*retract/, "", s); gsub(/[\[\],]/, " ", s); if (s ~ /[0-9]/) print s }')
  if [ -z "$hit" ]; then ok R5
  else fail R5 "go.mod retracts $hit, which covers $VERSION" "remove or narrow that retract in go.mod: a retracted version cannot be released"; fi
}

# --- R6 blocklist age ----------------------------------------------------
check_r6() {
  local out
  if out="$("$root/scripts/blocklist-age-check.sh" 2>&1)"; then ok R6
  else fail R6 "$(printf '%s' "$out" | tr '\n' ' ')" "run scripts/update-blocklist.sh and commit blocklist/embedded/"; fi
}

# --- R7 target is an ancestor of the source ------------------------------
check_r7() {
  if git rev-parse -q --verify "$TGT^{commit}" >/dev/null && git merge-base --is-ancestor "$TGT" "$SRC"; then ok R7
  else fail R7 "$TGT is not an ancestor of $SRC (or does not exist here)" "back-merge $TGT into the source branch first (git fetch origin, then merge it), then rerun"; fi
}

# --- R8 image Go version against go.mod ----------------------------------
check_r8() {
  local img tag pin want got gm tc gl
  # Only the top-level variables: block counts; a job's own variables do not.
  img="$(show .gitlab-ci.yml | awk '/^variables:/ { f = 1; next } /^[^ \t#]/ { f = 0 } f && /^[ \t]+GOLANG_IMAGE:/ { print; exit }' | sed 's/^[[:space:]]*GOLANG_IMAGE:[[:space:]]*//' | sed 's/[[:space:]]*#.*$//' | tr -d "\"'")"
  tag="${img#*:}"; tag="${tag%%@*}"
  pin=""; case "$img" in *@*) pin="${img#*@}" ;; esac
  gm="$(show go.mod || true)"
  tc="$(printf '%s\n' "$gm" | sed -n 's/^toolchain[[:space:]]*go//p' | head -1)"
  gl="$(printf '%s\n' "$gm" | sed -n 's/^go[[:space:]]*//p' | head -1)"
  if [ -n "$tc" ]; then want="$tc"; got="$tag"
  else want="$(printf '%s' "$gl" | cut -d. -f1,2)"; got="$(printf '%s' "$tag" | cut -d. -f1,2)"; fi
  if [ -z "$img" ] || [ "$got" != "$want" ]; then
    fail R8 "GOLANG_IMAGE is '$img' (Go ${tag:-?}), go.mod wants Go $want" "move GOLANG_IMAGE (tag and digest) in .gitlab-ci.yml, or go.mod's go/toolchain line, so they agree"
    return
  fi
  ok R8
  local live="${READINESS_IMAGE_DIGEST:-}"
  if [ -z "$live" ] && command -v docker >/dev/null 2>&1 && [ -n "$pin" ]; then
    live="$(timeout 30 docker buildx imagetools inspect "${img%%@*}" 2>/dev/null | sed -n 's/^Digest:[[:space:]]*//p' | head -1 || true)"
  fi
  if [ -z "$live" ]; then echo "R8 digest: not checked here (no registry digest given)"
  elif [ -n "$pin" ] && [ "$live" != "$pin" ]; then
    echo "WARN R8: the registry serves $live for ${img%%@*}, GOLANG_IMAGE pins $pin; consider moving the digest"
  fi
}

# --- the audit issue (local, personal token only) ------------------------
check_audit() {
  if [ -z "${GITLAB_TOKEN:-}" ] || [ -n "${CI_JOB_TOKEN:-}" ] || ! command -v glab >/dev/null 2>&1; then
    echo "audit issue: not checked here (needs a personal GITLAB_TOKEN and glab, outside CI); the releaser confirms docs/releasing.md step 1"
    return
  fi
  local proj="${READINESS_PROJECT:-ai/gauntlet}" enc found=0 open=0 m out
  enc="${proj//\//%2F}"
  m="v$VERSION"
  if ! out="$(glab api "projects/$enc/issues?labels=security&milestone=$m&state=all&per_page=100" 2>/dev/null)"; then
    fail audit "could not query GitLab for the audit issue of milestone $m" "check GITLAB_TOKEN and glab access to $proj, then rerun"
    return
  fi
  found="$(printf '%s' "$out" | { grep -oE '"state": ?"[a-z]*"' || true; } | wc -l)"
  open="$(printf '%s' "$out" | { grep -oE '"state": ?"opened"' || true; } | wc -l)"
  if [ "$found" -gt 0 ] && [ "$open" -eq 0 ]; then echo "ok audit issue: closed, labelled security, in milestone v$VERSION"
  else fail audit "no closed security-labelled audit issue in milestone v$VERSION ($found found, $open open)" "close the release audit issue in that milestone with a comment linking each finding to its fix (docs/releasing.md step 1)"; fi
}

# A check that trips set -e must not end the run: `||` keeps errexit off
# inside it, and a check that could not finish says so instead.
for c in check_r1 check_r2 check_r3 check_r4 check_r5 check_r6 check_r7 check_r8 check_audit; do
  "$c" || fail "${c#check_}" "the check ended early (see above)" "rerun from a full checkout of the source branch with the target fetched"
done

[ "$nfail" -eq 0 ] || { echo "$nfail check(s) failed"; exit 1; }
echo "release-readiness: all checks passed"
