#!/usr/bin/env bash
set -euo pipefail

# Exercises apidiff.sh against a throwaway module in a temp directory: an
# additive change passes, a removed identifier fails, a major version
# bump lets the removal through, and -- the case #62 is about -- a run
# during which go.sum changes fails even though the API is fine. Needs
# apidiff's pinned version in the module cache or a reachable proxy.
# Run directly; exits non-zero on the first assertion that fails.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
REAL_GO="$(command -v go)"
export GOTOOLCHAIN="${GOTOOLCHAIN:-$(cd "$ROOT" && go env GOVERSION)}"

repo="$WORK/repo"
mkdir -p "$repo/scripts"
cp "$ROOT/scripts/apidiff.sh" "$repo/scripts/"
cd "$repo"
printf 'module example.com/apidifftest\n\ngo 1.27.0\n' > go.mod
: > go.sum
printf 'package apidifftest\n\nfunc Kept() {}\n\nfunc Removed() {}\n' > a.go
echo 0.1.0 > VERSION
git init -q
git add -A
git -c user.name=test -c user.email=test@example.invalid commit -q -m base
git tag v0.1.0

expect() {
  local want="$1" desc="$2" got
  shift 2
  if "$@" > "$WORK/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: $desc -- expected $want, got $got" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
  echo "ok: $desc"
}

printf 'package apidifftest\n\nfunc Kept() {}\n\nfunc Removed() {}\n\nfunc Added() {}\n' > a.go
expect pass "an added function passes" scripts/apidiff.sh
[ -z "$(git status --short go.mod go.sum)" ] || { echo "FAIL: a passing run left go.mod or go.sum changed" >&2; exit 1; }

printf 'package apidifftest\n\nfunc Kept() {}\n' > a.go
expect fail "a removed function fails" scripts/apidiff.sh
grep -q 'Removed: removed' "$WORK/out" || { echo "FAIL: the report does not name Removed" >&2; cat "$WORK/out" >&2; exit 1; }

echo 1.0.0 > VERSION
expect pass "a removal passes with a major version bump" scripts/apidiff.sh
echo 0.1.0 > VERSION

# A `go` that appends to go.sum when the script first asks for the
# module path, standing in for anything that writes go.sum mid-run.
printf 'package apidifftest\n\nfunc Kept() {}\n\nfunc Removed() {}\n' > a.go
mkdir "$WORK/stub"
cat > "$WORK/stub/go" <<STUB
#!/usr/bin/env bash
if [ "\${1:-} \${2:-}" = "list -m" ]; then
  echo "example.org/stray v1.0.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" >> go.sum
fi
exec "$REAL_GO" "\$@"
STUB
chmod +x "$WORK/stub/go"
expect fail "a run that changes go.sum fails" env PATH="$WORK/stub:$PATH" scripts/apidiff.sh
grep -q 'go.mod or go.sum changed' "$WORK/out" || { echo "FAIL: the failure does not say go.sum changed" >&2; cat "$WORK/out" >&2; exit 1; }
git checkout -q -- go.sum

# With -mod=mod in the environment (as `go env -w GOFLAGS=-mod=mod`
# leaves it on a workstation), the script still leaves the files alone.
expect pass "GOFLAGS=-mod=mod in the environment changes nothing" env GOFLAGS=-mod=mod scripts/apidiff.sh
[ -z "$(git status --short go.mod go.sum)" ] || { echo "FAIL: -mod=mod run changed go.mod or go.sum" >&2; exit 1; }

echo "apidiff_test.sh: all cases passed"
