#!/usr/bin/env bash
set -euo pipefail

# Exercises licence-check.sh against small fake modules in a temp
# directory (#64): a main module named like gauntlet's, and one
# dependency, example.com/dep, wired in with a `replace` so `go list` and
# go-licenses read it from disk and nothing touches the network. Each new
# rule has a case the old gate -- `go-licenses check` alone -- passes and
# the new gate fails. Needs go-licenses' pinned version in the module
# cache or a reachable proxy, as licence-check.sh itself does. Run
# directly; exits non-zero on the first assertion that fails.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATE="$ROOT/scripts/licence-check.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MIT='Copyright (c) 2026 Example Authors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'

ISC='ISC License

Copyright (c) 2026 Other Authors

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.'

# new_case NAME [VERSION]: a main module requiring example.com/dep at
# VERSION (default v1.0.0), and the dependency's root package, MIT.
new_case() {
  C="$WORK/$1"
  mkdir -p "$C/main" "$C/dep"
  printf 'module github.com/tomlawesome/gauntlet\n\ngo 1.27.0\n\nrequire example.com/dep %s\n\nreplace example.com/dep => ../dep\n' \
    "${2:-v1.0.0}" > "$C/main/go.mod"
  printf 'module example.com/dep\n\ngo 1.27.0\n' > "$C/dep/go.mod"
  printf '%s\n' "$MIT" > "$C/dep/LICENSE"
  printf 'package dep\n' > "$C/dep/dep.go"
  printf 'example.com/dep\n' > "$C/imports"
  : > "$C/test-imports"
}

# pkg DIR: a Go package in the dependency at DIR.
pkg() {
  mkdir -p "$C/dep/$1"
  printf 'package %s\n\nfunc F() {}\n' "$(basename "$1")" > "$C/dep/$1/$(basename "$1").go"
}

# link DIR: the main module imports the dependency's package at DIR.
link() { pkg "$1"; printf 'example.com/dep/%s\n' "$1" >> "$C/imports"; }

# embed DIR FILE: a linked package at DIR embedding FILE (relative to it).
embed() {
  mkdir -p "$C/dep/$1/$(dirname "$2")"
  printf 'x\n' > "$C/dep/$1/$2"
  printf 'package %s\n\nimport _ "embed"\n\n//go:embed %s\nvar Asset []byte\n' \
    "$(basename "$1")" "$2" > "$C/dep/$1/$(basename "$1").go"
}

# policy LICENCE... -- REVIEW...: the allow-list, then go-bundled-assets.
policy() {
  {
    echo "allow-licenses:"
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do echo "  - $1"; shift; done
    [ $# -gt 0 ] && shift
    echo
    if [ $# -eq 0 ]; then
      echo "go-bundled-assets: []"
    else
      echo "go-bundled-assets:"
      for r in "$@"; do echo "  - $r"; done
    fi
  } > "$C/policy.yml"
}

write_main() {
  {
    echo "package gauntlet"
    echo
    echo "import ("
    sed 's/.*/\t_ "&"/' "$C/imports"
    echo ")"
  } > "$C/main/main.go"
  if [ -s "$C/test-imports" ]; then
    {
      echo "package gauntlet"
      echo
      echo "import ("
      sed 's/.*/\t_ "&"/' "$C/test-imports"
      echo ")"
    } > "$C/main/main_test.go"
  fi
}

# gate WANT DESC [NEEDLE]: the whole of licence-check.sh.
gate() {
  local want="$1" desc="$2" needle="${3:-}" got
  write_main
  if (cd "$C/main" && POLICY_FILE="$C/policy.yml" "$GATE") > "$WORK/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: $desc -- expected the gate to $want, got $got" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" "$WORK/out"; then
    echo "FAIL: $desc -- output does not say '$needle'" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
  echo "ok: $desc"
}

# old_gate WANT DESC: what licence-check.sh ran before #64, go-licenses
# alone, with the same allow-list.
old_gate() {
  local want="$1" desc="$2" got allowed
  write_main
  allowed="$(sed -n 's/^  - \([A-Za-z0-9.-]*\)$/\1/p' "$C/policy.yml" | head -n 5 | paste -sd, -)"
  if (cd "$C/main" && "$GO_LICENSES" check ./... --ignore github.com/tomlawesome/gauntlet \
      --allowed_licenses="$allowed") > "$WORK/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: old gate, $desc -- expected $want, got $got" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
  echo "ok: old gate would $want: $desc"
}

new_case clean
policy MIT
gate pass "a dependency with nothing inside passes"
GO_LICENSES="$(go env GOBIN)"
GO_LICENSES="${GO_LICENSES:-$(go env GOPATH)/bin}/go-licenses"
[ -x "$GO_LICENSES" ] || { echo "FAIL: go-licenses not found at $GO_LICENSES after the gate ran" >&2; exit 1; }
old_gate pass "a dependency with nothing inside"

# Vendored code with no licence of its own: go-licenses credits it to
# the module's MIT licence.
new_case vendored
link third_party/foo
policy MIT
old_gate pass "vendored code with no licence file"
gate fail "vendored code with no licence file fails" "vendored code, no licence of its own"
policy MIT -- "example.com/dep@v1.0.0 third_party/foo/ MIT-reviewed"
gate pass "vendored code with a recorded review passes" "passed by recorded review"

# Another module cannot import an internal package, so a public one in
# the dependency does, the way a real module uses its internal/.
new_case vendored-deep
pkg internal/third_party/foo/sub
link wrap
printf 'package wrap\n\nimport _ "example.com/dep/internal/third_party/foo/sub"\n' > "$C/dep/wrap/wrap.go"
policy MIT
gate fail "internal/third_party is vendored too" "internal/third_party/foo/sub/"

# Vendored code that does carry its own licence faces the same
# allow-list as the module: go-licenses already held it to that, and
# still does. Shown here so it stays true.
new_case vendored-licensed
link third_party/isc
printf '%s\n' "$ISC" > "$C/dep/third_party/isc/LICENSE"
policy MIT
old_gate fail "vendored code under a licence outside the allow-list"
gate fail "vendored code under a licence outside the allow-list fails" "ISC"
policy MIT ISC
gate pass "vendored code under an allowed licence of its own passes, named in the log" "third_party/isc/LICENSE"

# Embedded files carry no licence field at all.
new_case embedded
link ui
embed ui static/logo.png
policy MIT
old_gate pass "an embedded image"
gate fail "an unreviewed embedded file fails" "ui/static/ (1 file(s), embedded)"
policy MIT -- "example.com/dep@v1.0.0 ui/static/ MIT-own-artwork"
gate pass "a reviewed embedded file passes" "ui/static/ (1) -- MIT-own-artwork"

# A version bump stops the review matching: the file is unreviewed again
# and the old entry is stale.
new_case bumped v1.1.0
link ui
embed ui static/logo.png
policy MIT -- "example.com/dep@v1.0.0 ui/static/ MIT-own-artwork"
gate fail "a version bump re-triggers the review" "example.com/dep@v1.1.0 ui/static/"
grep -qF "stale go-bundled-assets" "$WORK/out" || { echo "FAIL: the old review is not reported stale" >&2; exit 1; }
echo "ok: the old version's review is reported stale"

new_case stale
policy MIT -- "example.com/dep@v1.0.0 ui/static/ MIT-own-artwork"
gate fail "a review matching nothing is stale and fails" "stale go-bundled-assets"

# What ships nowhere needs no review: an embedding package only the
# tests import, a vendored directory nothing links, a file nothing
# embeds. Each is still named in the log.
new_case unshipped
pkg testui
embed testui static/logo.png
printf 'example.com/dep/testui\n' >> "$C/test-imports"
pkg third_party/unused
link third_party/used
printf '%s\n' "$MIT" > "$C/dep/third_party/used/LICENSE"
printf 'x\n' > "$C/dep/badge.svg"
policy MIT
gate pass "test-only, unlinked and unembedded files pass" "third_party/unused/ (vendored, not linked)"
grep -qF "badge.svg (not embedded by linked code)" "$WORK/out" || { echo "FAIL: badge.svg not listed" >&2; cat "$WORK/out" >&2; exit 1; }
echo "ok: files that ship nowhere are listed"

echo "licence-check_test.sh: all cases passed"
