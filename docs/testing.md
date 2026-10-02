# Testing

How gauntlet is tested, what the CI gate measures, and the rules a change
has to meet.

## Layers

| Layer | What runs | Where |
| --- | --- | --- |
| Go unit and package tests | `go test ./... -race` | `test:go` |
| Static checks | `go vet`, `gofmt`, `golangci-lint` | `lint:go` |
| Licence gate | `go-licenses` against `supply-chain/licence-policy.yml` | `lint:licences` |
| Vulnerability scan | `govulncheck` | `lint:vulncheck` |
| Secret scan | `gitleaks` | `lint:secrets` |
| HTTP contract | `gate/contracttest` (its own Go module) against `docs/api/auth.yaml` | `test:contract` |
| Go API compatibility | `scripts/apidiff.sh` against the last `v*` tag | `lint:apidiff` |
| Common-password list age | `scripts/blocklist-age-check.sh` (its own cases: `scripts/blocklist-age-check_test.sh`, run by hand) | `release:version` |

There is no frontend, no shipped image and no live-stack e2e stage here
(unlike birdcage/mikroview): gauntlet ships a tag, not a running service,
and every behaviour it has is reachable from a Go test.

The common-password list's code (`blocklist`, `cmd/pwlist`, #52) is
tested against `httptest` fakes of HIBP's range API, the list's
download host and GitHub's releases API, with synthetic hashes and
Ed25519 keys made per test. No test reaches the network, and no real
HIBP response is recorded in this repository: the owner has not
approved one as a fixture. What only the real producer can show -- the
real corpus's size and counts -- is checked by the build's own sanity
bars on every scheduled run.

## Compatibility checks

ADR-0002 promises that from v0.1.0 nothing callers rely on is removed
or changed, only added. Two CI checks enforce most of this. One gap is
left to review: a field removed or renamed in `docs/api/auth.yaml`
itself, which ADR-0002 allows only in a new major version.

- **HTTP contract.** To add a route or a response field, change the
  handler and `docs/api/auth.yaml` in the same commit.
  `docs/api/auth.yaml` (OpenAPI 3.1) describes every route
  `gate.Routes` serves. `TestContractEveryRoute` drives each route
  through its success path and the refusals a test can reach, and
  validates every request and response against the document with
  `kin-openapi` (test scope only). An undocumented status fails, and each
  documented success or redirect status must be seen at least once. The
  document closes each response body (`additionalProperties: false`),
  so a field the handler drops, renames or adds without the document
  also fails. One deliberate exception: on the passkey routes, the
  WebAuthn options `register/begin` and `login/factor/begin` answer and
  the `credential` and `assertion` request fields are open objects.
  They are the W3C's `PublicKeyCredential` JSON, made and read by the
  WebAuthn library and the browser, and a library update that adds a
  W3C field must not fail the contract (ADR-0004 decision 6). `TestContractRoutesMatchDocument` checks that the routes
  `routes.go` registers (read from the source code and confirmed
  against the running router) are the same list as the document
  describes, in both directions. `TestContractRequestBodiesMatchHandlers`
  does the same for the fields each handler reads from a request body
  (also read from the source code) and the document's request bodies.
  `TestContractDocumentVersionMatchesVERSION` fails if the document's
  `info.version` differs from `VERSION`.
  These tests are a separate Go module, `gate/contracttest`, so
  `kin-openapi` stays out of the library's `go.mod` (#30). Run them
  with `cd gate/contracttest && go test ./...`. They use `gate` only
  through its exported API, the same way an application does.
- **Go API.** The only way past a breaking change is to raise the first
  number in `VERSION` (0.x.y to 1.0.0). A minor bump such as 0.1 to 0.2
  is not enough. `scripts/apidiff.sh [BASE_REF]` compares the module's
  exported API with the newest `v*` tag reachable from `HEAD` (or
  `BASE_REF`), using `golang.org/x/exp/cmd/apidiff` via `go run` at a
  pinned pseudo-version, never in `go.mod`. Internal packages are
  skipped.

What each check fails on:

| Change | Caught by |
| --- | --- |
| Removed or renamed exported identifier, changed signature, removed struct field | `scripts/apidiff.sh` |
| Removed route | `TestContractRoutesMatchDocument` (route no longer served) and `TestContractEveryRoute` (the route no longer answers as documented) |
| Changed response field (renamed, removed, retyped) | `TestContractEveryRoute` |
| New status code the document lacks | `TestContractEveryRoute` |
| Added identifier, route or response field, with the document updated | passes both |

## Coverage is a ratchet, not a target

`test:go` writes a profile and `scripts/coverage-floor.py` checks it
against `supply-chain/coverage-floors.yml`, one floor per package, copied
from birdcage's script. A package fails below its floor, and also fails
more than 5 points above it -- that means the floor is stale, and the fix
is to raise it, never to leave the headroom. Floors only ever go up.

Go measures statement coverage, not branch coverage: a 100% package means
every line ran, not that every condition was tried both ways.

## What a test has to prove

- New behaviour needs a test that would fail without it; prefer what a
  caller sees over internal detail.
- A bug fix carries a regression test that reproduces the bug first. A
  test that has never failed proves nothing; if shipping without one, say
  so on the issue.
- Where a type or function is copied from mikroview's implementation
  (`persist`, and later the accounts, session and token stores), its
  ported tests come with it -- see each file's doc comment for where it
  came from. Divergence from mikroview's behaviour needs its own test,
  not just a comment explaining the difference.
- A refusal is behaviour: fail-closed paths (`persist.Open` on an
  unparseable document, an unknown token kind, a refused OIDC issuer) get
  negative tests, not only the happy path.
- Every mutating `Store` and `TokenStore` method has a test that makes
  the backend write fail and checks both the returned error and that the
  in-memory change was rolled back.
- A check that fails and passes again on unchanged code is a flake:
  record it in `docs/flakes.md` (create it on first use), and file an
  issue on its third sighting.
