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

There is no frontend, no shipped image and no live-stack e2e stage here
(unlike birdcage/mikroview): gauntlet ships a tag, not a running service,
and every behaviour it has is reachable from a Go test.

## Compatibility is checked, not reviewed

ADR-0002 promises additive-only change from v0.1.0. Two checks hold
that line (#22):

- **HTTP contract.** `docs/api/auth.yaml` (OpenAPI 3.1) describes every
  route `gate.Routes` serves. `TestContractEveryRoute` drives each route
  through its success path and the refusals a test can reach, and
  validates every request and response against the document with
  `kin-openapi` (test scope only). An undocumented status fails, and each
  documented success or redirect status must be seen at least once. JSON
  response bodies are closed in the document, so a field the handler
  drops, renames or adds without the document fails.
  `TestContractRoutesMatchDocument` compares the patterns `routes.go`
  registers (read from source, confirmed against the live mux) with the
  document's operations, both ways, and
  `TestContractRequestBodiesMatchHandlers` compares the fields each
  handler's request type decodes (also read from source) with the
  document's request body. To add a route or field: change the handler
  and the document in the same commit. These tests are their own Go
  module, `gate/contracttest`, so `kin-openapi` stays out of the
  library's `go.mod` (#30); run them with
  `cd gate/contracttest && go test ./...`. From there they reach `gate`
  only through its exported API, as an application does.
- **Go API.** `scripts/apidiff.sh [BASE_REF]` compares the module's
  exported API with the newest `v*` tag reachable from `HEAD` (or
  `BASE_REF`), using `golang.org/x/exp/cmd/apidiff` via `go run` at a
  pinned pseudo-version, never in `go.mod`. Internal packages are
  skipped. A major-version bump in `VERSION` is the only way past an
  incompatible change.

What each check fails on:

| Change | Caught by |
| --- | --- |
| Removed or renamed exported identifier, changed signature, removed struct field | `scripts/apidiff.sh` |
| Removed route | `TestContractRoutesMatchDocument` (route no longer served) and `TestContractEveryRoute` (the route no longer answers as documented) |
| Changed response field (renamed, removed, retyped) | `TestContractEveryRoute` |
| New status code the document lacks | `TestContractEveryRoute` |
| Added identifier, route or response field, with the document updated | passes both |

Renaming a field in the document along with the handler passes the
contract test, so a removal or rename in `docs/api/auth.yaml` itself is
a review point: ADR-0002 allows it only across a major version.

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
