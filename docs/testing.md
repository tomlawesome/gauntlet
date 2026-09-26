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

There is no frontend, no shipped image and no live-stack e2e stage here
(unlike birdcage/mikroview): gauntlet ships a tag, not a running service,
and every behaviour it has is reachable from a Go test.

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
- A check that fails and passes again on unchanged code is a flake:
  record it in `docs/flakes.md` (create it on first use), and file an
  issue on its third sighting.
