# Testing

How gauntlet is tested, what the CI gate measures, and the rules a change
has to meet.

## Layers

The last column gives the job's name in `.gitlab-ci.yml`.

| Layer | What runs | CI job |
| --- | --- | --- |
| Go unit and package tests | `go test ./... -race` | `test:go` |
| Static checks | `go vet`, `gofmt`, `golangci-lint` | `lint:go` |
| Licence gate | Checks that every library linked into the shipped code has an allowed licence, and that any copied (vendored) code or embedded file inside one has a recorded licence review: `go-licenses` against `supply-chain/licence-policy.yml`, then `scripts/licence-check-bundled.py` for vendored code and embedded files in the same modules (its own cases: `scripts/licence-check_test.sh`, run by hand) | `lint:licences` |
| Vulnerability scan | `govulncheck` | `lint:vulncheck` |
| Secret scan | `gitleaks` | `lint:secrets` |
| HTTP contract | `gate/contracttest` (its own Go module) checks the real behaviour against `docs/api/auth.yaml`, the written description of the web routes | `test:contract` |
| Go API compatibility | `scripts/apidiff.sh` against the last `v*` tag (its own cases: `scripts/apidiff_test.sh`, run by hand) | `lint:apidiff` |
| Common-password list age | `scripts/blocklist-age-check.sh` (its own cases: `scripts/blocklist-age-check_test.sh`, run by hand) | `release:version` |

There is no frontend, no shipped image and no end-to-end stage here (a
stage that starts the whole running application and tests it from
outside, unlike birdcage/mikroview): gauntlet ships a tag, not a running
service, and every behaviour can be tested directly from Go test code.

The common-password list's code (`blocklist`, `cmd/pwlist`, #52) is
tested against small fake servers that run inside the test (Go's
`httptest` package). They stand in for Have I Been Pwned (HIBP)'s
range API -- the service that takes the first five characters of a
password hash and returns every hash that starts with them -- the
list's download site, and GitHub's releases API. The tests use made-up
hashes and Ed25519 keys made per test. No test reaches the network,
and no real HIBP response is recorded in this repository: the owner
has not approved one as a fixture. What only the real data can show --
its size and counts -- is checked by the size checks in the scheduled
job that rebuilds the list.

The real list committed in `blocklist/embedded/` is checked on every
pipeline too. `TestEmbeddedCopy` parses it and verifies its signature
against the committed key in `blocklist/keys/`.
`TestCommittedKeysParse` fails if a committed key does not load, and
`TestCommittedKeysRefuseAnUncommittedSigner` that a list signed by any
other key is refused. `scripts/blocklist-age-check.sh` checks only the
list's age and presence, and leaves the signature to these tests.

The new-password checks (#43) are tested the same way: the live check's
`blocklist.PwnedChecker` is tested against a fake range API, and the
test confirms each request sends only the first five characters of the
password hash. The accounts store and the HTTP layer (`gate`) are tested
with simple fake versions of the password list and the breach check,
passed in by the test, so each test controls which passwords count as
common. The range
response's shape in those fakes is from HIBP's API documentation, not
a recorded response. A test against the real API would be the only
proof that shape still holds.

The sign-in country's `geoip` package (#54) is tested against an
`httptest` fake of both providers. Its country files are built inside each
test with MaxMind's file-writing tool, `mmdbwriter` (used only by tests,
never by the library), mapping a
couple of public networks to made-up countries; no provider's data is
in this repository. Tests confirm that the downloader refuses private
and other non-public addresses, both when asked directly and when one
local test server redirects it to another. Whether the
real providers still deliver downloads in the same file layout and with
the same response headers as the fake is something only a real download
shows.

## Compatibility checks

ADR-0002 promises that from v0.1.0 nothing callers rely on is removed
or changed, only added. Two CI checks enforce most of this. No automatic
check catches one case, so a human must catch it in review: removing or
renaming a field in `docs/api/auth.yaml` itself, which ADR-0002 allows
only in a new major version.

- **HTTP contract.** To add a route or a response field, change the
  handler and `docs/api/auth.yaml` in the same commit.
  `docs/api/auth.yaml` (a standard OpenAPI 3.1 file listing the routes
  and their data) describes every route `gate.Routes` serves. Run the checks with
  `cd gate/contracttest && go test ./...`. What each one checks:
  - `TestContractEveryRoute` drives each route through its success path
    and the refusals a test can reach, and checks every request and
    response against the document with `kin-openapi` (test scope only).
    A status the document does not list fails, and each documented
    success or redirect status must be seen at least once. The document
    lists every field a response may contain and allows no others
    (`additionalProperties: false`), so a handler that removes, renames
    or adds a field without a matching document change fails too.
  - `TestContractRoutesMatchDocument` checks that the routes
    `routes.go` registers (found by reading `routes.go` and confirmed
    by starting the real routes) are the same list as the document
    describes, in both directions.
  - `TestContractRequestBodiesMatchHandlers` does the same for the
    fields each handler reads from a request body (also read from the
    source code) and the document's request bodies.
  - `TestContractDocumentVersionMatchesVERSION` fails if the document's
    `info.version` differs from `VERSION`.
  - `TestContractDocNoCutValues` (`yamlcut_test.go`, #98) fails on any
    `docs/api/auth.yaml` value cut short by an unquoted ` #`. YAML reads
    a space followed by `#` as the start of a comment, even in the
    middle of a value, so the rest of the value is lost and the file
    still loads. Double-quote such a value.

  One deliberate exception to "no other fields": the passkey data is
  open. A passkey is a sign-in key held by the person's device, and
  WebAuthn is the browser standard for using one. The passkey data is
  not checked field by field, because its shape is set by that web
  standard (the W3C's `PublicKeyCredential` JSON), and the WebAuthn
  library and the browser make and read it, not a frontend's own code.
  It covers:
  - the settings the five begin routes send back to the browser:
    `login/prove/begin`, `login/factor/begin`, `login/passkey/begin`,
    `step-up/passkey/begin` and `passkeys/register/begin`;
  - the `assertion` every passkey sign-in or re-check sends, and the
    `credential` that `passkeys/register/finish` sends;
  - the `adminAssertion` that `POST /api/auth/users` sends when creating
    an admin account: the requesting admin's own passkey proof.

  A library update that adds a new W3C field must not fail the contract
  (ADR-0004 decision 6).

  These tests are a separate Go module, `gate/contracttest`, so
  `kin-openapi` stays out of the library's `go.mod` (#30). They use
  `gate` only through its exported API, the same way an application
  does.
- **Go API.** A change that breaks existing callers is allowed only with
  a new major version: raise the first number in `VERSION` (for example
  0.x.y to 1.0.0). A minor bump such as 0.1 to 0.2
  is not enough. `scripts/apidiff.sh [BASE_REF]` compares the module's
  exported API with the newest `v*` tag reachable from `HEAD` (or
  `BASE_REF`), using the apidiff tool (`golang.org/x/exp/cmd/apidiff`,
  one pinned version). It is installed in a temporary folder, so it
  never becomes a dependency of the library. Internal packages are
  skipped. The script fails if `go.mod` or `go.sum` changed while it
  ran, so a check can never quietly add a dependency line that then
  gets committed by accident (#62).

What each check fails on:

| Change | Caught by |
| --- | --- |
| Removed or renamed exported identifier, changed signature, removed struct field | `scripts/apidiff.sh` |
| Removed route | `TestContractRoutesMatchDocument` (route no longer served) and `TestContractEveryRoute` (the route no longer answers as documented) |
| Changed response field (renamed, removed, retyped) | `TestContractEveryRoute` |
| New status code the document lacks | `TestContractEveryRoute` |
| Added identifier, route or response field, with the document updated | passes both |

## Coverage is a ratchet, not a target

Each package has a minimum percentage of code
run by tests (its floor). `test:go` writes a coverage profile and
`scripts/coverage-floor.py` checks it against
`supply-chain/coverage-floors.yml`, which holds one floor per package.
The script is copied from birdcage's. A package fails if it is below its floor, and also if it is
more than 5 percentage points above it. That means the floor is stale,
and the fix is to raise it, never to leave the headroom. Floors only
ever go up.

Go counts which lines ran, not whether every yes/no choice went both
ways (statement coverage, not branch coverage): a 100% package means
every line ran, not that every condition was tried both ways.

## What a test has to prove

- The test comes before the code, for new behaviour and fixes alike. It
  is written from the issue (and ADR) alone, run, and seen to fail; the
  commit message records that failure
  (`Failed first: TestName -- <the line it failed with>`). A test that has
  never failed proves nothing.
- A test that fails only because the code it calls does not exist yet is
  checked again once the code exists, by breaking the code briefly and
  watching the test fail. A test that expects a refusal is kept next to
  a test of the allowed case, because it would pass even if no code
  existed at all.
- Prefer what a caller sees over internal detail.
- Shipping a change without a test needs the reason put to the owner, and
  their approval, first.
- Where a type or function is copied from mikroview's implementation
  (`persist`, and later the accounts, session and token stores), its
  ported tests come with it. See each file's doc comment for where it
  came from. Divergence from mikroview's behaviour needs its own test,
  not just a comment explaining the difference.
- A refusal is behaviour: fail-closed paths (`persist.Open` on an
  unparseable document, an unknown token kind, a refused OIDC issuer) get
  negative tests, not only the happy path.
- Every mutating `Store` and `TokenStore` method has a test that makes
  saving fail, then checks that an error is returned and that the
  change in memory is undone.
- A check that fails and passes again on unchanged code is a flake:
  record it in `docs/flakes.md`, and file an issue on its third
  sighting.
