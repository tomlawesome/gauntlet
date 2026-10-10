# Gauntlet agent instructions

Applies alongside the global agent instructions (instruction authority,
delivery and credential rules live there).

## What this is

A shared Go library: local accounts, sessions, tokens, OIDC, the passkey
(WebAuthn) ceremony and the HTTP auth middleware birdcage and (later)
mikroview both need, so a security fix lands once instead of being
copied between the two. See [docs/design.md](docs/design.md) and
[docs/adr/0001-shared-auth-module.md](docs/adr/0001-shared-auth-module.md).
Its users are self-hosted home apps, not enterprise tools: weigh design
calls against that (owner, 2026-10-07).

`passkey/` (G8, [ADR-0004](docs/adr/0004-passkey-ceremony.md)) is a leaf:
no non-test file in `gate` or the root package may import it or
go-webauthn, so an app that never imports it never links the library.
`go list -deps ./gate | grep -i webauthn` must print nothing.
`geoip/` (#54, [ADR-0008](docs/adr/0008-sign-in-country.md)) is a leaf
the same way for maxminddb: `go list -deps ./gate ./ | grep -i
maxminddb` must print nothing (`lint:go` checks both).

No UI of its own: docs describe steps on other sites (GitLab, MaxMind,
IPinfo) in words, without screenshots (owner, 2026-10-08).

**Belongs in the apps, not here:** a database-table backend (each app
supplies its own `persist.Backend`), the public URL a relying party is
built from, and anything that reaches back into birdcage's or
mikroview's own types. Encryption at rest is the one exception:
`persist.Encrypt` seals the document before any app backend stores it,
and the encrypted file backend (`persist.EncryptedFileBackend`) is that
wrapper over a file (#18, #50, ADR-0005); finding and reading the key
file stays with the app.

**Mikroview's auth code is the reference this module is read against**,
continuously, until mikroview actually moves onto it (birdcage ADR-0005
decision 3, mikroview #1202) -- not a one-time source to copy from.
Read it from mikroview's GitLab `dev` (`git -C ~/projects/mikroview show
gitlab/dev:<path>`), never the GitHub `origin/dev`: mikroview is
GitLab-first and the mirror lags by days (owner, 2026-09-27).

## Delivery host

GitLab-first: `gitlab.tomlawson.io/ai/gauntlet` (project id 56), default
branch `dev`. The public GitHub mirror, `github.com/tomlawesome/gauntlet`,
is created at v0.1.0 so birdcage can `go get` the tag by its module path
(#17, owner 2026-09-29, replacing 2026-09-27's "mirror at v0.2.0"). GitHub
is the mirror only: no GitHub issues or pull requests.

## Runner tags

Every job runs on the shared `light` lane except the common-password
list's two (#52, ADR-0007): `blocklist:sign` on `gauntlet-signing`
(signing key at `/etc/gauntlet-signing/`) and `blocklist:publish` on
`gauntlet-publish` (GitHub release token at `/etc/gauntlet-github/`).
Both are protected, locked to this project, and set up by the owner
(docs/releasing.md); no other job may use those tags.

## Dependency updates

Renovate (#63): `renovate.json`, the `renovate` job and a weekly schedule
on `dev` with `RENOVATE=true` (owner setup: docs/releasing.md). Go
versions are looked up from Git hosts (`GOPROXY=direct`), never the proxy.

## Closing issues from commits

Same trap as birdcage: GitLab treats `Implements`/`Closes`/`Fixes` next to
an issue number as closing it, even mid-sentence or inside a warning
about this rule. Use a placeholder such as `#N` in any prose that must
name the pattern itself, and `Refs #N` for a commit that doesn't finish
an issue.

## Approved third-party modules

None in G1-G4. `golang.org/x/crypto/argon2`, `github.com/coreos/go-oidc/v3`
and `golang.org/x/oauth2` are approved for G2/G5 (birdcage #8,
owner 2026-09-26) -- see docs/adr/0001-shared-auth-module.md. For v0.2.0
(owner 2026-09-30): `golang.org/x/exp/cmd/apidiff` in CI only and
`github.com/getkin/kin-openapi` v0.149.0 (MIT) in tests only, both for
#22 and ADR-0002; `github.com/go-webauthn/webauthn` v0.18.2 in `passkey/`
for G8 (#20), and in its test fake (`internal/passkeytest`), in gate's test
files and in the contract module. For #54 (owner 2026-10-04):
`github.com/oschwald/maxminddb-golang/v2` v2.6.0 (ISC) in `geoip/` only,
to read MaxMind and IPinfo country files, and `github.com/maxmind/mmdbwriter`
v1.2.0 (Apache-2.0 or MIT) in `geoip/` tests only, to build their fixture
files (it brings `go4.org/netipx`). Anything else goes to the owner first.
A linked module's embedded files and vendored code without its own
licence need an owner-recorded `go-bundled-assets:` review (#64).

## Checks

Run them under CI's Go: `export GOTOOLCHAIN=go1.27.2`. Go 1.27.0 and
1.27.1 over-count coverage statements, so their figures miss the floors
(re-measured under 1.27.2, !51).

```
gofmt -l .                     # must print nothing
go build ./... && go vet ./... && go test ./... -race -coverprofile=coverage.out
(cd gate/contracttest && go vet ./... && golangci-lint run ./... && go test ./... -race)  # own module
python3 scripts/coverage-floor.py coverage.out
golangci-lint run ./...
scripts/licence-check.sh
scripts/apidiff.sh             # exported API vs the last v* tag
GOTOOLCHAIN=go1.27.2 go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...  # the Go in CI's image
gitleaks detect --no-banner
python3 -c "import yaml; yaml.safe_load(open('.gitlab-ci.yml'))"
```
