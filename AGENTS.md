# Gauntlet agent instructions

Applies alongside the global agent instructions (instruction authority,
delivery and credential rules live there).

## What this is

A shared Go library: local accounts, sessions, tokens, OIDC and the HTTP
auth middleware birdcage and (later) mikroview both need, so a security
fix lands once instead of being copied between the two. See
[docs/design.md](docs/design.md) and
[docs/adr/0001-shared-auth-module.md](docs/adr/0001-shared-auth-module.md).

**Belongs in the apps, not here:** any concrete storage backend (a file,
a database table -- each app supplies its own `persist.Backend`), the
WebAuthn ceremony (`passkey/`, deferred to G8), and anything that reaches
back into birdcage's or mikroview's own types.

**Mikroview's auth code is the reference this module is read against**,
continuously, until mikroview actually moves onto it (birdcage ADR-0005
decision 3, mikroview #1202) -- not a one-time source to copy from.

## Delivery host

GitLab-first: `gitlab.tomlawson.io/ai/gauntlet` (project id 56), default
branch `dev`. A GitHub mirror is created only once v0.1.0 tags (owner,
2026-09-26) -- no mirror, no GitHub issues or pull requests before that.

## Closing issues from commits

Same trap as birdcage: GitLab treats `Implements`/`Closes`/`Fixes` next to
an issue number as closing it, even mid-sentence or inside a warning
about this rule. Use a placeholder such as `#N` in any prose that must
name the pattern itself, and `Refs #N` for a commit that doesn't finish
an issue.

## Approved third-party modules

None in G1-G4. `golang.org/x/crypto/argon2`, `github.com/coreos/go-oidc/v3`
and `golang.org/x/oauth2` are approved for G2/G5 (birdcage #8,
owner 2026-09-26) -- see docs/adr/0001-shared-auth-module.md. `go-webauthn`
is not approved; it waits for G8. Anything else goes to the owner first.

## Checks

```
go build ./... && go vet ./... && go test ./... -race -coverprofile=coverage.out
python3 scripts/coverage-floor.py coverage.out
golangci-lint run ./...
scripts/licence-check.sh
govulncheck ./...
gitleaks detect --no-banner
python3 -c "import yaml; yaml.safe_load(open('.gitlab-ci.yml'))"
```
