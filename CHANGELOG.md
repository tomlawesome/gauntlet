# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Repository skeleton: licence, agent and contributor docs, the design
  document and its ADR, and CI (build/vet/test with coverage floors,
  golangci-lint, gitleaks, govulncheck, licence check).
- `persist` package: the `Backend`/`VersionReader` storage interface and
  a `Memory` backend for tests, copied from mikroview's
  `internal/persist`.
- `oidc` package: the OIDC/SSO relying-party layer -- provider discovery,
  Authorization Code + PKCE, ID token verification, the self-hosted-only
  `AllowIssuer`/`IsMultiTenantIssuer` policy and the sealed `FlowState`
  cookie codec -- moved unchanged from mikroview's `internal/oidc`.
  Depends on `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`
  (owner-approved, AGENTS.md). `internal/testutil` carries the fake OIDC
  provider used by its tests, and by `gate`'s once that package exists.
