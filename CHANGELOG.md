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
