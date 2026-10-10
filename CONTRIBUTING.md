# Contributing

Gauntlet is a small, solo-maintained library. This document records how
the maintainer works in this repository, so expectations are explicit.

**Outside merge requests are not accepted.** Issues are read and are
information for the maintainer, not work items taken from outside
contributors.

## Branching

Branch from `dev` and send merge requests to `dev`, the default branch.
The repository also has `preview` and `main` branches, which the build
system copies to the public GitHub copy of the repository. Only the
owner merges into them, in the order `dev`, then `preview`, then `main`,
by merge request. Never branch from them or send work to them. A release
is a version tag on `main`, made by the owner pressing a release button
in the automated build that runs on `main`; `dev` and `preview` are not
releases. See
[docs/releasing.md](docs/releasing.md).

## Before starting work

These steps are for the maintainer and anyone the maintainer has
invited.

If the work isn't already an issue, open one first: decisions and scope
belong in the repository, not left implicit in a merge request
description or a commit message.

## Testing expectations

- Write the test first, for new features and bug fixes alike. Write it
  from the issue, run it, and watch it fail before writing the code that
  makes it pass. Prefer testing observable behavior over
  internal implementation details.
- Where gauntlet's code is copied from mikroview (the application
  gauntlet's auth code was factored out of; see
  [ADR-0001](docs/adr/0001-shared-auth-module.md)), the copied code
  keeps mikroview's original tests rather than being re-tested from
  scratch; only behaviour that differs from mikroview gets a new test. See
  [docs/testing.md](docs/testing.md).

## Secrets

Never commit credentials or real personal data to the repository,
including in test fixtures. See [SECURITY.md](SECURITY.md).

## Security by design

New features are researched before they are designed. That includes a
search for publicly known security flaws (CVEs) in similar software,
and a comparison with designs known to be safe and unsafe. See
[docs/security-by-design.md](docs/security-by-design.md).
