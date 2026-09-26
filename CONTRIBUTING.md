# Contributing

Gauntlet is a small, solo-maintained library. This document records how
the maintainer works in this repository, so expectations are explicit.

**Outside merge requests are not accepted.** Issues are read and are
information for the maintainer, not work items taken from outside
contributors.

## Branching

Branch from and target `dev` for issue work. `dev` is the default branch;
there is no `preview`/`main` promotion pipeline here -- a tagged release
is the promotion, not a protected branch.

## Before starting work

If what you want to do isn't already an issue, open one first: decisions
and scope belong in the repository, not left implicit in a merge request
description or a commit message.

## Testing expectations

- New behavior needs a test that would fail without it -- prefer testing
  observable behavior over internal implementation details.
- A bug fix should include a regression test reproducing the bug where
  practical.
- Where gauntlet's code is copied from mikroview's, the port carries
  mikroview's own tests across with it rather than being re-tested from
  scratch. See [docs/testing.md](docs/testing.md).

## Secrets

Never commit credentials or real personal data to the repository,
including in test fixtures. See [SECURITY.md](SECURITY.md).

## Security by design

New features are researched before they are designed -- including an
explicit CVE search and a comparison against known secure and insecure
implementations. See
[docs/security-by-design.md](docs/security-by-design.md).
