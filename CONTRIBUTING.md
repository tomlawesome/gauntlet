# Contributing

Gauntlet is a small, solo-maintained library. This document records how
the maintainer works in this repository, so expectations are explicit.

**Outside merge requests are not accepted.** Issues are read and are
information for the maintainer, not work items taken from outside
contributors.

## Branching

Branch from `dev` and send merge requests to `dev`, the default branch.
The repository also has `preview` and `main` branches, which CI copies
to the GitHub mirror; only the owner promotes work into them, `dev` to
`preview` to `main`, by merge request. Never branch from them or send
work to them. A release is a version tag on `main`, created by a button
in the `main` pipeline; `dev` and `preview` are not releases. See
[docs/releasing.md](docs/releasing.md).

## Before starting work

These steps are for the maintainer and anyone the maintainer has
invited.

If the work isn't already an issue, open one first: decisions and scope
belong in the repository, not left implicit in a merge request
description or a commit message.

## Testing expectations

- New behavior needs a test that would fail without it -- prefer testing
  observable behavior over internal implementation details.
- A bug fix should include a regression test reproducing the bug where
  practical.
- Where gauntlet's code is copied from mikroview (the application
  gauntlet's auth code was factored out of; see [the
  README](README.md)), the port carries mikroview's own tests across
  with it. It is not re-tested from scratch. See
  [docs/testing.md](docs/testing.md).

## Secrets

Never commit credentials or real personal data to the repository,
including in test fixtures. See [SECURITY.md](SECURITY.md).

## Security by design

New features are researched before they are designed. That includes a
search for publicly known security flaws (CVEs) in similar software,
and a comparison with designs known to be safe and unsafe. See
[docs/security-by-design.md](docs/security-by-design.md).
