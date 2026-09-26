# Security by design

Gauntlet's copy of the policy shared with mikroview and birdcage,
shortened to what applies to a library with no network listener, no
lures and no infrastructure of its own.

Every new feature is **researched before it is designed** -- not designed
and then reviewed. A security review at the end can only find flaws in
the architecture already chosen; research done first changes which
architecture gets chosen.

## What "researched" means here

Four things, all required, before an implementation plan is written.

1. **Research first, plan second.** The output of research is expected to
   change the design; if it never does, the research wasn't real.
2. **Search CVEs explicitly**, for every dependency and pattern the
   feature touches -- against the Go vulnerability database
   (`vuln.go.dev`) and the GitHub Advisory Database, reading the
   authoritative record rather than secondary coverage of it.
3. **Compare against known secure and insecure architectures.** Find who
   has built this before and what went wrong for them.
4. **Treat industry norms as direction, not proof.** A norm carries real
   weight but is a starting point to verify, not a conclusion to accept.

Because this module's compromise compromises every application that
imports it at once, the bar is higher, not lower, than a single
application's own feature: a mistake here ships everywhere gauntlet is
used.

## Minimum bar for a feature issue

Before implementation starts, the issue records:

- the **threat model** -- what an attacker gains if this component is
  compromised, stated concretely
- **CVEs and prior incidents** found, with links to the authoritative
  records
- **what the research changed** about the design, or an explicit note
  that it confirmed it
- **fail-closed behaviour** for every error path
- **what is deliberately not being done**, and why

Anything contested or uncertain is written down as contested, not
silently resolved in one direction.

## Verification standard

A finding is not acted on until it is reproduced -- research, including
research from an automated agent, is a lead, not a conclusion. Where a
fix is made, a test proves the flaw existed first.
