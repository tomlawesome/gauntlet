# ADR-0018: `ProtectBackground`, a protected route that counts as no activity

**Status:** Accepted (design decision on #126, 2026-11-18)
**Date:** 2026-11-23
**Relates to:** #126 (this change), #104 and ADR-0016 (the read-only
check and `decideAccess`), ADR-0002 (compatibility), birdcage #190

## Context

An application that polls its own API (birdcage's dashboard, every 30 s)
through `Protect` slides the session's idle expiry on every request, so an
untouched tab stays signed in until the 24-hour ceiling instead of timing
out after the idle limit. NIST SP 800-63B measures inactivity by the
person, not by traffic the application makes for itself. ADR-0016 solved
this for an already-open response; an ordinary request needs the same.

## Decision

Pattern: **one decision function, thin wrappers that choose a mode**, as
`Protect` and `StillSignedIn` already share `decideAccess` (ADR-0016).

Add `func (g *Gate) ProtectBackground(next http.Handler) http.Handler`:
`Protect` with `decideAccess(r, now, false)`. Every refusal, door and
dispatch is identical; the session is read with `Sessions.Peek` and a
bearer token with `Tokens.Peek`, so `ExpiresAt` and `LastUsedAt` do not
move and nothing is written. A session issued before `SessionCutoff` is
refused but not revoked; the next `Protect` request revokes it. An
idle-expired session is refused 401 `sign-in-required`.

The application decides which routes are background by choosing the
wrapper. Gauntlet reads no header for it: a header is the client's to set.

Rejected: a variadic option on `Protect` (changes its type and breaks
callers that mount `g.Protect` as a `func(http.Handler) http.Handler`),
and a per-request marker (still needs every route wrapped, and a header
is client-controlled).

## Consequences

- Additive under ADR-0002: a new method, nothing else changes.
- A refusal cannot exist in one wrapper and not the other.
- The application must choose carefully: a route marked background never
  keeps a session awake.
