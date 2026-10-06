# ADR-0009: Unusual sign-ins: judge, flag, confirm or block

**Status:** Accepted (owner decisions 2026-10-04 on #55)
**Date:** 2026-10-04
**Amended by:** #65 (the `prove` action, decision 10; owner answers
2026-10-05)
**Relates to:** #55 (this change), #44 (the known-browser memory it
judges against), #53 and ADR-0006 (the sign-in history it adds to),
#54 and ADR-0008 (the country it judges against), #73 (the
account-event hook it is told through, folded in after this design was
settled), #65

## Context

A sign-in that gets the password and the second factor right is not
always the account's owner: a stolen password reused elsewhere, or a
session cookie copied, still has to pass this module's door, but a
brand-new browser or a login from the other side of the world is a
sign something is wrong even when the credential is right. Mikroview
and birdcage have no way to notice that today. #44 already remembers a
browser that completed a sign-in, for the known-browser allowance
during a lockout; #54 already records the country a sign-in came from.
#55 asks gauntlet to judge a completed sign-in against what the account
remembers, and let the application decide what happens next.

## Decision

1. **Three signals, raised only against something remembered.**
   `new-browser`, `new-country` and `impossible-travel`
   (`gauntlet.SignInSignals`, a bit set, fixed order). Each is raised
   only when the account already remembers something of that kind and
   this sign-in does not match it: an account that remembers nothing of
   a kind remembers this sign-in instead and raises nothing. That
   covers a new account's first sign-in, every existing account's first
   sign-in after the upgrade, and the first sign-in after a reset code
   or sign out everywhere, without a special case for any of them.
2. **Judged once, after every credential and before any session
   exists.** The one-step password path, the second-factor step and the
   SSO callback's sign-in branch each judge (`Store.JudgeSignIn`,
   read-only). Every other session issue -- register, a password
   change, TOTP or recovery-code confirm, sign out everywhere, an SSO
   link -- never judges, since its caller already holds a session or is
   the first account, but still remembers (decision 3).
3. **Memory on the account record, accounts document version 8.**
   `User.SeenCountries` keeps up to three country codes with a
   last-seen time, 90 days each; `User.LastPlace` keeps the one latest
   located sign-in's coordinates, accuracy radius and time -- a point,
   not a trail. Both are cleared wherever known browsers are cleared
   (sign out everywhere, an admin reset code, account deletion): "sign
   out everywhere forgets what the account trusts" already governs the
   known-browser list, and the same reasoning applies to a country or a
   place.
4. **The known-browser cookie carries one token per account.** Today's
   cookie holds one token for the last account that completed a sign-in
   in that browser, so a browser shared by two accounts looks new to
   whichever one is switched to. It now holds up to four tokens, joined
   by a character base64url never produces, one issued per account; a
   one-token cookie from before this change still reads as a list of
   one.
5. **Settings decide first; an optional `Decide` function can overrule
   them, fixed 3 seconds, fails closed.** `gate.Config.UnusualSignIns`
   (`UnusualSignInPolicy`) sets a base action and, optionally, one
   override per signal; the strictest resolved action among the
   signals raised wins. If `Decide` is set it is asked once, with the
   settings' answer and the case (account, signals, country, client);
   whatever it returns replaces that answer. It runs under a fixed
   `DecideTimeout` (3 seconds, not configurable, so a function cannot
   quietly make itself the slow path on every login) and may do local
   I/O within that. A panic, an error, a timeout, or an answer that is
   not one of the actions (five since #65) refuses the sign-in (`block`): a check
   that lets people in when it breaks would make breaking it the
   attack.
6. **Four actions (five since #65, decision 10).** `off` drops the
   signal entirely (nothing shown, told or refused, though memory still accumulates). `flag`, the
   default, lets the sign-in complete and marks it on the session, the
   sign-in history and the audit record: every local-password account
   already passes a mandatory second factor (#49), so "end this
   session" is the remedy, and a blocking default on an application
   with nothing wired to deliver a code would lock every second browser
   out. `confirm` holds the sign-in for a code the application
   delivers, typed into the same sign-in page (GitHub's shape).
   `block` refuses this one attempt, never the account: the real owner
   signs in from a browser or country the account already trusts, or an
   administrator issues a reset code, which clears the trust and sets a
   fresh baseline.
7. **Impossible travel needs the City file, MaxMind only.** `geoip`
   gains a `GeoLite2-City` edition and a `Locate` lookup
   (`gate.Config.Locate`); the signal compares the great-circle distance
   between the account's last located sign-in and this one, minus both
   lookups' accuracy radii, against `ImpossibleTravelSpeedKmh` (800,
   Okta's number) over the elapsed time. IPinfo Lite has no coordinates,
   so the signal can never fire under it.
8. **One hook each for a notice and a code, not a dedicated
   notifier.** The application is told through `gate.Config.Notices`
   (`AccountNotifier`), the same hook #73 later generalised to every
   account event: an unusual sign-in flagged or blocked is one more
   `NoticeKind` (`NoticeUnusualSignIn`, detail `UnusualSignInDetail`),
   asked at most once per account per hour for `flag` and `block`
   together. A confirmation code is different on purpose and travels
   through its own field, `gate.Config.DeliverConfirmCode`
   (`ConfirmCode`): called synchronously, before the sign-in is
   answered, since no code reaching anyone means none is owed, with no
   rate limit -- the notice is the code the person is waiting for.
   (This design first specified a single-purpose `UnusualSignInNotifier`
   field, `Config.NotifyUnusualSignIn`; #73, decided and built the next
   day, replaced it with the two hooks above before this issue's code
   shipped, so there never was a release carrying the single-purpose
   field.)
9. **The answer says only what is needed.** Before a session exists,
   nothing says which signal was raised, which country the account
   uses, or, under `confirm`, which address the code went to: the 200,
   403 or confirm-challenge responses already confirm to a holder of
   the right credential that a policy exists, which is as much as a
   stranger needs to know and the owner already knows.

10. **Amended by #65: a fifth action, `prove`.** Step-up authentication
    with a phishing-resistant factor: the sign-in is held, like
    `confirm`, until the browser answers a passkey assertion for the
    same account, which a mailed code cannot match (a code can be typed
    into a look-alike page; an origin-bound key cannot). `prove` ranks
    between `confirm` and `block`, is settable per signal and
    returnable from `Decide`, and `New` validates it like the others; it
    needs nothing wired, since it falls back (below).
    - **It resolves per sign-in.** A sign-in whose method is `passkey` or
      `passkey_alone` is already proved and is flagged. An account with
      no passkey usable at this address (current RP ID, none on hold) is
      held for a code (`confirm`) when `Config.DeliverConfirmCode` is
      set, else refused (`block`) -- the owner's answer on #65, not
      `flag`, since a policy that asks for proof must not fall open.
      `UnusualSignInCase.CanProve` tells `Decide` which applies.
    - **It reuses the confirm ticket.** `confirmLoginState` gains
      `Prove`, with no code hash; the 200 is `{"prove": "passkey",
      "passkeyOrigin": ...}` where confirm's is `{"confirm": true}`, and
      the SSO callback redirects with `?prove=1` where confirm's has
      `?confirm=1`. `POST /api/auth/login/prove/begin` and `POST
      /api/auth/login/prove {assertion}` run the existing
      non-discoverable ceremony for that account (`BeginLogin`,
      `FinishLogin`; user verification preferred, not required:
      possession of the key is the point, so a security key without a PIN
      qualifies), the post-verify step #77 extracted
      (`recordVerifiedAssertion`) and the login limiter as confirm does.
      A wrong, another account's or failed assertion is handled as a
      wrong code is: 401, the reservation kept, counted as a failed
      second factor. Success records `Confirmed` with `action=prove`.
      The two ticket kinds are not interchangeable.
    - **The block reason `prove-failed`** is a ticket that could not be
      made, as `notify-failed` is a code that could not be delivered.
    - **Standard pattern:** step-up authentication (ASVS 5.0 7.5.3), as
      ADR-0010's role grant.

## Rejected options

- **A country-only travel rule**, comparing only the country between
  two sign-ins. Rejected: that is not travel -- a mobile carrier's exit
  point, a VPN toggle or the Eurostar all cross a border inside an
  hour. Microsoft's own country-level version needs a bordering-country
  exemption to be usable at all, and even then only alerts; it does not
  block.
- **A held sign-in released by a link or an administrator**, rather
  than a code typed into the same page. Rejected: no major system holds
  an attempt open for the person to come back to later, and nobody
  should be made to sign in twice for what one confirmation step
  already proves.
- **`admin` role approval** of a held sign-in. Dropped for the same
  reason as the previous option: it is the same "come back later" shape
  with an administrator in place of a link.
- **Fail open on a failing `Decide`.** Rejected: a hook that lets
  people in when it fails makes breaking the hook the attack; failing
  closed costs an occasional extra confirmation or refusal, never an
  admitted stranger.
- **`Decide` alone, with no settings underneath.** Rejected: both
  applications would end up writing the same action-per-signal switch
  inside their own `Decide`, which the settings already give them for
  free; `Decide` is for the cases the settings cannot express, such as
  the lone admin (§17a of the design note).
- **A four-way table of per-role fields** instead of one policy plus
  `Decide`. Rejected: it is surface without a user -- nothing asked for
  per-role defaults, and `Decide` already sees the account's role when
  a per-role rule is actually needed.
- **A method added to the existing `Notifier` interface.** Rejected:
  adding a method to an exported interface breaks every type that
  already implements it. A separate hook keeps the seam visible and
  additive, which is why #73 later folded unusual sign-ins into a
  typed-detail hook rather than a new interface method either.
- **A `GET` link that releases a held sign-in.** Rejected: mail
  scanners and link previewers fetch `GET` links automatically, which
  would release a confirm-held sign-in nobody asked for.
- **Keeping the memory in the sign-in history, or in process memory
  only.** Rejected: the history is optional and capped, so an account
  without one configured could never judge anything, and memory alone
  would make every account look new again after every restart.
- **Judging only after the password step**, before any second factor.
  Rejected: the password step alone is not yet AAL2, and judging there
  would mean raising a signal, and possibly blocking, before the
  account has proven the one thing its door actually requires.
- **A blocking default.** Rejected: on a deployment with nothing wired
  to deliver a confirmation code, a default of `block` would lock out
  the owner's own second browser on its first unusual sign-in.
- **A slice of signals on `SessionClient`.** Rejected: a slice field
  would make `SessionClient` non-comparable, which `scripts/apidiff.sh`
  reports as a breaking change; a bit set (`SignInSignals`) keeps it
  comparable.

## Consequences

- An application wires `Config.UnusualSignIns`, and optionally
  `Config.Locate` and `Config.DeliverConfirmCode`, to get anything
  beyond the default `flag`; one with nothing wired still gets `flag`
  on every signal it can raise (every one but `impossible-travel`,
  which needs `Config.Locate`).
- The accounts document is version 8; an older build refuses it. The
  sign-in history document is version 3, for the stored `unusual` and
  `confirmed` fields; an older build refuses that too.
- Gauntlet holds one admin account design decision open: under `block`,
  a lone admin signing in from an untrusted browser and place with
  nobody else to issue them a reset code is refused until they reach a
  trusted browser. The first remedy is to add a second admin (ADR-0010,
  #67): another admin can issue the reset code, so the risk is only the
  lone admin's. Shipped as designed, documented (design.md §4's
  pitfalls table); the follow-up, a server-log escape code, is
  [ADR-0011](0011-escape-code.md) (#66).
- An SSO-only account under `block` has no administrator remedy in
  this release: it is refused at the SSO callback (`ssoError=refused`),
  and the reset code needs a local password, so the way back is a
  browser or place it has signed in from before. An admin "allow the
  next sign-in for a short window" is a next-release issue (#79).
- `geoip` gains a dependency on the City file's larger download (tens
  of megabytes rather than a few) wherever `EditionCity` is chosen; the
  128 MiB cap and the existing refresh schedule are unchanged.
