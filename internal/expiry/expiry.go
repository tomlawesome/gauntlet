// Package expiry is the one rule every sealed ticket in this module is
// judged by: a ticket issued at some instant with some life is valid only
// while now is before issuedAt+life, and refused from that instant on.
// That is the shape RFC 7519 §4.1.4 gives a JWT's "exp" claim: the token
// "MUST NOT be accepted for processing" on or after its expiration time.
//
// The pending-login cookie and the OIDC flow state used to accept a
// ticket at exactly its maximum age while the confirm and escape tickets
// refused it, and each spent-set claim restated its own expiry beside
// them (#90). Every check and every spent.Claim forget time now comes
// from here, so the instant a ticket stops opening and the instant its
// one-time ID may be forgotten are the same instant by construction.
package expiry

import "time"

// At is the instant a ticket issued at issuedAt with the given life
// expires: the first instant at which it is refused. It is also the
// forget time a caller passes to spent.Claim for that ticket's ID.
func At(issuedAt time.Time, life time.Duration) time.Time {
	return issuedAt.Add(life)
}

// Expired reports whether a ticket issued at issuedAt with the given life
// is no longer valid at now: true when now is not before At(issuedAt,
// life), so the expiry instant itself is already too late. A zero life
// is expired the moment it is issued.
func Expired(issuedAt time.Time, life time.Duration, now time.Time) bool {
	return !now.Before(At(issuedAt, life))
}
