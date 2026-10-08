package gauntlet

import "time"

// The escape code (#66, ADR-0011): a lone admin whom the unusual-sign-in
// policy refuses (block) from a browser the account has never used has
// nobody to ask. gate lets that one attempt through with a code written
// to the server's own log -- host access, not the address -- the same
// break-glass shape as the setup and unlock codes. The code itself lives
// only in gate's sealed ticket; this file holds what the root package
// contributes: the generator the three codes share and the question "can
// another admin act instead?".

// NewOneTimeCode returns a fresh one-time code in its display form,
// xxxx-xxxx-xxxx-xxxx, and the canonical form (no dashes, upper case) it
// is hashed and compared in. It is the generator the setup and unlock
// codes use: 80 bits from crypto/rand over the reset-code alphabet, typed
// back in either case with or without the dashes (NormaliseResetCode).
// The caller keeps only a hash of the canonical form.
func NewOneTimeCode() (display, canonical string) {
	canonical = newResetCode()
	return FormatResetCode(canonical), canonical
}

// OtherAdminCanAct reports whether an admin other than userID could act
// at now, so that the lone-admin escape (#66) is not needed: some other
// account holds the admin role and its local sign-in is not disabled
// (User.LoginDisabled, which lifts after LoginDisableDuration, #70).
// Locked out for a while does not count against it: a lockout ends
// within the hour. Another admin who would be refused by the
// unusual-sign-in policy as well cannot be known here and still counts as
// able.
//
// It is the question lockedOutAdmin asks of the whole store, asked of
// every admin but one, and at a given time because a disable now ends by
// itself.
func (s *Store) OtherAdminCanAct(userID string, now time.Time) bool {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.byID {
		if u.ID != userID && u.Role == RoleAdmin && !u.LoginDisabled(now) {
			return true
		}
	}
	return false
}
