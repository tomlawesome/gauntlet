package gauntlet

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
)

// The lone-admin unlock code (#44). MaxConsecutiveLoginFailures failed
// sign-ins in a row disable an account's local sign-in until an admin
// unlocks it -- and when the account is the admin's own, no other admin
// exists to do it (this package holds exactly one, ErrSingleAdmin). So
// when the store opens and finds that admin disabled, it makes a
// one-time code and announces it in the server's log, as an empty store
// announces its setup code (setupcode.go): taking the code needs access
// to the server, not just its address, which is the trust boundary the
// setup code already rests on.
//
// The code only lifts the disable (owner, 2026-10-02). It is not a
// password reset, an account reset or an admin transfer: the admin then
// signs in as normal, with the password they already have and their
// second factor, and the escalating lockout applies from zero. Whoever
// was guessing gets nothing from it they did not have.
//
// The shape is the setup code's, for the same reasons: made at
// OpenStore, kept in process memory as a SHA-256 hash only (never
// written to the document or anywhere else), announced once, compared in
// constant time, and gone with the process -- a lost code means restart
// and read the log again. It is single use: the check does not spend it,
// but it stops working the moment the admin's sign-in is no longer
// disabled, which is exactly what redeeming it does -- and so does an
// unlock by any other means, in this process (every write re-checks it)
// or another (on the next reload). There is no clock expiry, as there is
// none on the setup code: the code is 80 bits and a gate counts each
// attempt against the client's address.
//
// It is issued only at OpenStore, never on a reload or as the limiter
// disables the account at runtime: the owner's design writes it "at
// startup", and a restart is what an admin who finds themselves disabled
// does to get it.

// UnlockCodeHandler receives the unlock code a store announces when it
// opens with the admin's sign-in disabled -- Options.OnUnlockCode. An
// interface rather than a bare func so that Options stays comparable
// (ADR-0002), as SetupCodeHandler is; UnlockCodeFunc adapts a plain
// function.
type UnlockCodeHandler interface {
	// UnlockCode is called with the disabled admin's username and the
	// code in its display form, xxxx-xxxx-xxxx-xxxx, outside the store's
	// lock.
	UnlockCode(username, code string)
}

// UnlockCodeFunc adapts a function to UnlockCodeHandler.
type UnlockCodeFunc func(username, code string)

// UnlockCode calls f(username, code).
func (f UnlockCodeFunc) UnlockCode(username, code string) { f(username, code) }

// ErrUnlockCodeInvalid is CheckUnlockCode's one refusal, whatever is
// wrong: the code, the username, no code outstanding, or an admin whose
// sign-in is not disabled. One error for all of them, so a caller cannot
// learn from it which account is the admin or whether it is disabled.
var ErrUnlockCodeInvalid = errors.New("gauntlet: the username or unlock code is wrong -- the current code, if any, is in the server's log")

// unlockCodeLogLine is what Options.Log carries when
// Options.OnUnlockCode is not set. One line, at Warn, like the setup
// code's: until it is used, anyone who reads it can lift the disable
// (though not sign in).
func unlockCodeLogLine(username, code string) string {
	return fmt.Sprintf("sign-in for the admin account %q is disabled after %d failed attempts in a row, and no other admin can unlock it -- "+
		"lift the disable with unlock code %s (valid until the account is unlocked or this process restarts; "+
		"the admin then signs in with their existing password and second factor)",
		username, MaxConsecutiveLoginFailures, code)
}

// lockedOutAdmin returns the admin account whose local sign-in is
// disabled when no admin account remains that is not -- the case where
// nobody can use the admin unlock route -- or nil.
//
// This package holds exactly one admin, so today that is "the admin, if
// disabled"; the loop says the rule rather than the cardinality, as
// HasLocalAdmin does, so a second admin able to unlock the first would
// mean no code. With several all disabled, the first by username gets
// it, deterministically.
func (st *storeState) lockedOutAdmin() *User {
	var out *User
	for _, u := range st.byID {
		if u.Role != RoleAdmin {
			continue
		}
		if u.LoginDisabledAt.IsZero() {
			return nil
		}
		if out == nil || u.Username < out.Username {
			out = u
		}
	}
	return out
}

// issueUnlockCodeLocked makes a new code if the store opened with a
// locked-out admin (lockedOutAdmin) and is persisted, and returns the
// admin's username and the code's display form; ("", "") when none was
// made. The caller announces it after releasing s.mu, so
// Options.OnUnlockCode never runs under the store's lock. Called only
// from OpenStore.
func (s *Store) issueUnlockCodeLocked() (username, code string) {
	if !s.Persisted() || s.hasRefusedVersion {
		s.unlockCodeHash, s.unlockCodeFor = nil, ""
		return "", ""
	}
	admin := s.lockedOutAdmin()
	if admin == nil {
		s.unlockCodeHash, s.unlockCodeFor = nil, ""
		return "", ""
	}
	if s.unlockCodeHash != nil && s.unlockCodeFor == admin.ID {
		return "", ""
	}
	// The setup code's generator: same alphabet, length and grouping
	// (80 bits), and only its hash is kept.
	display, hash := newSetupCode()
	s.unlockCodeHash, s.unlockCodeFor = hash, admin.ID
	return admin.Username, display
}

// retireUnlockCodeLocked ends the outstanding code once the account it
// was made for is no longer the locked-out admin: unlocked, by the code
// or any other way, or no longer the admin at all. Called wherever this
// store installs a state -- a write (mutateLocked) or a load
// (applyLoaded) -- so the code cannot outlive the disable it was for and
// come back to life if the account is disabled again later.
func (s *Store) retireUnlockCodeLocked() {
	if s.unlockCodeHash == nil {
		return
	}
	if admin := s.lockedOutAdmin(); admin == nil || admin.ID != s.unlockCodeFor {
		s.unlockCodeHash, s.unlockCodeFor = nil, ""
	}
}

// announceUnlockCode hands a freshly issued code to the application:
// through Options.OnUnlockCode when set, otherwise as one Warn line on
// Options.Log. Both unset means nobody sees it, which fails closed --
// the admin stays disabled -- rather than open.
func (s *Store) announceUnlockCode(username, code string) {
	if code == "" {
		return
	}
	if s.onUnlockCode != nil {
		s.onUnlockCode.UnlockCode(username, code)
		return
	}
	if s.log != nil {
		s.log.Warn(unlockCodeLogLine(username, code))
	}
}

// CheckUnlockCode reports whether code is the unlock code this process
// announced, and username names the locked-out admin it was made for.
// On success it returns that account, with its credentials blanked, for
// the caller to unlock and record: LoginLimiter.UnlockLogin in a process
// with a limiter (as gate does), Store.UnlockLogin otherwise. The check
// does not spend the code; that unlock does, by ending the disable the
// code exists for (retireUnlockCodeLocked) -- so two simultaneous
// correct attempts both unlock the same account, which is harmless.
//
// The code is typed with or without dashes, in either case. Every
// refusal is ErrUnlockCodeInvalid, whatever is wrong (see there), and
// the comparisons all run whichever fails, so neither the error nor its
// timing says which.
//
// The code only lifts the disable. Nothing here or in the unlock touches
// the password, the second factors, the sessions or the role.
//
// A gate calls this before anything costly and counts the attempt
// against the client's address with the login limiter, as it does the
// setup code: at 80 bits the limiter is there to notice probing, not to
// make guessing infeasible.
func (s *Store) CheckUnlockCode(username, code string) (*User, error) {
	// An unlock in another process retires the code here too.
	s.reloadIfStale()
	sum := sha256.Sum256([]byte(NormaliseResetCode(code)))

	s.mu.RLock()
	defer s.mu.RUnlock()
	admin := s.lockedOutAdmin()
	want := s.unlockCodeHash
	if want == nil {
		want = make([]byte, sha256.Size) // compared anyway; never a match on its own
	}
	codeOK := subtle.ConstantTimeCompare(sum[:], want) == 1 && s.unlockCodeHash != nil
	adminOK := admin != nil && admin.ID == s.unlockCodeFor && !s.hasRefusedVersion
	nameOK := admin != nil && s.byName[strings.ToLower(username)] == admin.ID
	if !codeOK || !adminOK || !nameOK {
		return nil, ErrUnlockCodeInvalid
	}
	cp := *admin
	cp.blankCredentials()
	return &cp, nil
}
