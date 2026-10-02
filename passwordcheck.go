package gauntlet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/tomlawesome/gauntlet/blocklist"
)

// The checks a new local password passes before it is hashed (#43):
// the length (minPasswordLength), then the account's own context, then
// the common-password list, then -- when the application opted in --
// the live Have I Been Pwned check. Cheapest first, so a password
// refused locally never leaves the process. NIST SP 800-63B-4 §3.1.1.2
// makes the list a SHALL and asks that the refusal say why; ASVS 5.0
// V6.2.4, V6.2.11, V6.2.12 and V6.1.2 ask for the same three sources.

var (
	// ErrPasswordBlocked is returned by Register, CreateUser and
	// SetPassword for a password on the common-password list
	// (Options.PasswordBlocklist), in any case, or one the live breach
	// check (Options.BreachCheck) found in a known breach.
	ErrPasswordBlocked = errors.New("gauntlet: that password is on a list of common or breached passwords -- choose a different one")
	// ErrPasswordContext is returned by Register, CreateUser and
	// SetPassword for a password that is the account's username or
	// Options.ProductName, give or take case, punctuation and digits
	// around it (PasswordMatchesContext). gate also refuses its
	// Config.ProductName with it.
	ErrPasswordContext = errors.New("gauntlet: that password is too close to the username or the product's name -- choose a different one")
)

// PasswordList is a set of passwords no account may choose.
// *blocklist.List (blocklist.Embedded) and *blocklist.Refresher both
// satisfy it. Contains is asked about the password as typed and in
// lower case, so a list holds each entry once, in lower case, as
// HIBP's most common entries already are.
type PasswordList interface {
	Contains(password string) bool
}

// BreachChecker answers whether a password has appeared in a known
// breach -- in practice *blocklist.PwnedChecker, HIBP's k-anonymity
// range API. An error means it could not tell; see Options.BreachCheck
// for what the store does then.
type BreachChecker interface {
	Breached(ctx context.Context, password string) (bool, error)
}

// BreachCheckTimeout bounds every live breach check the store makes,
// whatever the BreachChecker does with its context: a check still
// running when it expires counts as unreachable. Setting a password, or
// signing in on an account owed a recheck, never waits longer than
// this for HIBP.
const BreachCheckTimeout = 5 * time.Second

// PasswordMatchesContext reports whether password is one of words, or
// a simple derivative of one: compared in lower case, with everything
// but letters and digits left out, and with leading and trailing digits
// stripped from both. So for the word "Alice_Liddell", "aliceliddell",
// "Alice.Liddell", "AliceLiddell1990!" and "2024aliceliddell" all
// match, while "alice liddell went down the rabbit hole" does not: the
// check is on the whole password, not a substring of it. A password
// with no letters matches only a word with the same digits. An empty
// word matches nothing.
func PasswordMatchesContext(password string, words ...string) bool {
	p := contextForm(password)
	if p == "" {
		return false
	}
	pCore := strings.Trim(p, "0123456789")
	for _, w := range words {
		w := contextForm(w)
		if w == "" {
			continue
		}
		wCore := strings.Trim(w, "0123456789")
		switch {
		case p == w:
			return true
		case pCore != "" && pCore == wCore:
			return true
		}
	}
	return false
}

// contextForm is s in lower case with only its letters and digits.
func contextForm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkNewPassword runs the checks above for username's new password,
// after the length check. pending is true when the password passed
// every local check but the live breach check could not answer: the
// password is accepted, the miss logged, and the account marked
// (User.BreachCheckPending) for a recheck at its next sign-in (owner,
// 2026-10-02, on #43).
func (s *Store) checkNewPassword(username, password string) (pending bool, err error) {
	if PasswordMatchesContext(password, username, s.productName) {
		return false, ErrPasswordContext
	}
	if s.passwordList.Contains(password) || s.passwordList.Contains(strings.ToLower(password)) {
		return false, ErrPasswordBlocked
	}
	if s.breachCheck == nil {
		return false, nil
	}
	breached, err := s.breached(password)
	if err != nil {
		s.warn(fmt.Sprintf("breach check unavailable for %q's new password, accepted against the built-in list and marked for a recheck at its next sign-in: %v", username, err))
		return true, nil
	}
	if breached {
		return false, ErrPasswordBlocked
	}
	return false, nil
}

// breached asks the BreachChecker about password, giving up after
// s.breachTimeout even if the checker ignores its context: the call
// runs in its own goroutine, which is left to finish on its own.
func (s *Store) breached(password string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.breachTimeout)
	defer cancel()
	type answer struct {
		breached bool
		err      error
	}
	done := make(chan answer, 1)
	go func() {
		b, err := s.breachCheck.Breached(ctx, password)
		done <- answer{b, err}
	}()
	select {
	case a := <-done:
		return a.breached, a.err
	case <-ctx.Done():
		return false, fmt.Errorf("no answer within %v: %w", s.breachTimeout, ctx.Err())
	}
}

// recheckBreach is the recheck at sign-in: u has just signed in with
// password and is owed a breach check (BreachCheckPending). A hit
// requires a password change, in one write that also ends every
// session the account holds, as requirePasswordChange does and for the
// same reason: the change-password door asks for no current password
// while the flag is set. A clean answer clears the mark. No answer
// leaves it, and the sign-in goes ahead either way. The write applies
// only while the account still has the password that was checked.
//
// Called by Authenticate after the password has been verified, never
// with a wrong one, and outside the lock, since the check is a network
// call.
func (s *Store) recheckBreach(u *User, password string, now time.Time) *User {
	breached, err := s.breached(password)
	if err != nil {
		s.warn(fmt.Sprintf("breach recheck at sign-in unavailable for %q, still owed: %v", u.Username, err))
		return u
	}
	var updated User
	err = s.mutate(func(st *storeState) error {
		cur, ok := st.byID[u.ID]
		if !ok || cur.PasswordHash != u.PasswordHash || !cur.BreachCheckPending {
			return errNoChange
		}
		cur.BreachCheckPending = false
		if breached {
			cur.MustChangePassword = true
			cur.SessionsEndedAt = now
		}
		updated = *cur
		return nil
	})
	if err != nil {
		s.warn(fmt.Sprintf("saving the breach recheck for %q failed, still owed: %v", u.Username, err))
		return u
	}
	if updated.ID == "" {
		return u
	}
	if breached {
		s.warn(fmt.Sprintf("%q signed in with a password found in a known breach; a password change is now required", u.Username))
	}
	return &updated
}

// warn logs msg at Warn when the store has a log.
func (s *Store) warn(msg string) {
	if s.log != nil {
		s.log.Warn(msg)
	}
}

// passwordListOrEmbedded is opts' list, or the one compiled into this
// release when there is none.
func passwordListOrEmbedded(l PasswordList) PasswordList {
	if l == nil {
		return blocklist.Embedded()
	}
	return l
}
