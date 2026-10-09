package gauntlet

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// The first admin is created with a one-time setup code (issue #37,
// ADR-0003). An empty accounts store is not only a fresh install: a
// deleted file, a wrong path or a botched restore all start a server
// with no accounts, and until this code existed the first visitor took
// admin. Now whoever registers first has to show the code, and the code
// is only ever shown in the server's own log -- so taking admin needs
// access to the server, not just its address.
//
// The shape follows ORBIT's ADR-0022, the owner's existing version of
// this: made when a persisted store opens empty, kept in process memory
// only (never written to the document or anywhere else), announced once,
// compared in constant time, inert as soon as any account exists, and
// gone with the process -- a lost code means restart and read the log
// again. There is no clock expiry and no CLI to print it: a CLI's own
// process cannot see the server's code, and CreateUser does not make
// admins, so a CLI opening the store for one command passes an
// Options.OnSetupCode that does nothing.
//
// The code is checked here, in the store, so every HTTP caller shares
// one check; Register itself stays the host-side primitive gate calls
// after it.

// SetupCodeHandler receives the setup code an empty store announces --
// Options.OnSetupCode. An interface rather than a bare func so that
// Options stays comparable, as it was in v0.1.0 (ADR-0002); SetupCodeFunc
// adapts a plain function, as http.HandlerFunc does.
type SetupCodeHandler interface {
	// SetupCode is called with the code in its display form,
	// xxxx-xxxx-xxxx-xxxx, outside the store's lock.
	SetupCode(code string)
}

// SetupCodeFunc adapts a function to SetupCodeHandler.
type SetupCodeFunc func(code string)

// SetupCode calls f(code).
func (f SetupCodeFunc) SetupCode(code string) { f(code) }

var (
	// ErrSetupCodeInvalid is CheckSetupCode's refusal of a code that
	// does not match the one this process announced, including when it
	// announced none.
	ErrSetupCodeInvalid = errors.New("gauntlet: the setup code is wrong -- the current one is in the server's log")
	// ErrSetupRequired is FindOrCreateOIDCUser's refusal while no
	// account exists: the first admin is a local account created with
	// the setup code, never an identity an outside provider vouches for.
	ErrSetupRequired = errors.New("gauntlet: no account exists yet -- the first admin is created with the setup code before anyone can sign in through SSO")
)

// setupCodeLogLine is what Options.Log carries when Options.OnSetupCode
// is not set. One line, at Warn so it is seen at any ordinary log level:
// until someone uses it, anyone who reads it is the next admin.
func setupCodeLogLine(code string) string {
	return fmt.Sprintf("no account exists yet -- create the first admin with setup code %s (valid until an account exists or this process restarts)", code)
}

// newSetupCode returns a fresh code in display form and the hash kept
// to check it against. Same alphabet, length and grouping as a reset
// code (80 bits, xxxx-xxxx-xxxx-xxxx), typed back with or without the
// dashes and in either case. Only the hash is kept, so nothing in this
// process can print the code again after announcing it.
func newSetupCode() (display string, hash []byte) {
	display, canonical := NewOneTimeCode() // also the escape code's (#66)
	sum := sha256.Sum256([]byte(canonical))
	return display, sum[:]
}

// setupCodeMatches reports whether typed is the code whose hash is want:
// the SHA-256 of its normalised form, compared in constant time. It is
// the one check for both codes newSetupCode makes, the setup code and
// the unlock code, which used to spell it out each (#90). A nil want (no
// code issued) never matches, but is still compared against a zero hash,
// so a caller that runs every check whichever fails (CheckUnlockCode)
// takes the same time either way.
func setupCodeMatches(typed string, want []byte) bool {
	sum := sha256.Sum256([]byte(normaliseCode(typed)))
	issued := want != nil
	if !issued {
		want = make([]byte, sha256.Size) // compared anyway; never a match on its own
	}
	return subtle.ConstantTimeCompare(sum[:], want) == 1 && issued
}

// issueSetupCodeLocked makes a new code if the store needs one -- empty,
// persisted, and not sitting behind a document it refused to apply --
// and retires the current one otherwise. Returns the display form of a
// code just made, or "" when none was: the caller announces it after
// releasing s.mu, so Options.OnSetupCode never runs under the store's
// lock.
func (s *Store) issueSetupCodeLocked() string {
	if !s.Persisted() || len(s.byID) > 0 || s.hasRefusedVersion {
		s.setupCodeHash = nil
		return ""
	}
	if s.setupCodeHash != nil {
		return ""
	}
	display, hash := newSetupCode()
	s.setupCodeHash = hash
	return display
}

// announceSetupCode hands a freshly issued code to the application:
// through Options.OnSetupCode when set, otherwise as one Warn line on
// Options.Log. Both unset means nobody sees it, which fails closed --
// no account can be created -- rather than open.
func (s *Store) announceSetupCode(code string) {
	if code == "" {
		return
	}
	if s.onSetupCode != nil {
		s.onSetupCode.SetupCode(code)
		return
	}
	if s.log != nil {
		s.log.Warn(setupCodeLogLine(code))
	}
}

// CheckSetupCode reports whether code is the one this process announced
// for creating the first admin. nil means it is, and Register may go
// ahead; the code is not used up by the check -- it stops working the
// moment an account exists, which is also what makes two simultaneous
// correct attempts end with one admin (Register's own guard decides
// that). Typed with or without dashes, in either case.
//
// ErrSetupCodeInvalid when the code is wrong or none was announced;
// ErrRegistrationClosed once any account exists, or a document holding
// accounts is on disk even though this process refused to apply it;
// ErrNotPersisted when nothing could be set up anyway.
//
// A gate calls this before hashing the password, so a guess costs the
// server nothing but a hash comparison, and counts the attempt against
// the client's address with the login limiter -- the code has 80 bits,
// so the limiter is there to notice probing, not to make guessing
// infeasible.
func (s *Store) CheckSetupCode(code string) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.byID) > 0 || s.hasRefusedVersion {
		return ErrRegistrationClosed
	}
	if !setupCodeMatches(code, s.setupCodeHash) {
		return ErrSetupCodeInvalid
	}
	return nil
}
