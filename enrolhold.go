// Hold until confirmed (#58): an account's first second factor -- its
// first passkey or its first authenticator app -- and the ten recovery
// codes that back it are saved together, in one write, on hold. Neither
// is live until the account's owner confirms they have saved the codes
// (ConfirmHeldEnrolment), which takes both off hold in one more write.
// Saving them together means no crash or failed save can leave a live
// second factor with no recovery codes behind it -- the gap the earlier
// "register now, mint codes in a second write" order had. Holding them
// until confirmed means codes that were never seen (a lost response, a
// closed tab) never become the account's only way back in.
//
// An enrolment not confirmed within HeldEnrolmentLifetime is deleted,
// factor and codes both: lazily, by the next write that starts or
// confirms an enrolment on the account (dropExpiredHold), and refused
// by ConfirmHeldEnrolment. Until then the expired hold is inert: a held
// factor is never in Passkeys, RecoveryCodes or the live TOTP fields,
// so nothing that signs anyone in can reach it.
//
// One enrolment at a time: while one is held, starting another
// (SetPendingTOTPSecretAt, HoldFirstPasskey, HoldFirstTOTP) is refused
// with ErrEnrolmentHeld. A later factor, on an account that already has
// a live one, is never held: it is added live, without codes, since an
// account keeps one set of recovery codes across all its factors.

package gauntlet

import (
	"errors"
	"slices"
	"time"
)

const (
	// HeldEnrolmentLifetime is how long a held first factor waits for
	// its owner to confirm they saved its recovery codes before it is
	// deleted (#58).
	HeldEnrolmentLifetime = 10 * time.Minute
	// TOTPPendingLifetime is how long a scanned but unconfirmed
	// authenticator-app secret (SetPendingTOTPSecretAt) can still be
	// confirmed (#58). After it the secret is treated as absent.
	TOTPPendingLifetime = 10 * time.Minute
)

var (
	// ErrEnrolmentHeld is returned when a second-factor enrolment is
	// started, or a factor confirmed, while another enrolment is on hold
	// waiting for its owner to confirm its recovery codes: one at a time.
	ErrEnrolmentHeld = errors.New("gauntlet: a second factor is waiting for you to confirm you have saved its recovery codes -- confirm it, or wait ten minutes for it to expire, before starting another")
	// ErrSecondFactorExists is returned by HoldFirstPasskey and
	// HoldFirstTOTP when the account already has a live second factor:
	// only the first is held with recovery codes, and a later one is
	// added live (AddPasskey, ConfirmTOTP) without codes.
	ErrSecondFactorExists = errors.New("gauntlet: this account already has a second factor")
	// ErrNoHeldEnrolment is returned by ConfirmHeldEnrolment when
	// nothing is on hold.
	ErrNoHeldEnrolment = errors.New("gauntlet: no second factor is waiting to be confirmed")
	// ErrHeldEnrolmentExpired is returned by ConfirmHeldEnrolment when
	// the enrolment on hold was not confirmed within
	// HeldEnrolmentLifetime. The held factor and its codes are deleted
	// by the same call; the owner enrols again.
	ErrHeldEnrolmentExpired = errors.New("gauntlet: the second factor was not confirmed in time and has been removed -- set it up again")
)

// HeldFactorKind names which kind of second factor a HeldEnrolment
// holds.
type HeldFactorKind string

const (
	// HeldFactorPasskey: HeldEnrolment.Passkey is the held credential.
	HeldFactorPasskey HeldFactorKind = "passkey"
	// HeldFactorTOTP: the held authenticator app is the account's
	// pending TOTPSecret, already proved by a code, whose
	// TOTPConfirmedAt ConfirmHeldEnrolment sets.
	HeldFactorTOTP HeldFactorKind = "totp"
)

// HeldEnrolment is a first second factor and its recovery codes, saved
// on hold until the account's owner confirms (User.HeldEnrolment).
type HeldEnrolment struct {
	Kind HeldFactorKind `json:"kind"`
	// Passkey is the held credential when Kind is HeldFactorPasskey,
	// nil otherwise. Its ID is the credential ID the hold is tied to.
	Passkey *Passkey `json:"passkey,omitempty"`
	// RecoveryCodes are the ten codes minted for this enrolment, hashed
	// as User.RecoveryCodes are, and shown to their owner once when the
	// hold was made. They become User.RecoveryCodes on confirmation.
	RecoveryCodes []RecoveryCode `json:"recoveryCodes"`
	// HeldUntil is when the hold expires: HeldEnrolmentLifetime after it
	// was made.
	HeldUntil time.Time `json:"heldUntil"`
}

func (h *HeldEnrolment) clone() *HeldEnrolment {
	cp := *h
	if h.Passkey != nil {
		pk := h.Passkey.clone()
		cp.Passkey = &pk
	}
	cp.RecoveryCodes = slices.Clone(h.RecoveryCodes)
	return &cp
}

// EnrolmentHeld reports whether u has an enrolment on hold that has not
// yet expired at now.
func (u *User) EnrolmentHeld(now time.Time) bool {
	return u.HeldEnrolment != nil && now.Before(u.HeldEnrolment.HeldUntil)
}

// TOTPPending reports whether u holds a pending (scanned, unconfirmed)
// authenticator-app secret that can still be confirmed at now: set, not
// confirmed, and set less than TOTPPendingLifetime ago.
func (u *User) TOTPPending(now time.Time) bool {
	return u.TOTPSecret != "" && u.TOTPConfirmedAt.IsZero() &&
		now.Before(u.TOTPPendingSince.Add(TOTPPendingLifetime))
}

// dropExpiredHold deletes u's held enrolment if it has expired at now:
// the held factor (a held authenticator app's secret with it) and its
// codes. It reports whether it deleted one. Called inside the ops of
// every write that starts or confirms an enrolment, so an expired hold
// is gone by the time the next one begins.
func dropExpiredHold(u *User, now time.Time) bool {
	if u.HeldEnrolment == nil || now.Before(u.HeldEnrolment.HeldUntil) {
		return false
	}
	clearHold(u)
	return true
}

// clearHold deletes u's held enrolment unconditionally, with a held
// authenticator app's pending secret.
func clearHold(u *User) {
	if u.HeldEnrolment == nil {
		return
	}
	if u.HeldEnrolment.Kind == HeldFactorTOTP && u.TOTPConfirmedAt.IsZero() {
		clearTOTPFields(u)
	}
	u.HeldEnrolment = nil
}

// clearTOTPFields removes every authenticator-app field from u.
func clearTOTPFields(u *User) {
	u.TOTPSecret = ""
	u.TOTPConfirmedAt = time.Time{}
	u.TOTPLastCounter = 0
	u.TOTPPendingSince = time.Time{}
}

// mintRecoveryCodes makes recoveryCodeCount fresh codes: the clear form
// to show their owner once, and the hashes to store. Hashing is slow by
// design (Argon2id), so every caller does this before taking the
// store's lock.
func mintRecoveryCodes() (clear []string, hashed []RecoveryCode, err error) {
	clear = make([]string, recoveryCodeCount)
	hashed = make([]RecoveryCode, recoveryCodeCount)
	for i := range hashed {
		code := newRecoveryCode()
		hash, err := HashPassword(code)
		if err != nil {
			return nil, nil, err
		}
		clear[i] = FormatRecoveryCode(code)
		hashed[i] = RecoveryCode{Hash: hash}
	}
	return clear, hashed, nil
}

// holdRefusal is the refusal a hold for userID would meet at now,
// decided from the account as this store holds it, without writing:
// the refusals the hold's own write makes, asked first so a refused
// hold mints no codes (ten Argon2id hashes, #80). The write decides
// again against the document it saves; this only spares the hashing.
// totpSecret is the secret HoldFirstTOTP checked a code against, or ""
// for a passkey hold.
func (s *Store) holdRefusal(userID, totpSecret string, now time.Time) error {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[userID]
	switch {
	case !ok:
		return ErrUserNotFound
	case u.EnrolmentHeld(now):
		return ErrEnrolmentHeld
	case u.HasSecondFactor():
		return ErrSecondFactorExists
	case totpSecret != "" && (!u.TOTPPending(now) || u.TOTPSecret != totpSecret):
		return ErrNoPendingTOTP
	}
	return nil
}

// HoldFirstPasskey saves pk, userID's first second factor, on hold
// together with ten new recovery codes for it, in one write, and
// returns the stored passkey (its name normalised, as AddPasskey does)
// and the codes in clear, exactly once. Neither is live until
// ConfirmHeldEnrolment; an unconfirmed hold expires at
// now+HeldEnrolmentLifetime.
//
// The codes are minted by this call, for this credential, so they can
// belong to no other registration. Refused with ErrSecondFactorExists
// when the account already has a live second factor (add the passkey
// live with AddPasskey instead), and with ErrEnrolmentHeld while
// another enrolment is on hold. Before either, a name that is not plain
// text is refused with ErrPasskeyNameInvalid. The write deletes an
// expired hold first.
func (s *Store) HoldFirstPasskey(userID string, pk Passkey, now time.Time) (Passkey, []string, error) {
	if err := checkPasskeyName(pk.Name); err != nil {
		return Passkey{}, nil, err
	}
	if !s.Persisted() {
		return Passkey{}, nil, ErrNotPersisted
	}
	if err := s.holdRefusal(userID, "", now); err != nil {
		return Passkey{}, nil, err
	}
	// Hashed before the lock: see mintRecoveryCodes.
	clear, hashed, err := mintRecoveryCodes()
	if err != nil {
		return Passkey{}, nil, err
	}

	s.reloadIfStale()

	// A hold that only exists in memory must not be reported as made:
	// the caller is about to show these codes as the account's only way
	// back in. mutate installs it only once it is saved, and every
	// refusal is decided against the document being saved.
	var held Passkey
	err = s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		dropExpiredHold(u, now)
		if u.HeldEnrolment != nil {
			return ErrEnrolmentHeld
		}
		if u.HasSecondFactor() {
			return ErrSecondFactorExists
		}
		p := pk.clone()
		p.Name = normalisePasskeyName(pk.Name, len(u.Passkeys)+1)
		u.HeldEnrolment = &HeldEnrolment{
			Kind:          HeldFactorPasskey,
			Passkey:       &p,
			RecoveryCodes: slices.Clone(hashed),
			HeldUntil:     now.Add(HeldEnrolmentLifetime),
		}
		held = p.clone()
		return nil
	})
	if err != nil {
		return Passkey{}, nil, err
	}
	return held, clear, nil
}

// HoldFirstTOTP saves userID's pending authenticator app, its first
// second factor, on hold together with ten new recovery codes for it,
// in one write, and returns the codes in clear, exactly once.
// encodedSecret is the secret the caller checked a code against and
// matchedCounter that code's counter (VerifyTOTP); the hold is refused
// with ErrNoPendingTOTP unless that secret is still the one pending and
// still inside TOTPPendingLifetime. The app does not verify a code, and
// the codes redeem nothing, until ConfirmHeldEnrolment; an unconfirmed
// hold expires at now+HeldEnrolmentLifetime and takes the secret with
// it.
//
// Refused with ErrSecondFactorExists when the account already has a
// live second factor (confirm the app live with ConfirmTOTP instead),
// and with ErrEnrolmentHeld while another enrolment is on hold.
func (s *Store) HoldFirstTOTP(userID, encodedSecret string, matchedCounter uint64, now time.Time) ([]string, error) {
	if !s.Persisted() {
		return nil, ErrNotPersisted
	}
	if encodedSecret == "" {
		return nil, ErrNoPendingTOTP
	}
	if err := s.holdRefusal(userID, encodedSecret, now); err != nil {
		return nil, err
	}
	clear, hashed, err := mintRecoveryCodes()
	if err != nil {
		return nil, err
	}

	s.reloadIfStale()

	err = s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		dropExpiredHold(u, now)
		if u.HeldEnrolment != nil {
			return ErrEnrolmentHeld
		}
		if u.HasSecondFactor() {
			return ErrSecondFactorExists
		}
		if !u.TOTPPending(now) || u.TOTPSecret != encodedSecret {
			return ErrNoPendingTOTP
		}
		// Recorded now, not at confirmation: the code that proved the
		// enrolment must not also work as the first sign-in.
		u.TOTPLastCounter = matchedCounter
		u.HeldEnrolment = &HeldEnrolment{
			Kind:          HeldFactorTOTP,
			RecoveryCodes: slices.Clone(hashed),
			HeldUntil:     now.Add(HeldEnrolmentLifetime),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return clear, nil
}

// ConfirmHeldEnrolment takes userID's held enrolment off hold in one
// write: the held passkey joins Passkeys (or the held authenticator app
// is confirmed at now) and the held codes become the account's recovery
// codes. It returns what was confirmed, without the code hashes.
//
// ErrNoHeldEnrolment when nothing is held. ErrHeldEnrolmentExpired when
// the hold expired before now: the held factor and its codes are
// deleted by this same call, and that deletion is saved.
func (s *Store) ConfirmHeldEnrolment(userID string, now time.Time) (HeldEnrolment, error) {
	if !s.Persisted() {
		return HeldEnrolment{}, ErrNotPersisted
	}
	s.reloadIfStale()

	var (
		confirmed HeldEnrolment
		expired   bool
	)
	err := s.mutate(func(st *storeState) error {
		confirmed, expired = HeldEnrolment{}, false
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		h := u.HeldEnrolment
		if h == nil {
			return ErrNoHeldEnrolment
		}
		if dropExpiredHold(u, now) {
			expired = true
			return nil
		}
		switch h.Kind {
		case HeldFactorPasskey:
			if h.Passkey == nil {
				return ErrNoHeldEnrolment
			}
			if findPasskeyIndex(u, h.Passkey.ID) != -1 {
				return ErrPasskeyDuplicate
			}
			if len(u.Passkeys) >= maxPasskeysPerAccount {
				return ErrPasskeyLimitReached
			}
			u.Passkeys = append(u.Passkeys, h.Passkey.clone())
		case HeldFactorTOTP:
			if u.TOTPSecret == "" || !u.TOTPConfirmedAt.IsZero() {
				return ErrNoHeldEnrolment
			}
			u.TOTPConfirmedAt = now
			u.TOTPPendingSince = time.Time{}
		default:
			return ErrNoHeldEnrolment
		}
		u.RecoveryCodes = slices.Clone(h.RecoveryCodes)
		u.HeldEnrolment = nil
		confirmed = *h.clone()
		confirmed.RecoveryCodes = nil
		return nil
	})
	if err != nil {
		return HeldEnrolment{}, err
	}
	if expired {
		return HeldEnrolment{}, ErrHeldEnrolmentExpired
	}
	return confirmed, nil
}
