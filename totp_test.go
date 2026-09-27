// Ported from mikroview's internal/auth/totp_test.go and the TOTP
// portion of internal/auth/store_test.go. Adapted: Open(path)/
// OpenWithBackend(budget) -> openTestStore(t)/OpenStore(budget,
// Options{}); s.HasActiveTOTP(id) -> Get(id) then .HasActiveTOTP()
// (this package has no Store-level convenience wrapper, since Get
// already returns an unblanked copy -- see totp.go's package comment).
// Dropped: TestHasActiveTOTPUnknownUserIsFalse (that method doesn't
// exist here) and TestRecordTOTPCounterOnlyMovesForward (that method
// doesn't exist here either -- VerifyAndRecordTOTP replaces it, tested
// below instead). TestUnconfirmedTOTPSecretIsNotAnActiveFactor and its
// setTOTPForTest helper are also not here -- store_test.go already has
// both, added alongside G2's User.HasActiveTOTP.

package gauntlet

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestGenerateTOTPCodeRFC6238Vectors is the reason any of this can be
// trusted: RFC 6238 Appendix B's SHA-1 column, computed against the
// shared secret the RFC itself specifies ("12345678901234567890", 20
// ASCII bytes -- exactly totpSecretLen).
//
// The RFC's published vectors are 8-digit codes; this package produces
// 6. RFC 4226 §5.3's truncation is "DT mod 10^Digit" against the same
// 31-bit DT regardless of digit count, so the 6-digit code is exactly
// the low 6 digits of the RFC's 8-digit OTP -- not a different value
// that happens to be close. Each case below carries the RFC's original
// 8-digit OTP in a comment so it can be checked against the RFC text
// directly.
func TestGenerateTOTPCodeRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")

	tests := []struct {
		unixSeconds int64
		want        string // low 6 digits of the RFC's 8-digit OTP
	}{
		{59, "287082"},          // RFC OTP 94287082, T = 0000000000000001
		{1111111109, "081804"},  // RFC OTP 07081804, T = 00000000023523EC
		{1111111111, "050471"},  // RFC OTP 14050471, T = 00000000023523ED
		{1234567890, "005924"},  // RFC OTP 89005924, T = 000000000273EF07
		{2000000000, "279037"},  // RFC OTP 69279037, T = 0000000003F940AA
		{20000000000, "353130"}, // RFC OTP 65353130, T = 0000000027BC86AA
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("t=%d", tc.unixSeconds), func(t *testing.T) {
			counter := totpCounter(time.Unix(tc.unixSeconds, 0).UTC(), totpStep)
			if got := GenerateTOTPCode(secret, counter); got != tc.want {
				t.Errorf("GenerateTOTPCode at unix time %d (counter %d) = %q, want %q",
					tc.unixSeconds, counter, got, tc.want)
			}
		})
	}
}

func TestGenerateTOTPSecretShape(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(secret) != totpSecretLen {
		t.Fatalf("len(secret) = %d, want %d", len(secret), totpSecretLen)
	}

	other, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if bytes.Equal(secret, other) {
		t.Fatal("two draws from GenerateTOTPSecret produced the same secret")
	}
}

func TestEncodeDecodeTOTPSecretRoundTrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	encoded := EncodeTOTPSecret(secret)

	tests := []struct {
		name  string
		input string
	}{
		{"as encoded", encoded},
		{"lower case, as a person might type it", strings.ToLower(encoded)},
		{"with padding added back", encoded + strings.Repeat("=", (8-len(encoded)%8)%8)},
		{"with a stray space", encoded[:4] + " " + encoded[4:]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeTOTPSecret(tc.input)
			if err != nil {
				t.Fatalf("DecodeTOTPSecret(%q): %v", tc.input, err)
			}
			if !bytes.Equal(decoded, secret) {
				t.Errorf("DecodeTOTPSecret(%q) = %x, want %x", tc.input, decoded, secret)
			}
		})
	}
}

func TestDecodeTOTPSecretRefusesMalformedOrEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"not base32 at all", "not-valid-base32!!!"},
		{"padding only", "===="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeTOTPSecret(tc.input); err == nil {
				t.Errorf("DecodeTOTPSecret(%q): want error, got none", tc.input)
			}
		})
	}
}

// TestTOTPEnrollmentURIEscapesUsername covers a username containing a
// space or a colon, which must not produce a URI that an authenticator
// app parses differently from what we intend. It also pins this
// package's divergence from mikroview: the product name is a
// parameter, not a hard-coded "MikroView" (totp.go's package comment).
func TestTOTPEnrollmentURIEscapesUsername(t *testing.T) {
	secret := []byte("12345678901234567890")

	tests := []struct {
		name           string
		username       string
		wantLabel      string   // the escaped "Birdcage:<username>" segment
		mustNotContain []string // raw forms that would signal broken escaping
	}{
		{
			name:      "plain username",
			username:  "alice",
			wantLabel: "Birdcage:alice",
		},
		{
			name:      "username with a space",
			username:  "bob smith",
			wantLabel: "Birdcage:bob%20smith",
		},
		{
			name:           "username with a colon",
			username:       "eve:evil",
			wantLabel:      "Birdcage:eve%3Aevil",
			mustNotContain: []string{"Birdcage:eve:evil"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uri := TOTPEnrollmentURI("Birdcage", tc.username, secret)

			if !strings.HasPrefix(uri, "otpauth://totp/"+tc.wantLabel+"?") {
				t.Errorf("TOTPEnrollmentURI(%q) = %q, want it to start with otpauth://totp/%s?",
					tc.username, uri, tc.wantLabel)
			}
			for _, bad := range tc.mustNotContain {
				if strings.Contains(uri, bad) {
					t.Errorf("TOTPEnrollmentURI(%q) = %q, contains unescaped %q", tc.username, uri, bad)
				}
			}
			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatalf("TOTPEnrollmentURI(%q) = %q, does not parse as a URI: %v", tc.username, uri, err)
			}
			if got := parsed.Query().Get("issuer"); got != "Birdcage" {
				t.Errorf("issuer query param = %q, want Birdcage", got)
			}
			if got := parsed.Query().Get("secret"); got != EncodeTOTPSecret(secret) {
				t.Errorf("secret query param = %q, want %q", got, EncodeTOTPSecret(secret))
			}
		})
	}
}

func TestVerifyTOTPAcceptsCurrentAndAdjacentSteps(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	encoded := EncodeTOTPSecret(secret)
	now := time.Unix(1_700_000_000, 0).UTC()
	current := totpCounter(now, totpStep)

	tests := []struct {
		name    string
		counter uint64
	}{
		{"current step", current},
		{"one step ahead", current + 1},
		{"one step behind", current - 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code := GenerateTOTPCode(secret, tc.counter)
			matched, ok := VerifyTOTP(encoded, code, now, 0)
			if !ok {
				t.Fatalf("VerifyTOTP(code for counter %d) at current counter %d: want accepted, got refused",
					tc.counter, current)
			}
			if matched != tc.counter {
				t.Errorf("matched counter = %d, want %d", matched, tc.counter)
			}
		})
	}
}

func TestVerifyTOTPRejectsTwoStepsAway(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	encoded := EncodeTOTPSecret(secret)
	now := time.Unix(1_700_000_000, 0).UTC()
	current := totpCounter(now, totpStep)

	tests := []struct {
		name    string
		counter uint64
	}{
		{"two steps ahead", current + 2},
		{"two steps behind", current - 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code := GenerateTOTPCode(secret, tc.counter)
			if _, ok := VerifyTOTP(encoded, code, now, 0); ok {
				t.Fatalf("VerifyTOTP(code for counter %d) at current counter %d: want refused, got accepted",
					tc.counter, current)
			}
		})
	}
}

// TestVerifyTOTPRefusesReplay is the guard the store depends on: the
// same code, matched to the same counter, must work exactly once.
func TestVerifyTOTPRefusesReplay(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	encoded := EncodeTOTPSecret(secret)
	now := time.Unix(1_700_000_000, 0).UTC()
	current := totpCounter(now, totpStep)
	code := GenerateTOTPCode(secret, current)

	matched, ok := VerifyTOTP(encoded, code, now, 0)
	if !ok {
		t.Fatal("first use of the code: want accepted, got refused")
	}
	if matched != current {
		t.Fatalf("matched counter = %d, want %d", matched, current)
	}

	if _, ok := VerifyTOTP(encoded, code, now, matched); ok {
		t.Fatal("replay of the same code at the same counter: want refused, got accepted")
	}
}

func TestVerifyTOTPRefusesMalformedOrEmptySecret(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	tests := []struct {
		name   string
		secret string
	}{
		{"empty secret", ""},
		{"not valid base32", "not-valid-base32!!!"},
		{"padding only, decodes to nothing", "===="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := VerifyTOTP(tc.secret, "123456", now, 0); ok {
				t.Errorf("VerifyTOTP with %s: want refused, got accepted", tc.name)
			}
		})
	}
}

func TestVerifyTOTPRefusesMalformedCodeWithoutPanicking(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	encoded := EncodeTOTPSecret(secret)
	now := time.Unix(1_700_000_000, 0).UTC()

	tests := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"letters, not digits", "abcdef"},
		{"too short", "12345"},
		{"too long", "1234567"},
		{"contains a space", "12 456"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := VerifyTOTP(encoded, tc.code, now, 0); ok {
				t.Errorf("VerifyTOTP with code %q: want refused, got accepted", tc.code)
			}
		})
	}
}

// TestClearTOTPRemovesEveryPart is the "disable 2FA" path: it must
// leave nothing behind that a stale recovery code could still redeem,
// or that a later re-enrollment could accidentally inherit (the old
// counter, in particular, would let a replay-guard check pass against a
// fresh secret's early codes).
func TestClearTOTPRemovesEveryPart(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 7)
	codes, err := s.GenerateRecoveryCodes(u.ID, now)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if active, _ := s.Get(u.ID); !active.HasActiveTOTP() {
		t.Fatal("test setup: expected an active factor before clearing it")
	}

	if err := s.ClearTOTP(u.ID); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}

	got, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected the user to still exist after ClearTOTP")
	}
	if got.TOTPSecret != "" {
		t.Error("ClearTOTP left the secret behind")
	}
	if !got.TOTPConfirmedAt.IsZero() {
		t.Error("ClearTOTP left the confirmation timestamp behind")
	}
	if got.TOTPLastCounter != 0 {
		t.Error("ClearTOTP left the replay counter behind")
	}
	if len(got.RecoveryCodes) != 0 {
		t.Error("ClearTOTP left recovery codes behind")
	}
	if got.HasActiveTOTP() {
		t.Error("HasActiveTOTP is still true after ClearTOTP")
	}
	// A code from before the clear must not still work afterward.
	if ok, err := s.BurnRecoveryCode(u.ID, codes[0], now); err != nil || ok {
		t.Errorf("a pre-clear recovery code still worked after ClearTOTP: ok=%v err=%v", ok, err)
	}
}

func TestClearTOTPUnknownUserReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	if err := s.ClearTOTP("no-such-user"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("ClearTOTP on an unknown user = %v, want %v", err, ErrUserNotFound)
	}
}

// TestClearTOTPLeavesStateWhenPersistFails follows the same
// restore-on-failure contract every other credential-changing method in
// this package documents (SetPassword, IssueResetCode, ...): a clear
// that cannot be durably saved must not be reported as done, and must
// not leave the in-memory state ahead of what's on disk.
func TestClearTOTPLeavesStateWhenPersistFails(t *testing.T) {
	// Budget covers exactly Register (1) and setTOTPForTest's fixture
	// write (1); GenerateRecoveryCodes and ClearTOTP each get their own
	// budget set just before they run, below.
	budget := &saveBudgetBackend{left: 2}
	s, err := OpenStore(budget, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 3)

	budget.left = 1
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	budget.left = 0

	if err := s.ClearTOTP(u.ID); err == nil {
		t.Fatal("ClearTOTP against a backend that cannot save = nil error, want one")
	}
	got, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected the user to still exist")
	}
	if got.TOTPSecret == "" || got.TOTPConfirmedAt.IsZero() || len(got.RecoveryCodes) == 0 {
		t.Error("ClearTOTP's in-memory state changed even though the write failed")
	}
}

// TestEnrolThenConfirmActivatesTheFactor walks the two store writes an
// enrolment route makes, in order, and pins the thing that separates
// them: the secret exists after the first call but must not gate a
// sign-in until the second.
func TestEnrolThenConfirmActivatesTheFactor(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetPendingTOTPSecret(u.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("SetPendingTOTPSecret: %v", err)
	}
	got, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected the user to still exist")
	}
	if got.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTPSecret = %q after enrolment, want the pending secret", got.TOTPSecret)
	}
	if got.HasActiveTOTP() {
		t.Error("a pending, unconfirmed secret counts as an active factor -- it must not gate a sign-in")
	}

	if err := s.ConfirmTOTP(u.ID, now, 57); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	got, _ = s.Get(u.ID)
	if !got.HasActiveTOTP() {
		t.Error("the factor is not active after ConfirmTOTP")
	}
	if !got.TOTPConfirmedAt.Equal(now) {
		t.Errorf("TOTPConfirmedAt = %v, want %v", got.TOTPConfirmedAt, now)
	}
	if got.TOTPLastCounter != 57 {
		t.Errorf("TOTPLastCounter = %d after confirming, want the counter that proved the enrolment (57)", got.TOTPLastCounter)
	}
}

// TestSetPendingTOTPSecretRefusesToReplaceAnActiveFactor covers the
// lockout ErrTOTPAlreadyActive exists to prevent: if enrolling again
// overwrote a live secret, abandoning that enrolment would leave
// HasActiveTOTP true against a secret no authenticator app holds.
func TestSetPendingTOTPSecretRefusesToReplaceAnActiveFactor(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 9)

	if err := s.SetPendingTOTPSecret(u.ID, "MZXW6YTBOI======"); !errors.Is(err, ErrTOTPAlreadyActive) {
		t.Errorf("enrolling over an active factor = %v, want %v", err, ErrTOTPAlreadyActive)
	}
	got, _ := s.Get(u.ID)
	if got.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("the live secret was replaced anyway: %q", got.TOTPSecret)
	}
	if got.TOTPLastCounter != 9 {
		t.Errorf("TOTPLastCounter = %d, want the live factor's 9 left alone", got.TOTPLastCounter)
	}
}

// TestSetPendingTOTPSecretResetsTheReplayCounter covers the abandoned
// enrolment: a counter left over from an earlier secret would refuse
// the new one's early codes, which reads as an authenticator app that
// simply does not work.
func TestSetPendingTOTPSecretResetsTheReplayCounter(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	// An enrolment that got a secret and a counter but was never
	// confirmed -- so it is replaceable, unlike the test above.
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", time.Time{}, 12345)

	if err := s.SetPendingTOTPSecret(u.ID, "MZXW6YTBOI======"); err != nil {
		t.Fatalf("SetPendingTOTPSecret over an abandoned enrolment: %v", err)
	}
	got, _ := s.Get(u.ID)
	if got.TOTPSecret != "MZXW6YTBOI======" {
		t.Errorf("TOTPSecret = %q, want the new pending secret", got.TOTPSecret)
	}
	if got.TOTPLastCounter != 0 {
		t.Errorf("TOTPLastCounter = %d, want 0 -- the old secret's counter must not carry over", got.TOTPLastCounter)
	}
}

// TestConfirmTOTPNeedsSomethingPending pins both halves of
// ErrNoPendingTOTP: nothing started, and already finished.
func TestConfirmTOTPNeedsSomethingPending(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.ConfirmTOTP(u.ID, now, 1); !errors.Is(err, ErrNoPendingTOTP) {
		t.Errorf("confirming with no enrolment = %v, want %v", err, ErrNoPendingTOTP)
	}

	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 40)
	if err := s.ConfirmTOTP(u.ID, now.Add(time.Hour), 1); !errors.Is(err, ErrNoPendingTOTP) {
		t.Errorf("confirming an already-confirmed factor = %v, want %v", err, ErrNoPendingTOTP)
	}
	got, _ := s.Get(u.ID)
	if got.TOTPLastCounter != 40 {
		t.Errorf("TOTPLastCounter = %d, want the confirmed factor's 40 -- a rejected confirm must not wind the guard back", got.TOTPLastCounter)
	}
	if !got.TOTPConfirmedAt.Equal(now) {
		t.Error("a rejected confirm moved TOTPConfirmedAt")
	}
}

// TestVerifyAndRecordTOTPAcceptsOnceThenRefusesReplay is the seam
// between this file's two halves wired together: a real generated code
// verifies and is recorded, and using it again is refused.
func TestVerifyAndRecordTOTPAcceptsOnceThenRefusesReplay(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encoded := EncodeTOTPSecret(secret)
	if err := s.SetPendingTOTPSecret(u.ID, encoded); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.Get(u.ID)
	code := GenerateTOTPCode(secret, totpCounter(now, totpStep))
	matched, ok := VerifyTOTP(stored.TOTPSecret, code, now, stored.TOTPLastCounter)
	if !ok {
		t.Fatal("the enrolment code did not verify against the pending secret")
	}
	if err := s.ConfirmTOTP(u.ID, now, matched); err != nil {
		t.Fatal(err)
	}

	// Sign-in, moments later, with the same code still on screen: it
	// must not verify a second time.
	if ok, err := s.VerifyAndRecordTOTP(u.ID, code, now); err != nil || ok {
		t.Errorf("VerifyAndRecordTOTP replaying the enrolment code: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// The next window's code still works, and spending it advances the
	// guard -- the point of the counter is to move on, not to wedge.
	later := now.Add(totpStep)
	next := GenerateTOTPCode(secret, totpCounter(later, totpStep))
	ok, err = s.VerifyAndRecordTOTP(u.ID, next, later)
	if err != nil || !ok {
		t.Fatalf("VerifyAndRecordTOTP(next window's code): ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if ok, err := s.VerifyAndRecordTOTP(u.ID, next, later); err != nil || ok {
		t.Errorf("VerifyAndRecordTOTP replaying the sign-in code: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestVerifyAndRecordTOTPRefusesWrongCodeAndUnknownUser(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, u.ID, testTOTPSecret, now, 0)

	if ok, err := s.VerifyAndRecordTOTP(u.ID, "000000", now); err != nil || ok {
		t.Errorf("VerifyAndRecordTOTP with a wrong code: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
	got, _ := s.Get(u.ID)
	if got.TOTPLastCounter != 0 {
		t.Errorf("TOTPLastCounter moved to %d after a wrong code, want 0", got.TOTPLastCounter)
	}

	if _, err := s.VerifyAndRecordTOTP("no-such-user", "000000", now); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("VerifyAndRecordTOTP on an unknown user = %v, want %v", err, ErrUserNotFound)
	}
}

// TestTOTPWritesLeaveStateWhenPersistFails holds every write in this
// file to the same restore-on-failure contract: a change that cannot be
// durably saved is not reported as done, and does not leave memory
// ahead of disk.
func TestTOTPWritesLeaveStateWhenPersistFails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	newStore := func(t *testing.T) (*Store, *saveBudgetBackend, string) {
		t.Helper()
		// Budget covers Register (1); each case sets its own budget
		// before the write it is testing.
		budget := &saveBudgetBackend{left: 1}
		s, err := OpenStore(budget, Options{})
		if err != nil {
			t.Fatal(err)
		}
		u, err := s.Register("admin", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		return s, budget, u.ID
	}

	t.Run("SetPendingTOTPSecret", func(t *testing.T) {
		s, budget, id := newStore(t)
		budget.left = 0
		if err := s.SetPendingTOTPSecret(id, "JBSWY3DPEHPK3PXP"); err == nil {
			t.Fatal("SetPendingTOTPSecret against a backend that cannot save = nil error, want one")
		}
		if got, _ := s.Get(id); got.TOTPSecret != "" {
			t.Errorf("TOTPSecret = %q in memory even though the write failed", got.TOTPSecret)
		}
	})

	t.Run("ConfirmTOTP", func(t *testing.T) {
		s, budget, id := newStore(t)
		budget.left = 1
		if err := s.SetPendingTOTPSecret(id, "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		budget.left = 0
		if err := s.ConfirmTOTP(id, now, 5); err == nil {
			t.Fatal("ConfirmTOTP against a backend that cannot save = nil error, want one")
		}
		got, _ := s.Get(id)
		if got.HasActiveTOTP() {
			t.Error("the factor reads as active even though the confirmation could not be saved")
		}
		if got.TOTPLastCounter != 0 {
			t.Errorf("TOTPLastCounter = %d after a failed confirm, want 0", got.TOTPLastCounter)
		}
	})

	t.Run("VerifyAndRecordTOTP", func(t *testing.T) {
		s, budget, id := newStore(t)
		budget.left = 1
		secret, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		encoded := EncodeTOTPSecret(secret)
		setTOTPForTest(t, s, id, encoded, now, 30)
		code := GenerateTOTPCode(secret, totpCounter(now, totpStep)+1)

		budget.left = 0
		ok, err := s.VerifyAndRecordTOTP(id, code, now)
		if err == nil {
			t.Fatal("VerifyAndRecordTOTP against a backend that cannot save = nil error, want one")
		}
		if !ok {
			t.Error("VerifyAndRecordTOTP reported the code as not matching, even though the failure was persistence, not verification")
		}
		got, _ := s.Get(id)
		if got.TOTPLastCounter != 30 {
			t.Errorf("TOTPLastCounter = %d after a failed write, want the stored 30", got.TOTPLastCounter)
		}
	})
}
