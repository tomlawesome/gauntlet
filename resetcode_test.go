// Ported from mikroview's internal/auth/resetcode_test.go. Adapted:
// Open(path)/OpenWithBackend(budget) -> openTestStore(t)/OpenStore(budget,
// Options{}); the plaintext-leak check reads persist.Memory's Load
// instead of os.ReadFile. Dropped: TestResetStateSurvivesAReopen --
// this package's roundtrip_test.go already covers a full reload with
// every second-factor field populated (issue #5's acceptance test), so
// a second, smaller reopen test here would only duplicate it.

package gauntlet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// Every password in this file is an obvious placeholder, never anything
// shaped like a credential somebody might really be using.
const (
	resetTestOldPassword = "old-password-placeholder"
	resetTestNewPassword = "new-password-placeholder"
)

// newResetTestStore returns a persisted store holding an admin and one
// ordinary account, with the ordinary account's ID -- the shape every
// test below starts from.
func newResetTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	s := openTestStore(t)
	if _, err := s.Register("admin", "admin-password-placeholder", time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser("bilbo", resetTestOldPassword, RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s, u.ID
}

func TestResetCodeShape(t *testing.T) {
	code := FormatResetCode(newResetCode())

	tests := []struct {
		name string
		want func(t *testing.T)
	}{
		{"grouped in four runs of four", func(t *testing.T) {
			groups := strings.Split(code, "-")
			if len(groups) != resetCodeLength/resetCodeGroup {
				t.Fatalf("got %d groups in %q, want %d", len(groups), code, resetCodeLength/resetCodeGroup)
			}
			for _, g := range groups {
				if len(g) != resetCodeGroup {
					t.Errorf("group %q is %d characters, want %d", g, len(g), resetCodeGroup)
				}
			}
		}},
		{"only unambiguous characters", func(t *testing.T) {
			for _, r := range strings.ReplaceAll(code, "-", "") {
				if !strings.ContainsRune(resetCodeAlphabet, r) {
					t.Errorf("character %q is not in the unambiguous alphabet", r)
				}
			}
			for _, banned := range []string{"0", "O", "1", "I"} {
				if strings.Contains(code, banned) {
					t.Errorf("code %q contains %q, which reads as another character when dictated", code, banned)
				}
			}
		}},
		{"a fresh code each time", func(t *testing.T) {
			seen := map[string]bool{}
			for range 50 {
				c := newResetCode()
				if seen[c] {
					t.Fatalf("newResetCode repeated %q within 50 draws", c)
				}
				seen[c] = true
			}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.want(t) })
	}
}

func TestNormaliseResetCodeAcceptsWhatAPersonTypes(t *testing.T) {
	tests := []struct {
		name  string
		typed string
		want  string
	}{
		{"as displayed", "ABCD-EFGH-JKLM-NPQR", "ABCDEFGHJKLMNPQR"},
		{"without the dashes", "ABCDEFGHJKLMNPQR", "ABCDEFGHJKLMNPQR"},
		{"in lower case", "abcd-efgh-jklm-npqr", "ABCDEFGHJKLMNPQR"},
		{"with spaces instead", "ABCD EFGH JKLM NPQR", "ABCDEFGHJKLMNPQR"},
		{"a mistyped character is kept, not dropped", "ABCD!EFGH", "ABCD!EFGH"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormaliseResetCode(tc.typed); got != tc.want {
				t.Errorf("NormaliseResetCode(%q) = %q, want %q", tc.typed, got, tc.want)
			}
		})
	}
}

// TestResetCodeStaysUnspentWhenTheSpendCannotBeSaved is the rule at the
// other end of the reset: a spend that only lands in memory is undone
// by a restart, and the code is live again for whoever saw it. The
// login is refused instead, and the code still works once the store can
// write again.
func TestResetCodeStaysUnspentWhenTheSpendCannotBeSaved(t *testing.T) {
	backend := &saveBudgetBackend{left: 3} // register, create user, issue code
	s, err := OpenStore(backend, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("admin", "admin-password-placeholder", time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser("bilbo", resetTestOldPassword, RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, code, err := s.IssueResetCode(u.ID, now)
	if err != nil {
		t.Fatalf("IssueResetCode: %v", err)
	}

	if _, err := s.Authenticate("bilbo", code, now); err == nil {
		t.Fatal("Authenticate with a reset code the store cannot record as spent = nil error, want one")
	}

	backend.left = 1
	if _, err := s.Authenticate("bilbo", code, now); err != nil {
		t.Fatalf("expected the code to still be live once the store can write again, got %v", err)
	}
	if _, err := s.Authenticate("bilbo", code, now); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected the code to be spent after a recorded login, got %v", err)
	}
}

// TestIssueResetCodeKillsTheOldPasswordAndLetsTheCodeIn is the positive
// path: the code works in the password box, the old password does not,
// and the account comes back flagged for a forced change.
func TestIssueResetCodeKillsTheOldPasswordAndLetsTheCodeIn(t *testing.T) {
	s, id := newResetTestStore(t)
	now := time.Now()

	if _, err := s.Authenticate("bilbo", resetTestOldPassword, now); err != nil {
		t.Fatalf("expected the old password to work before the reset: %v", err)
	}

	user, code, err := s.IssueResetCode(id, now)
	if err != nil {
		t.Fatalf("IssueResetCode: %v", err)
	}
	if !user.MustChangePassword {
		t.Error("expected the reset to flag the account for a forced password change")
	}
	if !user.PasswordChangedAt.Equal(now) {
		t.Errorf("PasswordChangedAt = %v, want %v -- the reset replaced the password", user.PasswordChangedAt, now)
	}
	if !user.SessionsEndedAt.Equal(now) {
		t.Errorf("SessionsEndedAt = %v, want %v -- it is what ends sessions issued before the reset", user.SessionsEndedAt, now)
	}
	if user.ResetCodeHash != "" {
		t.Error("expected the returned copy to carry no credential verifier")
	}

	if _, err := s.Authenticate("bilbo", resetTestOldPassword, now); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected the old password to be dead the moment the admin resets, got %v", err)
	}

	got, err := s.Authenticate("bilbo", code, now)
	if err != nil {
		t.Fatalf("expected the code to be accepted in the password box: %v", err)
	}
	if !got.MustChangePassword {
		t.Error("expected the account redeeming the code to still be flagged for a forced change")
	}
}

// TestIssueResetCodeLeavesTheOldPasswordWorkingWhenPersistFails: a reset
// that cannot be saved must not kill the old password or mint a live
// code in memory either, or a restart before the next good write would
// silently un-reset the account while the admin has already read a code
// out that no longer does anything.
func TestIssueResetCodeLeavesTheOldPasswordWorkingWhenPersistFails(t *testing.T) {
	// Register and CreateUser below each persist too, so the fixture
	// needs a backend that saves twice before failing, not one that
	// fails outright.
	s, err := OpenStore(&saveBudgetBackend{left: 2}, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("admin", "admin-password-placeholder", time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser("bilbo", resetTestOldPassword, RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.IssueResetCode(u.ID, time.Now()); err == nil {
		t.Fatal("IssueResetCode against a backend that cannot save = nil error, want one")
	}

	if _, err := s.Authenticate("bilbo", resetTestOldPassword, time.Now()); err != nil {
		t.Errorf("expected the old password to still work after a failed persist, got %v", err)
	}
	got, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected the account to still be there")
	}
	if got.MustChangePassword {
		t.Error("expected MustChangePassword to stay false after a failed persist")
	}
	if got.ResetCodeHash != "" {
		t.Error("expected no reset code to be live after a failed persist")
	}
}

// TestResetCodeRefusals covers the two accounts this must never mint a
// code for, plus a request for an account that is not there.
func TestResetCodeRefusals(t *testing.T) {
	tests := []struct {
		name    string
		target  func(t *testing.T, s *Store) string
		wantErr error
	}{
		{
			name: "an SSO-only account belongs to its provider",
			target: func(t *testing.T, s *Store) string {
				u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-placeholder", "frodo", time.Now())
				if err != nil {
					t.Fatal(err)
				}
				return u.ID
			},
			wantErr: ErrNoLocalPassword,
		},
		{
			name: "an account converted to SSO-only by linking",
			target: func(t *testing.T, s *Store) string {
				u, err := s.CreateUser("sam", resetTestOldPassword, RoleUser, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "another-subject-placeholder", time.Now()); err != nil {
					t.Fatal(err)
				}
				return u.ID
			},
			wantErr: ErrNoLocalPassword,
		},
		{
			name:    "no such account",
			target:  func(t *testing.T, s *Store) string { return "not-a-real-user-id" },
			wantErr: ErrUserNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newResetTestStore(t)
			id := tc.target(t, s)
			if _, _, err := s.IssueResetCode(id, time.Now()); !errors.Is(err, tc.wantErr) {
				t.Errorf("IssueResetCode = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestResetCodeStopsWorking is the single-use, expiry and
// second-reset-kills-the-first trio -- the three ways a code that was
// once valid must stop being so.
func TestResetCodeStopsWorking(t *testing.T) {
	issued := time.Now()

	tests := []struct {
		name string
		// spend runs against a store that has just issued code, and
		// returns the secret and the clock the follow-up attempt should
		// use -- always against the "bilbo" account newResetTestStore
		// creates.
		spend func(t *testing.T, s *Store, id, code string) (secret string, at time.Time)
	}{
		{
			name: "single use -- the code is spent by the login that redeems it",
			spend: func(t *testing.T, s *Store, id, code string) (string, time.Time) {
				if _, err := s.Authenticate("bilbo", code, issued); err != nil {
					t.Fatalf("expected the first use to succeed: %v", err)
				}
				return code, issued
			},
		},
		{
			name: "expired -- 24 hours after it was issued",
			spend: func(t *testing.T, s *Store, id, code string) (string, time.Time) {
				return code, issued.Add(ResetCodeTTL).Add(time.Second)
			},
		},
		{
			name: "superseded -- a second reset kills the first code",
			spend: func(t *testing.T, s *Store, id, code string) (string, time.Time) {
				if _, second, err := s.IssueResetCode(id, issued); err != nil {
					t.Fatal(err)
				} else if second == code {
					t.Fatal("expected the second reset to mint a different code")
				}
				return code, issued
			},
		},
		{
			name: "replaced -- setting a password ends the reset",
			spend: func(t *testing.T, s *Store, id, code string) (string, time.Time) {
				if err := s.SetPassword("bilbo", resetTestNewPassword, issued); err != nil {
					t.Fatal(err)
				}
				return code, issued
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, id := newResetTestStore(t)
			_, code, err := s.IssueResetCode(id, issued)
			if err != nil {
				t.Fatal(err)
			}

			secret, at := tc.spend(t, s, id, code)
			if _, err := s.Authenticate("bilbo", secret, at); !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("expected the code to be refused, got %v", err)
			}
		})
	}
}

// TestSecondResetCodeStillWorksAfterTheFirstIsKilled is the other half
// of "superseded" above: killing the first code must not leave the
// account unreachable.
func TestSecondResetCodeStillWorksAfterTheFirstIsKilled(t *testing.T) {
	s, id := newResetTestStore(t)
	now := time.Now()

	if _, _, err := s.IssueResetCode(id, now); err != nil {
		t.Fatal(err)
	}
	_, second, err := s.IssueResetCode(id, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("bilbo", second, now); err != nil {
		t.Errorf("expected the newest code to work: %v", err)
	}
}

// TestResetCodeIsSpentByTheLoginThatRedeemsIt is the owner's ruling
// restored after a pre-release audit had amended it (mikroview
// #1245 Q21, CHANGELOG #1251): a code that stays live until the
// password is actually set is replayable for its whole 24 hours by
// anyone who saw it -- over a shoulder, on a screen share -- and
// whoever completes the change first takes the account and revokes the
// other session. Losing the first session instead costs an admin a
// round trip for a new code, which is not a lockout: an admin can
// always issue another, and the sole admin recovers through the
// console, never through this mechanism.
func TestResetCodeIsSpentByTheLoginThatRedeemsIt(t *testing.T) {
	s, id := newResetTestStore(t)
	now := time.Now()

	_, code, err := s.IssueResetCode(id, now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Authenticate("bilbo", code, now); err != nil {
		t.Fatalf("expected the first login with the code to succeed: %v", err)
	}

	// Spent, whether or not the forced change was completed: a second
	// holder of the same code cannot follow the first one in.
	if _, err := s.Authenticate("bilbo", code, now); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected the code to be spent by the login that redeemed it, got %v -- it is replayable by anyone who saw it", err)
	}
}

func TestSetPasswordClearsTheForcedChangeFlag(t *testing.T) {
	s, id := newResetTestStore(t)
	now := time.Now()

	if _, _, err := s.IssueResetCode(id, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword("bilbo", resetTestNewPassword, now); err != nil {
		t.Fatal(err)
	}

	u, ok := s.Get(id)
	if !ok {
		t.Fatal("expected the account to still be there")
	}
	if u.MustChangePassword {
		t.Error("expected setting a password to clear the forced-change flag")
	}
	if u.ResetCodeHash != "" || !u.ResetCodeExpiresAt.IsZero() {
		t.Error("expected setting a password to clear the outstanding reset")
	}
	if _, err := s.Authenticate("bilbo", resetTestNewPassword, now); err != nil {
		t.Errorf("expected the newly set password to work: %v", err)
	}
}

func TestListNeverIncludesResetCodeHashes(t *testing.T) {
	s, id := newResetTestStore(t)
	if _, _, err := s.IssueResetCode(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, u := range s.List() {
		if u.ResetCodeHash != "" {
			t.Errorf("List exposed a reset-code hash for %q", u.Username)
		}
	}
}

// TestIssueResetCodeOnlyHashIsPersisted mirrors
// TestGenerateRecoveryCodesOnlyHashesArePersisted (recoverycodes_test.go):
// the code IssueResetCode hands back in clear must never reach the
// backend's stored document, only its Argon2id hash.
func TestIssueResetCodeOnlyHashIsPersisted(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("admin", "admin-password-placeholder", time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser("bilbo", resetTestOldPassword, RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	_, code, err := s.IssueResetCode(u.ID, time.Now())
	if err != nil {
		t.Fatalf("IssueResetCode: %v", err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw := string(snap.Payload)
	if strings.Contains(raw, NormaliseResetCode(code)) {
		t.Fatalf("the issued code %q was written to the accounts document in clear", code)
	}

	got, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected bilbo to still exist")
	}
	if !strings.HasPrefix(got.ResetCodeHash, "argon2id$") {
		t.Errorf("ResetCodeHash = %q, not an Argon2id hash", got.ResetCodeHash)
	}
}

// breachHook is a BreachChecker that runs hook on its first call and
// reports nothing breached: the way into the window SetPassword leaves
// between reading the account and its write, since the check runs
// before the hash.
type breachHook struct {
	once sync.Once
	hook func()
}

func (b *breachHook) Breached(context.Context, string) (bool, error) {
	if b.hook != nil {
		b.once.Do(b.hook)
	}
	return false, nil
}

// An admin reset issued while a password change on the same account is
// still being checked and hashed must not be overwritten by it: the
// change used to clear the new code on its way in, so the code the
// admin read out never worked (#80). The change is refused instead and
// the reset stands.
func TestSetPasswordDoesNotOverwriteAResetIssuedDuringIt(t *testing.T) {
	checker := &breachHook{}
	s, _ := openCheckedStore(t, Options{BreachCheck: checker})
	alice, err := s.CreateUser("alice", "alice first passphrase", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var code string
	checker.hook = func() {
		_, c, err := s.IssueResetCode(alice.ID, time.Now())
		if err != nil {
			t.Errorf("IssueResetCode: %v", err)
		}
		code = c
	}

	if err := s.SetPassword("alice", "alice second passphrase", time.Now()); !errors.Is(err, ErrResetDuringChange) {
		t.Fatalf("SetPassword across a reset = %v, want ErrResetDuringChange", err)
	}
	if code == "" {
		t.Fatal("the reset was never issued")
	}
	u, err := s.Authenticate("alice", code, time.Now())
	if err != nil {
		t.Fatalf("the admin's reset code does not sign in: %v", err)
	}
	if !u.MustChangePassword {
		t.Error("the sign-in with the reset code is not held for a password change")
	}
	if _, err := s.Authenticate("alice", "alice second passphrase", time.Now()); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the refused change's password signs in: %v", err)
	}

	// The forced change that follows, from the code's own sign-in, is
	// not a change the reset raced: it goes through.
	if err := s.SetPassword("alice", "alice third passphrase", time.Now()); err != nil {
		t.Fatalf("the forced change after the reset: %v", err)
	}
}
