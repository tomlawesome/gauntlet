// Ported from mikroview's internal/auth/username_test.go. Adapted:
// Open(path) -> openTestStore(t) (gauntlet has no file backend).

package gauntlet

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestValidateUsernameRejectsHostileInput(t *testing.T) {
	cases := []struct {
		name     string
		username string
		why      string
	}{
		{"ANSI erase-line", "alice\x1b[2K\rroot", "rewrites a terminal table as it prints"},
		{"bare escape", "alice\x1b", "starts a control sequence"},
		{"newline", "alice\nadmin", "forges an extra line in the audit trail"},
		{"carriage return", "alice\radmin", "overwrites the line already printed"},
		{"NUL", "alice\x00", "truncates in anything C-based downstream"},
		{"BEL", "alice\a", "control character"},
		{"C1 control", "alice\u0085", "next-line control character"},
		{"RTL override", "alice\u202eeslaf", "renders as a different name than it stores"},
		{"LTR override", "alice\u202d", "bidi override"},
		{"zero-width joiner", "ali\u200dce", "invisible, so two accounts can look identical"},
		{"leading space", " alice", "indistinguishable from alice in a list"},
		{"trailing space", "alice ", "indistinguishable from alice in a list"},
		{"empty", "", "no name at all"},
		{"too long", strings.Repeat("a", 65), "unbounded render cost downstream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateUsername(tc.username); err == nil {
				t.Errorf("accepted %q -- %s", tc.username, tc.why)
			}
		})
	}
}

func TestValidateUsernameAcceptsRealNames(t *testing.T) {
	// Non-ASCII is deliberately allowed: refusing everyone whose name
	// isn't ASCII to save writing a validator is not a security measure.
	for _, username := range []string{
		"alice",
		"tom.lawson",
		"tom@example.com",
		"user-1",
		"Ann_Marie",
		"José",
		"Ω-operator",
		"日本語",
		strings.Repeat("a", 64),
	} {
		if err := ValidateUsername(username); err != nil {
			t.Errorf("rejected legitimate username %q: %v", username, err)
		}
	}
}

// Every locally-created account funnels through createAccount, so both
// entry points inherit the check.
func TestRegisterAndCreateUserRejectAHostileUsername(t *testing.T) {
	s := openTestStore(t)

	if _, err := s.Register("admin\x1b[2K\rroot", "password123", time.Now()); err == nil {
		t.Error("Register accepted a username containing an ANSI escape")
	}
	if s.Count() != 0 {
		t.Fatalf("a refused Register created an account anyway (count=%d)", s.Count())
	}

	if _, err := s.Register("admin", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := s.CreateUser("bob\nadmin", "password456", RoleUser, time.Now()); err == nil {
		t.Error("CreateUser accepted a username containing a newline")
	}
}

// An identity provider's claim is not under this deployment's control,
// and the person signing in has already authenticated. A hostile hint
// must be dropped in favour of the generated name, never turned into a
// failed login.
func TestOIDCProvisioningFallsBackRatherThanFailingOnAHostileHint(t *testing.T) {
	s := openTestStoreWithAdmin(t)

	u, created, err := s.FindOrCreateOIDCUser(
		"https://idp.example", "subject-1", "victim\x1b[2K\radmin", time.Now())
	if err != nil {
		t.Fatalf("provisioning failed on a hostile username hint: %v", err)
	}
	if !created {
		t.Fatal("expected a new account")
	}
	if err := ValidateUsername(u.Username); err != nil {
		t.Errorf("provisioned account has an invalid username %q: %v", u.Username, err)
	}
	if !strings.HasPrefix(u.Username, "oidc-") {
		t.Errorf("expected the generated fallback name, got %q", u.Username)
	}

	// And the fallback stays stable: signing in again resolves to the
	// same account rather than minting another one.
	again, created, err := s.FindOrCreateOIDCUser(
		"https://idp.example", "subject-1", "victim\x1b[2K\radmin", time.Now())
	if err != nil {
		t.Fatalf("second sign-in failed: %v", err)
	}
	if created || again.ID != u.ID {
		t.Error("the same identity was provisioned twice")
	}
}

func TestOIDCProvisioningKeepsAUsableHint(t *testing.T) {
	s := openTestStoreWithAdmin(t)

	u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-1", "tom@example.com", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if u.Username != "tom@example.com" {
		t.Errorf("username = %q, want the hint preserved", u.Username)
	}
}

// TestOIDCFallbackUsernameAlwaysValidates drives uniqueUsername
// down its fallback chain: a 64-character hint (the longest a username
// may be) already taken, then the hash-derived names in turn. Whatever
// it lands on is written to the store without further checks, so it has
// to pass ValidateUsername and fit maxUsernameLength -- the longest
// hash-derived candidate, "oidc-" plus all 64 hex digits, does not.
//
// The walk is pinned here rather than derived from the same loop the
// code runs: with the 8- to 48-digit names taken the answer is exactly
// "oidc-" plus 56 digits (61 characters, the longest that fits), and
// with that taken too it is the random fallback.
func TestOIDCFallbackUsernameAlwaysValidates(t *testing.T) {
	s := openTestStoreWithAdmin(t)
	now := time.Now()
	hint := strings.Repeat("a", maxUsernameLength)

	first, _, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-1", hint, now)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if first.Username != hint {
		t.Fatalf("username = %q, want the 64-character hint kept", first.Username)
	}

	hashOf := func(subject string) string {
		sum := sha256.Sum256([]byte("https://idp.example" + "\x00" + subject))
		return hex.EncodeToString(sum[:])
	}
	occupy := func(full string, lengths ...int) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, n := range lengths {
			s.byName["oidc-"+full[:n]] = "someone-else"
		}
	}
	signIn := func(subject string) string {
		t.Helper()
		u, created, err := s.FindOrCreateOIDCUser("https://idp.example", subject, hint, now)
		if err != nil {
			t.Fatalf("FindOrCreateOIDCUser(%s): %v", subject, err)
		}
		if !created {
			t.Fatalf("FindOrCreateOIDCUser(%s): expected a new account", subject)
		}
		if err := ValidateUsername(u.Username); err != nil {
			t.Errorf("fallback username %q (%d characters) does not validate: %v",
				u.Username, utf8.RuneCountInString(u.Username), err)
		}
		return u.Username
	}

	full := hashOf("subject-2")
	occupy(full, 8, 16, 24, 32, 40, 48)
	if got, want := signIn("subject-2"), "oidc-"+full[:56]; got != want {
		t.Errorf("with the 8- to 48-digit names taken, username = %q, want %q", got, want)
	}

	full = hashOf("subject-3")
	occupy(full, 8, 16, 24, 32, 40, 48, 56)
	if got := signIn("subject-3"); strings.Contains(got, full[:8]) {
		t.Errorf("with every name that fits taken, username = %q, want the random fallback, not a longer slice of the hash", got)
	}
}
