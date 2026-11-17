package gauntlet

import (
	"strings"
	"testing"
	"time"
)

// The escape code's two root-package pieces (#66): the generator it
// shares with the setup and unlock codes, and OtherAdminCanAct.

func TestNewOneTimeCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		display, canonical := NewOneTimeCode()
		if len(display) != 19 || display[4] != '-' || display[9] != '-' || display[14] != '-' {
			t.Fatalf("display = %q, want xxxx-xxxx-xxxx-xxxx", display)
		}
		if len(canonical) != 16 || strings.ContainsAny(canonical, "-abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("canonical = %q, want 16 upper-case characters, no dashes", canonical)
		}
		if NormaliseResetCode(display) != canonical || NormaliseResetCode(strings.ToLower(display)) != canonical {
			t.Errorf("%q does not normalise to %q", display, canonical)
		}
		if seen[canonical] {
			t.Fatalf("code %q was made twice", canonical)
		}
		seen[canonical] = true
	}
}

func TestOtherAdminCanAct(t *testing.T) {
	s, alice, bob, carol := storeWithTwoAdmins(t)
	now := time.Now()
	if !s.OtherAdminCanAct(alice.ID, now) || !s.OtherAdminCanAct(bob.ID, now) {
		t.Error("with two admins neither sees the other as unable")
	}
	if !s.OtherAdminCanAct(carol.ID, now) {
		t.Error("a plain user is not an admin, so the two admins count as able")
	}

	// A lockout is not a disable: it ends within the hour.
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	failWindow(t, l, s, bob.ID, now)
	if !s.OtherAdminCanAct(alice.ID, now) {
		t.Error("an admin locked out for a while was counted as unable")
	}

}

// Disabled: unable, until the disable lifts by itself (#70).
func TestOtherAdminCanActIgnoresADisabledAdmin(t *testing.T) {
	s, alice, bob, _ := storeWithTwoAdmins(t)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	failConsecutively(t, l, s, bob.ID, MaxConsecutiveLoginFailures, escalationStart)
	u, _ := s.Get(bob.ID)
	if u.LoginDisabledAt.IsZero() {
		t.Fatal("precondition: bob is not disabled")
	}
	during := u.LoginDisabledAt.Add(time.Minute)
	if s.OtherAdminCanAct(alice.ID, during) {
		t.Error("a disabled admin was counted as able")
	}
	if !s.OtherAdminCanAct(bob.ID, during) {
		t.Error("bob's own check is about alice, who can act")
	}
	if !s.OtherAdminCanAct(alice.ID, u.LoginDisabledAt.Add(LoginDisableDuration)) {
		t.Error("an admin whose disable has lifted was counted as unable")
	}
}

func TestOtherAdminCanActWithOneAdmin(t *testing.T) {
	s := openTestStore(t)
	alice, err := s.Register("alice", "correct-horse-battery-staple", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("carol", "correct-horse-battery-staple", RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.OtherAdminCanAct(alice.ID, time.Now()) {
		t.Error("the only admin has another admin able to act")
	}
}
