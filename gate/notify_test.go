package gate

import (
	"net/http"
	"testing"

	"github.com/tomlawesome/gauntlet"
)

// Config.Notices (#73): every account event this module raises carries
// the right Kind and the one detail pointer it names. Flag, block and
// sessions-ended are covered in unusual_test.go and
// users_logoutall_handler_test.go; this file covers the rest.

// lastNotice waits for the background notices, then returns the newest
// one of kind, failing the test if none arrived.
func lastNotice(t *testing.T, g *Gate, rec *noticeRecorder, kind NoticeKind) AccountNotice {
	t.Helper()
	g.notifying.Wait()
	all := rec.all()
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Kind == kind {
			return all[i]
		}
	}
	t.Fatalf("no %s notice among %+v", kind, all)
	return AccountNotice{}
}

func TestNoticePasswordReset(t *testing.T) {
	g, ts, admin := totpFixture(t)
	rec := &noticeRecorder{}
	g.cfg.Notices = rec
	bobID := totpBobID(t, g)

	status, body := readAll(t, postJSON(t, admin, ts.URL+"/api/auth/users/"+bobID+"/reset-password", adminStepUpRequest{Password: testAdminPassword}))
	if status != http.StatusOK {
		t.Fatalf("reset = %d %s", status, body)
	}
	n := lastNotice(t, g, rec, NoticePasswordReset)
	if n.UserID != bobID || n.Username != totpBobUsername || n.Role != gauntlet.RoleUser || n.By != "admin" ||
		n.PasswordReset == nil || n.PasswordReset.ExpiresAt.IsZero() || n.At.IsZero() {
		t.Errorf("notice = %+v", n)
	}
}

// A first second factor, held until its recovery codes are confirmed
// (#58), is a second-factor-added notice only once confirmed -- never
// at the hold itself, which is noticed for nothing until then.
func TestNoticeSecondFactorAddedAtFirstFactorConfirm(t *testing.T) {
	t.Run("totp", func(t *testing.T) {
		g, ts, _ := totpFixture(t)
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
		totpEnrolAndConfirm(t, bob, ts)
		n := lastNotice(t, g, rec, NoticeSecondFactorAdded)
		bobID := totpBobID(t, g)
		if n.UserID != bobID || n.Username != totpBobUsername || n.Role != gauntlet.RoleUser || n.By != "" ||
			n.SecondFactor == nil || n.SecondFactor.Method != "totp" || n.SecondFactor.Name != "" || n.SecondFactor.All {
			t.Errorf("notice = %+v", n)
		}
	})
	t.Run("passkey", func(t *testing.T) {
		g, ts, _ := heldPasskeyFixture(t)
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		registerPasskeyHeld(t, bilbo, ts, g, "first")
		confirmEnrolmentOK(t, bilbo, ts)
		n := lastNotice(t, g, rec, NoticeSecondFactorAdded)
		bilboID := passkeyBilboID(t, g)
		if n.UserID != bilboID || n.Username != passkeyBilboUsername || n.By != "" ||
			n.SecondFactor == nil || n.SecondFactor.Method != "passkey" || n.SecondFactor.Name != "first" || n.SecondFactor.All {
			t.Errorf("notice = %+v", n)
		}
	})
}

// A later factor, added to an account that already has one, goes live
// at once and is noticed from the factor's own route, not the hold path.
func TestNoticeSecondFactorAddedDirect(t *testing.T) {
	t.Run("totp", func(t *testing.T) {
		g, ts, _ := heldPasskeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		registerPasskeyHeld(t, bilbo, ts, g, "first")
		confirmEnrolmentOK(t, bilbo, ts)
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		totpEnrolAndConfirmLive(t, bilbo, ts, g.now())
		n := lastNotice(t, g, rec, NoticeSecondFactorAdded)
		if n.SecondFactor == nil || n.SecondFactor.Method != "totp" || n.SecondFactor.Name != "" {
			t.Errorf("notice = %+v", n)
		}
	})
	t.Run("passkey", func(t *testing.T) {
		g, ts, _ := heldPasskeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		registerPasskeyHeld(t, bilbo, ts, g, "first")
		confirmEnrolmentOK(t, bilbo, ts)
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		registerPasskeyHeld(t, bilbo, ts, g, "second")
		n := lastNotice(t, g, rec, NoticeSecondFactorAdded)
		if n.SecondFactor == nil || n.SecondFactor.Method != "passkey" || n.SecondFactor.Name != "second" {
			t.Errorf("notice = %+v", n)
		}
	})
}

// handleTOTPDelete and handlePasskeyDelete are both DELETE with a JSON
// body.
func TestNoticeSecondFactorRemoved(t *testing.T) {
	t.Run("totp self", func(t *testing.T) {
		g, ts, _ := totpFixture(t)
		bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
		totpEnrolAndConfirm(t, bob, ts)
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		status, body := readAll(t, deleteJSON(t, bob, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: totpBobPassword}))
		if status != http.StatusOK {
			t.Fatalf("delete = %d %s", status, body)
		}
		n := lastNotice(t, g, rec, NoticeSecondFactorRemoved)
		if n.By != "" || n.SecondFactor == nil || n.SecondFactor.Method != "totp" || n.SecondFactor.All {
			t.Errorf("notice = %+v", n)
		}
	})
	t.Run("totp admin", func(t *testing.T) {
		g, ts, admin := totpFixture(t)
		bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
		totpEnrolAndConfirm(t, bob, ts)
		bobID := totpBobID(t, g)
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		status, body := readAll(t, deleteJSON(t, admin, ts.URL+"/api/auth/users/"+bobID+"/totp", adminStepUpRequest{Password: testAdminPassword}))
		if status != http.StatusOK {
			t.Fatalf("admin clear = %d %s", status, body)
		}
		n := lastNotice(t, g, rec, NoticeSecondFactorRemoved)
		if n.By != "admin" || n.SecondFactor == nil || n.SecondFactor.Method != "totp" || !n.SecondFactor.All {
			t.Errorf("notice = %+v", n)
		}
	})
	t.Run("passkey self", func(t *testing.T) {
		g, ts, _ := passkeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		_, out := registerPasskey(t, bilbo, ts, g, "YubiKey")
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		status, body := readAll(t, deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword}))
		if status != http.StatusOK {
			t.Fatalf("delete = %d %s", status, body)
		}
		n := lastNotice(t, g, rec, NoticeSecondFactorRemoved)
		if n.By != "" || n.SecondFactor == nil || n.SecondFactor.Method != "passkey" || n.SecondFactor.Name != "YubiKey" || n.SecondFactor.All {
			t.Errorf("notice = %+v", n)
		}
	})
	t.Run("passkey admin", func(t *testing.T) {
		g, ts, admin := passkeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		registerPasskey(t, bilbo, ts, g, "YubiKey")
		bilboID := passkeyBilboID(t, g)
		rec := &noticeRecorder{}
		g.cfg.Notices = rec
		status, body := readAll(t, deleteJSON(t, admin, ts.URL+"/api/auth/users/"+bilboID+"/passkeys", adminStepUpRequest{Password: testAdminPassword}))
		if status != http.StatusOK {
			t.Fatalf("admin clear = %d %s", status, body)
		}
		n := lastNotice(t, g, rec, NoticeSecondFactorRemoved)
		if n.By != "admin" || n.SecondFactor == nil || n.SecondFactor.Method != "passkey" || !n.SecondFactor.All {
			t.Errorf("notice = %+v", n)
		}
	})
}

func TestNoticeRecoveryCodesRegenerated(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)
	rec := &noticeRecorder{}
	g.cfg.Notices = rec
	status, body := readAll(t, postJSON(t, bob, ts.URL+"/api/auth/recovery-codes", recoveryCodesRegenerateRequest{Password: totpBobPassword}))
	if status != http.StatusOK {
		t.Fatalf("regenerate = %d %s", status, body)
	}
	bobID := totpBobID(t, g)
	n := lastNotice(t, g, rec, NoticeRecoveryCodesRegenerated)
	if n.UserID != bobID || n.Username != totpBobUsername || n.Role != gauntlet.RoleUser ||
		n.PasswordReset != nil || n.SecondFactor != nil || n.Lockout != nil || n.SessionsEnded != nil || n.UnusualSignIn != nil {
		t.Errorf("notice = %+v, want no detail set", n)
	}
}

// A lockout and, after enough of them, a disable each raise their own
// notice with no account record loaded (Role zero).
func TestNoticeAccountLockedAndDisabled(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	rec := &noticeRecorder{}
	g.cfg.Notices = rec
	bobID := totpBobID(t, g)

	failLoginWindow(t, g, ts, clock, totpBobUsername)
	locked := lastNotice(t, g, rec, NoticeAccountLocked)
	if locked.UserID != bobID || locked.Username != totpBobUsername || locked.Role != "" ||
		locked.By != "" || locked.Lockout == nil || locked.Lockout.Until.IsZero() || locked.Lockout.Lockouts != 1 || locked.Lockout.Address == "" {
		t.Errorf("locked notice = %+v", locked)
	}

	for failed := 5; failed < gauntlet.MaxConsecutiveLoginFailures; failed += 5 {
		failLoginWindow(t, g, ts, clock, totpBobUsername)
	}
	disabled := lastNotice(t, g, rec, NoticeSignInDisabled)
	if disabled.UserID != bobID || disabled.Username != totpBobUsername || disabled.By != "" || disabled.Lockout == nil {
		t.Errorf("disabled notice = %+v", disabled)
	}
}
