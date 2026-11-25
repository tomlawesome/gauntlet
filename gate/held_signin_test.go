package gate

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// The held sign-in on the account (#107): which outcomes write it, which
// leave it, and what clears it. "Held" is every credential right and the
// unusual-sign-in policy stopping the session.

const heldTestAgent = "Firefox/131.0 (test)" // what browser.at sends

func (e *unusualEnv) heldOf(t *testing.T) *gauntlet.HeldSignIn {
	t.Helper()
	u, ok := e.g.deps.Users.Get(e.bobID)
	if !ok {
		t.Fatal("bob is gone")
	}
	return u.HeldSignIn
}

func requireHold(t *testing.T, got *gauntlet.HeldSignIn, outcome gauntlet.SignInOutcome, at time.Time, country string) {
	t.Helper()
	if got == nil {
		t.Fatalf("no held sign-in on the account, want %s", outcome)
	}
	if got.Outcome != outcome || !got.At.Equal(at) || got.UserAgent != heldTestAgent || got.Country != country {
		t.Errorf("held sign-in = %+v, want outcome %s at %v, agent %q, country %q", *got, outcome, at, heldTestAgent, country)
	}
}

// blockEnvHeld is a block-policy env with bob known from London in
// known, and one refused sign-in from a new browser in Paris at the
// returned time.
func blockEnvHeld(t *testing.T) (e *unusualEnv, known *browser, held *browser, at time.Time) {
	t.Helper()
	e, _ = newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInBlock})
	known = newTestBrowser(t)
	e.mustSignIn(t, known, addrLondon)
	e.advance(time.Hour)
	held = newTestBrowser(t)
	at = e.clock.now()
	if status, body := e.signIn(t, held, addrParis); status != http.StatusForbidden {
		t.Fatalf("a new browser under block = %d %s, want 403", status, body)
	}
	return e, known, held, at
}

func TestRefusedSignInHoldsTheAccount(t *testing.T) {
	e, _, _, at := blockEnvHeld(t)
	requireHold(t, e.heldOf(t), gauntlet.SignInRefused, at, "FR")
}

func TestConfirmSentHoldsTheAccount(t *testing.T) {
	e, _, b := confirmEnv(t)
	at := e.clock.now()
	if status, _ := e.signIn(t, b, addrParis); status != http.StatusOK {
		t.Fatal("no challenge")
	}
	requireHold(t, e.heldOf(t), gauntlet.SignInConfirmSent, at, "FR")
}

func TestProveChallengeHoldsTheAccount(t *testing.T) {
	e := newProveEnv(t)
	e.held(t)
	u, _ := e.g.deps.Users.Get(e.id)
	if u.HeldSignIn == nil {
		t.Fatal("a held prove challenge left no held sign-in")
	}
	if u.HeldSignIn.Outcome != gauntlet.SignInConfirmSent || !u.HeldSignIn.At.Equal(e.clock.now()) {
		t.Errorf("held sign-in = %+v, want confirm_sent at %v", *u.HeldSignIn, e.clock.now())
	}
}

// A lone admin's refusal also issues an escape code: the outcome is
// escape_issued, not refused.
func TestLoneAdminRefusalHoldsAsEscapeIssued(t *testing.T) {
	e := loneAdminEnv(t)
	at := e.clock.now()
	e.refusedFrom(t, addrLondon2)
	requireHold(t, e.heldOf(t), gauntlet.SignInEscapeIssued, at, "GB")
}

// The latest hold stands.
func TestASecondHoldReplacesTheFirst(t *testing.T) {
	e, _, _, _ := blockEnvHeld(t)
	e.advance(time.Hour)
	at := e.clock.now()
	if status, _ := e.signIn(t, newTestBrowser(t), addrNewYork); status != http.StatusForbidden {
		t.Fatal("second refusal not 403")
	}
	requireHold(t, e.heldOf(t), gauntlet.SignInRefused, at, "US")
}

// Wrong confirm and escape codes, limiter refusals and credential
// failures do not change the held state.
func TestWrongConfirmCodeLeavesTheHold(t *testing.T) {
	e, _, b := confirmEnv(t)
	at := e.clock.now()
	if status, _ := e.signIn(t, b, addrParis); status != http.StatusOK {
		t.Fatal("no challenge")
	}
	e.advance(time.Minute)
	if _, status, _ := e.postConfirm(t, b, addrParis, "00000000"); status != http.StatusUnauthorized {
		t.Fatalf("a wrong code = %d, want 401", status)
	}
	requireHold(t, e.heldOf(t), gauntlet.SignInConfirmSent, at, "FR")
}

func TestWrongEscapeCodeLeavesTheHold(t *testing.T) {
	e := loneAdminEnv(t)
	at := e.clock.now()
	b, _ := e.refusedFrom(t, addrLondon2)
	e.advance(time.Minute)
	if _, status, _ := e.postEscape(t, b, addrLondon2, "AAAA-AAAA-AAAA-AAAA"); status != http.StatusUnauthorized {
		t.Fatalf("a wrong escape code = %d, want 401", status)
	}
	requireHold(t, e.heldOf(t), gauntlet.SignInEscapeIssued, at, "GB")
}

func TestCredentialFailureAndLockoutDoNotHold(t *testing.T) {
	e, _ := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInBlock})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)

	resp := postJSON(t, newTestBrowser(t).at(addrParis), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: "wrong-password-placeholder"})
	if status, _ := readAll(t, resp); status != http.StatusUnauthorized {
		t.Fatalf("a wrong password = %d, want 401", status)
	}
	if got := e.heldOf(t); got != nil {
		t.Errorf("a wrong password held the account: %+v", *got)
	}

	if err := e.g.deps.Users.SetLoginLockedUntil(e.bobID, e.clock.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if status, _ := e.signIn(t, newTestBrowser(t), addrParis); status != http.StatusTooManyRequests {
		t.Fatalf("a locked account = %d, want 429", status)
	}
	if got := e.heldOf(t); got != nil {
		t.Errorf("a locked-out attempt held the account: %+v", *got)
	}
}

// A failed write is logged and does not change the answer.
func TestFailedHoldWriteIsLoggedAndTheAnswerUnchanged(t *testing.T) {
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	e := newUnusualEnvWith(t, backend, func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
	})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	before := strings.Count(e.logText(), "level=ERROR")
	backend.left = 0
	resp := postJSON(t, newTestBrowser(t).at(addrParis), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	checkRefused(t, e.g, resp)
	backend.left = -1
	if got := strings.Count(e.logText(), "level=ERROR") - before; got < 1 {
		t.Errorf("no error line for the failed hold write:\n%s", e.logText())
	}
	if got := e.heldOf(t); got != nil {
		t.Errorf("a failed write left a hold: %+v", *got)
	}
}

// Every way of completing a sign-in clears the hold.
func TestCompletedSignInsClearTheHold(t *testing.T) {
	t.Run("direct, from a known browser", func(t *testing.T) {
		e, known, _, _ := blockEnvHeld(t)
		e.advance(time.Minute)
		e.mustSignIn(t, known, addrLondon)
		if got := e.heldOf(t); got != nil {
			t.Errorf("hold survived a completed sign-in: %+v", *got)
		}
	})
	t.Run("after a confirm code", func(t *testing.T) {
		e, rec, b := confirmEnv(t)
		if status, _ := e.signIn(t, b, addrParis); status != http.StatusOK {
			t.Fatal("no challenge")
		}
		if e.heldOf(t) == nil {
			t.Fatal("precondition: no hold")
		}
		e.advance(time.Minute)
		if _, status, body := e.postConfirm(t, b, addrParis, confirmCode(t, rec)); status != http.StatusOK {
			t.Fatalf("confirm = %d %s", status, body)
		}
		if got := e.heldOf(t); got != nil {
			t.Errorf("hold survived the confirmed sign-in: %+v", *got)
		}
	})
	t.Run("after an escape code", func(t *testing.T) {
		e := loneAdminEnv(t)
		b, _ := e.refusedFrom(t, addrLondon2)
		if e.heldOf(t) == nil {
			t.Fatal("precondition: no hold")
		}
		if _, status, body := e.postEscape(t, b, addrLondon2, e.loggedCode()); status != http.StatusOK {
			t.Fatalf("escape = %d %s", status, body)
		}
		if got := e.heldOf(t); got != nil {
			t.Errorf("hold survived the escape sign-in: %+v", *got)
		}
	})
	t.Run("after an allowance", func(t *testing.T) {
		e, _, held, _ := blockEnvHeld(t)
		e.allow(t, e.bobID)
		if got := e.heldOf(t); got != nil {
			t.Errorf("allowing the next sign-in left the hold: %+v", *got)
		}
		e.advance(time.Minute)
		if status, body := e.signIn(t, held, addrParis); status != http.StatusOK {
			t.Fatalf("the allowed sign-in = %d %s", status, body)
		}
		if got := e.heldOf(t); got != nil {
			t.Errorf("hold survived the allowed sign-in: %+v", *got)
		}
	})
}
