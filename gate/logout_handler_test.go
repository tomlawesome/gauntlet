package gate

import (
	"net/http"
	"testing"
	"time"
)

// Sign out everywhere asks for no credential, so the session it issues
// continues the caller's and keeps that sign-in's 24-hour ceiling.
// Issued as a fresh sign-in, a cookie used on this route once an hour
// would never expire.
func TestLogoutAllKeepsTheOriginalCeiling(t *testing.T) {
	f := newResumeFixture(t)
	before, ok := f.g.deps.Sessions.Validate(f.cookie, f.clock.now())
	if !ok {
		t.Fatal("bob's session is not live")
	}

	f.keepAlive(t, 23*time.Hour, f.bob)
	resp := postJSON(t, f.bob, f.ts.URL+"/api/auth/logout-all", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all at +23h returned %d", resp.StatusCode)
	}
	maxAge := 0
	for _, c := range resp.Cookies() {
		if c.Name == testCookieName {
			maxAge = c.MaxAge
		}
	}
	if maxAge <= 0 || maxAge > 60*60 {
		t.Errorf("cookie Max-Age = %d, want at most the hour left to the ceiling", maxAge)
	}

	after := sessionCookie(t, f.bob, f.ts)
	if after == f.cookie {
		t.Fatal("logout-all kept the old session ID")
	}
	sess, ok := f.g.deps.Sessions.Validate(after, f.clock.now())
	if !ok {
		t.Fatal("the session logout-all issued is not live")
	}
	if !sess.IssuedAt.Equal(before.IssuedAt) {
		t.Errorf("IssuedAt = %v, want the original sign-in's %v", sess.IssuedAt, before.IssuedAt)
	}

	f.at(23*time.Hour + 30*time.Minute)
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusOK {
		t.Fatalf("the new session was refused inside the ceiling: %d", got)
	}
	f.at(24*time.Hour + time.Second)
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusUnauthorized {
		t.Errorf("the session from logout-all outlived the original ceiling: %d", got)
	}
}
