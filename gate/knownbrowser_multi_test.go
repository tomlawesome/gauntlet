package gate

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// The known-browser cookie carries one token per account, up to
// maxKnownBrowserTokens, so a browser used for two accounts is known to
// both (#55 §4).

const (
	carolUsername = "carol"
	carolPassword = "carol-password-placeholder"
)

// addCarol creates a second ordinary account beside bob, signing in in
// one step like bob does before he enrols a factor.
func addCarol(t *testing.T, g *Gate, ts *httptest.Server, admin *http.Client) string {
	t.Helper()
	resp := postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{Username: carolUsername, Password: carolPassword, Role: "user"})
	if status, body := readAll(t, resp); status != http.StatusCreated {
		t.Fatalf("creating carol = %d %s", status, body)
	}
	u, _ := g.deps.Users.ByUsername(carolUsername)
	return u.ID
}

// knownTokens is the cookie's tokens, in order.
func knownTokens(t *testing.T, client *http.Client, ts *httptest.Server) []string {
	t.Helper()
	u, _ := url.Parse(ts.URL + loginPath)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == knownBrowserCookieName {
			return strings.Split(c.Value, ".")
		}
	}
	return nil
}

// setKnownCookie puts value in client's jar as the known-browser cookie.
func setKnownCookie(t *testing.T, client *http.Client, ts *httptest.Server, value string) {
	t.Helper()
	u, _ := url.Parse(ts.URL + "/api/auth")
	client.Jar.SetCookies(u, []*http.Cookie{{Name: knownBrowserCookieName, Value: value, Path: "/api/auth"}})
}

func randomToken(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// One browser, two accounts: each keeps its allowance through its own
// lockout, whichever signed in last.
func TestABrowserIsKnownToEveryAccountItSignsInTo(t *testing.T) {
	g, ts, admin := totpFixture(t)
	clock := &escalationClock{t: g.now()}
	g.cfg.Now = clock.now
	var n atomic.Int64
	g.cfg.ClientIP = func(*http.Request) string { return fmt.Sprintf("192.0.2.%d", n.Add(1)) }
	bobID := totpBobID(t, g)
	carolID := addCarol(t, g, ts, admin)
	browser := &http.Client{Jar: mustCookieJar(t)}
	for _, who := range [][2]string{{totpBobUsername, totpBobPassword}, {carolUsername, carolPassword}} {
		if status := signInFrom(t, browser, ts, who[0], who[1]); status != http.StatusOK {
			t.Fatalf("%s's sign-in = %d", who[0], status)
		}
	}
	tokens := knownTokens(t, browser, ts)
	if len(tokens) != 2 {
		t.Fatalf("the cookie holds %d tokens after two accounts, want 2: %q", len(tokens), tokens)
	}
	now := g.now()
	if !g.deps.Users.KnowsBrowser(carolID, tokens[0], now) || !g.deps.Users.KnowsBrowser(bobID, tokens[1], now) {
		t.Fatal("want carol's fresh token first, then bob's")
	}

	failLoginWindow(t, g, ts, clock, totpBobUsername)
	if status := signInFrom(t, browser, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Errorf("bob from the shared browser during his lockout = %d, want 200", status)
	}
	failLoginWindow(t, g, ts, clock, carolUsername)
	if status := signInFrom(t, browser, ts, carolUsername, carolPassword); status != http.StatusOK {
		t.Errorf("carol from the shared browser during her lockout = %d, want 200", status)
	}
	if got := knownTokens(t, browser, ts); len(got) != 2 {
		t.Errorf("after each account's sign-in again the cookie holds %d tokens, want 2", len(got))
	}
	for id, n := range map[string]int{bobID: 1, carolID: 1} {
		if u, _ := g.deps.Users.Get(id); len(u.KnownBrowsers) != n {
			t.Errorf("account %s remembers %d browsers, want %d", id, len(u.KnownBrowsers), n)
		}
	}
}

// A cookie issued before this change holds one token; it still works.
func TestAOneTokenCookieStillWorks(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	bobID := totpBobID(t, g)
	token, err := g.deps.Users.RememberBrowser(bobID, "", clock.now())
	if err != nil {
		t.Fatal(err)
	}
	failLoginWindow(t, g, ts, clock, totpBobUsername)
	browser := &http.Client{Jar: mustCookieJar(t)}
	setKnownCookie(t, browser, ts, token)
	if status := signInFrom(t, browser, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Fatalf("a one-token cookie during the lockout = %d, want 200", status)
	}
	got := knownTokens(t, browser, ts)
	if len(got) != 1 || got[0] == token || !g.deps.Users.KnowsBrowser(bobID, got[0], clock.now()) {
		t.Errorf("after the sign-in the cookie = %q, want one fresh token replacing the old", got)
	}
}

// The cookie holds at most four tokens: a fifth account evicts the one
// that signed in longest ago, the last in the cookie.
func TestTheFifthTokenEvictsTheOldest(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bobID := totpBobID(t, g)
	carried := []string{randomToken(t), randomToken(t), randomToken(t), randomToken(t)}
	browser := &http.Client{Jar: mustCookieJar(t)}
	setKnownCookie(t, browser, ts, strings.Join(carried, "."))
	if status := signInFrom(t, browser, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Fatalf("sign-in = %d", status)
	}
	got := knownTokens(t, browser, ts)
	if len(got) != maxKnownBrowserTokens {
		t.Fatalf("the cookie holds %d tokens, want %d", len(got), maxKnownBrowserTokens)
	}
	if !g.deps.Users.KnowsBrowser(bobID, got[0], g.now()) {
		t.Error("the fresh token is not first")
	}
	if !slices.Equal(got[1:], carried[:3]) {
		t.Errorf("carried tokens = %q, want the first three kept in order and the last evicted", got[1:])
	}
}

// A part that is not a well-formed token is ignored on read and dropped
// from the next cookie; the well-formed part beside it still counts.
func TestAMalformedPartIsIgnored(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	bobID := totpBobID(t, g)
	token, err := g.deps.Users.RememberBrowser(bobID, "", clock.now())
	if err != nil {
		t.Fatal(err)
	}
	failLoginWindow(t, g, ts, clock, totpBobUsername)
	browser := &http.Client{Jar: mustCookieJar(t)}
	setKnownCookie(t, browser, ts, "not-a-token."+token+"..x")
	if status := signInFrom(t, browser, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Fatalf("a cookie with a malformed part beside bob's token = %d, want 200", status)
	}
	got := knownTokens(t, browser, ts)
	if len(got) != 1 || !g.deps.Users.KnowsBrowser(bobID, got[0], clock.now()) {
		t.Errorf("the next cookie = %q, want only the fresh token", got)
	}
}

// Sign out everywhere forgets the browsers of the account it is called
// for, and only that account: the shared browser's token for the other
// account stays in the cookie and stays known.
func TestSignOutEverywhereKeepsTheOtherAccountsToken(t *testing.T) {
	g, ts, admin := totpFixture(t)
	bobID := totpBobID(t, g)
	carolID := addCarol(t, g, ts, admin)
	browser := &http.Client{Jar: mustCookieJar(t)}
	if status := signInFrom(t, browser, ts, carolUsername, carolPassword); status != http.StatusOK {
		t.Fatalf("carol's sign-in = %d", status)
	}
	carolToken := knownTokens(t, browser, ts)[0]
	if status := signInFrom(t, browser, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Fatalf("bob's sign-in = %d", status)
	}
	totpEnrolAndConfirm(t, browser, ts) // past the enrolment door
	if status, body := readAll(t, postJSON(t, browser, ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: totpBobPassword})); status != http.StatusOK {
		t.Fatalf("bob's sign out everywhere = %d %s", status, body)
	}
	got := knownTokens(t, browser, ts)
	now := g.now()
	if len(got) == 0 || !g.deps.Users.KnowsBrowser(bobID, got[0], now) {
		t.Fatalf("after sign out everywhere the cookie = %q, want bob's fresh token first", got)
	}
	if !slices.Contains(got, carolToken) || !g.deps.Users.KnowsBrowser(carolID, carolToken, now) {
		t.Errorf("carol's token left the cookie or carol forgot it: cookie %q", got)
	}
	if u, _ := g.deps.Users.Get(bobID); len(u.KnownBrowsers) != 1 {
		t.Errorf("bob remembers %d browsers, want only this one", len(u.KnownBrowsers))
	}
}
