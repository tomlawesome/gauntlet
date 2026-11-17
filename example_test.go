// Runnable usage examples for godoc (`go doc`, pkg.go.dev). Each Example
// exercises one entry point an application actually calls: OpenStore,
// NewSessionStore, OpenTokenStore, NewLoginLimiter. Output is checked and
// kept deterministic -- no ids, hashes or wall-clock times are printed,
// only fixed `now` values the caller supplies.
package gauntlet_test

import (
	"fmt"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// ExampleOpenStore opens an empty store, which announces a one-time
// setup code (through Options.OnSetupCode here; through Options.Log
// when that is nil), checks the code the way a first-run screen's
// handler would, registers the first account (which always becomes
// admin -- see Store.Register), then authenticates it once with the
// right password and once with a wrong one. The code itself is random,
// so it is checked rather than printed.
func ExampleOpenStore() {
	var setupCode string
	store, err := gauntlet.OpenStore(persist.NewMemory(), gauntlet.Options{
		OnSetupCode: gauntlet.SetupCodeFunc(func(code string) { setupCode = code }),
	})
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	fmt.Println("setup code accepted:", store.CheckSetupCode(setupCode) == nil)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	admin, err := store.Register("alice", "correct horse battery staple", now)
	if err != nil {
		fmt.Println("register:", err)
		return
	}
	fmt.Println("role:", admin.Role)

	if _, err := store.Authenticate("alice", "correct horse battery staple", now); err != nil {
		fmt.Println("authenticate:", err)
	} else {
		fmt.Println("authenticated")
	}

	_, err = store.Authenticate("alice", "not the right password", now)
	fmt.Println("wrong password:", err == gauntlet.ErrInvalidCredentials)

	// Output:
	// setup code accepted: true
	// role: admin
	// authenticated
	// wrong password: true
}

// ExampleNewSessionStore creates a session, validates it while live, then
// shows that Revoke ends it. now is passed explicitly throughout, as a
// caller would when driving expiry from its own request clock rather
// than time.Now.
func ExampleNewSessionStore() {
	sessions := gauntlet.NewSessionStore(15*time.Minute, time.Hour)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sess := sessions.Create("user-1", now)

	if _, ok := sessions.Validate(sess.ID, now.Add(time.Minute)); ok {
		fmt.Println("valid before revoke")
	}

	sessions.Revoke(sess.ID)
	_, ok := sessions.Validate(sess.ID, now.Add(time.Minute))
	fmt.Println("valid after revoke:", ok)

	// Output:
	// valid before revoke
	// valid after revoke: false
}

// ExampleOpenTokenStore registers a token kind the caller defines itself
// (TokenOptions.Kinds is how an application adds one beyond the built-in
// TokenKindAPI/TokenKindIngest), then shows that Authenticate only
// accepts a token for the kind it was created with. The raw token value
// is never printed -- only Create ever sees it.
func ExampleOpenTokenStore() {
	const kindWebhook gauntlet.TokenKind = "webhook"

	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{
		Kinds: []gauntlet.TokenKind{kindWebhook},
	})
	if err != nil {
		fmt.Println("open:", err)
		return
	}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	raw, tok, err := tokens.Create("ci webhook", kindWebhook, "", nil, now)
	if err != nil {
		fmt.Println("create:", err)
		return
	}
	fmt.Println("kind:", tok.Kind)

	if _, ok := tokens.Authenticate(raw, kindWebhook, now); ok {
		fmt.Println("right kind: accepted")
	}
	if _, ok := tokens.Authenticate(raw, gauntlet.TokenKindAPI, now); !ok {
		fmt.Println("wrong kind: rejected")
	}

	// Output:
	// kind: webhook
	// right kind: accepted
	// wrong kind: rejected
}

// ExampleNewLoginLimiter shows the two ways to guard a login attempt.
// Reserve/Release brackets a slow credential comparison: the reservation
// is held for its duration and released only on success, so a failed
// attempt simply stays counted (it does not also call RecordFailure for
// the same attempt). RecordFailure is for a caller with nothing slow to
// hold a reservation around -- it just records the failure directly.
// Both reach the same threshold-driven lock-out.
func ExampleNewLoginLimiter() {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	limiter, err := gauntlet.NewLoginLimiter(2, time.Minute)
	if err != nil {
		fmt.Println("new limiter:", err)
		return
	}

	limiter.Reserve("alice", now) // attempt 1: comparison fails, stays counted
	limiter.Reserve("alice", now) // attempt 2: comparison fails, stays counted
	fmt.Println("locked out after 2 failed attempts:", !limiter.Reserve("alice", now))

	limiter.RecordFailure("bob", now)
	limiter.RecordFailure("bob", now)
	fmt.Println("locked out after 2 recorded failures:", !limiter.Reserve("bob", now))

	limiter.Reserve("carol", now)
	limiter.Release("carol", now) // a success releases the reservation
	fmt.Println("still allowed after a released success:", limiter.Reserve("carol", now))

	// Output:
	// locked out after 2 failed attempts: true
	// locked out after 2 recorded failures: true
	// still allowed after a released success: true
}
