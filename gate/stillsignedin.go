package gate

import (
	"fmt"
	"net/http"
)

// Refusal is StillSignedIn's answer when Protect would no longer
// admit the request. Status and Class are what Protect's response
// would carry (docs/api/errors.md), so an application can end the
// stream with the same reason -- a websocket close reason, a last
// server-sent event -- that the next ordinary request will get.
type Refusal struct {
	Status int    // 401, 403 or 503
	Class  string // "sign-in-required", "invalid-credentials", "csrf-required", "forbidden", "must-change-password", "must-enrol-passkey", "must-enrol-factor", "setup-required"
}

// Error names the status and the class:
// "gate: no longer admitted: 403 must-enrol-factor".
func (e *Refusal) Error() string {
	return fmt.Sprintf("gate: no longer admitted: %d %s", e.Status, e.Class)
}

// StillSignedIn answers, for a request Protect admitted earlier and
// whose response is still open, whether Protect would admit it again
// now: nil while it would, otherwise the refusal Protect would write.
// It reads the same cookie or Authorization header, applies the same
// rules in the same order -- the undecided state, the bearer kinds
// registered with Handle, the CSRF header, Exempt paths, the session,
// the account, its role, and the three doors, each against the
// request's own path -- and differs in one way: it touches nothing.
// The session's expiry does not slide, no LastUsedAt moves, no
// document is written, nothing is revoked, and none of Protect's
// refusal lines is logged. (A store that meets a document written by a
// newer build still logs that once, as it would on any request.)
// A stream that calls it on a timer therefore idles out when the
// person does, not while the tab is open (#104).
//
// The clock is Config.Now. r is the request as the handler received
// it; it is read, never changed, so one request may be checked from
// the handler's goroutine while other requests are served. A request
// on an Exempt path is admitted whatever its cookie says, as Protect
// admits it: a route that must be re-checked must not be exempt.
//
// The decision is Protect's own (decideAccess, ADR-0016), asked not to
// touch, so the two cannot disagree on a refusal.
func (g *Gate) StillSignedIn(r *http.Request) error {
	if _, ref := g.decideAccess(r, g.now(), false); ref != nil {
		return &Refusal{Status: ref.status, Class: ref.class.anchor}
	}
	return nil
}
