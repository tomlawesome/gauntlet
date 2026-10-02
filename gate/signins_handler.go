package gate

import (
	"net/http"
	"strconv"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// GET /api/auth/sign-ins (#53): the sign-in history, for admins. Every
// attempt recordSignIn sees is appended to Deps.SignIns; this route
// pages through it, newest first. With no history configured it answers
// 404, as the OIDC and passkey routes do when theirs are off.

// signInRow is one row of the history -- a closed shape, so nothing a
// row holds reaches a page unless it is named here. An unrecorded row
// (the attempts past a bucket's failure budget) carries only the
// required fields.
type signInRow struct {
	Seq      uint64                 `json:"seq"`
	At       time.Time              `json:"at"`
	Until    time.Time              `json:"until"`
	Count    int                    `json:"count"`
	Outcome  gauntlet.SignInOutcome `json:"outcome"`
	UserID   string                 `json:"userId,omitempty"`
	Username string                 `json:"username,omitempty"`
	Method   gauntlet.SignInMethod  `json:"method,omitempty"`
	// Address and UserAgent are the first attempt's, as
	// gauntlet.SessionClient holds a session's.
	Address     string    `json:"address,omitempty"`
	UserAgent   string    `json:"userAgent,omitempty"`
	LockedUntil time.Time `json:"lockedUntil,omitzero"`
	Disabled    bool      `json:"disabled,omitempty"`
}

// signInListResponse is GET /api/auth/sign-ins's body.
type signInListResponse struct {
	SignIns []signInRow `json:"signIns"`
	// More is true when rows beyond this page match: ask again with
	// before set to the last row's seq.
	More bool `json:"more"`
	// Total is how many rows the history holds, and Since when the
	// oldest began -- how full it is and how far back it goes. Since is
	// absent while it holds none.
	Total int       `json:"total"`
	Since time.Time `json:"since,omitzero"`
}

// signInOutcomes is every outcome the route filters on.
var signInOutcomes = map[gauntlet.SignInOutcome]bool{
	gauntlet.SignInSuccess: true, gauntlet.SignInPasswordOK: true, gauntlet.SignInNoSuchUser: true,
	gauntlet.SignInWrongPassword: true, gauntlet.SignInFactorRefused: true, gauntlet.SignInLocked: true,
	gauntlet.SignInDisabled: true, gauntlet.SignInRateLimited: true, gauntlet.SignInSSORefused: true,
	gauntlet.SignInUnrecorded: true,
}

// signInQuery reads the route's query: user (an account id), address
// (exact, at most gauntlet.MaxSessionAddress bytes), outcome, before (a
// row's seq) and limit (1 to gauntlet.MaxSignInListLimit). reason says
// what is wrong with a value out of range, and is empty otherwise.
func signInQuery(r *http.Request) (q gauntlet.SignInQuery, reason string) {
	v := r.URL.Query()
	q.UserID = v.Get("user")
	q.Address = v.Get("address")
	if len(q.Address) > gauntlet.MaxSessionAddress {
		return q, "address is too long"
	}
	if o := v.Get("outcome"); o != "" {
		q.Outcome = gauntlet.SignInOutcome(o)
		if !signInOutcomes[q.Outcome] {
			return q, "unknown outcome"
		}
	}
	if b := v.Get("before"); b != "" {
		n, err := strconv.ParseUint(b, 10, 64)
		if err != nil || n == 0 {
			return q, "before must be a row's seq"
		}
		q.Before = n
	}
	q.Limit = gauntlet.DefaultSignInListLimit
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > gauntlet.MaxSignInListLimit {
			return q, "limit must be between 1 and " + strconv.Itoa(gauntlet.MaxSignInListLimit)
		}
		q.Limit = n
	}
	return q, ""
}

// handleSignInsList answers GET /api/auth/sign-ins (admin only, through
// adminOnly).
func (g *Gate) handleSignInsList(w http.ResponseWriter, r *http.Request) {
	if g.deps.SignIns == nil {
		http.Error(w, "sign-in history is not configured", http.StatusNotFound)
		return
	}
	q, reason := signInQuery(r)
	if reason != "" {
		http.Error(w, reason, http.StatusBadRequest)
		return
	}
	rows, more := g.deps.SignIns.List(q)
	total, since := g.deps.SignIns.Summary()
	resp := signInListResponse{SignIns: make([]signInRow, 0, len(rows)), More: more, Total: total, Since: since}
	for _, row := range rows {
		resp.SignIns = append(resp.SignIns, signInRow{
			Seq: row.Seq, At: row.At, Until: row.Until, Count: row.Count, Outcome: row.Outcome,
			UserID: row.UserID, Username: row.Username, Method: row.Method,
			Address: row.Client.Address, UserAgent: row.Client.UserAgent,
			LockedUntil: row.LockedUntil, Disabled: row.Disabled,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}
