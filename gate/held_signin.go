package gate

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// holdSignIn records on the account that its latest sign-in was held by
// the unusual-sign-in policy (#107), right after the event is recorded.
// The browser and country are the event's own cleaned client. A failed
// write is logged and changes nothing the person sees.
func (g *Gate) holdSignIn(r *http.Request, user *gauntlet.User, res loginReservation, outcome gauntlet.SignInOutcome, now time.Time) {
	client := g.signInClient(r, res.address)
	held := gauntlet.HeldSignIn{At: now, Outcome: outcome, UserAgent: client.UserAgent, Country: client.Country}
	if err := g.deps.Users.HoldSignIn(user.ID, held); err != nil {
		g.logError(fmt.Sprintf("gate: recording the held sign-in on account %q: %s", user.Username, err.Error()))
	}
}
