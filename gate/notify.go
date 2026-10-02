package gate

import (
	"context"
	"fmt"
	"time"
)

// Notifier is how an application hears that an admin ended another
// account's sessions (#53), so it can tell the account's owner -- by
// mail, in practice. gauntlet sends nothing itself: the application maps
// the username to an address and writes the message. nil
// (Config.Notify) means nobody is told.
//
// SessionsEnded is called after the admin's response has been written,
// in its own goroutine, with a context that ends after notifyTimeout (10
// seconds). It never delays or changes that response: an error it
// returns, or a panic, is one error line in Config.Log. So the admin's
// "notified" means the application was asked, not that a mail arrived.
type Notifier interface {
	SessionsEnded(ctx context.Context, n SessionsEndedNotice) error
}

// SessionsEndedNotice is what a Notifier is told.
type SessionsEndedNotice struct {
	// UserID and Username are the account whose sessions ended.
	UserID   string
	Username string
	// EndedBy is the username of the admin who ended them.
	EndedBy string
	// Reason is what the admin gave, possibly empty; when it is, the
	// message should still say an administrator signed them out (owner,
	// 2026-10-02).
	Reason string
	// Ended is how many live sessions ended.
	Ended int
	At    time.Time
}

// notifyTimeout bounds one SessionsEnded call. A variable so tests can
// shorten it.
var notifyTimeout = 10 * time.Second

// notifySessionsEnded asks Config.Notify, if set, to tell n's account,
// in the background. Call it only once the response is written.
func (g *Gate) notifySessionsEnded(ctx context.Context, n SessionsEndedNotice) {
	notify := g.cfg.Notify
	if notify == nil {
		return
	}
	// The request's context ends when its handler returns; the
	// notification outlives it, keeping only its values.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
	g.notifying.Add(1)
	go func() {
		defer g.notifying.Done()
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				g.logError(fmt.Sprintf("gate: the sessions-ended notifier panicked for account %q: %q", n.Username, fmt.Sprint(p)))
			}
		}()
		if err := notify.SessionsEnded(ctx, n); err != nil {
			g.logError(fmt.Sprintf("gate: the sessions-ended notifier failed for account %q: %q", n.Username, err.Error()))
		}
	}()
}
