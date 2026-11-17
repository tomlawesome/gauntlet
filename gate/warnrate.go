package gate

import (
	"fmt"
	"sync"
	"time"
)

// Refused requests leave a Warn line (#45): a limiter refusal, a missing
// CSRF header, a malformed Authorization header, a role or door 403. Each
// is something a stranger can send as fast as they like, so the lines
// are rated: at most one per key per warnRateInterval, the key naming
// the kind of refusal and the client address. The next line written for
// a key says how many were left out since the last.

// warnRateInterval is how long a key stays quiet after a line. A
// variable so tests can shorten it.
var warnRateInterval = time.Minute

// maxWarnRateKeys caps how many keys are tracked, like
// maxLoginLimiterKeys: past it, keys whose interval has passed are
// dropped, and if none has, the new key shares one overflow line with
// every other untracked source, so a flood from many addresses still
// writes a bounded number of lines. A variable so tests can shrink it.
var maxWarnRateKeys = 4096

type warnRate struct {
	last       time.Time
	suppressed int
}

// warnRater is the rating state behind Gate.warnRated, and behind the
// hourly unusual-sign-in notices (#55): at most one allowed per key per
// interval.
type warnRater struct {
	// interval points at the variable holding how long a key stays
	// quiet after it is allowed, so a test that shortens the variable
	// shortens the rater; nil means warnRateInterval.
	interval *time.Duration
	mu       sync.Mutex
	keys     map[string]*warnRate
	overflow warnRate
}

// every is the rater's interval.
func (w *warnRater) every() time.Duration {
	if w.interval == nil {
		return warnRateInterval
	}
	return *w.interval
}

// allow reports whether a line for key may be written at now, how many
// were left out before it, and whether key shared the overflow line.
func (w *warnRater) allow(key string, now time.Time) (ok bool, suppressed int, overflow bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.keys == nil {
		w.keys = make(map[string]*warnRate)
	}
	e, found := w.keys[key]
	if !found {
		if len(w.keys) >= maxWarnRateKeys {
			w.pruneLocked(now)
		}
		if len(w.keys) >= maxWarnRateKeys {
			e, overflow = &w.overflow, true
		} else {
			e = &warnRate{}
			w.keys[key] = e
		}
	}
	if !e.last.IsZero() && now.Sub(e.last) < w.every() {
		e.suppressed++
		return false, 0, overflow
	}
	suppressed, e.suppressed, e.last = e.suppressed, 0, now
	return true, suppressed, overflow
}

// pruneLocked drops keys whose interval has passed. Lines they left out
// are carried to the overflow line's count rather than lost.
func (w *warnRater) pruneLocked(now time.Time) {
	for k, e := range w.keys {
		if now.Sub(e.last) >= w.every() {
			w.overflow.suppressed += e.suppressed
			delete(w.keys, k)
		}
	}
}

// warnRated writes msg as a Warn line unless key had one within
// warnRateInterval (see warnRate). msg must already quote anything the
// client chose.
func (g *Gate) warnRated(key, msg string) {
	if g.cfg.Log == nil {
		return
	}
	ok, suppressed, overflow := g.warns.allow(key, g.now())
	if !ok {
		return
	}
	if overflow {
		msg = "gate: refused requests from more sources than are rated one by one; the latest: " + msg
	}
	if suppressed > 0 {
		msg += fmt.Sprintf(" (%d more like this not logged since the last line)", suppressed)
	}
	g.logWarn(msg)
}
