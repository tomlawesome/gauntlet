package gate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// Unusual sign-ins (#55). A sign-in is judged when it would issue a
// session -- the one-step password path (handleLogin), the second-factor
// step (completeLoginFactor) and the SSO callback's sign-in branch --
// after every credential has passed and before any session exists.
// gauntlet.Store.JudgeSignIn raises the signals; the application's
// policy (Config.UnusualSignIns) says what each one does. Every other
// session issue -- register, a password change, TOTP or recovery-code
// confirm, sign out everywhere, an SSO link -- never judges, since its
// caller already holds a session or is the first account, but every
// session issue remembers the browser, country and place
// (gauntlet.Store.RememberSignIn), whatever the policy.

// UnusualSignInAction is what an unusual sign-in leads to.
type UnusualSignInAction string

const (
	// UnusualSignInOff drops the signal: nothing is shown, told or
	// refused. What the account remembers still accumulates, so turning
	// the signal on later starts from a baseline.
	UnusualSignInOff UnusualSignInAction = "off"
	// UnusualSignInFlag, the default, lets the sign-in complete and marks
	// it: on the session in the person's own session list, on the
	// sign-in history row and in the audit record.
	UnusualSignInFlag UnusualSignInAction = "flag"
	// UnusualSignInConfirm holds the sign-in until a code the
	// application delivers is typed into the same sign-in.
	UnusualSignInConfirm UnusualSignInAction = "confirm"
	// UnusualSignInBlock refuses this one attempt, never the account.
	UnusualSignInBlock UnusualSignInAction = "block"
)

// rank orders the actions by strictness; an unknown one ranks nowhere.
func (a UnusualSignInAction) rank() int {
	switch a {
	case UnusualSignInFlag:
		return 1
	case UnusualSignInConfirm:
		return 2
	case UnusualSignInBlock:
		return 3
	}
	return 0
}

// UnusualSignInPolicy is what each unusual-sign-in signal does
// (Config.UnusualSignIns). The zero value flags every signal.
type UnusualSignInPolicy struct {
	// Action is the base for every signal. "" means UnusualSignInFlag.
	Action UnusualSignInAction
	// NewBrowser, NewCountry and ImpossibleTravel override Action for
	// their own signal; "" means Action. Of the signals one sign-in
	// raises, any that resolve to off are dropped and the strictest of
	// the rest decides (block over confirm over flag).
	NewBrowser, NewCountry, ImpossibleTravel UnusualSignInAction
	// Decide, if set, is asked once per unusual sign-in after every
	// credential has passed and before any session exists, with the
	// settings' answer in c.Default; what it returns replaces that
	// answer. It is not asked when no signal is kept. It runs under ctx,
	// which ends after DecideTimeout; it may do I/O within that (a local
	// lookup, not a web call) and must honour ctx. A panic, an error, a
	// timeout, or an answer that is not flag, confirm or block -- or
	// confirm with no Config.NotifyUnusualSignIn to deliver the code --
	// refuses this attempt (block), audited and noticed with the reason
	// (decide-failed, decide-timeout, decide-invalid): a check that
	// lets people in when it breaks would make breaking it the attack.
	Decide func(ctx context.Context, c UnusualSignInCase) (UnusualSignInAction, error)
}

// UnusualSignInCase is one unusual sign-in as the policy sees it. It
// carries no request, header, password, code or session: nothing a
// function handed it could complete a sign-in with or leak.
type UnusualSignInCase struct {
	UserID, Username string
	Role             gauntlet.Role
	Signals          gauntlet.SignInSignals
	// Country is what Config.Country answered; "" if unknown.
	Country string
	// PreviousCountry is the account's last place's country when
	// impossible-travel is raised; "" otherwise.
	PreviousCountry string
	Method          gauntlet.SignInMethod
	// Client is the resolved address and agent, never the headers.
	Client gauntlet.SessionClient
	// Default is what the settings decided.
	Default UnusualSignInAction
}

// UnusualSignInDetail is NoticeUnusualSignIn's detail (Config.Notices):
// an unusual sign-in flagged, confirmed or blocked. It never carries the
// account's coordinates. The application chooses the wording, address
// and channel; it should treat Client.UserAgent as text, never markup.
//
// Under flag the notice is asked for after the response is written, as
// every AccountNotice is; a block and the confirm notifier.go sends are
// the same. At most one flag or block notice per account per hour is
// sent; one held back is "notify=quiet" in the audit.
type UnusualSignInDetail struct {
	// Action is what happened: flag, confirm or block.
	Action  UnusualSignInAction
	Signals gauntlet.SignInSignals
	Method  gauntlet.SignInMethod
	// Client is the address, agent (text, never markup) and country the
	// sign-in came from.
	Client gauntlet.SessionClient
	// SessionRef, under flag, is the session's ref as the person's own
	// session list shows it, so a message can say "end this session".
	SessionRef string
	// Reason, under block, says why: policy, decide-failed,
	// decide-timeout, decide-invalid or notify-failed.
	Reason string
}

// DecideTimeout bounds the synchronous calls an unusual sign-in makes
// before it is answered: UnusualSignInPolicy.Decide, and the notice
// carrying a confirmation code. Fixed, not configurable: Decide should
// be a local lookup, and the notifier should hand the message to its
// mailer and return.
const DecideTimeout = 3 * time.Second

// decideTimeout is DecideTimeout, a variable so tests can shorten it.
var decideTimeout = DecideTimeout

// errCallTimedOut is callBounded's error for a function still running
// at the deadline.
var errCallTimedOut = errors.New("did not return within the deadline")

// callBounded runs fn in its own goroutine under a context that ends
// after decideTimeout, and waits for it or the deadline, whichever comes
// first. A panic is an error carrying the panic text, so a failing
// function fails closed. A function that ignores its context is
// abandoned at the deadline and left to finish on its own; what it
// returns then goes nowhere.
func (g *Gate) callBounded(ctx context.Context, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), decideTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("panicked: %q", fmt.Sprint(p))
			}
		}()
		done <- fn(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errCallTimedOut
	}
}

// stopSignIn is confirm and block for a judged sign-in, after the
// caller has handed the limiter back and dropped the pending login. It
// reports whether a confirmation code went out (answer "confirm"); if
// not, the attempt was refused (answer sign-in-refused) and notice is
// the block notice to send once the response is written, nil for none.
// A confirm whose code could not be delivered is refused as
// notify-failed: no code reached anyone.
func (g *Gate) stopSignIn(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, v unusualVerdict, now time.Time) (confirmSent bool, notice *AccountNotice) {
	reason := v.reason
	if v.action == UnusualSignInConfirm {
		if g.startConfirm(w, r, user, res, method, place, v.signals, now) {
			return true, nil
		}
		reason = "notify-failed"
	}
	return false, g.refuseSignIn(r, user, res, method, place, v.signals, reason, now)
}

// stopsSignIn reports whether v is confirm or block.
func (v unusualVerdict) stopsSignIn() bool {
	return v.action == UnusualSignInConfirm || v.action == UnusualSignInBlock
}

// confirmChallenge is the 200 a sign-in owing a confirmation code gets.
var confirmChallenge = map[string]bool{"confirm": true}

// unusualNoticeInterval is how long an account's flag and block notices
// stay quiet after one is sent. A variable so tests can shorten it.
var unusualNoticeInterval = time.Hour

// noticeAllowed decides, before the audit record is written, whether a
// flag or block notice for userID may be sent at now: "" when there is
// no notifier (nothing about notices is recorded), else "asked" or
// "quiet".
func (g *Gate) noticeAllowed(userID string, now time.Time) string {
	if g.cfg.Notices == nil {
		return ""
	}
	if ok, _, _ := g.notices.allow(userID, now); ok {
		return "asked"
	}
	return "quiet"
}

// checkUnusualPolicy is New's check of Config.UnusualSignIns: every
// field one of the four actions or empty; confirm only where something
// can deliver the code; impossible travel turned on only where it can
// be judged.
func checkUnusualPolicy(cfg Config) error {
	p := cfg.UnusualSignIns
	for _, f := range []struct {
		name string
		a    UnusualSignInAction
	}{
		{"Action", p.Action}, {"NewBrowser", p.NewBrowser}, {"NewCountry", p.NewCountry}, {"ImpossibleTravel", p.ImpossibleTravel},
	} {
		switch f.a {
		case "", UnusualSignInOff, UnusualSignInFlag:
		case UnusualSignInConfirm:
			if cfg.DeliverConfirmCode != nil {
				continue
			}
			return fmt.Errorf("gate: Config.UnusualSignIns.%s is confirm, which needs Config.DeliverConfirmCode to deliver the code", f.name)
		case UnusualSignInBlock:
		default:
			return fmt.Errorf("gate: Config.UnusualSignIns.%s is %q; want %q, %q, %q or %q",
				f.name, f.a, UnusualSignInOff, UnusualSignInFlag, UnusualSignInConfirm, UnusualSignInBlock)
		}
	}
	if p.ImpossibleTravel != "" && p.ImpossibleTravel != UnusualSignInOff && cfg.Locate == nil {
		return fmt.Errorf("%w: Config.Locate (Config.UnusualSignIns.ImpossibleTravel is %s, and without it the signal can never be raised)", errMissingDep, p.ImpossibleTravel)
	}
	return nil
}

// signalAction is the action the policy gives one signal.
func (p UnusualSignInPolicy) signalAction(s gauntlet.SignInSignals) UnusualSignInAction {
	var own UnusualSignInAction
	switch s {
	case gauntlet.SignalNewBrowser:
		own = p.NewBrowser
	case gauntlet.SignalNewCountry:
		own = p.NewCountry
	case gauntlet.SignalImpossibleTravel:
		own = p.ImpossibleTravel
	}
	switch {
	case own != "":
		return own
	case p.Action != "":
		return p.Action
	}
	return UnusualSignInFlag
}

// allSignals is every signal, for walking them one at a time.
var allSignals = []gauntlet.SignInSignals{gauntlet.SignalNewBrowser, gauntlet.SignalNewCountry, gauntlet.SignalImpossibleTravel}

// resolveUnusual applies the policy to the raised signals: each takes
// its own field, else Action, else flag; one that resolves to off is
// dropped; among those kept the strictest action wins. No kept signal
// is an ordinary sign-in: "" and none.
func (g *Gate) resolveUnusual(signals gauntlet.SignInSignals) (UnusualSignInAction, gauntlet.SignInSignals) {
	var action UnusualSignInAction
	var kept gauntlet.SignInSignals
	for _, s := range allSignals {
		if !signals.Has(s) {
			continue
		}
		a := g.cfg.UnusualSignIns.signalAction(s)
		if a == UnusualSignInOff {
			continue
		}
		kept |= s
		if a.rank() > action.rank() {
			action = a
		}
	}
	return action, kept
}

// judgesNothing reports whether every signal resolves to off, so no
// sign-in needs judging at all.
func (g *Gate) judgesNothing() bool {
	for _, s := range allSignals {
		if g.cfg.UnusualSignIns.signalAction(s) != UnusualSignInOff {
			return false
		}
	}
	return true
}

// signInPlace is where a request came from, looked up once for the
// judgement, the session and what the account remembers.
type signInPlace struct {
	client gauntlet.SessionClient
	loc    *gauntlet.Location
}

// placeOf is r's client (signInClient) and, when Config.Locate is set
// and answers for the address, its location.
func (g *Gate) placeOf(r *http.Request, address string) signInPlace {
	p := signInPlace{client: g.signInClient(r, address)}
	if g.cfg.Locate != nil {
		if loc, ok := g.cfg.Locate(p.client.Address); ok {
			p.loc = &loc
		}
	}
	return p
}

// unusualVerdict is what the policy made of one completed sign-in.
type unusualVerdict struct {
	// action is "" for an ordinary sign-in.
	action  UnusualSignInAction
	signals gauntlet.SignInSignals
	// reason is why a block is a block: policy unless something failed.
	reason string
	// previousCountry is the last place's country when impossible
	// travel is kept.
	previousCountry string
}

// judgeSignIn judges user's completed sign-in from place: read-only,
// and skipped altogether when the policy turns every signal off. When
// a signal is kept and the policy has a Decide, Decide's answer
// replaces the settings' (decide).
func (g *Gate) judgeSignIn(r *http.Request, user *gauntlet.User, method gauntlet.SignInMethod, place signInPlace, now time.Time) unusualVerdict {
	if g.judgesNothing() {
		return unusualVerdict{}
	}
	j := g.deps.Users.JudgeSignIn(user.ID, knownBrowserTokens(r), place.client.Country, place.loc, now)
	action, kept := g.resolveUnusual(j.Signals)
	v := unusualVerdict{action: action, signals: kept, reason: "policy"}
	if kept.Has(gauntlet.SignalImpossibleTravel) {
		v.previousCountry = j.PreviousCountry
	}
	if kept != 0 && g.cfg.UnusualSignIns.Decide != nil {
		v.action, v.reason = g.decide(r, user, method, place, v)
	}
	return v
}

// decide asks the policy's Decide about v, in its own goroutine with a
// recover and a DecideTimeout context (callBounded), and returns the
// action and, for a block, the reason. Every failure is block: a panic
// or an error is decide-failed, the deadline decide-timeout, and an
// answer that is not flag, confirm or block -- or confirm with nothing
// to deliver the code -- decide-invalid. Each failure leaves one error
// line with what happened; the audit carries only the reason.
func (g *Gate) decide(r *http.Request, user *gauntlet.User, method gauntlet.SignInMethod, place signInPlace, v unusualVerdict) (UnusualSignInAction, string) {
	client := place.client
	client.Unusual = v.signals
	c := UnusualSignInCase{
		UserID: user.ID, Username: user.Username, Role: user.Role,
		Signals: v.signals, Country: place.client.Country, PreviousCountry: v.previousCountry,
		Method: method, Client: client, Default: v.action,
	}
	decide := g.cfg.UnusualSignIns.Decide
	var answer UnusualSignInAction
	err := g.callBounded(r.Context(), func(ctx context.Context) error {
		a, err := decide(ctx, c)
		answer = a
		return err
	})
	fail := func(reason, what string) (UnusualSignInAction, string) {
		g.logError(fmt.Sprintf("gate: the unusual sign-in Decide for account %q %s; the sign-in is refused (%s)", user.Username, what, reason))
		return UnusualSignInBlock, reason
	}
	switch {
	case errors.Is(err, errCallTimedOut):
		return fail("decide-timeout", fmt.Sprintf("did not answer within %v", decideTimeout))
	case err != nil:
		return fail("decide-failed", fmt.Sprintf("failed: %q", err.Error()))
	}
	switch answer {
	case UnusualSignInFlag, UnusualSignInBlock:
		return answer, "policy"
	case UnusualSignInConfirm:
		if g.cfg.DeliverConfirmCode != nil {
			return answer, "policy"
		}
		return fail("decide-invalid", "answered confirm, and no Config.DeliverConfirmCode can deliver a code")
	}
	return fail("decide-invalid", fmt.Sprintf("answered %q, which is not flag, confirm or block", string(answer)))
}

// completeSignIn issues the session a judged sign-in has earned and
// records it: the session carries the verdict's signals, as do the
// history row and the audit record (unusual=...; action=...;
// notify=...; before the existing detail). When remembering the sign-in
// fails, nothing is flagged and nobody is told: the signals are dropped
// (issueSignInSession). It returns the notice to send once the response
// is written (notifyUnusualSignIn), nil for none.
func (g *Gate) completeSignIn(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, v unusualVerdict, now time.Time) *AccountNotice {
	sess, signals := g.issueSignInSession(w, r, user.ID, place, v.signals, now)
	ev := loginEvent(user, "", gauntlet.SignInSuccess, method)
	ev.Client.Unusual = signals
	if signals == 0 {
		g.recordSignIn(r, ev, res, now)
		return nil
	}
	note := fmt.Sprintf("unusual=%s; action=%s; ", signals, v.action)
	notify := g.noticeAllowed(user.ID, now)
	if notify != "" {
		note += "notify=" + notify + "; "
	}
	g.recordSignInNote(r, ev, res, note, now)
	if notify != "asked" {
		return nil
	}
	return &AccountNotice{
		Kind: NoticeUnusualSignIn, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		UnusualSignIn: &UnusualSignInDetail{
			Action: v.action, Signals: signals, Method: method, Client: sess.Client, SessionRef: sess.Ref(),
		},
	}
}

// signInRefusedDetail is the sign-in-refused class's one detail. It
// never says which signal was raised or whether a code would have been
// sent.
const signInRefusedDetail = "this sign-in was refused by the account's sign-in policy -- use a browser or place this account has signed in from before, or ask an administrator to reset the account"

// writeSignInRefused answers a refused sign-in: 403 sign-in-refused,
// with no X-Auth-Gate header, which marks a session stopped at a door,
// and no session exists here.
func writeSignInRefused(w http.ResponseWriter) {
	writeProblem(w, http.StatusForbidden, classSignInRefused, signInRefusedDetail, nil)
}

// refuseSignIn is block: one attempt refused, never the account. The
// caller has handed the limiter back (releaseLogin: the credential was
// right, so it is no failure to count, and nothing completed, so the
// account's count is not reset) and cleared the pending cookie; nothing
// is written to the account and no cookie is set. This records the
// refused row with the signals and user.login_refused, and returns the
// notice to send once the response is written, nil for none. reason is
// policy, or why a Decide or the confirm notice failed.
func (g *Gate) refuseSignIn(r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, signals gauntlet.SignInSignals, reason string, now time.Time) *AccountNotice {
	ev := loginEvent(user, "", gauntlet.SignInRefused, method)
	ev.Client.Unusual = signals
	note := fmt.Sprintf("unusual=%s; reason=%s; method=%s; ", signals, reason, method)
	notify := g.noticeAllowed(user.ID, now)
	if notify != "" {
		note += "notify=" + notify + "; "
	}
	g.recordSignInNote(r, ev, res, note, now)
	if notify != "asked" {
		return nil
	}
	client := place.client
	client.Unusual = signals
	return &AccountNotice{
		Kind: NoticeUnusualSignIn, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		UnusualSignIn: &UnusualSignInDetail{
			Action: UnusualSignInBlock, Signals: signals, Method: method, Client: client, Reason: reason,
		},
	}
}
