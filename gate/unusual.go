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
	// UnusualSignInProve holds the sign-in until the browser answers a
	// passkey assertion for this account (#65, ADR-0009). A sign-in
	// that was itself a passkey one is already proved and is flagged.
	// An account with no passkey usable here cannot prove: it is held
	// for a code instead when Config.DeliverConfirmCode is set, else
	// refused.
	UnusualSignInProve UnusualSignInAction = "prove"
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
	case UnusualSignInProve:
		return 3
	case UnusualSignInBlock:
		return 4
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
	// the rest decides (block over prove over confirm over flag).
	NewBrowser, NewCountry, ImpossibleTravel UnusualSignInAction
	// Decide, if set, is asked once per unusual sign-in after every
	// credential has passed and before any session exists, with the
	// settings' answer in c.Default; what it returns replaces that
	// answer. It is not asked when no signal is kept. It runs under ctx,
	// which ends after DecideTimeout; it may do I/O within that (a local
	// lookup, not a web call) and must honour ctx. A panic, an error, a
	// timeout, or an answer that is not flag, confirm, prove or block --
	// or confirm with no Config.DeliverConfirmCode to deliver the code --
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
	// CanProve is true when answering prove would hold this sign-in for
	// a passkey: the account has a passkey usable here and this sign-in
	// was not itself a passkey one. Otherwise prove is flag (a passkey
	// sign-in), confirm (a code can be delivered) or block (#65).
	CanProve bool
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
	// decide-timeout, decide-invalid, notify-failed or prove-failed. On the notice of
	// a block let through by a lone admin's escape code (#66, ADR-0011)
	// it is "escape", with SessionRef set.
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

// stopOutcome is how stopSignIn ended.
type stopOutcome int

const (
	// stopRefused: the attempt was refused (answer sign-in-refused).
	stopRefused stopOutcome = iota
	// stopHeld: a confirmation code went out, or a passkey is owed
	// (answer heldChallenge).
	stopHeld
	// stopLimited: held for a code, and the account's
	// confirmation-code budget is spent (#84). No code, ticket or
	// cookie; answer 429 rate-limited.
	stopLimited
)

// stopSignIn is confirm, prove and block for a judged sign-in, after the
// caller has handed the limiter back and dropped the pending login. It
// reports whether the sign-in is held, refused or past the send limit;
// when refused, notice is the block notice to send once the response is
// written, nil for none. A confirm whose code could not be delivered is
// refused as notify-failed: no code reached anyone; a prove whose ticket
// could not be made, as prove-failed. A lone admin, refused or held,
// also gets the escape code (startEscape, #66), except on the SSO
// callback: every admin keeps a local password (ADR-0010).
//
// A confirm past the account's confirmation-code budget (#84) is
// stopLimited: no code, no block notice and no escape code, and a
// rate_limited row (recordSendLimited). Nothing here takes or returns a
// reservation on the login buckets.
func (g *Gate) stopSignIn(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, v unusualVerdict, now time.Time) (stopOutcome, *AccountNotice) {
	reason := v.reason
	// A lone admin held for a passkey they have lost, or for a code that
	// never arrives, would be held again on every attempt with nobody to
	// reset them: the escape code is their way out, as it is from a
	// block. The held challenge is answered as before.
	switch v.action {
	case UnusualSignInConfirm:
		switch g.startConfirm(w, r, user, res, method, place, v.signals, now) {
		case confirmSent:
			g.startEscape(w, r, user, res, method, place, v.signals, now)
			return stopHeld, nil
		case confirmLimited:
			g.recordSendLimited(r, user, res, method, v.signals, now)
			return stopLimited, nil
		}
		reason = "notify-failed"
	case UnusualSignInProve:
		if g.startProve(w, r, user, res, method, v.signals, now) {
			g.startEscape(w, r, user, res, method, place, v.signals, now)
			return stopHeld, nil
		}
		reason = "prove-failed"
	}
	return stopRefused, g.refuseSignIn(w, r, user, res, method, place, v.signals, reason, now)
}

// recordSendLimited records a held sign-in refused by the send limit
// (#84) as rate_limited with its signals: a rated Warn line, never
// user.login_failed, so it counts toward neither the address ban nor a
// lockout -- the accounting a refused login/passkey/begin has. Only the
// address is taken from res: the attempt's own reservation was handed
// back, and any lockout it decided with it.
func (g *Gate) recordSendLimited(r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, signals gauntlet.SignInSignals, now time.Time) {
	ev := loginEvent(user, "", gauntlet.SignInRateLimited, method)
	ev.Client.Unusual = signals
	g.recordSignIn(r, ev, loginReservation{address: res.address, refusal: gauntlet.SignInRateLimited}, now)
}

// answerStopped writes the JSON answer to a sign-in stopSignIn stopped:
// the held challenge, 429 rate-limited past the send limit, or
// sign-in-refused, sending notice once the refusal is written.
func (g *Gate) answerStopped(w http.ResponseWriter, r *http.Request, v unusualVerdict, out stopOutcome, notice *AccountNotice) {
	switch out {
	case stopHeld:
		writeJSON(w, http.StatusOK, g.heldChallenge(v))
	case stopLimited:
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
	default:
		writeSignInRefused(w)
		g.notify(r.Context(), notice)
	}
}

// stopsSignIn reports whether v is confirm, prove or block.
func (v unusualVerdict) stopsSignIn() bool {
	switch v.action {
	case UnusualSignInConfirm, UnusualSignInProve, UnusualSignInBlock:
		return true
	}
	return false
}

// confirmChallenge is the 200 a sign-in owing a confirmation code gets.
var confirmChallenge = map[string]bool{"confirm": true}

// heldChallenge is the 200 a held sign-in gets (stopSignIn answered
// stopHeld for it): confirmChallenge, or for prove {"prove": "passkey",
// "passkeyOrigin": ...}, where the origin is what the browser's
// navigator.credentials.get() must be run against, as the second-step
// answer's is.
func (g *Gate) heldChallenge(v unusualVerdict) any {
	if v.action != UnusualSignInProve {
		return confirmChallenge
	}
	return map[string]any{"prove": "passkey", "passkeyOrigin": g.deps.Passkeys.Origin()}
}

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
// field one of the five actions or empty; confirm only where something
// can deliver the code (prove needs nothing here: it falls back to
// confirm or block for an account that cannot prove); impossible travel turned on only where it can
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
		case UnusualSignInProve, UnusualSignInBlock:
		default:
			return fmt.Errorf("gate: Config.UnusualSignIns.%s is %q; want %q, %q, %q, %q or %q",
				f.name, f.a, UnusualSignInOff, UnusualSignInFlag, UnusualSignInConfirm, UnusualSignInProve, UnusualSignInBlock)
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
	// escape marks a sign-in completed with the escape code (#66): a
	// block that was let through. completeSignIn then records it
	// confirmed, with escape=used in the audit detail, and a notice
	// whose Reason is "escape".
	escape bool
}

// escapeUsedNote is the audit note a sign-in completed with an escape
// code carries (#66), after unusual= and action=.
const escapeUsedNote = "escape=used; "

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
	if v.action == UnusualSignInProve {
		v.action = g.resolveProve(user, method)
	}
	return v
}

// canProve reports whether prove would hold user's sign-in for a
// passkey: one is usable here (a passkey registered under the current RP
// ID, none on hold, relying party ready) and the sign-in was not itself
// a passkey one.
func (g *Gate) canProve(user *gauntlet.User, method gauntlet.SignInMethod) bool {
	return !passkeyMethod(method) && g.usablePasskeyCount(user) > 0
}

// passkeyMethod is true for the two sign-in methods that are a passkey
// assertion.
func passkeyMethod(m gauntlet.SignInMethod) bool {
	return m == gauntlet.SignInMethodPasskey || m == gauntlet.SignInMethodPasskeyAlone
}

// resolveProve is what an answer of prove comes to for this sign-in
// (#65): a sign-in that was a passkey one is already proved, so flag;
// an account with a passkey usable here is held for one (prove); one
// without is held for a code when the application can deliver one
// (confirm), else refused (block).
func (g *Gate) resolveProve(user *gauntlet.User, method gauntlet.SignInMethod) UnusualSignInAction {
	switch {
	case passkeyMethod(method):
		return UnusualSignInFlag
	case g.canProve(user, method):
		return UnusualSignInProve
	case g.cfg.DeliverConfirmCode != nil:
		return UnusualSignInConfirm
	}
	return UnusualSignInBlock
}

// decide asks the policy's Decide about v, in its own goroutine with a
// recover and a DecideTimeout context (callBounded), and returns the
// action and, for a block, the reason. Every failure is block: a panic
// or an error is decide-failed, the deadline decide-timeout, and an
// answer that is not flag, confirm, prove or block -- or confirm with nothing
// to deliver the code -- decide-invalid. Each failure leaves one error
// line with what happened; the audit carries only the reason.
func (g *Gate) decide(r *http.Request, user *gauntlet.User, method gauntlet.SignInMethod, place signInPlace, v unusualVerdict) (UnusualSignInAction, string) {
	client := place.client
	client.Unusual = v.signals
	c := UnusualSignInCase{
		UserID: user.ID, Username: user.Username, Role: user.Role,
		Signals: v.signals, Country: place.client.Country, PreviousCountry: v.previousCountry,
		Method: method, Client: client, Default: v.action,
		CanProve: g.canProve(user, method),
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
	case UnusualSignInFlag, UnusualSignInProve, UnusualSignInBlock:
		return answer, "policy"
	case UnusualSignInConfirm:
		if g.cfg.DeliverConfirmCode != nil {
			return answer, "policy"
		}
		return fail("decide-invalid", "answered confirm, and no Config.DeliverConfirmCode can deliver a code")
	}
	return fail("decide-invalid", fmt.Sprintf("answered %q, which is not flag, confirm, prove or block", string(answer)))
}

// completeSignIn issues the session a judged sign-in has earned and
// records it: the session carries the verdict's signals, as do the
// history row and the audit record (unusual=...; action=...;
// notify=...; before the existing detail). When remembering the sign-in
// fails, nothing is flagged and nobody is told: the signals are dropped
// (issueSignInSession). It returns the notice to send once the response
// is written (notifyUnusualSignIn), nil for none.
func (g *Gate) completeSignIn(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, v unusualVerdict, now time.Time) *AccountNotice {
	sess, signals := g.issueSignInSession(w, r, user.ID, place, v.signals, method, now)
	ev := loginEvent(user, "", gauntlet.SignInSuccess, method)
	ev.Client.Unusual, ev.Confirmed = signals, v.escape
	if signals == 0 {
		if v.escape {
			g.recordSignInNote(r, ev, res, escapeUsedNote, now)
			return nil
		}
		g.recordSignIn(r, ev, res, now)
		return nil
	}
	note := fmt.Sprintf("unusual=%s; action=%s; ", signals, v.action)
	if v.escape {
		note += escapeUsedNote
	}
	notify := g.noticeAllowed(user.ID, now)
	if notify != "" {
		note += "notify=" + notify + "; "
	}
	g.recordSignInNote(r, ev, res, note, now)
	if notify != "asked" {
		return nil
	}
	detail := &UnusualSignInDetail{Action: v.action, Signals: signals, Method: method, Client: sess.Client, SessionRef: sess.Ref()}
	if v.escape {
		detail.Reason = v.reason
	}
	return &AccountNotice{
		Kind: NoticeUnusualSignIn, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		UnusualSignIn: detail,
	}
}

// signInRefusedDetail is the sign-in-refused class's one detail. It
// never says which signal was raised or whether a code would have been
// sent. Only an account with a local password gets this answer: an
// SSO-only one is refused at the SSO callback, which redirects with
// ssoError=refused and carries no text.
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
//
// For an admin no other admin can act for, on the password or factor
// path, it first issues the escape code (startEscape, #66): the ticket
// cookie is set on w, the code goes to the server's log, and the audit
// note gains "escape=issued; ". The answer stays the same 403.
func (g *Gate) refuseSignIn(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, signals gauntlet.SignInSignals, reason string, now time.Time) *AccountNotice {
	// A lone admin with no one to reset them gets an escape code in the
	// server's log and a ticket in this browser (#66); the refusal itself
	// is unchanged.
	escape := g.startEscape(w, r, user, res, method, place, signals, now)
	ev := loginEvent(user, "", gauntlet.SignInRefused, method)
	ev.Client.Unusual = signals
	note := fmt.Sprintf("unusual=%s; reason=%s; method=%s; ", signals, reason, method)
	if escape {
		note += "escape=issued; "
	}
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
