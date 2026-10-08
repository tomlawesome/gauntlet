package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// AccountNotifier is the one hook an application wires to hear about
// account events -- a password reset, a second factor added or removed,
// a lockout or disable, every session ended, an unusual sign-in (#73,
// folding in #53 and #55), a role changed (#67), a sign-in allowed by an
// admin (#81) -- so it can tell the account's owner. nil
// (Config.Notices) means nobody is told; gauntlet sends nothing itself.
//
// AccountEvent is called after the response that caused it has been
// written, in its own goroutine, with a context that ends after
// notifyTimeout (10 seconds): exactly Notifier's contract (see its
// Deprecated note). An error it returns, or a panic, is one error line
// in Config.Log and changes nothing about the request that raised the
// event.
type AccountNotifier interface {
	AccountEvent(ctx context.Context, n AccountNotice) error
}

// NoticeKind is which account event an AccountNotice carries.
type NoticeKind string

const (
	NoticePasswordReset            NoticeKind = "password-reset"
	NoticeSecondFactorAdded        NoticeKind = "second-factor-added"
	NoticeSecondFactorRemoved      NoticeKind = "second-factor-removed"
	NoticeRecoveryCodesRegenerated NoticeKind = "recovery-codes-regenerated"
	NoticeAccountLocked            NoticeKind = "account-locked"
	NoticeSignInDisabled           NoticeKind = "sign-in-disabled"
	NoticeSessionsEnded            NoticeKind = "sessions-ended"
	NoticeUnusualSignIn            NoticeKind = "unusual-sign-in"
	// NoticeRoleChanged (#67, #75, #76): an admin changed an account's
	// role, or created an account as an admin, or the identity provider's
	// groups moved an SSO account at sign-in (By is "" and ViaSSO is
	// set).
	NoticeRoleChanged NoticeKind = "role-changed"
	// NoticeTokenExpiring (#74): an API token the account created
	// expires within a week. Raised by Gate.SweepTokens, not by a
	// request, so By is empty. The sweep waits for AccountEvent rather
	// than running it in the background, and an error from it means the
	// notice is offered again at the next sweep.
	NoticeTokenExpiring NoticeKind = "token-expiring"
	// NoticeSignInAllowed (#81): an admin allowed the account's next
	// sign-in from any browser or place, until SignInAllowedDetail.Until.
	// By is the admin, who may be the account's own holder.
	NoticeSignInAllowed NoticeKind = "sign-in-allowed"
)

// AccountNotice is what an AccountNotifier is told. Exactly one of the
// detail pointers is set -- the one Kind names -- except
// NoticeRecoveryCodesRegenerated, which carries no detail beyond the
// fields below.
type AccountNotice struct {
	Kind             NoticeKind
	UserID, Username string
	// Role is the account's role, zero for NoticeAccountLocked and
	// NoticeSignInDisabled: the attempt that raises either never loads
	// the account's record, only its id and username off the limiter's
	// decision.
	Role gauntlet.Role
	At   time.Time
	// By is the admin's username when an admin caused the event; "" when
	// the account's own holder did, or nothing caused it (a lockout, a
	// disable).
	By string

	PasswordReset *PasswordResetDetail
	SecondFactor  *SecondFactorDetail
	Lockout       *LockoutDetail
	SessionsEnded *SessionsEndedDetail
	UnusualSignIn *UnusualSignInDetail
	RoleChanged   *RoleChangeDetail
	TokenExpiring *TokenExpiringDetail
	SignInAllowed *SignInAllowedDetail
}

// SignInAllowedDetail is NoticeSignInAllowed's detail: when the
// allowance ends. It ends sooner at the account's next completed
// sign-in, which spends it.
type SignInAllowedDetail struct {
	Until time.Time
}

// TokenExpiringDetail is NoticeTokenExpiring's detail: which token, and
// when it stops working. The token's value is never here -- it was shown
// once, at creation.
type TokenExpiringDetail struct {
	TokenID string
	Name    string
	Kind    gauntlet.TokenKind
	// ExpiresAt is when Authenticate starts refusing the token.
	ExpiresAt time.Time
}

// RoleChangeDetail is NoticeRoleChanged's detail. By on the notice is
// the admin who made the change, and "" when ViaSSO is set.
type RoleChangeDetail struct {
	// From is the role before; "" when the account was created with To.
	From gauntlet.Role
	// To is the role the account holds now.
	To gauntlet.Role
	// ViaSSO is true when the identity provider's groups caused the
	// change, at the account's SSO sign-in (Policy.RoleFromGroups,
	// ADR-0013), rather than an admin.
	ViaSSO bool
}

// PasswordResetDetail is NoticePasswordReset's detail. The code itself
// never travels here: an admin reads it out to the account's owner in
// person or over a trusted call.
type PasswordResetDetail struct {
	ExpiresAt time.Time
}

// SecondFactorDetail is NoticeSecondFactorAdded and
// NoticeSecondFactorRemoved's detail.
type SecondFactorDetail struct {
	// Method is "totp" or "passkey".
	Method string
	// Name is the passkey's own name; "" for totp, or when All is set.
	Name string
	// All is set when an admin cleared every factor of Method in one
	// call (the lost-phone admin routes), rather than the account's
	// owner removing one of their own.
	All bool
}

// LockoutDetail is NoticeAccountLocked and NoticeSignInDisabled's
// detail: the attempt's own address, and, for a lockout, when it ends
// and how many the account has had since its last completed sign-in.
// Until and Lockouts are both zero for NoticeSignInDisabled unless the
// same attempt also started a lockout.
type LockoutDetail struct {
	Until    time.Time
	Lockouts int
	Address  string
}

// SessionsEndedDetail is NoticeSessionsEnded's detail -- Notifier's old
// SessionsEndedNotice minus the fields AccountNotice already carries.
type SessionsEndedDetail struct {
	// Reason is what the admin gave, possibly empty; when it is, the
	// message should still say an administrator signed them out (owner,
	// 2026-10-02).
	Reason string
	// Ended is how many live sessions ended.
	Ended int
}

// notifyTimeout bounds one AccountNotifier.AccountEvent call, and the
// deprecated Notifier.SessionsEnded. A variable so tests can shorten it.
var notifyTimeout = 10 * time.Second

// asyncNotify runs fn in its own goroutine under ctx bounded by
// notifyTimeout, recovering a panic and logging a panic or an error as
// one line naming who. g.notifying tracks it, so a test can wait for it.
func (g *Gate) asyncNotify(ctx context.Context, who string, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
	g.notifying.Add(1)
	go func() {
		defer g.notifying.Done()
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				g.logError(fmt.Sprintf("gate: the account notifier panicked for account %q: %q", who, fmt.Sprint(p)))
			}
		}()
		if err := fn(ctx); err != nil {
			g.logError(fmt.Sprintf("gate: the account notifier failed for account %q: %q", who, err.Error()))
		}
	}()
}

// notifyNow asks Config.Notices to tell n's account and waits for the
// answer, under a context bounded by notifyTimeout: for a caller that
// must know the notice went out before recording that it did
// (SweepTokens). It reports whether AccountEvent returned nil. A
// failure, a panic or the deadline is one error line, as asyncNotify
// logs; a notifier still running at the deadline is abandoned and left
// to finish on its own, tracked by g.notifying. False when
// Config.Notices is unset or n is nil: nothing was sent.
func (g *Gate) notifyNow(ctx context.Context, n *AccountNotice) bool {
	notices := g.cfg.Notices
	if notices == nil || n == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	done := make(chan error, 1)
	g.notifying.Add(1)
	go func() {
		defer g.notifying.Done()
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("panicked: %q", fmt.Sprint(p))
			}
		}()
		done <- notices.AccountEvent(ctx, *n)
	}()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		g.logError(fmt.Sprintf("gate: the account notifier failed for account %q: %q", n.Username, err.Error()))
		return false
	}
	return true
}

// notify asks Config.Notices, if set, to tell n's account, in the
// background (asyncNotify). Call it only once the response is written.
// A nil n is nothing to send.
func (g *Gate) notify(ctx context.Context, n *AccountNotice) {
	notices := g.cfg.Notices
	if notices == nil || n == nil {
		return
	}
	g.asyncNotify(ctx, n.Username, func(ctx context.Context) error {
		return notices.AccountEvent(ctx, *n)
	})
}

// Deprecated: Notifier is Config.Notify's old, single-purpose shape,
// kept for a minor release (ADR-0002 decision 2) now that
// AccountNotifier (Config.Notices) covers sessions-ended and every other
// account event (#73). New refuses a Config with both set.
//
// SessionsEnded is called after the admin's response has been written,
// in its own goroutine, with a context that ends after notifyTimeout (10
// seconds). It never delays or changes that response: an error it
// returns, or a panic, is one error line in Config.Log. So the admin's
// "notified" means the application was asked, not that a mail arrived.
type Notifier interface {
	SessionsEnded(ctx context.Context, n SessionsEndedNotice) error
}

// Deprecated: SessionsEndedNotice is what a Notifier is told. Use
// AccountNotice (NoticeSessionsEnded, SessionsEndedDetail) with
// Config.Notices instead.
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

// notifySessionsEnded asks Config.Notices, if set, to tell n's account
// about its sessions ending, else falls back to the deprecated
// Config.Notify (New refuses both set). Either way it runs in the
// background (asyncNotify); call it only once the response is written.
// role is the target account's role, for the Notices path's
// AccountNotice.Role -- not carried by the deprecated SessionsEndedNotice.
func (g *Gate) notifySessionsEnded(ctx context.Context, role gauntlet.Role, n SessionsEndedNotice) {
	if g.cfg.Notices != nil {
		g.notify(ctx, &AccountNotice{
			Kind: NoticeSessionsEnded, UserID: n.UserID, Username: n.Username, Role: role, At: n.At, By: n.EndedBy,
			SessionsEnded: &SessionsEndedDetail{Reason: n.Reason, Ended: n.Ended},
		})
		return
	}
	notify := g.cfg.Notify
	if notify == nil {
		return
	}
	g.asyncNotify(ctx, n.Username, func(ctx context.Context) error {
		return notify.SessionsEnded(ctx, n)
	})
}
