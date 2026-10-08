package gate

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// TokenSweep is what one SweepTokens call did (#74).
type TokenSweep struct {
	// Removed is how many tokens were deleted for going unused for a
	// year.
	Removed int
	// Warned is how many tokens were marked as reported, each only once,
	// because they expire within a week. A token is marked only once
	// its notice went out through Config.Notices; one with no creating
	// account to tell, or with no Config.Notices, is marked all the same.
	Warned int
	// Orphaned is how many tokens were deleted because the account that
	// created them no longer exists.
	Orphaned int
}

// SweepTokens is the token maintenance pass: call it once a day from the
// application (this package runs no timer or goroutine of its own). It
// removes tokens unused for a year, auditing each as
// token.removed_unused; removes tokens whose creating account is gone,
// auditing each as token.removed_orphaned; and tells the creating
// account, through Config.Notices, about each token expiring within a
// week (NoticeTokenExpiring). See gauntlet.TokenStore.Sweep for the
// rules.
//
// now is a parameter so the caller's clock, or a test's, decides. The
// expiry notices are sent here, one at a time, each bounded by the
// notify timeout, and a token is marked warned only once its notice was
// accepted: a send that fails is one error line in Config.Log and is
// tried again at the next sweep. A crash between a send and the mark
// can repeat a notice; it never loses one.
//
// An error means one of the sweep's writes could not be saved. The
// first (the unused removal) failing changes nothing; a later one
// failing leaves what the result counts done, and the rest is tried
// again at the next sweep.
func (g *Gate) SweepTokens(ctx context.Context, now time.Time) (TokenSweep, error) {
	if err := ctx.Err(); err != nil {
		return TokenSweep{}, err
	}
	res, err := g.deps.Tokens.Sweep(now)
	if err != nil {
		return TokenSweep{}, err
	}
	out := TokenSweep{Removed: len(res.Removed)}
	for _, t := range res.Removed {
		last, what := t.LastUsedAt, "last_used"
		if last.IsZero() {
			last, what = t.CreatedAt, "never_used_created"
		}
		g.auditRecord("system", "token.removed_unused", t.Name,
			fmt.Sprintf("id=%s kind=%s %s=%s", t.ID, t.Kind, what, last.UTC().Format(time.RFC3339)))
	}

	// Deleting an account revokes its tokens in a second write, after
	// the account is gone. A crash or failure between the two leaves the
	// tokens working, and the delete handler cannot retry what it never
	// got to record -- so the sweep, which runs anyway, finds and
	// removes them.
	var errs []error
	orphaned := map[string]bool{}
	if g.deps.Users != nil {
		gone, err := g.deps.Tokens.RemoveOrphans(func(id string) bool {
			_, ok := g.deps.Users.Get(id)
			return ok
		}, now)
		if err != nil {
			errs = append(errs, err)
		}
		for _, t := range gone {
			orphaned[t.ID] = true
			g.auditRecord("system", "token.removed_orphaned", t.Name,
				fmt.Sprintf("id=%s kind=%s created_by=%s created_by_username=%s", t.ID, t.Kind, t.CreatedBy, t.CreatedByUsername))
		}
		out.Orphaned = len(gone)
	}

	// Send, then mark: a warning is recorded only once it was delivered.
	var warned []string
	for _, t := range res.Expiring {
		if orphaned[t.ID] {
			continue
		}
		if ctx.Err() != nil {
			// Unsent, so unmarked: the next sweep offers it again.
			break
		}
		if t.CreatedBy == "" || g.deps.Users == nil || g.cfg.Notices == nil {
			// Nobody will ever send this one; marking it stops the sweep
			// offering it forever.
			warned = append(warned, t.ID)
			continue
		}
		owner, ok := g.deps.Users.Get(t.CreatedBy)
		if !ok {
			warned = append(warned, t.ID)
			continue
		}
		if g.notifyNow(ctx, &AccountNotice{
			Kind: NoticeTokenExpiring, UserID: owner.ID, Username: owner.Username, Role: owner.Role, At: now,
			TokenExpiring: &TokenExpiringDetail{TokenID: t.ID, Name: t.Name, Kind: t.Kind, ExpiresAt: t.ExpiresAt},
		}) {
			warned = append(warned, t.ID)
		}
	}
	if err := g.deps.Tokens.MarkExpiryWarned(warned, now); err != nil {
		errs = append(errs, err)
	} else {
		out.Warned = len(warned)
	}
	return out, errors.Join(errs...)
}
