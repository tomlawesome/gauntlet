package gate

import (
	"context"
	"fmt"
	"time"
)

// TokenSweep is what one SweepTokens call did (#74).
type TokenSweep struct {
	// Removed is how many tokens were deleted for going unused for a
	// year.
	Removed int
	// Warned is how many tokens were marked as reported, each only once,
	// because they expire within a week. A notice is sent through
	// Config.Notices for each one whose creating account still exists;
	// one with no such account is marked all the same.
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
// account, through
// Config.Notices, about each token expiring within a week
// (NoticeTokenExpiring), once per token. See gauntlet.TokenStore.Sweep
// for the rules.
//
// now is a parameter so the caller's clock, or a test's, decides. The
// notices are sent in the background, as every account notice is. An
// error means one of the sweep's writes could not be saved. The first
// (the unused removal) failing changes nothing; the orphan removal
// failing leaves what the result counts done, and is tried again at the
// next sweep.
func (g *Gate) SweepTokens(ctx context.Context, now time.Time) (TokenSweep, error) {
	if err := ctx.Err(); err != nil {
		return TokenSweep{}, err
	}
	res, err := g.deps.Tokens.Sweep(now)
	if err != nil {
		return TokenSweep{}, err
	}
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
	out := TokenSweep{Removed: len(res.Removed), Warned: len(res.Expiring)}
	var orphanErr error
	if g.deps.Users != nil {
		gone, err := g.deps.Tokens.RemoveOrphans(func(id string) bool {
			_, ok := g.deps.Users.Get(id)
			return ok
		}, now)
		orphanErr = err
		for _, t := range gone {
			g.auditRecord("system", "token.removed_orphaned", t.Name,
				fmt.Sprintf("id=%s kind=%s created_by=%s created_by_username=%s", t.ID, t.Kind, t.CreatedBy, t.CreatedByUsername))
		}
		out.Orphaned = len(gone)
	}

	for _, t := range res.Expiring {
		if t.CreatedBy == "" || g.deps.Users == nil {
			continue
		}
		owner, ok := g.deps.Users.Get(t.CreatedBy)
		if !ok {
			continue
		}
		g.notify(ctx, &AccountNotice{
			Kind: NoticeTokenExpiring, UserID: owner.ID, Username: owner.Username, Role: owner.Role, At: now,
			TokenExpiring: &TokenExpiringDetail{TokenID: t.ID, Name: t.Name, Kind: t.Kind, ExpiresAt: t.ExpiresAt},
		})
	}
	return out, orphanErr
}
