// The save-conflict replay loop Store and TokenStore share (#21).
//
// Every write to either store is a whole-document rewrite: the process
// holds the document in memory, changes it, and saves it with "I expect
// version V". When another process wrote in between (a CLI command
// against a live server), the save is refused with persist.ErrConflict.
// The loop below answers that by reloading the fresh document, running
// the same change against it, and saving again -- what a database does
// with a version column -- so no write is ever silently discarded and
// the caller never sees the conflict. Its predecessor (the persist
// package's deprecated save-and-retry helper) saved the stale document
// on top instead.
//
// # Converting a method onto the loop
//
// Store.DeleteUser (store.go) and TokenStore.Create (token.go) are the
// two converted templates; every other mutating method follows them:
//
//  1. Keep everything before the write lock as it is: argument checks,
//     Persisted(), hashing, reloadIfStale(). None of it moves.
//  2. Replace the block from s.mu.Lock() to the old save call
//     (tryPersistLocked, now deleted), including the rollback that
//     followed it, with one call:
//     s.mutate(func(st *storeState) error { ... }) (TokenStore: the
//     same, with *tokenState). The op reads what it needs from st --
//     never from s, and never from a *User or *Token pointer taken
//     before the call -- decides, returns the method's sentinel errors
//     (ErrUserNotFound, ErrCannotDeleteAdmin, ...) exactly where the
//     old code did, and changes st.
//  3. Results the method returns come out through variables captured
//     by the closure, assigned as the op's last act: the op may run
//     more than once and the final run overwrites the earlier ones, so
//     assign, never append or accumulate. Take copies (cp := *u) inside
//     the op; a pointer into st is owned by the state. And a captured
//     result counts only when mutate returns nil: on an error, return
//     the method's zero values, never the variable -- it may hold the
//     answer of a first run against memory that a refused replay then
//     threw away (VerifyAndRecordTOTP's ok). Resetting it at the start
//     of the op does not cover that; the check after mutate does.
//  4. Delete the hand-written rollback outright. A failed attempt's
//     state is a copy the loop throws away, so there is nothing to
//     undo, and the "prev..." locals that fed it go too.
//  5. Return mutate's error as it is. The old "saving accounts: %w"
//     wrapper goes: the loop already names the store and backend in
//     every persistence failure, and op errors come back unwrapped, so
//     errors.Is against the sentinels keeps working.
//  6. A method whose write is bookkeeping only (LastLogin, LastUsedAt)
//     uses mutateBestEffortLocked, which logs a failed save and keeps
//     the change in memory, as the old persistLocked did. When the op
//     itself refuses the freshly loaded document -- the account or
//     token is gone from what another process wrote -- the store takes
//     that document instead, so the method's re-read of the state
//     afterwards finds what the op found (Authenticate: not found).
//  7. Where the old code returned early without saving because there
//     was nothing to do (a value already set, a code already spent),
//     the op returns errNoChange: mutate saves nothing and returns nil,
//     and the method reports its own result from the captured
//     variables.
//
// A method that already holds mu (createLocked, or a branch inside
// Authenticate) calls mutateLocked instead of mutate; the op is the
// same. Everything the op writes must be built from st and the method's
// arguments: a value computed once outside and then modified inside the
// op would be modified again on replay. Generating an ID or hash
// outside the op is fine (it is the same on every run); appending to a
// slice that lives outside the op is not.
//
// Methods judged not mechanical, for whoever converts the rest:
//
//   - Store.Authenticate: two writes with different guarantees on one
//     path (the reset-code spend must fail loudly, the LastLogin bump
//     is best-effort), and both live under a lock the method already
//     holds after its unlocked hash check -- convert the spend with
//     mutateLocked and the bump with mutateBestEffortLocked, leaving
//     the granularity check where it is.
//   - Store.FindOrCreateOIDCUser: same split as Authenticate (create
//     fails loudly, the existing-account LastLogin is best-effort) plus
//     the username pick (storeState.uniqueUsername), which must read
//     the index of the state the op is given, st, not s.
//   - Store.createLocked and its guard: the guard (registration
//     open/closed, single admin) must run inside the op, against st,
//     since a replay may find that the fresh document already has an
//     admin.
//   - Store.GenerateRecoveryCodesIfAbsent: reloads twice and decides
//     between two outcomes; the decision moves inside the op, and the
//     codes are generated once before it (their hashes are what the op
//     writes, the same on every run).
//   - Store.TransferAdmin: touches two accounts and re-checks the
//     single-admin invariant; the check belongs in the op, against st.
//
// Every write on both stores is now on this loop, and the old save
// helpers (tryPersistLocked, persistLocked) are gone. A write that meets
// a document this store refuses (see reloadIfStale) fails instead of
// saving over it; one that finds the document gone fails with
// ErrDocumentRemoved instead of recreating it from memory; and a state
// the accounts store would refuse to open (no admin) is stopped at the
// save, whatever op produced it.
package gauntlet

import (
	"context"
	"errors"
	"fmt"

	"github.com/tomlawesome/gauntlet/persist"
)

// ErrSaveConflict is returned by a write that could not be saved after
// maxSaveAttempts tries, each refused because another process wrote in
// between. Nothing was written and the in-memory state is unchanged;
// the caller may simply try again. Reaching it takes a writer that
// never stops -- a runaway script -- rather than one CLI command against
// a live server, which the first replay absorbs.
var ErrSaveConflict = errors.New("gauntlet: the store kept changing under this write; nothing was saved")

// ErrDocumentRemoved is returned by a write that found the document
// this store loaded gone from the backend -- a file deleted or moved
// aside while the process ran. Nothing was written and the in-memory
// state is unchanged. The store does not recreate the document from
// memory: a file that vanished mid-run is an operator at work (a
// restore, a move-aside the startup error suggests), and a document
// rebuilt from one process's memory would hold only what that process
// knew -- for an accounts store, possibly no admin at all. Restore the
// document, or restart the process to start afresh.
var ErrDocumentRemoved = errors.New("gauntlet: the store's document has been removed since this process loaded it; nothing was saved")

// errNoChange is what an op returns when the state it was given already
// says what the call wanted -- a lockout already recorded, a code that
// no longer matches -- so there is nothing to save. mutate saves nothing
// and returns nil for it; it never reaches a caller.
var errNoChange = errors.New("gauntlet: nothing to change")

// maxSaveAttempts bounds how many times one write is replayed against a
// freshly loaded document before it gives up with ErrSaveConflict.
const maxSaveAttempts = 5

// document is what the replay loop needs to know about one store: how
// to copy its state, turn it into the persisted bytes, and turn a
// freshly loaded document back into state. S is the store's state type
// (storeState, tokenState).
type document[S any] struct {
	backend persist.Backend
	// what names the document in error text: "accounts", "API tokens".
	what string
	// clone deep-copies a state so the loop can change the copy and
	// throw it away on failure.
	clone func(*S) *S
	// encode is the state as it is saved.
	encode func(*S) ([]byte, error)
	// decode builds a state from a freshly loaded document, applying
	// the same checks the store applies when it opens (checkAdmins for
	// accounts). A document that fails them fails the write.
	decode func([]byte) (*S, error)
	// check, when non-nil, is run on every state about to be saved and
	// refuses one this store would refuse to open -- the same check
	// decode applies, turned on this process's own output. No op in
	// this package should produce such a state; this is the line of
	// defence for the one that does.
	check func(*S) error
}

// replay runs op against a copy of cur and saves the result, reloading
// and re-running op on a save conflict, up to maxSaveAttempts times. It
// returns the state to install and the version it was saved as; on any
// error cur is untouched and nothing was saved. An error from op comes
// back as is; every persistence failure is wrapped, so a store can wrap
// it again in its own words.
//
// One error carries a state with it: when op refuses a freshly loaded
// document (the account or token it was to change is gone from it),
// the state returned is that document as loaded, untouched, with its
// version. Nothing was saved, but it is what is out there, and the
// caller installs it so the store does not go on answering from the
// stale memory op was first run against. The same goes for errNoChange
// from op's re-run against a newer document (see below). Every other
// error returns a nil state.
//
// The caller holds the store's write lock throughout, as the old
// tryPersistLocked did: the version it saves with is the one the store holds, and nothing
// else may move it between the copy and the swap.
func (d document[S]) replay(cur *S, version int64, op func(*S) error) (*S, int64, error) {
	next := d.clone(cur)
	opErr := op(next)
	if d.backend == nil {
		if opErr != nil {
			return nil, 0, opErr
		}
		return next, version, nil // persistence not configured: memory only
	}
	if opErr != nil && !errors.Is(opErr, errNoChange) {
		return nil, 0, opErr
	}

	// One deadline for the whole loop -- every save and every reload one
	// write makes -- not one per call: the caller holds the store's
	// write lock throughout, and a slow backend that conflicts on every
	// attempt would otherwise hold it for maxSaveAttempts saves plus the
	// reloads between them, blocking every read and login for that long.
	ctx, cancel := context.WithTimeout(context.Background(), saveTimeout)
	defer cancel()

	// "Nothing to change" saves nothing, so no version check would ever
	// catch it being decided on stale memory -- a token another process
	// issued after this store last reloaded, missed by a revoke. Decide
	// again against the document as it is now. A store that has never
	// saved (version 0) finds no document and that is fine: nothing is
	// out there to overturn the decision. One that has saved and now
	// finds none must say so, as the save loop below does -- "nothing to
	// revoke" was never checked against the live document.
	if opErr != nil {
		fresh, freshVersion, err := d.load(ctx)
		if errors.Is(err, ErrDocumentRemoved) && version == 0 {
			return nil, 0, errNoChange
		}
		if err != nil {
			return nil, 0, err
		}
		if freshVersion == version {
			return nil, 0, errNoChange
		}
		next = d.clone(fresh)
		if err := op(next); err != nil {
			return fresh, freshVersion, err
		}
		version = freshVersion
	}

	for attempt := 1; ; attempt++ {
		if d.check != nil {
			if err := d.check(next); err != nil {
				return nil, 0, fmt.Errorf("not saving %s to %s: this change would leave a document the store refuses to open: %w", d.what, d.backend.Describe(), err)
			}
		}
		data, err := d.encode(next)
		if err != nil {
			return nil, 0, fmt.Errorf("encoding %s for persistence failed: %w", d.what, err)
		}
		saved, err := d.backend.Save(ctx, data, version)
		if err == nil {
			return next, saved, nil
		}
		if !errors.Is(err, persist.ErrConflict) {
			return nil, 0, fmt.Errorf("writing %s to %s failed: %w", d.what, d.backend.Describe(), err)
		}
		if attempt == maxSaveAttempts {
			return nil, 0, fmt.Errorf("writing %s to %s after %d attempts: %w", d.what, d.backend.Describe(), attempt, ErrSaveConflict)
		}
		// Checked here as well as inside each call, for a backend that
		// does not honour ctx (the file backends; see saveTimeout): it
		// can overrun one call, but not go round again.
		if err := ctx.Err(); err != nil {
			return nil, 0, fmt.Errorf("writing %s to %s ran out of time after %d attempts: %w", d.what, d.backend.Describe(), attempt, err)
		}

		// Another process wrote first. Its document is now the truth:
		// load it, apply this change to it, and try again with its
		// version. A document this process would refuse to open is
		// refused here too, loudly -- writing on top of it is exactly
		// what this loop exists to stop.
		fresh, freshVersion, err := d.load(ctx)
		if err != nil {
			return nil, 0, err
		}
		// op runs on a copy so that, if it refuses, the document as
		// loaded can be handed back untouched (see above): an op that
		// changes the state before deciding to fail must not leave
		// those changes in what the caller installs.
		next = d.clone(fresh)
		if err := op(next); err != nil {
			return fresh, freshVersion, err
		}
		version = freshVersion
	}
}

// load reads the document another process just wrote and turns it into
// a state, under the loop's deadline. A document that has been removed
// fails the write with ErrDocumentRemoved: the store never recreates it
// from memory (see ErrDocumentRemoved), and reloadIfStale keeps memory
// for the same reason.
func (d document[S]) load(ctx context.Context) (*S, int64, error) {
	snap, err := d.backend.Load(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("reloading %s from %s failed: %w", d.what, d.backend.Describe(), err)
	}
	if !snap.Exists {
		return nil, 0, fmt.Errorf("%s in %s: %w", d.what, d.backend.Describe(), ErrDocumentRemoved)
	}
	fresh, err := d.decode(snap.Payload)
	if err != nil {
		return nil, 0, fmt.Errorf("%s in %s were changed by another process to a document this store cannot apply, so this change was not saved: %w",
			d.what, d.backend.Describe(), err)
	}
	return fresh, snap.Version, nil
}
