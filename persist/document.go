package persist

import (
	"context"
	"errors"
)

// SaveWithRetry writes payload, handling the one conflict case every
// store hits the same way. Copied from mikroview's
// internal/persist/document.go.
//
// A conflict means another process wrote while this one held its change
// in memory -- in practice, a CLI command running against a live server.
// The change is then applied on top of whatever landed: last-writer-wins.
//
// Returning `conflicted` rather than logging here keeps this package
// free of logging policy: each store already has its own logger and its
// own words for what it just lost.
//
// Doing better than last-writer-wins would mean replaying the mutation
// against the reloaded document, which a whole-document API cannot
// express. That limitation is real and is documented rather than
// papered over.
func SaveWithRetry(ctx context.Context, b Backend, payload []byte, current int64) (version int64, conflicted bool, err error) {
	if b == nil {
		return current, false, nil // persistence not configured
	}

	version, err = b.Save(ctx, payload, current)
	if err == nil {
		return version, false, nil
	}
	if !errors.Is(err, ErrConflict) {
		return current, false, err
	}

	fresh, loadErr := b.Load(ctx)
	if loadErr != nil {
		return current, true, loadErr
	}
	version, err = b.Save(ctx, payload, fresh.Version)
	if err != nil {
		return current, true, err
	}
	return version, true, nil
}

// LoadDocument reads a store's document. A nil backend, or one that has
// never been written, returns (nil, 0, nil) -- both are the normal
// "nothing persisted yet" case rather than failures. Copied from
// mikroview's internal/persist/document.go.
func LoadDocument(ctx context.Context, b Backend) ([]byte, int64, error) {
	if b == nil {
		return nil, 0, nil
	}
	snap, err := b.Load(ctx)
	if err != nil {
		return nil, 0, err
	}
	if !snap.Exists {
		return nil, 0, nil
	}
	return snap.Payload, snap.Version, nil
}
