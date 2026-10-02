package gauntlet

import (
	"encoding/json"
	"errors"
	"fmt"
)

// The stored documents' format versions (#29, ADR-0002 decision 1): the
// version this build writes, and the highest it reads. v0.1.0 wrote no
// version at all; a document without one reads as version 1.
//
// Any change to what a document carries raises its version, a field
// added as much as a shape changed, so an older build refuses the
// document instead of saving it back without the field. An added field
// must read correctly as its zero value from an older document; then it
// needs no migration code, only the raised number. None has needed more
// yet, so there is no migration code.
//
// Accounts version 2 (#28) added User.SessionsEndedAt; a version-1
// document reads it as zero, which is what it meant.
const (
	accountsDocumentVersion = 2
	tokensDocumentVersion   = 1
)

// errNewerDocument is the decode error for a stored document whose
// version is higher than this build reads. It is refused on open, on
// reload and on a write's conflict reload alike, the way a document
// with no admin is: an older build -- one rolled back to, say -- that
// loaded it would drop every field it does not know on its next save,
// and with them a newer build's TOTP secrets or passkeys.
var errNewerDocument = errors.New("it was written by a newer gauntlet, and this build would drop what it does not know on the next save")

// documentVersion reads the version field of a stored document's
// top-level object, without parsing the rest: a newer document must be
// reported as newer even when the rest no longer parses as this build's
// shape. A document without the field is version 0, which reads as 1.
func documentVersion(data []byte) (int, error) {
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return 0, err
	}
	return head.Version, nil
}

// checkDocumentVersion refuses a document of version got when this
// build reads up to known, naming both so an operator can tell which
// build the file belongs to.
func checkDocumentVersion(what string, got, known int) error {
	if got <= known {
		return nil
	}
	return fmt.Errorf("the %s document is format version %d, and this build reads up to version %d: %w", what, got, known, errNewerDocument)
}
