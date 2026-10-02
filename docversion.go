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
// document reads it as zero, which is what it meant. Version 3 (#44)
// added User.LoginLockoutCount and User.LoginDisabledAt; an older
// document reads them as zero -- no lockouts counted since the last
// sign-in, sign-in not disabled -- which is what it meant, since no
// build that wrote it counted either. Version 4 (#44) added
// User.KnownBrowsers; an older document reads it as none remembered,
// which is what it meant: no browser carries a token a build without
// the field issued, so the allowance starts at each browser's next
// completed sign-in. A build that reads up to version 3 refuses a
// version-4 document rather than drop the field on its next save.
// Version 5 (#43) added User.BreachCheckPending; an older document reads
// it as false -- no breach recheck owed -- which is what it meant, since
// no build that wrote it accepted a password the live check had not
// answered for. A build that reads up to version 4 refuses a version-5
// document rather than drop a recheck that is owed.
const (
	accountsDocumentVersion = 5
	tokensDocumentVersion   = 1
)

// errNewerDocument is the decode error for a stored document whose
// version is higher than this build reads. It is refused on open, on
// reload and on a write's conflict reload alike, the way a document
// with no admin is: an older build -- one rolled back to, say -- that
// loaded it would drop every field it does not know on its next save,
// and with them a newer build's TOTP secrets or passkeys.
var errNewerDocument = errors.New("it was written by a newer gauntlet, and this build would drop what it does not know on the next save")

// errSealedDocument is the decode error for a document that is
// persist.Encrypt's sealed envelope rather than an accounts or tokens
// document (#50): the backend holds ciphertext and was opened without
// the wrapper -- an application that dropped persist.Encrypt from a
// backend whose document it had already sealed. Without this check the
// envelope, a JSON object with no "users" or "tokens" member, would
// read as an empty store, and the first write would seal nothing and
// write a plaintext document of no accounts over the ciphertext.
var errSealedDocument = errors.New("it is sealed (persist.Encrypt), and this backend was opened without the wrapper or its key")

// documentVersion reads the version field of a stored document's
// top-level object, without parsing the rest: a newer document must be
// reported as newer even when the rest no longer parses as this build's
// shape. A document without the field is version 0, which reads as 1.
// A sealed envelope is refused here, before any shape is read, for both
// stores at once -- see errSealedDocument.
func documentVersion(data []byte) (int, error) {
	var head struct {
		Version int             `json:"version"`
		Sealed  json.RawMessage `json:"sealed"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return 0, err
	}
	if head.Sealed != nil {
		return 0, errSealedDocument
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
