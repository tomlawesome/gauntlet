package gauntlet

import (
	"bytes"
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
// Version 6 (#59) added the top-level "seq" counter (see
// errStaleDocument below); an older document reads it as zero and is
// stamped with this process's own count on its next save, like any
// other added field.
//
// The sign-in history (#53, signins.go) is the third document, version 1
// from its first release: {"version":1,"nextSeq":n,"rows":[...]}, and
// carries no "seq" counter of its own: it saves but never re-reads a
// document another process may have written, so there is nothing for it
// to refuse (docs/design.md §4).
//
// Tokens' version 2 (#59) is the same "seq" addition as accounts'
// version 6, numbered on its own track since the two documents'
// versions have never moved together.
const (
	accountsDocumentVersion = 6
	tokensDocumentVersion   = 2
	signInsDocumentVersion  = 1
)

// errNewerDocument is the decode error for a stored document whose
// version is higher than this build reads. It is refused on open, on
// reload and on a write's conflict reload alike, the way a document
// with no admin is: an older build -- one rolled back to, say -- that
// loaded it would drop every field it does not know on its next save,
// and with them a newer build's TOTP secrets or passkeys.
var errNewerDocument = errors.New("it was written by a newer gauntlet, and this build would drop what it does not know on the next save")

// errStaleDocument is the decode error for a stored document whose
// "seq" counter (#59) is lower than the highest this process has
// already loaded or written. A running store judges a change on disk by
// "changed", not "newer" (docs/design.md §4): an older, valid copy of
// the file put back while the service runs -- a backup restore that
// missed the stop step -- would otherwise be adopted at the next
// request, undoing whatever changed since and reviving whatever it
// revoked, with nothing logged. Refused the same way a newer-version
// document is refused (errNewerDocument): the file on disk is left
// alone, this process keeps what it holds, and every write meets the
// same refusal until the file is replaced or the process restarts.
//
// This process has no memory of the counter across a restart -- a
// rollback made while the service is stopped is accepted when it starts
// again, the known limit docs/design.md §4 records.
var errStaleDocument = errors.New("it was written earlier than the copy this process already has -- only an older copy restored over a newer one goes backward like that")

// checkDocumentSeq refuses a document whose counter, got, is lower than
// haveSeen, the highest this process has loaded or written so far. what
// names the document in the error, as checkDocumentVersion does for a
// too-new one.
func checkDocumentSeq(what string, got, haveSeen int64) error {
	if got >= haveSeen {
		return nil
	}
	return fmt.Errorf("the %s document's sequence counter is %d, and this process has already seen %d: %w", what, got, haveSeen, errStaleDocument)
}

// errSealedDocument is the decode error for a document that is
// persist.Encrypt's sealed envelope rather than an accounts, tokens or
// sign-in history document (#50): the backend holds ciphertext and was opened without
// the wrapper -- an application that dropped persist.Encrypt from a
// backend whose document it had already sealed. Without this check the
// envelope, a JSON object with no "users" or "tokens" member, would
// read as an empty store, and the first write would seal nothing and
// write a plaintext document of no accounts over the ciphertext.
var errSealedDocument = errors.New("it is sealed (persist.Encrypt), and this backend was opened without the wrapper or its key")

// errNullDocument is the decode error for a stored document that is
// the JSON literal null. It parses, as an empty object would, so without
// this check it read as a fresh install: an accounts store with no
// accounts issues a setup code, and the next registration saves over
// every account that was there. Only a missing document is a fresh one.
var errNullDocument = errors.New("it is the JSON literal null, not a document")

// documentVersion reads the version field of a stored document's
// top-level object, without parsing the rest: a newer document must be
// reported as newer even when the rest no longer parses as this build's
// shape. A document without the field is version 0, which reads as 1.
// A sealed envelope is refused here, before any shape is read, for every
// store at once -- see errSealedDocument.
func documentVersion(data []byte) (int, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return 0, errNullDocument
	}
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
