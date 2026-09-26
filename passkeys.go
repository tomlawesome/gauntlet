package gauntlet

import "time"

// Passkey is the stored shape of one registered WebAuthn credential,
// from mikroview's internal/auth/passkeys.go. As with RecoveryCode, only
// the type is here for G2 -- User.Passkeys has to round-trip through a
// whole-document Store even before this module performs the WebAuthn
// ceremony (deferred to the gauntlet/passkey package, G8, per
// docs/design.md §1.6). The storage-only methods listed in docs/design.md
// §1.3 (AddPasskey, RenamePasskey, DeletePasskey,
// RecordPasskeyAssertionIfFresh, ClearPasskeys, PasskeyCount) are a
// later slice.
type Passkey struct {
	// ID is the credential ID the registration ceremony returned -- the
	// value every later assertion presents to say "this is the same
	// credential". JSON as base64, the standard encoding for a []byte
	// field.
	ID []byte `json:"id"`
	// PublicKey is the COSE-encoded public key the authenticator proved
	// it holds the matching private key for at registration -- needed to
	// verify every later assertion's signature. Not secret the way a
	// private key would be, but still credential material, not something
	// an admin-facing account list should serialize -- see Store.List.
	PublicKey []byte `json:"publicKey"`
	// SignCount is the authenticator's signature counter as of the most
	// recently accepted assertion. Forward-only, advanced only through
	// the ceremony's own replay guard (a later slice).
	SignCount uint32 `json:"signCount"`
	// Transports is what the authenticator reported it can be reached
	// over (usb, nfc, ble, internal, hybrid, ...) at registration.
	Transports []string `json:"transports,omitempty"`
	// Flags carries the four authenticator flags a real WebAuthn
	// credential exposes, reproduced here as PasskeyFlags so this
	// package does not depend on a WebAuthn library for the data shape.
	Flags PasskeyFlags `json:"flags"`
	// RPID is the relying-party ID (essentially the registered domain)
	// this credential was created against -- carried here so a later
	// caller can compare it against the server's current RPID to decide
	// whether the credential is stale.
	RPID string `json:"rpId"`
	// Name is the operator-chosen label shown in the passkey list --
	// never empty once stored.
	Name string `json:"name"`
	// CreatedAt is when this credential was registered.
	CreatedAt time.Time `json:"createdAt"`
	// LastUsedAt is when this credential last completed a login -- zero
	// until the first one.
	LastUsedAt time.Time `json:"lastUsedAt,omitzero"`
}

// PasskeyFlags mirrors the four authenticator flags a WebAuthn
// credential carries. Field names and JSON tags match mikroview's
// internal/auth/passkeys.go exactly, so a caller's conversion to and
// from a WebAuthn library type is a straight field-by-field copy, not a
// translation.
type PasskeyFlags struct {
	UserPresent    bool `json:"userPresent"`
	UserVerified   bool `json:"userVerified"`
	BackupEligible bool `json:"backupEligible"`
	BackupState    bool `json:"backupState"`
}
