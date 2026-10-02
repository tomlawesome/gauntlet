// Package passkey runs the WebAuthn ceremonies -- registration, which
// makes a passkey, and login (assertion), which proves one -- for an
// application with one relying party. It implements
// gauntlet.PasskeyCeremony, which gate drives through Deps.Passkeys
// (G8, docs/adr/0004-passkey-ceremony.md).
//
// It is a leaf: it imports the root package and
// github.com/go-webauthn/webauthn, never gate, and gate never imports
// it. An application that never imports this package never compiles
// the WebAuthn library in.
//
// What lives here: turning the application's public URL into a relying
// party, or a reason it cannot be one (New, Status); the two sealing
// keys that let the browser carry ceremony state it can neither read nor
// alter; the set of challenges already used; the library calls; and the
// conversion between gauntlet.Passkey and the library's credential. It
// never sees a request or a cookie -- gate owns routes, cookies, the
// login limiter, sessions, recovery codes and audit.
//
// Ported from mikroview's internal/api/webauthn.go (NewRelyingParty,
// webauthnSessionCodec, spentChallenges) and the ceremony half of
// internal/api/passkey.go (webauthnUser, passkeyToCredential,
// credentialToPasskey), read at mikroview gitlab/dev 8a78d662; the
// tests come with them (docs/testing.md).
package passkey
