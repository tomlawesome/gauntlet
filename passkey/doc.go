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
// party, or a reason it cannot be one (New, Status); the three sealing
// keys, one per ceremony, that let the browser carry ceremony state it
// can neither read nor alter; the set of login challenges already used
// (both login ceremonies draw on it; registrations are
// spent by gate, by the sealed cookie's hash, where the store decides);
// the library calls; and the
// conversion between gauntlet.Passkey and the library's credential. It
// never sees a request or a cookie -- gate owns routes, cookies, the
// login limiter, sessions, recovery codes and audit.
//
// Signing in with a passkey alone (gauntlet.PasskeySignIn, #77,
// docs/adr/0012-passkey-alone-sign-in.md) is the third ceremony, under
// the third sealing key; the same relying party runs it.
//
// Ported from mikroview's internal/api/webauthn.go (NewRelyingParty,
// webauthnSessionCodec; its spentChallenges became gauntlet's shared
// internal/spent) and the ceremony half of internal/api/passkey.go (webauthnUser, passkeyToCredential,
// credentialToPasskey), read at mikroview gitlab/dev 8a78d662; the
// tests come with them (docs/testing.md).
package passkey
