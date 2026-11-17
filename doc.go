// Package gauntlet is the shared authentication module: local accounts,
// sessions and API tokens, with the rules around them.
//
// The main types are:
//
//   - Store, the accounts: users and roles (User), Argon2id password
//     hashing, TOTP authenticator apps, passkeys, recovery codes and reset
//     codes, and the identity records for accounts that sign in through
//     single sign-on (Store.FindOrCreateOIDCUser).
//   - SessionStore, the signed-in sessions, with an idle timeout and a
//     lifetime ceiling.
//   - TokenStore, the read-only API tokens.
//   - LoginLimiter, the per-address and per-account attempt limits,
//     lockouts and address bans.
//
// Each store keeps its document through a persist.Backend, the storage
// interface, which lives in the gauntlet/persist package; the package
// implements no database itself. Open a store with OpenStore or
// OpenTokenStore.
//
// The HTTP layer lives in the gauntlet/gate package: gate.New builds a
// Gate whose Routes serve the sign-in, password, second-factor, session
// and token endpoints and whose Protect wraps the handlers that need an
// authenticated caller. The OpenID Connect protocol itself is in
// gauntlet/oidc, WebAuthn in gauntlet/passkey, and the design behind all
// of it in docs/design.md.
package gauntlet
