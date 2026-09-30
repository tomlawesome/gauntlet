// Copied from mikroview's internal/auth/token.go, with names kept
// (docs/adr/0001-shared-auth-module.md decision 3). Two changes from
// mikroview, both from docs/design.md §1.3:
//
//   - TokenOptions carries the *slog.Logger instead of a package-level
//     persistLog, same reason as Options in store.go: a module cannot
//     call an application's own logging constructor. nil means discard.
//   - TokenOptions.Kinds replaces the hard-coded TokenKind.Valid(): the
//     set of kinds a build accepts is now the caller's choice, not this
//     package's. Empty Kinds defaults to {TokenKindAPI, TokenKindIngest}.
//     Mikroview has a third kind, TokenKindDroplistPull, that is its own
//     business (#1224); it registers that kind via Kinds instead of this
//     package hard-coding it. A token whose kind is not registered is
//     kept in the document (never dropped on save) and logged, but can
//     never authenticate -- see OpenTokenStore below.
package gauntlet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tomlawesome/gauntlet/persist"
)

// Token is a long-lived bearer credential for service-to-service access
// -- e.g. a companion application pulling event/flag data with no
// browser to hold a session cookie. Unlike Session, a Token is
// persisted: it has to survive a restart without the caller
// re-provisioning it.
//
// The raw token value is never stored -- only HashedValue, its SHA-256
// digest -- and is shown to the creator exactly once, at creation time
// (see TokenStore.Create). SHA-256, not Argon2id: Argon2id's cost is
// there to slow down guessing a low-entropy, human-chosen password: a
// token's value is a 128-bit crypto/rand string (see newID), already
// far outside brute-forceable range, so a slow KDF buys nothing here
// and would only add needless CPU cost to every authenticated request
// (same reasoning GitHub/GitLab personal access tokens use).
//
// There is no expiry field: like sessions and accounts, a token stays
// valid until explicitly revoked (see TokenStore.Revoke) -- no silent-
// expiry surprises for whatever integration is holding it.
type Token struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind is what this token may be used for, and it is not advisory:
	// Authenticate takes the kind its caller expects and will not match
	// a token of any other, so there is no code path where a token of
	// one kind satisfies a check written for another. See TokenKind.
	Kind TokenKind `json:"kind"`
	// Device scopes an ingest token to exactly one principal -- a
	// router in mikroview, nothing yet in birdcage (docs/design.md
	// §1.3). Required for TokenKindIngest, and rejected for any other
	// kind.
	//
	// Uniqueness per device is deliberately *not* enforced. Rotation
	// needs a window where the replacement exists before the old one is
	// revoked, and forbidding that would push operators towards
	// revoke-then-reissue -- a gap where the device is silently not
	// reporting.
	Device      string    `json:"device,omitempty"`
	HashedValue string    `json:"hashedValue"`
	CreatedAt   time.Time `json:"createdAt"`
	LastUsedAt  time.Time `json:"lastUsedAt,omitzero"`
	// CreatedBy is the account ID that issued this token, so deleting
	// that account can revoke it (see RevokeAllCreatedBy).
	//
	// Empty on tokens written before this field existed. Those cannot be
	// attributed to anyone and so are never auto-revoked; they have to
	// be reviewed by hand in the token list.
	CreatedBy string `json:"createdBy,omitempty"`
	// CreatedByUsername is a display snapshot, taken at creation. Kept
	// alongside the ID because the point at which it is most useful --
	// after that account has been deleted -- is exactly when the ID can
	// no longer be resolved to a name. Never used for authorization.
	CreatedByUsername string `json:"createdByUsername,omitempty"`
}

// TokenKind separates the credentials a store holds. They are not
// interchangeable in either direction, and that is enforced
// structurally rather than by convention: Authenticate requires its
// caller to name the kind it expects, so "I forgot to check the kind" is
// not an available mistake.
type TokenKind string

const (
	// TokenKindAPI is a read-only service-to-service token.
	TokenKindAPI TokenKind = "api"
	// TokenKindIngest is a push-ingest token, scoped to one device and
	// accepted only by the ingest endpoint.
	TokenKindIngest TokenKind = "ingest"
)

var (
	// ErrTokenNotPersisted is returned by Create when no backend is
	// configured -- refusing rather than silently issuing a token that
	// would vanish (and become unrevocable, since it was never recorded)
	// on the next restart.
	ErrTokenNotPersisted = errors.New("gauntlet: no backend is configured, refusing to create a token that would not survive a restart")
	// ErrTokenNotFound is returned by Revoke for an unknown token ID.
	ErrTokenNotFound = errors.New("gauntlet: no such token")
	// ErrTokenKindInvalid is returned by Create for a kind this store
	// was not opened with (TokenOptions.Kinds). Defaulting an
	// unregistered kind to a registered one would be the wrong
	// direction to guess in.
	ErrTokenKindInvalid = errors.New("gauntlet: unknown or unregistered token kind")
	// ErrTokenDeviceRequired is returned by Create for an ingest token
	// with no device: an unscoped ingest token is the thing the scope
	// exists to prevent, so there is no "leave it blank for all
	// devices" reading of an empty value.
	ErrTokenDeviceRequired = errors.New("gauntlet: an ingest token must name the device it is issued for")
	// ErrTokenDeviceNotAllowed is returned by Create when a non-ingest
	// token carries a device. Accepting and ignoring it would leave the
	// caller believing in a scope that nothing enforces.
	ErrTokenDeviceNotAllowed = errors.New("gauntlet: only an ingest token may name a device")
	// ErrTokenDeviceInvalid is returned by Create for a device id that
	// cannot be one: too long, or carrying control/formatting
	// characters. The id is a display value (it appears in the token
	// list, an audit trail and log lines) as well as a scope key, and
	// an unbounded or control-bearing one is a typo that becomes a
	// permanently, invisibly dead token at best.
	ErrTokenDeviceInvalid = errors.New("gauntlet: device id must be at most 64 characters of printable text")
	// ErrTokenNameInvalid is returned by Create for a name that is too
	// long or carries control/formatting characters. The name is a
	// display value in the same places the device id is, and bounded
	// for the same reasons (see ErrTokenDeviceInvalid).
	ErrTokenNameInvalid = errors.New("gauntlet: token name must be at most 64 characters of printable text")
)

// defaultTokenKinds is TokenOptions.Kinds' value when left empty --
// mikroview's original hard-coded set, minus its third,
// deployment-specific kind (see this file's header comment).
var defaultTokenKinds = []TokenKind{TokenKindAPI, TokenKindIngest}

// TokenOptions configures OpenTokenStore.
type TokenOptions struct {
	// Log receives the same warnings/errors Options.Log does for Store
	// (store.go) -- an unrecognised token kind on load, and a change
	// that could not be persisted. nil discards both.
	Log *slog.Logger
	// Kinds is the set of token kinds this store will create or
	// authenticate. Empty means defaultTokenKinds. A token already on
	// disk whose kind is not in this set is kept (never dropped on
	// save) and logged, but Authenticate never matches it and Create
	// refuses to mint another one of that kind -- see OpenTokenStore.
	Kinds []TokenKind
}

// TokenStore persists API tokens through a persist.Backend, the same
// whole-document convention Store (store.go) uses.
type TokenStore struct {
	mu      sync.RWMutex
	backend persist.Backend
	log     *slog.Logger
	// version is the backend's token for the document as of the last
	// load or save -- see persist.SaveWithRetry.
	version int64
	byID    map[string]*Token
	// byHash maps a token's SHA-256 hash straight to its ID, so
	// Authenticate is an O(1) map lookup rather than scanning every
	// token -- possible only because, unlike Argon2id password hashes,
	// SHA-256 is unsalted and deterministic: the same raw value always
	// hashes to the same key. A token whose kind is not registered
	// (below) is never entered here, so it can never be found by any
	// raw value at all.
	byHash map[string]string
	// kinds is the registered-kind set from TokenOptions.Kinds,
	// resolved once at OpenTokenStore and never mutated afterwards --
	// safe to read without mu.
	kinds map[TokenKind]bool
}

// OpenTokenStore returns a TokenStore persisting through b. A nil b
// gives a usable but unpersisted store -- same "stays usable, just
// refuses to persist" contract OpenStore has, so a deployment with no
// tokens configured never fails to start over this.
//
// A document that exists but cannot be read or parsed is a hard error:
// OpenTokenStore returns (nil, err) rather than a store whose live
// backend would overwrite that document on the first write. See
// persist.Open.
//
// A token loaded from the document whose kind is not in
// opts.Kinds (or defaultTokenKinds, if empty) is kept in the store --
// listable and revocable -- but is deliberately left out of the
// hash index, so it can never authenticate. Failing closed is the only
// safe direction: the alternative is guessing which registered kind an
// unrecognised one meant, and guessing "read-only API" for a value that
// might read everything a caller knows is not a guess worth making. It
// is logged so an operator can see it in the token list and reissue it.
func OpenTokenStore(b persist.Backend, opts TokenOptions) (*TokenStore, error) {
	kindList := opts.Kinds
	if len(kindList) == 0 {
		kindList = defaultTokenKinds
	}
	kinds := make(map[TokenKind]bool, len(kindList))
	for _, k := range kindList {
		kinds[k] = true
	}

	s := &TokenStore{
		backend: b,
		log:     opts.Log,
		byID:    make(map[string]*Token),
		byHash:  make(map[string]string),
		kinds:   kinds,
	}

	version, existed, err := persist.Open(context.Background(), b, "the API tokens store", func(data []byte) error {
		var list []*Token
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		for _, t := range list {
			if t == nil { // see Store.applyLoaded's identical guard for why this is needed
				continue
			}
			s.byID[t.ID] = t
			if !s.kinds[t.Kind] {
				if s.log != nil {
					s.log.Warn(fmt.Sprintf("token %q has unregistered kind %q -- it will not authenticate; revoke and reissue it", t.Name, t.Kind))
				}
				continue
			}
			s.byHash[t.HashedValue] = t.ID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if existed {
		s.version = version
	}
	return s, nil
}

// Persisted reports whether this store can actually survive a restart.
func (s *TokenStore) Persisted() bool {
	return s.backend != nil
}

// hashTokenValue is the one place a raw token value is ever hashed --
// used identically by Create (to compute what gets stored) and
// Authenticate (to compute what gets looked up), so the two can never
// drift apart.
func hashTokenValue(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// MaxDeviceIDLen bounds a token's device scope. Nothing legitimate comes
// close: a configured id is operator-chosen and a discovered one is an
// IP literal (at most 45 characters for IPv6 with a zone).
const MaxDeviceIDLen = 64

// validDeviceID rejects a device scope that could not have come from a
// real device. Control and Unicode formatting characters are refused
// because this string reaches an operator's terminal and browser, and
// the length cap keeps an oversized value out of the token store.
func validDeviceID(device string) bool {
	if device == "" {
		return true // the required/not-allowed rules in Create already ruled on this
	}
	return printableWithin(device, MaxDeviceIDLen)
}

// MaxTokenNameLen bounds a token's display name, the same cap
// MaxDeviceIDLen puts on its device scope.
const MaxTokenNameLen = 64

// validTokenName applies validDeviceID's rules to a token's name, which
// reaches the same terminals and browsers. Empty stays allowed, as it
// always has been: a name is a label, not a scope.
func validTokenName(name string) bool {
	return printableWithin(name, MaxTokenNameLen)
}

// printableWithin is the check validDeviceID and validTokenName share:
// at most maxBytes of valid UTF-8, with no control or Unicode formatting
// characters.
func printableWithin(s string, maxBytes int) bool {
	if len(s) > maxBytes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return false
		}
	}
	return utf8.ValidString(s)
}

// Create generates a new token named name, of kind kind, and persists
// its metadata + hash. The returned raw string is the only time the
// actual bearer value ever exists outside the caller's memory -- it is
// not recoverable afterward, only re-issuable as a brand new token.
// creator identifies the account issuing the token, so it can be
// revoked if that account is later deleted.
//
// kind must be one of the kinds this store was opened with
// (TokenOptions.Kinds); anything else is ErrTokenKindInvalid. device
// scopes an ingest token to one device and must be empty for any other
// kind -- see Token.Device. name is trimmed and held to the same length
// and character rules as device (ErrTokenNameInvalid).
func (s *TokenStore) Create(name string, kind TokenKind, device string, creator *User, now time.Time) (raw string, tok *Token, err error) {
	if !s.Persisted() {
		return "", nil, ErrTokenNotPersisted
	}
	if !s.kinds[kind] {
		return "", nil, ErrTokenKindInvalid
	}
	name = strings.TrimSpace(name)
	if !validTokenName(name) {
		return "", nil, ErrTokenNameInvalid
	}
	device = strings.TrimSpace(device)
	if kind == TokenKindIngest && device == "" {
		return "", nil, ErrTokenDeviceRequired
	}
	if kind != TokenKindIngest && device != "" {
		return "", nil, ErrTokenDeviceNotAllowed
	}
	if !validDeviceID(device) {
		return "", nil, ErrTokenDeviceInvalid
	}

	// newID's generator -- same 128-bit crypto/rand source Session
	// already uses for its own unguessable IDs (see id.go).
	raw = newID()
	hash := hashTokenValue(raw)

	s.mu.Lock()
	defer s.mu.Unlock()

	t := &Token{
		ID:          newID(),
		Name:        name,
		Kind:        kind,
		Device:      device,
		HashedValue: hash,
		CreatedAt:   now,
	}
	if creator != nil {
		t.CreatedBy = creator.ID
		t.CreatedByUsername = creator.Username
	}
	s.byID[t.ID] = t
	s.byHash[hash] = t.ID
	if err := s.tryPersistLocked(); err != nil {
		// A token that only exists in memory must not be handed to the
		// caller: the raw value is shown exactly once, here, so a
		// restart before the next good write would leave the caller
		// holding a value that authenticates against nothing.
		delete(s.byID, t.ID)
		delete(s.byHash, hash)
		return "", nil, fmt.Errorf("saving API tokens: %w", err)
	}

	cp := *t
	return raw, &cp, nil
}

// lastUsedGranularity is how stale a token's persisted LastUsedAt may
// become before a write is worth it -- an hour is far finer than the
// question this field answers ("is this token still in use, or can I
// revoke it?") and coarse enough that a polling client writes once
// rather than continuously.
const lastUsedGranularity = time.Hour

// Authenticate validates a raw bearer token value *of kind want*,
// recording LastUsedAt on success. Returns (nil, false) for an unknown,
// malformed, or revoked token -- deliberately no distinction between
// those, same as Store.Authenticate's treatment of unknown-username vs.
// wrong-password -- and equally for a real, valid token of the wrong
// kind, or one whose kind was never registered with this store (see
// OpenTokenStore).
//
// want is a parameter rather than something the caller inspects
// afterwards on purpose: requiring the kind up front means "accepted an
// ingest token wherever it meant to accept a read-only one" cannot be
// made silently. LastUsedAt is left untouched on a mismatch, so a token
// presented at the wrong door does not look like it was used.
func (s *TokenStore) Authenticate(raw string, want TokenKind, now time.Time) (*Token, bool) {
	if raw == "" {
		return nil, false
	}
	hash := hashTokenValue(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byHash[hash]
	if !ok {
		return nil, false
	}
	t, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	if t.Kind != want {
		return nil, false
	}
	// See mikroview's own comment on this line (kept): persisting only
	// once the recorded value is more than lastUsedGranularity stale
	// keeps the display honest to the minute while collapsing a poll
	// loop's writes to one an hour instead of one per request.
	if now.Sub(t.LastUsedAt) >= lastUsedGranularity {
		t.LastUsedAt = now
		s.persistLocked()
	} else {
		t.LastUsedAt = now
	}
	cp := *t
	return &cp, true
}

// Revoke permanently deletes a token by ID -- there is no "disable and
// keep around" state, matching how a revoked session is deleted
// outright rather than flagged (see SessionStore.Revoke).
func (s *TokenStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.byID[id]
	if !ok {
		return ErrTokenNotFound
	}
	delete(s.byID, id)
	delete(s.byHash, t.HashedValue)
	if err := s.tryPersistLocked(); err != nil {
		// A revoke that only exists in memory must not be reported as
		// done: the caller tells its operator the token is dead, and a
		// restart before the next good write would let the raw value
		// authenticate again with nobody the wiser.
		s.byID[id] = t
		s.byHash[t.HashedValue] = id
		return fmt.Errorf("saving API tokens: %w", err)
	}
	return nil
}

// RevokeAllCreatedBy deletes every token issued by userID, returning how
// many went. Called when that account is deleted: the person still holds
// the raw values, so the account going away has to take its tokens with
// it.
//
// An empty userID matches nothing, deliberately -- pre-attribution
// tokens carry an empty CreatedBy, and treating that as a match would
// let deleting any one account wipe every unattributed token in the
// deployment.
//
// On a persistence failure the deletions are rolled back and the
// returned count is 0: a revoke that only exists in memory must not be
// reported as done.
func (s *TokenStore) RevokeAllCreatedBy(userID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := make([]*Token, 0)
	for id, t := range s.byID {
		if t.CreatedBy != userID {
			continue
		}
		delete(s.byID, id)
		delete(s.byHash, t.HashedValue)
		removed = append(removed, t)
	}
	if len(removed) == 0 {
		return 0, nil
	}
	if err := s.tryPersistLocked(); err != nil {
		for _, t := range removed {
			s.byID[t.ID] = t
			s.byHash[t.HashedValue] = t.ID
		}
		return 0, fmt.Errorf("saving API tokens: %w", err)
	}
	return len(removed), nil
}

// tokenOlder is the one order List, ByKind and the saved document use:
// oldest first, then by ID. The ID breaks ties between tokens created in
// the same instant, which would otherwise come out in map-iteration order
// -- different on every call, so a list that reshuffles on refresh and a
// document whose bytes change on every save.
func tokenOlder(a, b *Token) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return a.ID < b.ID
}

// List returns every token's metadata, oldest first -- HashedValue is
// always zeroed out (never the raw value either, since this store never
// retains it past Create's return) so a list response can never leak
// anything an attacker could use to authenticate.
func (s *TokenStore) List() []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Token, 0, len(s.byID))
	for _, t := range s.byID {
		cp := *t
		cp.HashedValue = ""
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return tokenOlder(&out[i], &out[j]) })
	return out
}

// ByKind returns every token of kind kind, oldest first -- the same
// copy-and-zero-hash contract List uses, so a caller holding the result
// can never use it to authenticate.
func (s *TokenStore) ByKind(kind TokenKind) []*Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Token
	for _, t := range s.byID {
		if t.Kind != kind {
			continue
		}
		cp := *t
		cp.HashedValue = ""
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return tokenOlder(out[i], out[j]) })
	return out
}

// tryPersistLocked is persistLocked's error-returning half, for the
// callers (Create, Revoke, RevokeAllCreatedBy) that issue or revoke a
// token and so must not let the caller believe a write happened when it
// didn't. Authenticate's LastUsedAt update keeps using persistLocked
// below, which keeps the swallow-and-log behaviour: that field is a
// display convenience, not worth failing an otherwise-valid
// authentication over.
func (s *TokenStore) tryPersistLocked() error {
	if s.backend == nil {
		return nil
	}
	list := make([]*Token, 0, len(s.byID))
	for _, t := range s.byID {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return tokenOlder(list[i], list[j]) })

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding API tokens for persistence failed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), saveTimeout)
	defer cancel()
	version, conflicted, err := persist.SaveWithRetry(ctx, s.backend, data, s.version)
	if err != nil {
		return fmt.Errorf("writing API tokens to %s failed: %w", s.backend.Describe(), err)
	}
	if conflicted && s.log != nil {
		s.log.Warn(fmt.Sprintf("API tokens store was modified by another process while this change "+
			"was pending (%s); this change was applied on top", s.backend.Describe()))
	}
	s.version = version
	return nil
}

// persistLocked is the swallow-and-log default -- see tryPersistLocked's
// doc comment for which callers keep it and why.
func (s *TokenStore) persistLocked() {
	if err := s.tryPersistLocked(); err != nil && s.log != nil {
		s.log.Error(fmt.Sprintf("%v -- this change exists only in memory and will be lost on restart", err))
	}
}
