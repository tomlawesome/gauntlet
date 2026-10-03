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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
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
	ErrTokenDeviceInvalid = errors.New("gauntlet: device id must be printable text of at most 64 bytes (fewer characters for non-Latin letters)")
	// ErrTokenNameInvalid is returned by Create for a name that is too
	// long or carries control/formatting characters. The name is a
	// display value in the same places the device id is, and bounded
	// for the same reasons (see ErrTokenDeviceInvalid).
	ErrTokenNameInvalid = errors.New("gauntlet: token name must be printable text of at most 64 bytes (fewer characters for non-Latin letters)")
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
	// load or save -- what mutate saves with, so a write from another
	// process is noticed rather than written over.
	version int64
	// tokenState is the tokens document as this process holds it,
	// guarded by mu. Embedded so the fields read as s.byID; a write
	// changes a copy and swaps it in whole -- see mutate.
	tokenState
	// kinds is the registered-kind set from TokenOptions.Kinds,
	// resolved once at OpenTokenStore and never mutated afterwards --
	// safe to read without mu.
	kinds map[TokenKind]bool

	// reloadInFlight is non-nil while one caller is checking the
	// backend for staleness -- see reloadIfStale, and Store's field of
	// the same name for why it is not guarded by mu.
	reloadMu       sync.Mutex
	reloadInFlight chan struct{}

	// refusedVersion is the last document version reloadIfStale refused
	// to apply (see checkDocumentVersion), so it is logged once rather
	// than on every request -- Store's fields of the same name, guarded
	// by mu the same way.
	refusedVersion    int64
	hasRefusedVersion bool

	// removalLogged is set once a write has met ErrDocumentRemoved and
	// logged it, so a removed document is reported once per removal
	// rather than on every write (#39). Cleared whenever this store
	// installs a document again -- a save or a reload -- so a restore
	// followed by a second removal is logged afresh. Guarded by mu.
	removalLogged bool
}

// tokenState is the in-memory index over the tokens document. It is
// what a write changes, as a whole -- see TokenStore.mutate -- and what
// OpenTokenStore builds on a load.
type tokenState struct {
	byID map[string]*Token
	// byHash maps a token's SHA-256 hash straight to its ID, so
	// Authenticate is an O(1) map lookup rather than scanning every
	// token -- possible only because, unlike Argon2id password hashes,
	// SHA-256 is unsalted and deterministic: the same raw value always
	// hashes to the same key. A token whose kind is not registered
	// (below) is never entered here, so it can never be found by any
	// raw value at all.
	byHash map[string]string
	// lastUsedSaved is each token's LastUsedAt as of the last load or
	// save, by ID -- what Authenticate measures staleness against (see
	// lastUsedGranularity), since the in-memory value may be ahead of
	// it. Store.lastLoginSaved is the same for LastLogin.
	lastUsedSaved map[string]time.Time
}

// clone deep-copies the state, so a change to the copy can be thrown
// away without having touched the original. Token holds no slices, so
// a struct copy of each one is a full copy.
func (st *tokenState) clone() *tokenState {
	cp := &tokenState{
		byID:          make(map[string]*Token, len(st.byID)),
		byHash:        make(map[string]string, len(st.byHash)),
		lastUsedSaved: make(map[string]time.Time, len(st.lastUsedSaved)),
	}
	for id, t := range st.byID {
		tc := *t
		cp.byID[id] = &tc
	}
	maps.Copy(cp.byHash, st.byHash)
	maps.Copy(cp.lastUsedSaved, st.lastUsedSaved)
	return cp
}

// recordSaved notes each token's LastUsedAt as the value just saved.
func (st *tokenState) recordSaved() {
	if st.lastUsedSaved == nil {
		st.lastUsedSaved = make(map[string]time.Time, len(st.byID))
	}
	clear(st.lastUsedSaved)
	for id, t := range st.byID {
		st.lastUsedSaved[id] = t.LastUsedAt
	}
}

// tokens is the tokens in document order -- see tokenOlder.
func (st *tokenState) tokens() []*Token {
	list := make([]*Token, 0, len(st.byID))
	for _, t := range st.byID {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return tokenOlder(list[i], list[j]) })
	return list
}

// tokenFile is the on-disk shape since #29: an object carrying the
// format version (tokensDocumentVersion) and the token list. v0.1.0
// wrote the bare list; parseTokens reads it as version 1, and the next
// save writes it in this shape.
type tokenFile struct {
	Version int      `json:"version"`
	Tokens  []*Token `json:"tokens"`
}

// encodeTokens is the state as the document is saved.
func encodeTokens(st *tokenState) ([]byte, error) {
	return json.MarshalIndent(tokenFile{Version: tokensDocumentVersion, Tokens: st.tokens()}, "", "  ")
}

// parseTokens parses a stored tokens document in either shape: v0.1.0's
// bare list, or a tokenFile, refusing one newer than this build reads
// (see checkDocumentVersion) before parsing the rest of it.
func parseTokens(data []byte) ([]*Token, error) {
	if trimmed := bytes.TrimLeft(data, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '[' {
		var list []*Token
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	version, err := documentVersion(data)
	if err != nil {
		return nil, err
	}
	if err := checkDocumentVersion("API tokens", version, tokensDocumentVersion); err != nil {
		return nil, err
	}
	var file tokenFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file.Tokens, nil
}

// indexTokens builds the state for a document's token list, leaving a
// token of an unregistered kind out of the hash index (see
// OpenTokenStore) and warning about it. Shared by OpenTokenStore and
// the conflict replay in mutate, so the two can't diverge on what
// loading means.
func (s *TokenStore) indexTokens(list []*Token) *tokenState {
	st := &tokenState{
		byID:          make(map[string]*Token, len(list)),
		byHash:        make(map[string]string, len(list)),
		lastUsedSaved: make(map[string]time.Time, len(list)),
	}
	for _, t := range list {
		if t == nil { // see indexUsers' identical guard for why this is needed
			continue
		}
		st.byID[t.ID] = t
		st.lastUsedSaved[t.ID] = t.LastUsedAt
		if !s.kinds[t.Kind] {
			if s.log != nil {
				s.log.Warn(fmt.Sprintf("token %q has unregistered kind %q -- it will not authenticate; revoke and reissue it", t.Name, t.Kind))
			}
			continue
		}
		st.byHash[t.HashedValue] = t.ID
	}
	return st
}

// decodeTokens is the document as it is opened.
func (s *TokenStore) decodeTokens(data []byte) (*tokenState, error) {
	list, err := parseTokens(data)
	if err != nil {
		return nil, err
	}
	return s.indexTokens(list), nil
}

// tokens is the replay loop's view of this store -- see mutate.go.
func (s *TokenStore) tokens() document[tokenState] {
	return document[tokenState]{
		backend: s.backend,
		what:    "API tokens",
		clone:   (*tokenState).clone,
		encode:  encodeTokens,
		decode:  s.decodeTokens,
	}
}

// mutate applies op to the tokens and saves the result, taking the
// write lock for the whole of it -- Store.mutate's contract exactly,
// including the reload-and-replay on a conflicting write from another
// process, which this store did not do before #21.
func (s *TokenStore) mutate(op func(*tokenState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateLocked(op)
}

// mutateLocked is mutate for a caller that already holds mu. As
// Store.mutateLocked, it installs the fresh document op refused on a
// replay as well as the saved one: a token revoked by another process
// is gone from this store the moment a write here meets that revoke.
func (s *TokenStore) mutateLocked(op func(*tokenState) error) error {
	next, version, err := s.tokens().replay(&s.tokenState, s.version, op)
	if next != nil {
		next.recordSaved()
		s.tokenState = *next
		s.version = version
		s.refusedVersion, s.hasRefusedVersion = 0, false
		s.removalLogged = false
	}
	if errors.Is(err, errNoChange) {
		return nil
	}
	if errors.Is(err, ErrDocumentRemoved) {
		s.logRemovalLocked()
	}
	return err
}

// logRemovalLocked tells the operator, once per removal, that the
// document this store loaded is gone and why every write now fails.
// The store never recreates it (see ErrDocumentRemoved); reads carry on
// from memory.
func (s *TokenStore) logRemovalLocked() {
	if s.removalLogged {
		return
	}
	s.removalLogged = true
	if s.log != nil {
		s.log.Error(fmt.Sprintf("API tokens store (%s) has been removed since this process loaded it; writes are refused until it is restored or the process restarts", s.backend.Describe()))
	}
}

// mutateBestEffortLocked is mutateLocked for a write not worth failing
// the caller over -- Authenticate's LastUsedAt bump. See
// Store.mutateBestEffortLocked, including why re-running op on the
// live state is safe when op is what failed.
func (s *TokenStore) mutateBestEffortLocked(op func(*tokenState) error) {
	err := s.mutateLocked(op)
	if err == nil {
		return
	}
	if opErr := op(&s.tokenState); opErr != nil {
		return
	}
	// A removed document has already been reported, once, by
	// logRemovalLocked; a line per login on top of it is noise.
	if s.log != nil && !errors.Is(err, ErrDocumentRemoved) {
		s.log.Error(fmt.Sprintf("%v -- this change exists only in memory and will be lost on restart", err))
	}
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
		kinds:   kinds,
	}
	s.tokenState = *s.indexTokens(nil)

	version, existed, err := persist.Open(context.Background(), b, "the API tokens store", func(data []byte) error {
		st, err := s.decodeTokens(data)
		if err != nil {
			return err
		}
		s.tokenState = *st
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

// reloadIfStale re-reads the tokens document if the backend has moved
// on since this store last loaded or saved it -- Store.reloadIfStale
// for tokens, called before every read, write and Authenticate for the
// same reason: a token revoked through the CLI must stop working on the
// running server then, not at its next restart (which, before #21, is
// when it did) and not at the next write that happens to conflict.
//
// The same three bounds apply: a deadline (reloadTimeout), one check
// in flight at a time with later callers joining it, and the cheap
// Version question first where the backend can answer it. Every
// failure is silent and keeps what is in memory. There is no admin rule
// for tokens, so the one document refused rather than skipped is a
// newer one (see checkDocumentVersion): it is logged once, as Store
// logs a refused document, and one that does not parse is kept out
// silently, as Store does for an unparseable one.
func (s *TokenStore) reloadIfStale() {
	if s.backend == nil {
		return
	}

	s.reloadMu.Lock()
	if inFlight := s.reloadInFlight; inFlight != nil {
		s.reloadMu.Unlock()
		<-inFlight
		return
	}
	done := make(chan struct{})
	s.reloadInFlight = done
	s.reloadMu.Unlock()
	defer func() {
		s.reloadMu.Lock()
		s.reloadInFlight = nil
		s.reloadMu.Unlock()
		close(done)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
	defer cancel()

	if vr, ok := s.backend.(persist.VersionReader); ok {
		version, exists, err := vr.Version(ctx)
		if err != nil || !exists {
			return
		}
		s.mu.RLock()
		stale := version != s.version
		refused := s.hasRefusedVersion && version == s.refusedVersion
		s.mu.RUnlock()
		if !stale || refused {
			return
		}
	}

	// See Store.reloadIfStale: the version captured before the unlocked
	// read is compared again under the write lock, so a write that
	// landed in between is not reverted by a snapshot read before it.
	s.mu.RLock()
	beforeLoad := s.version
	s.mu.RUnlock()

	snap, err := s.backend.Load(ctx)
	if err != nil || !snap.Exists || snap.Version == beforeLoad {
		return
	}
	s.mu.RLock()
	alreadyRefused := s.hasRefusedVersion && snap.Version == s.refusedVersion
	s.mu.RUnlock()
	if alreadyRefused {
		return
	}
	st, err := s.decodeTokens(snap.Payload)
	// A newer document and the literal null are both refused loudly:
	// someone wrote them, and the operator should hear why once.
	if errors.Is(err, errNewerDocument) || errors.Is(err, errNullDocument) {
		s.mu.Lock()
		s.refusedVersion, s.hasRefusedVersion = snap.Version, true
		s.mu.Unlock()
		if s.log != nil {
			s.log.Error(fmt.Sprintf("API tokens store (%s) was changed by another process and is not being applied: %v", s.backend.Describe(), err))
		}
		return
	}
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != beforeLoad {
		return
	}
	s.tokenState = *st
	s.version = snap.Version
	s.refusedVersion, s.hasRefusedVersion = 0, false
	s.removalLogged = false
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
	// Picking up another process's writes first avoids most save
	// conflicts; correctness does not depend on it -- see mutate.
	s.reloadIfStale()

	// A token that only exists in memory must not be handed to the
	// caller: the raw value is shown exactly once, here, so a restart
	// before the next good write would leave the caller holding a value
	// that authenticates against nothing. mutate installs the token
	// only once it is saved, and may run this op again against a
	// freshly loaded document if another process wrote first, so the
	// token is built inside it from the arguments alone and the result
	// is set last.
	id := newID()
	var created Token
	err = s.mutate(func(st *tokenState) error {
		t := &Token{
			ID:          id,
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
		st.byID[t.ID] = t
		st.byHash[hash] = t.ID
		created = *t
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return raw, &created, nil
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
	// Before the lookup, so a token revoked through the CLI is gone
	// from this store's index by the time it is looked up.
	s.reloadIfStale()

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
	// Measured against the saved value, not t.LastUsedAt, which every
	// use moves: against that, uses less than an hour apart would never
	// save again.
	if now.Sub(s.lastUsedSaved[id]) < lastUsedGranularity {
		t.LastUsedAt = now
		cp := *t
		return &cp, true
	}
	s.mutateBestEffortLocked(func(st *tokenState) error {
		t, ok := st.byID[id]
		if !ok {
			return ErrTokenNotFound
		}
		t.LastUsedAt = now
		return nil
	})
	if t, ok = s.byID[id]; !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

// Revoke permanently deletes a token by ID -- there is no "disable and
// keep around" state, matching how a revoked session is deleted
// outright rather than flagged (see SessionStore.Revoke).
func (s *TokenStore) Revoke(id string) error {
	// A revoke that only exists in memory must not be reported as done:
	// the caller tells its operator the token is dead, and a restart
	// before the next good write would let the raw value authenticate
	// again with nobody the wiser. mutate installs it only once it is
	// saved.
	s.reloadIfStale()
	return s.mutate(func(st *tokenState) error {
		t, ok := st.byID[id]
		if !ok {
			return ErrTokenNotFound
		}
		delete(st.byID, id)
		delete(st.byHash, t.HashedValue)
		return nil
	})
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
// On a persistence failure nothing is deleted and the returned count is
// 0: a revoke that only exists in memory must not be reported as done.
func (s *TokenStore) RevokeAllCreatedBy(userID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	s.reloadIfStale()
	// Counted inside the op, against the document being saved: a replay
	// after another process issued or revoked one of this account's
	// tokens must take what is there then.
	var removed int
	err := s.mutate(func(st *tokenState) error {
		removed = 0
		for id, t := range st.byID {
			if t.CreatedBy != userID {
				continue
			}
			delete(st.byID, id)
			delete(st.byHash, t.HashedValue)
			removed++
		}
		if removed == 0 {
			return errNoChange
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
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
	s.reloadIfStale()
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
	s.reloadIfStale()
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
