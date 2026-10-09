package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/tomlawesome/gauntlet/internal/expiry"
	"github.com/tomlawesome/gauntlet/internal/seal"
)

// FlowState is everything a caller needs to remember between redirecting
// the browser to the provider and it coming back to the callback: the
// CSRF state token, the OIDC nonce, and the PKCE code verifier. Held
// client-side in an encrypted cookie (see StateCodec) rather than
// server-side -- gauntlet's SessionStore is in-memory by design (ADR-0001:
// no signing keys, re-login after restart), and a login-in-progress is
// even more disposable than that: a mid-flow restart just fails the flow
// cleanly, no new bounded-map/eviction machinery needed the way a
// server-side store would require.
type FlowState struct {
	State        string
	Nonce        string
	CodeVerifier string
	IssuedAt     time.Time
	// LinkUserID, when set, marks this flow as a *link* rather than a
	// login: the identity that comes back is to be attached to this
	// existing account (see the root gauntlet package's
	// Store.LinkOIDCIdentity), not resolved or provisioned as its own.
	//
	// Carried inside the sealed state rather than as a separate cookie or
	// a query parameter because the whole point is that the browser can't
	// choose it. The state is AES-GCM sealed, so a caller can neither
	// read which account a flow targets nor forge one that targets
	// somebody else's.
	//
	// Empty for an ordinary login, which is what every flow created
	// before this field existed decodes as.
	LinkUserID string `json:",omitempty"`
}

// IsLink reports whether this flow was started to link an identity to an
// existing account rather than to sign in.
func (fs FlowState) IsLink() bool { return fs.LinkUserID != "" }

// NewFlowState generates a fresh State/Nonce (crypto/rand-backed) and
// PKCE CodeVerifier (oauth2.GenerateVerifier) for one login attempt.
func NewFlowState(now time.Time) (FlowState, error) {
	state, err := randomToken()
	if err != nil {
		return FlowState{}, fmt.Errorf("oidc: generating state token: %w", err)
	}
	nonce, err := randomToken()
	if err != nil {
		return FlowState{}, fmt.Errorf("oidc: generating nonce: %w", err)
	}
	return FlowState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: oauth2.GenerateVerifier(),
		IssuedAt:     now,
	}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ErrFlowStateInvalid covers every way a flow-state cookie can fail to
// decode: tampered, corrupt, or simply expired. Deliberately one error
// rather than several distinct ones -- which specific failure occurred
// isn't information a caller (or, transitively, an attacker probing the
// callback endpoint) needs to be able to distinguish.
var ErrFlowStateInvalid = errors.New("oidc: login flow expired or was tampered with")

// StateCodec seals/opens a FlowState into an opaque cookie value, so
// the cookie is both confidential (the PKCE verifier is never observable
// or guessable from the cookie itself) and tamper-evident. The sealing
// is internal/seal's AES-256-GCM under a key made once from crypto/rand
// and held only in memory, the same process-lifetime contract gauntlet's
// SessionStore already has. That package's doc says why.
//
// gate's tickets and passkey's ceremony state share that mechanism but
// not this type or its key: each wrapper names the one payload it
// carries, and a value sealed for one flow cannot be opened as another.
type StateCodec struct {
	codec *seal.Codec
}

// NewStateCodec generates a fresh in-memory AES-256-GCM key and returns a
// StateCodec ready to seal and open FlowState values.
func NewStateCodec() (*StateCodec, error) {
	c, err := seal.New()
	if err != nil {
		return nil, fmt.Errorf("oidc: building the state codec: %w", err)
	}
	return &StateCodec{codec: c}, nil
}

// Encode seals fs into a cookie-safe (base64 URL, no padding) string.
func (c *StateCodec) Encode(fs FlowState) (string, error) {
	sealed, err := c.codec.Seal(fs)
	if err != nil {
		return "", fmt.Errorf("oidc: sealing flow state: %w", err)
	}
	return sealed, nil
}

// Decode opens a cookie value produced by Encode, rejecting it
// (ErrFlowStateInvalid) if it's malformed, spelled other than Encode
// spelled it, fails the AEAD auth check, or is maxAge old or older as
// measured from FlowState.IssuedAt: it is refused from the instant it
// expires (internal/expiry).
func (c *StateCodec) Decode(cookieValue string, maxAge time.Duration, now time.Time) (FlowState, error) {
	var fs FlowState
	if !c.codec.Open(cookieValue, &fs) {
		return FlowState{}, ErrFlowStateInvalid
	}
	if expiry.Expired(fs.IssuedAt, maxAge, now) {
		return FlowState{}, ErrFlowStateInvalid
	}
	return fs, nil
}
