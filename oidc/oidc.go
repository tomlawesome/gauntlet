// Package oidc is gauntlet's OIDC/SSO relying-party layer: provider
// discovery, the Authorization Code + PKCE flow, and ID token
// verification. Protocol-only and provider-agnostic -- it knows nothing
// about an application's own User/Session model (the root gauntlet
// package and gate own identity storage and JIT provisioning). Nothing
// here assumes local auth doesn't exist; this is a strictly additive
// integration on top of it.
//
// Moved unchanged from mikroview's internal/oidc (oidc.go, policy.go,
// state.go -- mikroview issue #43), as docs/design.md §1.4 and
// docs/adr/0001-shared-auth-module.md record: mikroview's own move onto
// this package (#1202) is expected to see no functional difference. The
// self-hosted-only policy in policy.go (AllowIssuer, IsMultiTenantIssuer)
// is deliberately not made configurable -- mikroview's
// docs/decisions/multi-tenant-oidc.md decided that, and it moves as a
// fixed decision, not a knob a future caller can turn on.
package oidc

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// defaultHTTPTimeout bounds every HTTP call this package makes to the
// provider (discovery, JWKS, token exchange) -- without it, a slow or
// hung IdP could block a login, or an application's own startup during
// discovery, indefinitely. go-oidc and x/oauth2 share one mechanism for
// this (oidc.ClientContext, which sets the same context key
// oauth2.HTTPClient does), so setting it once in New and re-applying it
// in every method below covers all three call sites.
const defaultHTTPTimeout = 10 * time.Second

// Config holds the settings needed to talk to one OIDC provider, kept as
// plain fields so this package stays a leaf with no imports back into
// gauntlet's other packages.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	// RedirectURL is the only source AuthCodeURL uses for redirect_uri.
	// Callers must build it from their own configured public base URL,
	// never from a request's Host/X-Forwarded-Host header -- deriving a
	// redirect target from client-influenced input is a known
	// vulnerability class, and this package has no other input to build
	// it from by construction.
	RedirectURL string
	Scopes      []string
	// HTTPTimeout overrides defaultHTTPTimeout if non-zero -- exists
	// mainly so tests can shrink it rather than wait out the real
	// default against a deliberately slow fake provider.
	HTTPTimeout time.Duration
}

// Identity is the only data this package trusts out of a verified ID
// token. Issuer+Subject are the immutable identity key (see the root
// gauntlet package's Store.FindOrCreateOIDCUser) -- Email/PreferredUsername
// are display hints only, never used to match an existing account.
type Identity struct {
	Issuer            string
	Subject           string
	Nonce             string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	// Claims is the id_token's full claim set, kept so Policy can check
	// restrictions against claims this package has no reason to name --
	// group membership, Google's hosted domain, an Entra tenant id, or
	// whatever a given provider calls the equivalent. Populated only from
	// a token that already passed signature and issuer verification.
	Claims map[string]any
}

// claimValues reads one claim as a list of strings, tolerating the three
// shapes providers actually emit: a list, a single string, or a list
// containing non-strings. Anything it can't interpret yields no values,
// which Policy treats as a refusal rather than a pass.
func (i *Identity) claimValues(name string) []string {
	raw, ok := i.Claims[name]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	// No case []string: claims always arrive through encoding/json into
	// map[string]any, which yields []any for a JSON array and never
	// []string, so that branch was unreachable (mikroview #267 finding
	// 20). Confirmed against the vendored go-oidc source.
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Client is a configured connection to one OIDC provider -- discovery
// (the .well-known document + JWKS) happens once, in New, not per
// request.
type Client struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	httpClient   *http.Client
}

// New performs provider discovery and builds a Client ready to start
// login flows. Fails if the issuer's .well-known/openid-configuration
// document can't be fetched/parsed -- callers should treat this the same
// as any other optional-integration startup failure: log it and leave
// SSO off, never crash the whole process or fall back to a degraded
// verification path over it.
func New(ctx context.Context, cfg Config) (*Client, error) {
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	httpClient := &http.Client{Timeout: timeout}
	ctx = oidc.ClientContext(ctx, httpClient)

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovering provider at %s: %w", cfg.IssuerURL, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	} else {
		hasOpenID := false
		for _, s := range scopes {
			if s == oidc.ScopeOpenID {
				hasOpenID = true
				break
			}
		}
		if !hasOpenID {
			scopes = append([]string{oidc.ScopeOpenID}, scopes...)
		}
	}

	return &Client{
		httpClient: httpClient,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		// SupportedSigningAlgs is set explicitly to an asymmetric-only
		// allowlist -- go-oidc already defaults to RS256-only if left
		// unset, but this stays explicit and auditable in this package's
		// own code rather than implied by a library default a future
		// dependency bump could silently change, and covers Authentik
		// deployments configured for ES256 as well as the RS256 default.
		// HS256 and "none" are never accepted under any circumstance --
		// this is the algorithm-confusion defense.
		verifier: provider.Verifier(&oidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256, oidc.PS256},
		}),
	}, nil
}

// AuthCodeURL builds the URL to redirect the browser to for login --
// state is an opaque CSRF token, nonce defends against ID token replay,
// and codeVerifier is the PKCE verifier (its S256 challenge is derived
// automatically by oauth2.S256ChallengeOption). Callers must persist all
// three (see FlowState/StateCodec) and compare them against what comes
// back from Exchange/VerifyIDToken. The redirect_uri in the returned URL
// is always Config.RedirectURL as given to New -- there is no parameter
// here through which a caller (or a caller's own caller) could redirect
// it elsewhere.
func (c *Client) AuthCodeURL(state, nonce, codeVerifier string) string {
	return c.oauth2Config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(codeVerifier),
	)
}

// Exchange trades an authorization code for tokens, presenting
// codeVerifier so the provider can confirm it matches the challenge sent
// in AuthCodeURL -- the actual PKCE proof-of-possession check.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	ctx = oidc.ClientContext(ctx, c.httpClient)
	tok, err := c.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: exchanging authorization code: %w", err)
	}
	return tok, nil
}

// ErrNoIDToken is returned by VerifyIDToken if the token response has no
// id_token field at all -- a malformed/non-compliant provider response,
// not a normal failure mode.
var ErrNoIDToken = fmt.Errorf("oidc: token response contained no id_token")

// VerifyIDToken extracts and cryptographically verifies tok's ID token
// (signature against the provider's JWKS, issuer, audience, and expiry --
// see New's SupportedSigningAlgs for the accepted algorithm allowlist)
// and returns the claims this package trusts. Callers MUST separately
// compare the returned Identity.Nonce against the nonce generated for
// this flow (see VerifyNonce) -- go-oidc's Verify does not check nonce
// itself, and neither does this method, since the expected value is only
// known to whoever holds the flow state.
func (c *Client) VerifyIDToken(ctx context.Context, tok *oauth2.Token) (*Identity, error) {
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, ErrNoIDToken
	}

	// Verify may need to fetch the provider's JWKS (e.g. on first use, or
	// after a key rotation) -- bounded the same way Exchange/New are.
	ctx = oidc.ClientContext(ctx, c.httpClient)
	idToken, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("oidc: verifying id_token: %w", err)
	}

	var claims struct {
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: decoding id_token claims: %w", err)
	}

	// Decoded a second time, untyped, so Policy can inspect claims whose
	// names are configuration rather than something this package knows.
	// A token that decodes into the struct above but not into a map would
	// be malformed, so this failing is a hard error, not a soft one --
	// otherwise a group restriction would silently see no claims and
	// refuse every login.
	allClaims := map[string]any{}
	if err := idToken.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("oidc: decoding id_token claim set: %w", err)
	}

	return &Identity{
		Claims:            allClaims,
		Issuer:            idToken.Issuer,
		Subject:           idToken.Subject,
		Nonce:             idToken.Nonce,
		Email:             claims.Email,
		EmailVerified:     claims.EmailVerified,
		PreferredUsername: claims.PreferredUsername,
	}, nil
}

// VerifyNonce reports whether got matches want using a constant-time
// comparison -- called by the application's OIDC callback handler (gate,
// in gauntlet) after VerifyIDToken, comparing Identity.Nonce against the
// FlowState.Nonce stored for this login attempt. Not a secret-equality
// check in the cryptographic sense (the nonce isn't confidential), but
// consistent with how every other compare-then-branch security check in
// this codebase is written, and cheap enough that there's no reason not
// to.
func VerifyNonce(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
