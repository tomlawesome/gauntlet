// Package testutil holds test doubles shared across gauntlet's packages
// -- currently just the fake OIDC provider, exported (rather than living
// in an oidc_test.go) so gate's own tests can drive the same provider
// through a real login flow once gate exists (docs/design.md's G6
// done-when: "OIDC callback (fake provider)").
//
// FakeProvider is ported from mikroview's internal/oidc/fake_provider_test.go,
// with one deliberate change: mikroview signed test JWTs with
// github.com/go-jose/go-jose/v4, a dependency gauntlet does not otherwise
// need (go-oidc/x/oauth2 are the only two approved for this package --
// AGENTS.md). The signing here is hand-rolled against the JWS compact
// serialization (RFC 7515) with stdlib crypto only, producing bit-for-bit
// equivalent tokens for what these tests check: a real RS256 signature
// verifiable against the JWKS below, the classic HS256-with-the-public-key
// algorithm-confusion attempt, and a hand-crafted alg=none token.
package testutil

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// IDTokenClaims is the standard shape of claims gauntlet's oidc tests
// need to control -- mirrors the subset oidc.go's Identity reads plus the
// standard registered claims go-oidc validates.
type IDTokenClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	Expiry            int64  `json:"exp"`
	IssuedAt          int64  `json:"iat"`
	Nonce             string `json:"nonce"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Groups is the "groups" claim; omitted when nil.
	Groups []string `json:"groups,omitempty"`
}

// FakeProvider is a minimal in-process OIDC provider for testing gauntlet's
// oidc.Client against real HTTP + real JWT signing/verification, rather
// than mocking go-oidc's internals -- the whole point of these tests is
// proving the wiring (discovery, PKCE, algorithm allowlisting, nonce
// handling) actually works end to end.
type FakeProvider struct {
	T          *testing.T
	Server     *httptest.Server
	PrivateKey *rsa.PrivateKey
	KeyID      string

	// NextIDToken, if set, is returned verbatim by the token endpoint
	// instead of a freshly-signed one -- lets a test hand the token
	// endpoint an adversarial token (wrong algorithm, tampered, etc).
	NextIDToken string

	// TokenErrorStatus, when non-zero, makes the token endpoint answer
	// with that status and TokenErrorBody as a JSON body instead of a
	// token -- a provider refusing the code exchange (a wrong client
	// secret, an expired code).
	TokenErrorStatus int
	TokenErrorBody   string

	// ExpectCodeVerifier, when non-empty, makes the token endpoint behave
	// like a PKCE-enforcing provider (Authentik, Keycloak): a code
	// exchange whose code_verifier is missing or different is refused
	// with invalid_grant, as RFC 7636 §4.6 says. Set it to the verifier
	// the flow state carries to prove the caller sends that one.
	ExpectCodeVerifier string
}

// NewFakeProvider starts an httptest server serving discovery, JWKS and
// token endpoints, closed automatically via t.Cleanup.
func NewFakeProvider(t *testing.T) *FakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test RSA key: %v", err)
	}
	fp := &FakeProvider{T: t, PrivateKey: key, KeyID: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", fp.serveDiscovery)
	mux.HandleFunc("/jwks", fp.serveJWKS)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented -- tests call Client.AuthCodeURL directly, never follow it", http.StatusNotImplemented)
	})
	mux.HandleFunc("/token", fp.serveToken)
	fp.Server = httptest.NewServer(mux)
	t.Cleanup(fp.Server.Close)
	return fp
}

// Issuer returns the fake provider's own base URL, suitable as
// oidc.Config.IssuerURL.
func (fp *FakeProvider) Issuer() string { return fp.Server.URL }

func (fp *FakeProvider) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                fp.Server.URL,
		"authorization_endpoint":                fp.Server.URL + "/authorize",
		"token_endpoint":                        fp.Server.URL + "/token",
		"jwks_uri":                              fp.Server.URL + "/jwks",
		"userinfo_endpoint":                     fp.Server.URL + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

// jwk is the RFC 7518 §6.3.1 shape for an RSA public key -- the minimum
// go-oidc's JWKS fetch needs to verify an RS256 signature.
type jwk struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (fp *FakeProvider) serveJWKS(w http.ResponseWriter, r *http.Request) {
	pub := fp.PrivateKey.PublicKey
	set := map[string]any{
		"keys": []jwk{{
			Kty: "RSA",
			N:   b64url(pub.N.Bytes()),
			E:   b64url(big.NewInt(int64(pub.E)).Bytes()),
			Kid: fp.KeyID,
			Alg: "RS256",
			Use: "sig",
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (fp *FakeProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	if fp.TokenErrorStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fp.TokenErrorStatus)
		_, _ = w.Write([]byte(fp.TokenErrorBody))
		return
	}
	if fp.ExpectCodeVerifier != "" {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("code_verifier") != fp.ExpectCodeVerifier {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code_verifier missing or does not match"}`))
			return
		}
	}
	idToken := fp.NextIDToken
	if idToken == "" {
		fp.T.Fatal("serveToken called but no ID token was queued -- call fp.SignRS256 (or a sibling) and set fp.NextIDToken first")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"id_token":     idToken,
		"expires_in":   3600,
	})
}

// DefaultClaims returns a claim set that VerifyIDToken accepts outright:
// this provider as issuer, the given client as audience, an hour of
// validity, and a verified email.
func (fp *FakeProvider) DefaultClaims(clientID, nonce string) IDTokenClaims {
	now := time.Now().Unix()
	return IDTokenClaims{
		Issuer:            fp.Issuer(),
		Subject:           "test-subject-123",
		Audience:          clientID,
		Expiry:            now + 3600,
		IssuedAt:          now,
		Nonce:             nonce,
		Email:             "person@example.com",
		EmailVerified:     true,
		PreferredUsername: "person",
	}
}

// jwsSigningInput returns the base64url(header) + "." + base64url(payload)
// prefix common to every compact JWS, regardless of algorithm.
func jwsSigningInput(alg string, claims IDTokenClaims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return b64url(header) + "." + b64url(payload), nil
}

// SignRS256 signs claims with the fake provider's own RSA key -- a
// legitimate token as far as the provider is concerned.
func (fp *FakeProvider) SignRS256(t *testing.T, claims IDTokenClaims) string {
	t.Helper()
	signingInput, err := jwsSigningInput("RS256", claims)
	if err != nil {
		t.Fatalf("building RS256 signing input: %v", err)
	}
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, fp.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("signing RS256 token: %v", err)
	}
	return signingInput + "." + b64url(sig)
}

// SignHS256WithPublicKeyBytes crafts the classic algorithm-confusion
// attack: an attacker who only ever saw the provider's *public* RSA key
// (from the public JWKS endpoint -- not a secret) resigns a token using
// HS256, treating a serialization of those same public bytes as an HMAC
// secret. A verifier that blindly used "whatever key type is convenient"
// for whatever alg the token header claims would accept this; one that
// pins an allowed algorithm set up front (see oidc.go's
// SupportedSigningAlgs) rejects it outright, before any HMAC computation
// happens at all.
func (fp *FakeProvider) SignHS256WithPublicKeyBytes(t *testing.T, claims IDTokenClaims) string {
	t.Helper()
	pubDER := x509.MarshalPKCS1PublicKey(&fp.PrivateKey.PublicKey)
	signingInput, err := jwsSigningInput("HS256", claims)
	if err != nil {
		t.Fatalf("building HS256 signing input: %v", err)
	}
	mac := hmac.New(sha256.New, pubDER)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64url(mac.Sum(nil))
}

// SignNoneAlgorithm hand-crafts a header.payload. token with alg=none and
// an empty signature segment -- not a real signing algorithm, it's the
// "don't bother checking" footgun the JWT spec allows -- to prove the
// verifier rejects it too.
func (fp *FakeProvider) SignNoneAlgorithm(t *testing.T, claims IDTokenClaims) string {
	t.Helper()
	signingInput, err := jwsSigningInput("none", claims)
	if err != nil {
		t.Fatalf("building none-algorithm signing input: %v", err)
	}
	return signingInput + "."
}
