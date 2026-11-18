// The QR pattern in the POST /api/auth/totp/enrol reply (#120): the
// field `qr`, the failure that leaves nothing stored, and the paths that
// never reach the encoder.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// newQRTestGate is newTestGate with its own Config.ProductName, over a
// store that already holds one account, username, so a test can sign in
// without the enrolment door being open to it first. The first account
// a store holds is the admin; a TOTP factor is not yet enrolled on it.
func newQRTestGate(t *testing.T, productName, username, password string) (*Gate, *httptest.Server) {
	t.Helper()
	users := openTrackedStore(t, persist.NewMemory())
	if _, err := users.Register(username, password, time.Now()); err != nil {
		t.Fatalf("registering %q: %v", username, err)
	}
	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(Config{
		CookieName:      testCookieName,
		CSRFHeaderValue: testCSRFValue,
		ClientIP:        func(r *http.Request) string { return "198.51.100.1" },
		ProductName:     productName,
		LoginPath:       testLoginPath,
		AdminPasskey:    AdminPasskeyOptional,
	}, Deps{
		Users:    users,
		Sessions: gauntlet.NewSessionStore(gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime),
		Tokens:   tokens,
		Limiter:  mustNewLoginLimiter(t, 5, 5*time.Minute),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g, newTestServer(t, g)
}

// TestTOTPEnrolReplyCarriesTheQRPattern: the reply holds `qr` as a JSON
// array of strings (the wire shape, read raw), it is the pattern of
// `uri` -- the same matrix gauntlet.TOTPEnrollmentQR gives for it -- and
// it has the shape the contract promises. That the matrix decodes to the
// URI is proved in the root package (TestTOTPEnrollmentQRReadsBackAsTheURI).
func TestTOTPEnrolReplyCarriesTheQRPattern(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: totpBobPassword})
	status, raw := readAll(t, resp)
	if status != http.StatusOK {
		t.Fatalf("enrol returned %d: %s", status, raw)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"uri", "secret", "qr"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("reply has no %q field: %s", name, raw)
		}
	}
	var wire []string
	if err := json.Unmarshal(fields["qr"], &wire); err != nil {
		t.Fatalf("qr is not a JSON array of strings: %v (%s)", err, fields["qr"])
	}

	var enrolled totpEnrolResponse
	if err := json.Unmarshal([]byte(raw), &enrolled); err != nil {
		t.Fatal(err)
	}
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if want := gauntlet.TOTPEnrollmentURI(testProductName, totpBobUsername, secret); enrolled.URI != want {
		t.Errorf("uri = %q, want %q", enrolled.URI, want)
	}
	if !slices.Equal(enrolled.QR, wire) {
		t.Error("the typed qr and the wire qr differ")
	}
	want, err := gauntlet.TOTPEnrollmentQR(enrolled.URI)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(enrolled.QR, want) {
		t.Error("qr is not the pattern of uri")
	}

	n := len(enrolled.QR)
	if n < 21 || n > 177 || (n-17)%4 != 0 {
		t.Fatalf("qr side = %d, want 21 to 177 with (side-17) divisible by 4", n)
	}
	for r, row := range enrolled.QR {
		if len(row) != n || strings.Trim(row, "01") != "" {
			t.Errorf("qr row %d = %q, want %d characters of 0 and 1", r, row, n)
		}
	}
	if enrolled.QR[n-8][8] != '1' {
		t.Error("qr has a light dark-module position: the matrix is transposed or wrong")
	}
}

// A product name no QR code can hold is a misconfigured deployment: the
// enrolment is refused with 500 server-error, and because the pattern is
// made before the secret is stored, no pending secret is left behind.
func TestTOTPEnrolRefusedWhenTheURIIsTooLongForAQRCode(t *testing.T) {
	g, ts := newQRTestGate(t, strings.Repeat("P", 3000), "bob", totpBobPassword)
	bob := loggedInClient(t, ts, "bob", totpBobPassword)

	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: totpBobPassword})
	status, raw := readAll(t, resp)
	if status != http.StatusInternalServerError {
		t.Fatalf("enrol with a 3000-byte product name returned %d, want 500: %s", status, raw)
	}
	if p := decodeProblem(t, []byte(raw)); p.Type != problemTypeBase+"server-error" {
		t.Errorf("problem type = %q, want the server-error class", p.Type)
	}
	if strings.Contains(raw, "qr") || strings.Contains(raw, "otpauth") {
		t.Errorf("the refusal leaks enrolment material: %s", raw)
	}
	u, ok := g.deps.Users.ByUsername("bob")
	if !ok {
		t.Fatal("bob is gone")
	}
	if u.TOTPSecret != "" {
		t.Error("a refused enrolment left a pending TOTP secret on the account")
	}
}

// The longest username the form allows, 64 runes of 4 bytes each, still
// enrols: its escaped form is long but well inside what one code holds.
func TestTOTPEnrolSucceedsForALongNonASCIIUsername(t *testing.T) {
	username := strings.Repeat("\U00020000", 64)
	g, ts := newQRTestGate(t, testProductName, username, totpBobPassword)
	client := loggedInClient(t, ts, username, totpBobPassword)

	resp := postJSON(t, client, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: totpBobPassword})
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrol for a 64-rune 4-byte username returned %d: %s", resp.StatusCode, body)
	}
	var enrolled totpEnrolResponse
	if err := json.Unmarshal(body, &enrolled); err != nil {
		t.Fatal(err)
	}
	if len(enrolled.QR) < 21 {
		t.Errorf("qr has %d rows, want a full symbol", len(enrolled.QR))
	}
	if u, ok := g.deps.Users.ByUsername(username); !ok || u.TOTPSecret != enrolled.Secret {
		t.Error("the pending secret was not stored for the account")
	}
}

// The refusals that come before the encoder are unchanged, and none of
// them answers a `qr`: 400 for a body that is not JSON, 401 for a wrong
// or missing password, 409 while an app is already active.
func TestTOTPEnrolRefusalsCarryNoQRPattern(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	for name, tc := range map[string]struct {
		body any
		want int
	}{
		"not JSON":       {body: "not json", want: http.StatusBadRequest},
		"wrong password": {body: totpEnrolRequest{Password: "not-bobs-password"}, want: http.StatusUnauthorized},
		"no password":    {body: totpEnrolRequest{}, want: http.StatusUnauthorized},
	} {
		status, raw := readAll(t, postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", tc.body))
		if status != tc.want {
			t.Errorf("%s: enrol got %d, want %d: %s", name, status, tc.want, raw)
		}
		if strings.Contains(raw, `"qr"`) {
			t.Errorf("%s: the refusal carries a qr field: %s", name, raw)
		}
	}
	if u, ok := g.deps.Users.Get(totpBobID(t, g)); !ok || u.TOTPSecret != "" {
		t.Fatal("a refused enrolment left a pending secret on the account")
	}

	totpEnrolAndConfirm(t, bob, ts)
	status, raw := readAll(t, postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: totpBobPassword}))
	if status != http.StatusConflict || strings.Contains(raw, `"qr"`) {
		t.Errorf("enrolling while active got %d %s, want 409 with no qr", status, raw)
	}
}
