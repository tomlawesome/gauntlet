package contracttest

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/gate"
	"github.com/tomlawesome/gauntlet/persist"
)

// requireEnrolQR checks the `qr` member of an enrol reply against the
// document's promises (#120): a square of 0 and 1, a side from 21 to 177
// in steps of 4, the fixed patterns of a QR symbol in the places the
// standard puts them (which a transposed or mirrored matrix breaks), the
// format bits saying error-correction level M, and the pattern being the
// one gauntlet.TOTPEnrollmentQR makes for `uri`.
func requireEnrolQR(t *testing.T, enrolled totpEnrolResponse) {
	t.Helper()
	rows := enrolled.QR
	n := len(rows)
	if n < 21 || n > 177 || (n-17)%4 != 0 {
		t.Fatalf("qr side = %d, want 21 to 177 with (side-17) divisible by 4", n)
	}
	for r, row := range rows {
		if len(row) != n || strings.Trim(row, "01") != "" {
			t.Fatalf("qr row %d = %q, want %d characters of 0 and 1", r, row, n)
		}
	}
	finder := []string{"1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"}
	for _, corner := range [][2]int{{0, 0}, {0, n - 7}, {n - 7, 0}} {
		for i, want := range finder {
			if got := rows[corner[0]+i][corner[1] : corner[1]+7]; got != want {
				t.Errorf("finder at (%d,%d), row %d = %s, want %s", corner[0], corner[1], i, got, want)
			}
		}
	}
	for i := 8; i <= n-9; i++ {
		want := byte('0')
		if i%2 == 0 {
			want = '1'
		}
		if rows[6][i] != want || rows[i][6] != want {
			t.Errorf("timing line at %d = %c / %c, want %c", i, rows[6][i], rows[i][6], want)
		}
	}
	if rows[n-8][8] != '1' {
		t.Errorf("the dark module at row %d, column 8 is light: the matrix is transposed", n-8)
	}

	// Format bits: row 8 columns 0-5, 7, 8 then column 8 rows 7, 5..0,
	// most significant first; XOR 101010000010010; level bits 00 is M;
	// the BCH(15,5) remainder checks.
	word := 0
	for _, rc := range [][2]int{{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8},
		{7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8}} {
		word <<= 1
		if rows[rc[0]][rc[1]] == '1' {
			word |= 1
		}
	}
	word ^= 0b101010000010010
	rem := (word >> 10) << 10
	for i := 14; i >= 10; i-- {
		if rem>>i&1 == 1 {
			rem ^= 0x537 << (i - 10)
		}
	}
	if word>>13 != 0 || word&0x3FF != rem&0x3FF {
		t.Errorf("format word %015b is not error-correction level M with a valid BCH check", word)
	}

	want, err := gauntlet.TOTPEnrollmentQR(enrolled.URI)
	if err != nil {
		t.Fatalf("TOTPEnrollmentQR(%q): %v", enrolled.URI, err)
	}
	if !slices.Equal(rows, want) {
		t.Error("qr is not the pattern of uri")
	}
}

// TestTOTPEnrolQRSchema holds the document's `qr` schema to what it
// says: a reply with a proper pattern validates, and a row with any
// character but 0 or 1, a pattern too small to be a QR symbol, or no
// qr member at all does not.
func TestTOTPEnrolQRSchema(t *testing.T) {
	c := newContractChecker(t)
	op := c.doc.Paths.Find("/api/auth/totp/enrol").Post
	ok200 := op.Responses.Status(http.StatusOK)
	if ok200 == nil || ok200.Value == nil {
		t.Fatal("totp/enrol documents no 200")
	}
	media := ok200.Value.Content.Get("application/json")
	if media == nil {
		t.Fatal("totp/enrol's 200 documents no application/json body")
	}
	secret := []byte("12345678901234567890")
	uri := gauntlet.TOTPEnrollmentURI("Gate Test Suite", "bob", secret)
	rows, err := gauntlet.TOTPEnrollmentQR(uri)
	if err != nil {
		t.Fatal(err)
	}
	body := func(qr any) map[string]any {
		m := map[string]any{"uri": uri, "secret": gauntlet.EncodeTOTPSecret(secret)}
		if qr != nil {
			m["qr"] = qr
		}
		return m
	}
	anyRows := func(rs []string) []any {
		out := make([]any, len(rs))
		for i, r := range rs {
			out[i] = r
		}
		return out
	}
	check := func(m map[string]any) error {
		return media.Schema.Value.VisitJSON(m, openapi3.MultiErrors())
	}

	if err := check(body(anyRows(rows))); err != nil {
		t.Errorf("a proper reply does not validate: %v", err)
	}
	if err := check(body(nil)); err == nil {
		t.Error("a reply with no qr member validates, want it required")
	}
	bad := slices.Clone(rows)
	bad[3] = strings.Replace(bad[3], "1", "2", 1)
	if err := check(body(anyRows(bad))); err == nil {
		t.Error("a row holding the character 2 validates, want only 0 and 1")
	}
	if err := check(body(anyRows(rows[:20]))); err == nil {
		t.Error("a pattern of 20 rows validates, want at least 21")
	}
	if err := check(body("not an array")); err == nil {
		t.Error("a qr that is a string validates, want an array")
	}
	extra := body(anyRows(rows))
	extra["svg"] = "<svg/>"
	if err := check(extra); err == nil {
		t.Error("an undocumented member validates, want the body closed")
	}
}

// TestTOTPEnrolWhoseURIIsTooLongForAQRCodeIsAPlainServerError: a
// ProductName of 3,000 bytes cannot fit in a code, so enrolment answers
// 500 (documented, a plain server-error) and the account is left with no
// pending secret.
func TestTOTPEnrolWhoseURIIsTooLongForAQRCodeIsAPlainServerError(t *testing.T) {
	const pass = "contract-admin-password"
	c := newContractChecker(t)
	users, code := openStore(t, persist.NewMemory())
	g := newGateWith(t, gate.Deps{Users: users}, func(cfg *gate.Config) { cfg.ProductName = strings.Repeat("P", 3000) })
	ts := newTestServer(t, g)

	admin := c.client()
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", pass, code}}, 201, nil)
	resp, raw := c.send(admin, ts.URL, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: pass}})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("enrol with a 3000-byte product name returned %d, want 500: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "#server-error") {
		t.Errorf("the 500 body = %s, want a server-error problem", raw)
	}
	u, found := users.ByUsername("admin")
	if !found {
		t.Fatal("admin is gone")
	}
	if u.TOTPSecret != "" {
		t.Error("a refused enrolment left a pending TOTP secret")
	}
}
