// #99, part 2: a country Config.Country returns is recorded on a
// session and a sign-in history row only when it is exactly two ASCII
// letters, upper-cased; anything else is recorded as no country, so the
// "country" key is absent from GET /api/auth/sessions and GET
// /api/auth/sign-ins.
package gate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestContractFix99CountryIsTwoASCIILettersOrNothing(t *testing.T) {
	cases := []struct{ name, lookup, want string }{
		{"upper case", "GB", "GB"},
		{"lower case", "gb", "GB"},
		{"mixed case", "gB", "GB"},
		{"empty", "", ""},
		{"three letters", "GBR", ""},
		{"one letter", "G", ""},
		{"a digit", "G1", ""},
		{"leading space", " GB", ""},
		{"non-ASCII letters", "ÉÉ", ""},
	}
	g, ts, admin, codes := countryFixture(t)
	if len(codes) < len(cases) {
		t.Fatalf("%d recovery codes for %d sign-ins", len(codes), len(cases))
	}
	lookups := map[string]string{}
	for i, tc := range cases {
		lookups[fmt.Sprintf("203.0.113.%d", 70+i)] = tc.lookup
	}
	g.cfg.Country = func(address string) (string, bool) {
		c, ok := lookups[address]
		return c, ok
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address := fmt.Sprintf("203.0.113.%d", 70+i)
			bob := signInBob(t, ts, "Firefox/131.0", address, codes[i])

			// Every row at this address: the password step and the
			// completed sign-in.
			status, out, raw := getSignIns(t, admin, ts, "?address="+address)
			if status != http.StatusOK || len(out.SignIns) == 0 {
				t.Fatalf("GET /api/auth/sign-ins = %d %s, want rows for %s", status, raw, address)
			}
			for _, row := range out.SignIns {
				if row.Country != tc.want {
					t.Errorf("Country lookup %q: sign-in row country = %q, want %q", tc.lookup, row.Country, tc.want)
				}
			}
			if tc.want == "" && strings.Contains(raw, `"country"`) {
				t.Errorf("Country lookup %q: sign-in rows carry a country key: %s", tc.lookup, raw)
			}

			resp, err := bob.Get(ts.URL + "/api/auth/sessions")
			if err != nil {
				t.Fatal(err)
			}
			body := rawBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /api/auth/sessions = %d %s", resp.StatusCode, body)
			}
			var list struct {
				Sessions []map[string]any `json:"sessions"`
			}
			if err := json.Unmarshal([]byte(body), &list); err != nil {
				t.Fatalf("decoding %s: %v", body, err)
			}
			var current map[string]any
			for _, row := range list.Sessions {
				if row["current"] == true {
					current = row
				}
			}
			if current == nil {
				t.Fatalf("no current session in %s", body)
			}
			got, present := current["country"]
			switch {
			case tc.want == "" && present:
				t.Errorf("Country lookup %q: session row carries country %v, want the key absent", tc.lookup, got)
			case tc.want != "" && got != tc.want:
				t.Errorf("Country lookup %q: session row country = %v, want %q", tc.lookup, got, tc.want)
			}
		})
	}
}
