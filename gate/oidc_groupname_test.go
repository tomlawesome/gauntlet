package gate

import (
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
)

// The gate's group-to-role map and oidc.Policy.AllowedGroups compare
// group names by the same rule: trimmed, case-insensitive (#90 item 6).
// One group, spelled three ways -- in AllowedGroups, as a RoleFromGroups
// key and in the token -- must both let the person in and give them the
// mapped role, so a fix to the rule in one place cannot leave the other
// behind.
func TestSSOGroupSpellingAgreesBetweenAllowListAndRoleMap(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{
		AllowedGroups:  []string{" Staff ", "GUESTS"},
		RoleFromGroups: map[string]string{"STAFF  ": "user", "\tguests": "viewer"},
	})

	f.signIn(t, "staff-lower", []string{"staff"})
	f.signIn(t, "staff-padded", []string{"  sTaFf\t"})
	f.signIn(t, "guest-mixed", []string{"Guests"})
	f.signIn(t, "guest-padded", []string{" guests "})
	f.signIn(t, "both", []string{"GUESTS", " staff"})

	for subject, want := range map[string]gauntlet.Role{
		"staff-lower":  gauntlet.RoleUser,
		"staff-padded": gauntlet.RoleUser,
		"guest-mixed":  gauntlet.RoleViewer,
		"guest-padded": gauntlet.RoleViewer,
		"both":         gauntlet.RoleUser,
	} {
		if got := f.role(t, subject); got != want {
			t.Errorf("%s: role = %q, want %q", subject, got, want)
		}
	}
}

// The other side of the same rule: a name that is only a prefix of an
// allowed group is neither let in nor given the role.
func TestSSOGroupNearMissIsRefusedByBothAllowListAndRoleMap(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{
		AllowedGroups:  []string{" Staff "},
		RoleFromGroups: map[string]string{"STAFF": "user"},
	})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := f.fp.DefaultClaims(oidcTestClientID, fs.Nonce)
	claims.Subject, claims.PreferredUsername, claims.Email, claims.Groups = "near", "near", "near@example.com", []string{"staf", "stafff"}
	f.fp.NextIDToken = f.fp.SignRS256(t, claims)

	resp, err := noRedirectClient().Do(oidcCallbackRequest(t, f.g, f.ts, fs, "state="+fs.State+"&code=test-code"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc == "/" {
		t.Errorf("a near-miss group spelling was let in (redirected to %q)", loc)
	}
	if _, ok := f.g.deps.Users.ByOIDCIdentity(f.fp.Issuer(), "near"); ok {
		t.Error("an account was created for a near-miss group spelling")
	}
}
