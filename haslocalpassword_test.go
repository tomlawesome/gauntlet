// Ported from mikroview's internal/auth/haslocalpassword_test.go.
// Adapted: Open(path) -> openTestStore(t).

package gauntlet

import (
	"testing"
	"time"
)

func TestNewAccountsRecordTheFieldExplicitly(t *testing.T) {
	// A real path: Register refuses on an unpersisted store, since an
	// account that can't survive a restart is a trap rather than a
	// convenience.
	s := openTestStore(t)
	local, err := s.Register("admin", "correct-horse-battery-staple", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !local.HasLocalPassword {
		t.Error("Register recorded no local password for a password-created account")
	}

	sso, _, err := s.FindOrCreateOIDCUser("https://idp.example.com", "abc123", "ssouser", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sso.HasLocalPassword {
		t.Error("an SSO-provisioned account claims a local password -- its hash is random and unmatchable")
	}
}
