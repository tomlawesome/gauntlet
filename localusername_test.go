// Ported from mikroview's internal/auth/localusername_test.go. Adapted:
// Open(path) -> openTestStore(t); the raw-fixture test primes a
// persist.Memory backend directly instead of writing a temp file.

package gauntlet

import (
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// mikroview #1252: "REJECT using an email as a username for local
// accounts... we never have an email clash and we can ditch all that
// checking". The rule earns its keep by making a clash impossible rather
// than checkable -- an SSO-provisioned account is named by the
// provider's claim, which is an email; a local one never is; so nothing
// ever has to compare two addresses to decide whether a returning
// identity is an existing local person. It is also how this package
// goes on storing no email address anywhere.
func TestLocalCreationRefusesAnEmailShapedUsername(t *testing.T) {
	s := openTestStore(t)

	if _, err := s.Register("tom@example.com", "password123", time.Now()); err != ErrUsernameIsEmail {
		t.Fatalf("Register(email) = %v, want ErrUsernameIsEmail", err)
	}
	if s.Count() != 0 {
		t.Fatal("the refused registration created an account anyway")
	}

	// Half an address is refused too: the point is a namespace that
	// cannot overlap with what providers send, not a validator of
	// well-formed addresses.
	if _, err := s.Register("tom@", "password123", time.Now()); err != ErrUsernameIsEmail {
		t.Errorf("Register(\"tom@\") = %v, want ErrUsernameIsEmail", err)
	}

	admin, err := s.Register("tom", "password123", time.Now())
	if err != nil {
		t.Fatalf("Register(plain name) = %v, want a created account", err)
	}
	if admin.Username != "tom" {
		t.Errorf("Username = %q, want %q", admin.Username, "tom")
	}

	// The admin creating somebody else goes through the same funnel
	// (createLocked), so the rule cannot be walked around from the
	// people list.
	if _, err := s.CreateUser("bob@example.com", "password456", RoleUser, time.Now()); err != ErrUsernameIsEmail {
		t.Errorf("CreateUser(email) = %v, want ErrUsernameIsEmail", err)
	}
	if _, err := s.CreateUser("bob", "password456", RoleUser, time.Now()); err != nil {
		t.Errorf("CreateUser(plain name) = %v, want a created account", err)
	}
}

// The other side of the same rule: an account the identity provider
// vouches for keeps the name the provider sent, email or not. That is
// what makes the two namespaces disjoint, so sanitiseUsernameHint must
// go on running ValidateUsername rather than ValidateLocalUsername.
func TestSSOProvisioningKeepsAnEmailClaimAsTheUsername(t *testing.T) {
	s := openTestStoreWithAdmin(t)

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-1", "tom@example.com", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if !created {
		t.Fatal("no account was provisioned")
	}
	if u.Username != "tom@example.com" {
		t.Errorf("Username = %q, want the provider's claim -- the email ban must not reach this path", u.Username)
	}
}

// Validation runs at creation, never at sign-in. A deployment that
// already has a local account named as an email predates this rule and
// cannot be made to comply by its owner, so refusing it at the door
// would lock out somebody who did nothing wrong.
func TestAnExistingEmailNamedLocalAccountStillSignsIn(t *testing.T) {
	hash, err := HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}

	m := persist.NewMemory()
	data := `{"users":[{"id":"u1","username":"tom@example.com","passwordHash":"` + hash +
		`","role":"admin","createdAt":"2026-01-01T00:00:00Z","hasLocalPassword":true}]}`
	primeMemory(t, m, data)

	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}

	u, err := s.Authenticate("tom@example.com", "password123", time.Now())
	if err != nil {
		t.Fatalf("Authenticate: %v -- an account created before the rule was locked out by it", err)
	}
	if u.Username != "tom@example.com" {
		t.Errorf("Username = %q, want the stored name untouched", u.Username)
	}
}
