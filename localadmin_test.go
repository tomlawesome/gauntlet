// Ported from mikroview's internal/auth/localadmin_test.go. Adapted:
// Open(path) -> openTestStore(t).

package gauntlet

import (
	"errors"
	"testing"
	"time"
)

// HasLocalAdmin is "SSO is additive; keep a local admin" (mikroview
// #1252) as a predicate. It has to answer from HasLocalPassword rather
// than from the stored hash, which is deliberately indistinguishable
// between a real password and the unmatchable filler an SSO account
// carries.
func TestHasLocalAdminFollowsTheAdminsPassword(t *testing.T) {
	s := openTestStore(t)

	if s.HasLocalAdmin() {
		t.Error("an empty store claims a local admin")
	}

	admin, err := s.Register("alice", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !s.HasLocalAdmin() {
		t.Fatal("a freshly registered admin is not counted as the local way in")
	}

	// A second account with a password is not the break-glass account:
	// this package holds one admin, and a user cannot reach the
	// admin-gated screens an operator needs to get back in.
	if _, err := s.CreateUser("bob", "password456", RoleUser, time.Now()); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Linking used to end it. Under #1252's ruling the admin keeps its
	// password, so connecting SSO adds a way in rather than swapping
	// one -- and the deployment still has a way in that the identity
	// provider cannot take away.
	if err := s.LinkOIDCIdentity(admin.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}
	if !s.HasLocalAdmin() {
		t.Error("linking the admin removed the local way in that #1252 exists to keep")
	}
}

// An SSO-provisioned account holding the admin role is an admin with no
// password, which is exactly the state #1252 exists to keep a deployment
// out of. SSO never creates the first account (#37), linking no longer
// costs the admin its password, and transferring the role to an
// SSO-provisioned user is refused while it would leave no admin with a
// password (ErrLastLocalAdmin): the store keeps a local way in.
func TestHasLocalAdminIsFalseForAnSSOProvisionedAdmin(t *testing.T) {
	s := openTestStoreWithAdmin(t)

	if _, _, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-1", "carol", time.Now()); err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if _, _, err := s.TransferAdmin("carol", time.Now()); !errors.Is(err, ErrLastLocalAdmin) {
		t.Fatalf("TransferAdmin to an SSO-provisioned account = %v, want ErrLastLocalAdmin", err)
	}
	u, _ := s.ByUsername("carol")
	if u == nil || u.Role == RoleAdmin {
		t.Fatalf("carol = %+v, want not an admin", u)
	}
	if !s.HasLocalAdmin() {
		t.Error("the refused transfer should have left the local way in")
	}
}
