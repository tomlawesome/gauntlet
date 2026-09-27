// Ported from mikroview's internal/auth/localadmin_test.go. Adapted:
// Open(path) -> openTestStore(t).

package gauntlet

import (
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

	admin, err := s.Register("alice", "password123", time.Now())
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

// An SSO-provisioned first account is an admin with no password, which
// is exactly the state #1252 exists to keep a deployment out of -- and,
// since linking no longer costs the admin its password, the only way
// left to reach it.
func TestHasLocalAdminIsFalseForAnSSOProvisionedAdmin(t *testing.T) {
	s := openTestStore(t)

	u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-1", "carol", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if u.Role != RoleAdmin {
		t.Fatalf("Role = %q, want admin -- this test is not set up as it thinks", u.Role)
	}
	if s.HasLocalAdmin() {
		t.Error("an SSO-provisioned admin counts as a local way in")
	}
}
