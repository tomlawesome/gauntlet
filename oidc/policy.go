package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// defaultGroupsClaim is what most providers name the claim, but it is
// genuinely not standardised -- Authentik and Keycloak use "groups",
// Okta is commonly configured that way too, Azure emits "roles" or
// "wids". Policy.GroupsClaim overrides it.
const defaultGroupsClaim = "groups"

// Policy decides whether a verified identity is allowed to use this
// deployment at all -- a separate question from whether the ID token is
// authentic, which the verifier has already settled by the time this
// runs.
//
// For a self-hosted issuer the issuer URL is already the primary access
// control: configuring one restricts login to accounts in a directory
// the operator runs, and an empty Policy is the correct and complete
// answer for most deployments. A shared public issuer is accepted only
// when RequiredClaims pins the tenant (see AllowIssuerWithPolicy).
//
// This exists for scoping *within* that directory: an Authentik that
// also serves other household members, other tenants or other
// applications vouches for accounts that have no business reaching this
// one. allowedGroups is the common case.
//
// A zero Policy permits everyone the issuer vouches for. Each field that
// is set adds a condition, and all set conditions must hold.
type Policy struct {
	// AllowedGroups permits an identity carrying at least one of these in
	// its groups claim (GroupsClaim). Permit checks it on its own, with
	// its own refusal messages; it is not folded into RequiredClaims, so
	// setting both on the same claim means both must hold.
	AllowedGroups []string
	// GroupsClaim is where to read groups from; defaults to "groups".
	GroupsClaim string
	// AllowedEmails is an exact-address allowlist, compared
	// case-insensitively.
	AllowedEmails []string
	// AllowedEmailDomains permits an identity whose email is at one of
	// these domains -- the usual way to scope a Google Workspace or
	// Microsoft 365 tenant down to one organisation.
	AllowedEmailDomains []string
	// RequiredClaims is the general mechanism for any other claim: claim
	// name -> permitted values, where the identity must carry at least
	// one permitted value for every named claim. Permit checks it after,
	// and separately from, AllowedGroups and the two email fields. Nothing here is provider-specific, which is
	// the point -- Google Workspace's hosted-domain claim is
	// {"hd": ["example.com"]}, a single Entra tenant is
	// {"tid": ["<tenant-guid>"]}, and a provider inventing its own claim
	// tomorrow needs no code change.
	RequiredClaims map[string][]string
	// RoleFromGroups gives an SSO account a role from the groups claim
	// (GroupsClaim): group name -> "user" or "viewer", matched like
	// AllowedGroups (trimmed, case-insensitive). An identity in several
	// mapped groups gets the highest role. It is applied when the account
	// is provisioned and at every SSO sign-in, so the identity provider
	// stays the source of truth (ADR-0013).
	//
	// "admin" is never a value, and gate.New refuses one: admin comes
	// only through the admin role route, so a misconfigured or hostile
	// provider cannot mint admins. An account that is already an admin is
	// never changed by this map. The map narrows roles, not access: it
	// does not count in Restricted, and who may sign in at all stays with
	// AllowedGroups.
	RoleFromGroups map[string]string
	// RoleWithoutGroup is the role for an SSO account in none of the
	// groups RoleFromGroups names, including one with no groups claim at
	// all. "" means "viewer"; gate.New accepts "user" or "viewer". Only
	// read when RoleFromGroups is set.
	RoleWithoutGroup string
}

// Restricted reports whether this policy narrows anything at all.
//
// Deprecated: nothing calls it, and "narrows anything" is not the test
// for a shared issuer -- a group allowlist does not stop strangers at
// that provider. Use AllowIssuerWithPolicy, which asks for the tenant
// claim instead.
func (p Policy) Restricted() bool {
	return len(p.AllowedGroups) > 0 ||
		len(p.AllowedEmails) > 0 ||
		len(p.AllowedEmailDomains) > 0 ||
		len(p.RequiredClaims) > 0
}

// ErrNotPermitted is what Permit returns for an authentic identity that
// this deployment doesn't accept. Callers should surface it to the user
// as a plain refusal, without echoing back which condition failed --
// that detail tells an outsider how the allowlist is shaped.
type ErrNotPermitted struct{ Reason string }

func (e *ErrNotPermitted) Error() string { return "oidc: access not permitted: " + e.Reason }

// Permit reports whether id may sign in.
//
// Every check fails closed: a missing, empty, or unreadable claim is a
// refusal, never a pass. That direction is the entire value of the
// feature -- a group allowlist that admits everyone when the provider
// forgets to release the groups claim is not an allowlist, and the
// failure would be silent and permanent rather than visible.
func (p Policy) Permit(id *Identity) error {
	if id == nil {
		return &ErrNotPermitted{Reason: "no identity"}
	}

	if len(p.AllowedGroups) > 0 {
		claim := p.groupsClaim()
		got := id.claimValues(claim)
		if len(got) == 0 {
			return &ErrNotPermitted{Reason: fmt.Sprintf(
				"the %q claim is absent from the id_token -- the provider must be configured to release it", claim)}
		}
		if !intersects(got, p.AllowedGroups) {
			return &ErrNotPermitted{Reason: "not a member of any permitted group"}
		}
	}

	if len(p.AllowedEmails) > 0 || len(p.AllowedEmailDomains) > 0 {
		if err := p.permitEmail(id); err != nil {
			return err
		}
	}

	for claim, allowed := range p.RequiredClaims {
		got := id.claimValues(claim)
		if len(got) == 0 {
			return &ErrNotPermitted{Reason: fmt.Sprintf("the required claim %q is absent from the id_token", claim)}
		}
		if !intersects(got, allowed) {
			return &ErrNotPermitted{Reason: fmt.Sprintf("the %q claim carries no permitted value", claim)}
		}
	}

	return nil
}

// Groups returns the values id carries in the groups claim (GroupsClaim,
// default "groups") -- the same ones Permit reads for AllowedGroups --
// whether the provider sent a single string or a list. Empty when the
// claim is absent.
func (p Policy) Groups(id *Identity) []string {
	if id == nil {
		return nil
	}
	return id.claimValues(p.groupsClaim())
}

func (p Policy) groupsClaim() string {
	if p.GroupsClaim == "" {
		return defaultGroupsClaim
	}
	return p.GroupsClaim
}

// ValidateRoles checks every RoleFromGroups value, and a non-empty
// RoleWithoutGroup, against valid, so the caller decides which roles may
// come from a group. It names the first offender, in sorted order so the
// message is stable. "admin" is never acceptable: an identity provider
// does not mint admins (ADR-0013 decision 1), and gate passes a check
// that accepts only "user" and "viewer".
func (p Policy) ValidateRoles(valid func(role string) bool) error {
	groups := make([]string, 0, len(p.RoleFromGroups))
	for g := range p.RoleFromGroups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		if role := p.RoleFromGroups[g]; !valid(role) {
			return fmt.Errorf("oidc: RoleFromGroups maps group %q to role %q, which a group may not give", g, role)
		}
	}
	if p.RoleWithoutGroup != "" && !valid(p.RoleWithoutGroup) {
		return fmt.Errorf("oidc: RoleWithoutGroup %q is not a role a group may give", p.RoleWithoutGroup)
	}
	return nil
}

func (p Policy) permitEmail(id *Identity) error {
	// Without email_verified, an address restriction is decorative: any
	// provider that lets a user type their own unverified email lets them
	// type one inside the allowlist.
	if id.Email == "" {
		return &ErrNotPermitted{Reason: "no email claim in the id_token, but this deployment restricts by email"}
	}
	if !id.EmailVerified {
		return &ErrNotPermitted{Reason: "the email address in the id_token is not marked verified by the provider"}
	}

	email := strings.ToLower(strings.TrimSpace(id.Email))
	for _, allowed := range p.AllowedEmails {
		if email == strings.ToLower(strings.TrimSpace(allowed)) {
			return nil
		}
	}

	// The domain must be compared as a whole label, not as a string
	// suffix: "user@notexample.com" ends with "example.com", and a
	// HasSuffix check here would hand an attacker the entire allowlist by
	// registering one adjacent domain.
	at := strings.LastIndexByte(email, '@')
	if at >= 0 {
		domain := email[at+1:]
		for _, allowed := range p.AllowedEmailDomains {
			if domain == strings.ToLower(strings.TrimSpace(strings.TrimPrefix(allowed, "@"))) {
				return nil
			}
		}
	}

	return &ErrNotPermitted{Reason: "email address is not on the permitted list"}
}

func intersects(got, allowed []string) bool {
	for _, g := range got {
		for _, a := range allowed {
			if strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(a)) {
				return true
			}
		}
	}
	return false
}

// multiTenantIssuers are providers where a validating ID token proves
// only "this is a real account somewhere at this provider" -- which is
// no restriction at all. Each maps to its multi-tenant path prefixes
// (nil meaning "the whole host") and the claim that names the tenant an
// account belongs to ("" where the provider has none).
//
// This list is a safety net over a general mechanism, not the mechanism
// itself: Policy is provider-agnostic, and an unlisted public provider
// is still fully restrictable. Being absent from this list means the
// startup check won't catch that mistake for you, not that the tools are
// missing.
var multiTenantIssuers = map[string]struct {
	prefixes    []string
	tenantClaim string
}{
	"accounts.google.com":       {nil, "hd"},
	"appleid.apple.com":         {nil, ""},
	"login.live.com":            {nil, ""},
	"login.microsoftonline.com": {[]string{"/common", "/organizations", "/consumers"}, "tid"},
}

// ErrMultiTenantIssuer is returned by AllowIssuerWithPolicy for a
// provider whose user population is the general public and a Policy that
// does not pin the tenant. Callers should treat it the same as any other
// "SSO unavailable" startup condition: log it and leave SSO off, never
// downgrade it to a warning and continue.
var ErrMultiTenantIssuer = errors.New("oidc: multi-tenant issuers are not supported")

// AllowIssuerWithPolicy reports whether SSO may be enabled against issuer
// with p as the sign-in policy (docs/adr/0014-shared-issuers.md).
//
// A self-hosted issuer always passes. A shared one passes only when
// p.RequiredClaims names its tenant claim with at least one value --
// "hd" for accounts.google.com, "tid" for Entra's common, organizations
// and consumers endpoints -- because without it any account at that
// provider could sign itself in here. Apple and Microsoft personal
// accounts carry no tenant claim, so they are always refused. The check
// is at startup so a missing pin is a refusal to start, never a silently
// open door; Permit then refuses each token whose claim is absent or
// carries another tenant.
func AllowIssuerWithPolicy(issuer string, p Policy) error {
	host, shared := multiTenantHost(issuer)
	if !shared {
		return nil
	}
	claim := multiTenantIssuers[host].tenantClaim
	if claim == "" {
		return fmt.Errorf("%w: %s has no tenant claim a Policy could pin", ErrMultiTenantIssuer, issuer)
	}
	for _, v := range p.RequiredClaims[claim] {
		if strings.TrimSpace(v) != "" {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is shared by every account at that provider; Policy.RequiredClaims must name %q with the tenant to admit",
		ErrMultiTenantIssuer, issuer, claim)
}

// AllowIssuer reports whether SSO may be enabled against issuer with an
// empty Policy, so it refuses every shared issuer.
//
// Deprecated: use AllowIssuerWithPolicy with the Policy the deployment
// enforces; a shared issuer is accepted once that Policy pins the tenant.
func AllowIssuer(issuer string) error {
	return AllowIssuerWithPolicy(issuer, Policy{})
}

// IsMultiTenantIssuer reports whether issuer is a known provider whose
// user population is the general public rather than one organisation.
//
// Entra ID is the reason this isn't just a host check: the same host
// serves both a single tenant (.../<tenant-guid>/v2.0, which genuinely
// does scope logins to one organisation) and the shared endpoints, which
// don't.
func IsMultiTenantIssuer(issuer string) bool {
	_, shared := multiTenantHost(issuer)
	return shared
}

// multiTenantHost returns issuer's normalised host and whether issuer is
// one of multiTenantIssuers' shared endpoints.
func multiTenantHost(issuer string) (string, bool) {
	issuer = strings.TrimSpace(issuer)
	u, err := url.Parse(issuer)
	if err != nil {
		return "", false
	}
	// A scheme-less string parses with an empty Hostname and the whole
	// value in Path, so "login.microsoftonline.com/common/v2.0" matched
	// nothing and passed a check meant to refuse it (mikroview #267,
	// Uncertain). Provider discovery would fail on it later regardless,
	// but a security check that answers "no" because it could not read
	// its input is the wrong shape -- it should read the input.
	if u.Hostname() == "" {
		u, err = url.Parse("https://" + issuer)
		if err != nil {
			return "", false
		}
	}
	// "accounts.google.com." is the same host as "accounts.google.com"
	// to DNS and to TLS, but not to a map lookup: without the trim a
	// trailing root dot would slip a listed provider past this check.
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	entry, known := multiTenantIssuers[host]
	if !known {
		return "", false
	}
	if entry.prefixes == nil {
		return host, true
	}
	path := strings.ToLower(strings.TrimSuffix(u.Path, "/"))
	for _, p := range entry.prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return host, true
		}
	}
	return "", false
}
