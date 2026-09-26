package oidc

import (
	"errors"
	"fmt"
	"net/url"
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
// The issuer URL is already the primary access control -- this package
// only supports self-hosted issuers (see AllowIssuer), so configuring
// one restricts login to accounts in a directory the operator runs, and
// an empty Policy is the correct and complete answer for most
// deployments.
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
	// its groups claim. Sugar over RequiredClaims[GroupsClaim] -- see
	// Permit.
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
	// RequiredClaims is the general mechanism the two email fields and
	// AllowedGroups are conveniences over: claim name -> permitted
	// values, where the identity must carry at least one permitted value
	// for every named claim. Nothing here is provider-specific, which is
	// the point -- Google Workspace's hosted-domain claim is
	// {"hd": ["example.com"]}, a single Entra tenant is
	// {"tid": ["<tenant-guid>"]}, and a provider inventing its own claim
	// tomorrow needs no code change.
	RequiredClaims map[string][]string
}

// Restricted reports whether this policy narrows anything at all. Used at
// startup to refuse a combination that can't be safe -- see
// IsMultiTenantIssuer.
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
		claim := p.GroupsClaim
		if claim == "" {
			claim = defaultGroupsClaim
		}
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
// no restriction at all. Configuring one of these without a Policy is
// refused at startup rather than warned about, because the resulting
// deployment lets any account at that provider register itself as this
// deployment's first user, i.e. as an admin.
//
// This list is a safety net over a general mechanism, not the mechanism
// itself: Policy is provider-agnostic, and an unlisted public provider
// is still fully restrictable. Being absent from this list means the
// startup check won't catch that mistake for you, not that the tools are
// missing.
var multiTenantIssuers = map[string][]string{
	// host: multi-tenant path prefixes, or nil meaning "the whole host"
	"accounts.google.com":       nil,
	"appleid.apple.com":         nil,
	"login.live.com":            nil,
	"login.microsoftonline.com": {"/common", "/organizations", "/consumers"},
}

// ErrMultiTenantIssuer is returned by AllowIssuer for a provider whose
// user population is the general public. Callers should treat it the
// same as any other "SSO unavailable" startup condition: log it and
// leave SSO off, never downgrade it to a warning and continue.
var ErrMultiTenantIssuer = errors.New("oidc: multi-tenant issuers are not supported")

// AllowIssuer reports whether SSO may be enabled against issuer.
//
// Multi-tenant providers are refused unconditionally -- deliberately
// *not* rescuable by configuring a Policy, even though a correctly
// configured one would in fact restrict access safely. This package is
// built for self-hosters running their own IdP, where the issuer URL is
// already the access control; supporting public providers means the
// safety of every deployment rests on an operator getting an extra claim
// restriction exactly right, and a misconfiguration there hands admin to
// the first stranger who reaches the login page. The narrower promise is
// the one worth keeping.
//
// This is mikroview's docs/decisions/multi-tenant-oidc.md decision,
// carried over unchanged and deliberately not made configurable (see
// docs/design.md §1.4, docs/adr/0001-shared-auth-module.md) -- see that
// document for the full reasoning and the exact change that would
// reverse it, if that trade is ever revisited.
func AllowIssuer(issuer string) error {
	if IsMultiTenantIssuer(issuer) {
		return fmt.Errorf("%w: %s", ErrMultiTenantIssuer, issuer)
	}
	return nil
}

// IsMultiTenantIssuer reports whether issuer is a known provider whose
// user population is the general public rather than one organisation.
//
// Entra ID is the reason this isn't just a host check: the same host
// serves both a single tenant (.../<tenant-guid>/v2.0, which genuinely
// does scope logins to one organisation) and the shared endpoints, which
// don't.
func IsMultiTenantIssuer(issuer string) bool {
	issuer = strings.TrimSpace(issuer)
	u, err := url.Parse(issuer)
	if err != nil {
		return false
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
			return false
		}
	}
	prefixes, known := multiTenantIssuers[strings.ToLower(u.Hostname())]
	if !known {
		return false
	}
	if prefixes == nil {
		return true
	}
	path := strings.ToLower(strings.TrimSuffix(u.Path, "/"))
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}
