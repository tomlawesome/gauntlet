package oidc

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func identity(claims map[string]any) *Identity {
	id := &Identity{Issuer: "https://idp.example.com", Subject: "abc123", Claims: claims}
	if v, ok := claims["email"].(string); ok {
		id.Email = v
	}
	if v, ok := claims["email_verified"].(bool); ok {
		id.EmailVerified = v
	}
	return id
}

func TestZeroPolicyPermitsAnyoneTheIssuerVouchesFor(t *testing.T) {
	// The self-hosted-IdP case: the issuer URL is already the allowlist,
	// and delegating the rest to the IdP's own ACLs is the point of SSO.
	// This must stay frictionless or the restriction machinery has made
	// the common configuration worse.
	var p Policy
	if err := p.Permit(identity(map[string]any{"email": "someone@example.com"})); err != nil {
		t.Fatalf("zero Policy refused a login: %v", err)
	}
	if p.Restricted() {
		t.Error("zero Policy reports itself as restricted")
	}
}

func TestPolicyGroups(t *testing.T) {
	p := Policy{AllowedGroups: []string{"gauntlet-admins", "netops"}}

	if err := p.Permit(identity(map[string]any{"groups": []any{"staff", "netops"}})); err != nil {
		t.Errorf("member of a permitted group was refused: %v", err)
	}
	if err := p.Permit(identity(map[string]any{"groups": []any{"staff"}})); err == nil {
		t.Error("non-member was permitted")
	}

	// A provider that emits a single group as a bare string, not a list.
	if err := p.Permit(identity(map[string]any{"groups": "netops"})); err != nil {
		t.Errorf("single-string groups claim was refused: %v", err)
	}
}

// TestPolicyGroupsFailClosedWhenTheClaimIsMissing is the whole point of
// the feature. A provider that hasn't been configured to release the
// groups claim is the single most likely misconfiguration here, and the
// tempting implementation -- "no groups, no restriction to apply, allow"
// -- turns the allowlist off silently and permanently.
func TestPolicyGroupsFailClosedWhenTheClaimIsMissing(t *testing.T) {
	p := Policy{AllowedGroups: []string{"gauntlet-admins"}}

	for name, claims := range map[string]map[string]any{
		"claim absent":       {"email": "someone@example.com"},
		"claim empty list":   {"groups": []any{}},
		"claim empty string": {"groups": ""},
		"claim wrong type":   {"groups": 42},
		"claim null":         {"groups": nil},
	} {
		t.Run(name, func(t *testing.T) {
			if err := p.Permit(identity(claims)); err == nil {
				t.Error("permitted a login with no readable groups claim")
			}
		})
	}
}

// TestPolicyEmailDomainIsNotASuffixMatch pins the classic bug in this
// shape of check. With strings.HasSuffix, registering one adjacent
// domain name hands an attacker the entire allowlist.
func TestPolicyEmailDomainIsNotASuffixMatch(t *testing.T) {
	p := Policy{AllowedEmailDomains: []string{"example.com"}}

	for _, addr := range []string{
		"attacker@notexample.com",
		"attacker@evil-example.com",
		"attacker@example.com.evil.net",
		"attacker@wwwexample.com",
	} {
		err := p.Permit(identity(map[string]any{"email": addr, "email_verified": true}))
		if err == nil {
			t.Errorf("%s was permitted against an example.com allowlist", addr)
		}
	}

	if err := p.Permit(identity(map[string]any{"email": "real@example.com", "email_verified": true})); err != nil {
		t.Errorf("a genuine example.com address was refused: %v", err)
	}
	// Subdomains are a different organisation unit as far as this is
	// concerned; listing them explicitly is the operator's call.
	if err := p.Permit(identity(map[string]any{"email": "real@mail.example.com", "email_verified": true})); err == nil {
		t.Error("a subdomain was permitted without being listed")
	}
}

// TestPolicyEmailRequiresVerification: at a provider that lets a user set
// their own unverified address, an email allowlist without this check is
// decorative -- anyone types an address inside it and walks in.
func TestPolicyEmailRequiresVerification(t *testing.T) {
	for _, p := range []Policy{
		{AllowedEmailDomains: []string{"example.com"}},
		{AllowedEmails: []string{"real@example.com"}},
	} {
		err := p.Permit(identity(map[string]any{"email": "real@example.com", "email_verified": false}))
		if err == nil {
			t.Errorf("%+v permitted an unverified address", p)
		}
		if err := p.Permit(identity(map[string]any{"email_verified": true})); err == nil {
			t.Errorf("%+v permitted an identity with no email at all", p)
		}
	}
}

func TestPolicyEmailCaseInsensitive(t *testing.T) {
	p := Policy{AllowedEmails: []string{"Real@Example.COM"}}
	if err := p.Permit(identity(map[string]any{"email": "rEAL@example.com", "email_verified": true})); err != nil {
		t.Errorf("case difference caused a refusal: %v", err)
	}
}

// TestPolicyRequiredClaims covers the two configurations that make a
// public IdP usable safely -- Google Workspace's hosted domain and a
// single Entra tenant -- through the generic mechanism, with no
// provider-specific code involved.
func TestPolicyRequiredClaims(t *testing.T) {
	google := Policy{RequiredClaims: map[string][]string{"hd": {"example.com"}}}
	if err := google.Permit(identity(map[string]any{"hd": "example.com"})); err != nil {
		t.Errorf("matching hd claim refused: %v", err)
	}
	if err := google.Permit(identity(map[string]any{"hd": "other.com"})); err == nil {
		t.Error("wrong hd claim permitted")
	}
	// A personal @gmail.com account carries no hd claim at all -- this is
	// exactly the account that must not get in.
	if err := google.Permit(identity(map[string]any{"email": "stranger@gmail.com"})); err == nil {
		t.Error("an account with no hd claim was permitted")
	}

	tenant := "00000000-0000-0000-0000-000000000000"
	entra := Policy{RequiredClaims: map[string][]string{"tid": {tenant}}}
	if err := entra.Permit(identity(map[string]any{"tid": tenant})); err != nil {
		t.Errorf("matching tid claim refused: %v", err)
	}
	if err := entra.Permit(identity(map[string]any{"tid": "11111111-1111-1111-1111-111111111111"})); err == nil {
		t.Error("a different tenant was permitted")
	}
}

// Every configured condition must hold, not just one.
func TestPolicyConditionsCombineWithAnd(t *testing.T) {
	p := Policy{
		AllowedGroups:  []string{"netops"},
		RequiredClaims: map[string][]string{"hd": {"example.com"}},
	}
	if err := p.Permit(identity(map[string]any{"groups": []any{"netops"}, "hd": "example.com"})); err != nil {
		t.Errorf("identity satisfying both conditions refused: %v", err)
	}
	if err := p.Permit(identity(map[string]any{"groups": []any{"netops"}, "hd": "other.com"})); err == nil {
		t.Error("permitted despite failing the hd condition")
	}
	if err := p.Permit(identity(map[string]any{"groups": []any{"other"}, "hd": "example.com"})); err == nil {
		t.Error("permitted despite failing the group condition")
	}
}

func TestPolicyCustomGroupsClaim(t *testing.T) {
	p := Policy{AllowedGroups: []string{"Admin"}, GroupsClaim: "roles"}
	if err := p.Permit(identity(map[string]any{"roles": []any{"Admin"}})); err != nil {
		t.Errorf("custom groups claim refused: %v", err)
	}
	if err := p.Permit(identity(map[string]any{"groups": []any{"Admin"}})); err == nil {
		t.Error("read the default claim name despite GroupsClaim being set")
	}
}

func TestPolicyRefusalIsTypedAndCarriesNoUserFacingDetail(t *testing.T) {
	p := Policy{AllowedGroups: []string{"netops"}}
	err := p.Permit(identity(map[string]any{"groups": []any{"other"}}))

	var notPermitted *ErrNotPermitted
	if !errors.As(err, &notPermitted) {
		t.Fatalf("got %T, want *ErrNotPermitted", err)
	}
	if notPermitted.Reason == "" {
		t.Error("refusal carries no reason for the operator's log")
	}
}

func TestPolicyRefusesNilIdentity(t *testing.T) {
	if err := (Policy{}).Permit(nil); err == nil {
		t.Error("a nil identity was permitted")
	}
}

func TestIsMultiTenantIssuer(t *testing.T) {
	multiTenant := []string{
		"https://accounts.google.com",
		"https://accounts.google.com/",
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/organizations/v2.0",
		"https://login.microsoftonline.com/consumers/v2.0",
		"https://appleid.apple.com",
		// Scheme-less. url.Parse puts the whole value in Path and leaves
		// Hostname empty, so these matched nothing and passed a check
		// meant to refuse them (mikroview #267, Uncertain). Discovery
		// would have failed on them later anyway -- but a security check
		// answering "no" because it could not read its input is the wrong
		// shape.
		"accounts.google.com",
		"login.microsoftonline.com/common/v2.0",
		"  appleid.apple.com  ",
		// A trailing root dot names the same host to DNS and TLS; it must
		// not name a different one to this check.
		"https://accounts.google.com./",
		"https://login.microsoftonline.com./common/v2.0",
	}
	for _, issuer := range multiTenant {
		if !IsMultiTenantIssuer(issuer) {
			t.Errorf("%s not recognised as multi-tenant -- it would be allowed with no restriction", issuer)
		}
	}

	singleTenant := []string{
		// The multi-tenant Entra host, but scoped to one organisation:
		// this really does restrict logins, so it must not be refused.
		"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
		"https://authentik.example.com/application/o/gauntlet/",
		"https://keycloak.example.com/realms/home",
		"https://idp.internal",
		// Scheme-less single-tenant must stay allowed -- the fallback
		// parse must not turn everything into a match.
		"login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
		"authentik.example.com/application/o/gauntlet/",
		"",
		"://not a url",
	}
	for _, issuer := range singleTenant {
		if IsMultiTenantIssuer(issuer) {
			t.Errorf("%s wrongly refused as multi-tenant", issuer)
		}
	}
}

func TestPolicyRestricted(t *testing.T) {
	restricted := []Policy{
		{AllowedGroups: []string{"x"}},
		{AllowedEmails: []string{"x@y.z"}},
		{AllowedEmailDomains: []string{"y.z"}},
		{RequiredClaims: map[string][]string{"hd": {"y.z"}}},
	}
	for _, p := range restricted {
		if !p.Restricted() {
			t.Errorf("%+v reports itself unrestricted", p)
		}
	}
	// GroupsClaim alone narrows nothing -- it only says where to look.
	if (Policy{GroupsClaim: "roles"}).Restricted() {
		t.Error("GroupsClaim alone reported as a restriction")
	}
}

// TestAllowIssuerRefusesMultiTenantIssuers: the deprecated AllowIssuer
// is AllowIssuerWithPolicy with an empty Policy, which pins no tenant, so
// every shared issuer is still refused through it.
func TestAllowIssuerRefusesMultiTenantIssuers(t *testing.T) {
	for _, issuer := range []string{
		"https://accounts.google.com",
		"https://login.microsoftonline.com/common/v2.0",
		"https://appleid.apple.com",
		// Scheme-less -- see TestIsMultiTenantIssuer.
		"accounts.google.com",
		"login.microsoftonline.com/common/v2.0",
		"  appleid.apple.com  ",
	} {
		if err := AllowIssuer(issuer); err == nil {
			t.Errorf("AllowIssuer(%q) permitted a multi-tenant provider", issuer)
		} else if !errors.Is(err, ErrMultiTenantIssuer) {
			t.Errorf("AllowIssuer(%q) = %v, want ErrMultiTenantIssuer", issuer, err)
		}
	}
}

// TestAllowIssuerWithPolicyNeedsTheTenantClaim pins ADR-0014: Google is
// accepted only when RequiredClaims names "hd" with a value -- any other
// narrowing, or another claim, still lets strangers at that provider in
// -- and every other shared issuer is refused whatever the Policy says.
// Entra's shared endpoints are refused even with "tid" pinned, because
// go-oidc cannot discover them; the error points at the single-tenant
// issuer instead.
func TestAllowIssuerWithPolicyNeedsTheTenantClaim(t *testing.T) {
	hd := Policy{RequiredClaims: map[string][]string{"hd": {"example.com"}}}
	tid := Policy{RequiredClaims: map[string][]string{"tid": {"00000000-0000-0000-0000-000000000000"}}}
	const singleTenant = "https://login.microsoftonline.com/<tenant-guid>/v2.0"
	both := Policy{RequiredClaims: map[string][]string{"hd": {"example.com"}, "tid": {"00000000-0000-0000-0000-000000000000"}}}
	cases := []struct {
		name      string
		issuer    string
		policy    Policy
		wantClaim string // "" means accepted; "-" means refused, naming no claim
		wantText  string // the refusal must contain this, if set
	}{
		{"google with hd", "https://accounts.google.com", hd, "", ""},
		{"google scheme-less with hd", "accounts.google.com.", hd, "", ""},
		{"google without a policy", "https://accounts.google.com", Policy{}, "hd", ""},
		{"google with tid only", "https://accounts.google.com", tid, "hd", ""},
		{"google with a blank hd", "https://accounts.google.com", Policy{RequiredClaims: map[string][]string{"hd": {" "}}}, "hd", ""},
		{"google with an email domain only", "https://accounts.google.com", Policy{AllowedEmailDomains: []string{"example.com"}}, "hd", ""},
		{"entra common with tid", "https://login.microsoftonline.com/common/v2.0", tid, "-", singleTenant},
		{"entra organizations with tid", "https://login.microsoftonline.com/organizations/v2.0", tid, "-", singleTenant},
		{"entra consumers with tid", "https://login.microsoftonline.com/consumers/v2.0", tid, "-", singleTenant},
		{"entra common without a policy", "https://login.microsoftonline.com/common/v2.0", Policy{}, "-", singleTenant},
		{"entra common with hd only", "https://login.microsoftonline.com/common/v2.0", hd, "-", singleTenant},
		{"entra single tenant without a policy", "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0", Policy{}, "", ""},
		{"self-hosted without a policy", "https://authentik.example.com/application/o/gauntlet/", Policy{}, "", ""},
		{"apple with both claims", "https://appleid.apple.com", both, "-", ""},
		{"microsoft personal with both claims", "https://login.live.com", both, "-", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AllowIssuerWithPolicy(tc.issuer, tc.policy)
			switch {
			case tc.wantClaim == "":
				if err != nil {
					t.Errorf("AllowIssuerWithPolicy(%q) = %v, want accepted", tc.issuer, err)
				}
			case !errors.Is(err, ErrMultiTenantIssuer):
				t.Errorf("AllowIssuerWithPolicy(%q) = %v, want ErrMultiTenantIssuer", tc.issuer, err)
			case tc.wantClaim != "-" && !strings.Contains(err.Error(), `"`+tc.wantClaim+`"`):
				t.Errorf("AllowIssuerWithPolicy(%q) = %v, want it to name the %q claim", tc.issuer, err, tc.wantClaim)
			case !strings.Contains(err.Error(), tc.wantText):
				t.Errorf("AllowIssuerWithPolicy(%q) = %v, want it to mention %q", tc.issuer, err, tc.wantText)
			}
		})
	}
}

// TestPermitRefusesAnotherTenantAtASharedIssuer is the other half of
// ADR-0014: once a shared issuer is accepted, the tenant pin is enforced
// on every sign-in, so a Google account in another Workspace -- or with
// no hd claim at all, a personal account -- is refused.
func TestPermitRefusesAnotherTenantAtASharedIssuer(t *testing.T) {
	cases := []struct {
		issuer, claim, want, other string
	}{
		{"https://accounts.google.com", "hd", "example.com", "evil.example"},
	}
	for _, tc := range cases {
		p := Policy{RequiredClaims: map[string][]string{tc.claim: {tc.want}}}
		if err := AllowIssuerWithPolicy(tc.issuer, p); err != nil {
			t.Fatalf("test setup: AllowIssuerWithPolicy(%q) = %v", tc.issuer, err)
		}
		signIn := func(claims map[string]any) error {
			id := identity(claims)
			id.Issuer = tc.issuer
			return p.Permit(id)
		}
		if err := signIn(map[string]any{tc.claim: tc.want}); err != nil {
			t.Errorf("%s: an account in the pinned tenant was refused: %v", tc.issuer, err)
		}
		var denied *ErrNotPermitted
		if err := signIn(map[string]any{tc.claim: tc.other}); !errors.As(err, &denied) {
			t.Errorf("%s: an account in another tenant got %v, want ErrNotPermitted", tc.issuer, err)
		}
		if err := signIn(map[string]any{"email": "someone@gmail.example"}); !errors.As(err, &denied) {
			t.Errorf("%s: an account with no %q claim got %v, want ErrNotPermitted", tc.issuer, tc.claim, err)
		}
	}
}

func TestAllowIssuerPermitsSelfHostedProviders(t *testing.T) {
	for _, issuer := range []string{
		"https://authentik.example.com/application/o/gauntlet/",
		"https://keycloak.example.com/realms/home",
		"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
		"https://idp.internal",
	} {
		if err := AllowIssuer(issuer); err != nil {
			t.Errorf("AllowIssuer(%q) refused a self-hosted issuer: %v", issuer, err)
		}
	}
}

// Policy keeps its full value for scoping within a directory you run --
// that is why it survived the removal.
func TestPolicyStillScopesWithinASelfHostedDirectory(t *testing.T) {
	p := Policy{AllowedGroups: []string{"gauntlet"}}
	if err := p.Permit(identity(map[string]any{"groups": []any{"gauntlet"}})); err != nil {
		t.Errorf("permitted group refused: %v", err)
	}
	if err := p.Permit(identity(map[string]any{"groups": []any{"housemates"}})); err == nil {
		t.Error("an account outside the permitted group was allowed in")
	}
}

func TestPolicyGroupsReturnsTheClaimValues(t *testing.T) {
	var p Policy
	if got := p.Groups(identity(map[string]any{"groups": []any{"a", "b", 7, ""}})); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("list: got %v, want [a b]", got)
	}
	if got := p.Groups(identity(map[string]any{"groups": "solo"})); len(got) != 1 || got[0] != "solo" {
		t.Errorf("string: got %v, want [solo]", got)
	}
	if got := p.Groups(identity(map[string]any{"email": "x@example.com"})); len(got) != 0 {
		t.Errorf("absent: got %v, want none", got)
	}
	if got := p.Groups(nil); got != nil {
		t.Errorf("nil identity: got %v, want nil", got)
	}

	// GroupsClaim moves where the values are read from, for Permit too.
	custom := Policy{GroupsClaim: "roles"}
	if got := custom.Groups(identity(map[string]any{"roles": []any{"r1"}, "groups": []any{"g1"}})); len(got) != 1 || got[0] != "r1" {
		t.Errorf("custom claim: got %v, want [r1]", got)
	}
}

func TestPolicyValidateRoles(t *testing.T) {
	valid := func(role string) bool { return role == "user" || role == "viewer" }

	ok := Policy{RoleFromGroups: map[string]string{"staff": "user", "guests": "viewer"}, RoleWithoutGroup: "user"}
	if err := ok.ValidateRoles(valid); err != nil {
		t.Errorf("valid map refused: %v", err)
	}
	if err := (Policy{}).ValidateRoles(valid); err != nil {
		t.Errorf("zero policy refused: %v", err)
	}
	for name, p := range map[string]Policy{
		"admin value":         {RoleFromGroups: map[string]string{"ops": "admin"}},
		"unknown value":       {RoleFromGroups: map[string]string{"ops": "root"}},
		"empty value":         {RoleFromGroups: map[string]string{"ops": ""}},
		"admin without-group": {RoleFromGroups: map[string]string{"ops": "user"}, RoleWithoutGroup: "admin"},
	} {
		if err := p.ValidateRoles(valid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestPolicyValidateRefusesBlankAllowListEntries pins #91: a blank
// entry in an allow-list (typically a trailing comma when an app splits
// a setting) must be refused at startup, naming the field, rather than
// silently widening access.
func TestPolicyValidateRefusesBlankAllowListEntries(t *testing.T) {
	blanks := []string{"", " ", "\t"}
	for _, blank := range blanks {
		cases := map[string]Policy{
			"AllowedGroups":       {AllowedGroups: []string{"family", blank}},
			"AllowedEmails":       {AllowedEmails: []string{blank, "a@example.com"}},
			"AllowedEmailDomains": {AllowedEmailDomains: []string{"example.com", blank}},
			"RoleFromGroups":      {RoleFromGroups: map[string]string{"staff": "user", blank: "user"}},
		}
		for field, p := range cases {
			t.Run(fmt.Sprintf("%s/%q", field, blank), func(t *testing.T) {
				err := p.Validate()
				if err == nil {
					t.Fatalf("Validate accepted a blank %q entry", blank)
				}
				if !strings.Contains(err.Error(), field) {
					t.Errorf("error %q does not name %s", err, field)
				}
			})
		}
	}
}

func TestPolicyValidateAcceptsNonBlankEntries(t *testing.T) {
	if err := (Policy{}).Validate(); err != nil {
		t.Errorf("zero policy refused: %v", err)
	}
	ok := Policy{
		AllowedGroups:       []string{"family", "netops"},
		AllowedEmails:       []string{"a@example.com"},
		AllowedEmailDomains: []string{"example.com"},
		RoleFromGroups:      map[string]string{"staff": "user", "guests": "viewer"},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("all-non-blank policy refused: %v", err)
	}
}

// TestPolicyWhitespaceGroupNeverCountsAsAGroup pins #91: a groups claim
// value that is only whitespace is not a group, so it cannot satisfy an
// allow-list and does not appear in Groups.
func TestPolicyWhitespaceGroupNeverCountsAsAGroup(t *testing.T) {
	p := Policy{AllowedGroups: []string{"family"}}

	for name, claims := range map[string]map[string]any{
		"space only":        {"groups": []any{" "}},
		"tab only":          {"groups": []any{"\t"}},
		"bare space string": {"groups": " "},
	} {
		t.Run(name, func(t *testing.T) {
			err := p.Permit(identity(claims))
			if err == nil {
				t.Fatal("permitted an identity whose only group is whitespace")
			}
			// Refused the same way as an identity with no groups claim.
			absent := p.Permit(identity(map[string]any{"email": "someone@example.com"}))
			if absent == nil {
				t.Fatal("permitted an identity with no groups claim")
			}
			if err.Error() != absent.Error() || errors.Is(err, absent) != errors.Is(absent, err) {
				t.Errorf("refusal %q differs from the no-groups refusal %q", err, absent)
			}
		})
	}

	var open Policy
	got := open.Groups(identity(map[string]any{"groups": []any{" ", "", "\t", "family"}}))
	if len(got) != 1 || got[0] != "family" {
		t.Errorf("Groups = %q, want [family] with blank values dropped", got)
	}
}

// TestPolicyValidateRefusesBlankEmailDomainAfterTrim pins #91: a domain
// entry that is blank once a leading "@" and whitespace are removed is
// refused, naming the field; ordinary entries are accepted.
func TestPolicyValidateRefusesBlankEmailDomainAfterTrim(t *testing.T) {
	for _, entry := range []string{"@", "@ ", " @"} {
		t.Run(fmt.Sprintf("refuses/%q", entry), func(t *testing.T) {
			err := Policy{AllowedEmailDomains: []string{"example.com", entry}}.Validate()
			if err == nil {
				t.Fatalf("Validate accepted domain entry %q", entry)
			}
			if !strings.Contains(err.Error(), "AllowedEmailDomains") {
				t.Errorf("error %q does not name AllowedEmailDomains", err)
			}
		})
	}
	for _, entry := range []string{"@example.com", "example.com"} {
		t.Run(fmt.Sprintf("accepts/%q", entry), func(t *testing.T) {
			if err := (Policy{AllowedEmailDomains: []string{entry}}).Validate(); err != nil {
				t.Errorf("Validate refused domain entry %q: %v", entry, err)
			}
		})
	}
}

// TestPolicyPermitBlankEmailEntryNeverMatches pins #91 defence in depth:
// on a policy that was never validated, a blank allow-list entry must not
// widen access.
func TestPolicyPermitBlankEmailEntryNeverMatches(t *testing.T) {
	verified := func(email string) *Identity {
		return identity(map[string]any{"email": email, "email_verified": true})
	}

	t.Run("AllowedEmails", func(t *testing.T) {
		p := Policy{AllowedEmails: []string{"alice@example.com", ""}}
		for _, email := range []string{"", "   "} {
			if err := p.Permit(verified(email)); err == nil {
				t.Errorf("permitted verified email %q via a blank AllowedEmails entry", email)
			}
		}
		if err := p.Permit(verified("alice@example.com")); err != nil {
			t.Errorf("refused the listed address: %v", err)
		}
	})

	for _, blank := range []string{"", "@"} {
		t.Run(fmt.Sprintf("AllowedEmailDomains/%q", blank), func(t *testing.T) {
			p := Policy{AllowedEmailDomains: []string{"example.com", blank}}
			if err := p.Permit(verified("x@")); err == nil {
				t.Errorf("permitted verified email %q via blank domain entry %q", "x@", blank)
			}
			if err := p.Permit(verified("bob@example.com")); err != nil {
				t.Errorf("refused bob@example.com: %v", err)
			}
		})
	}
}
