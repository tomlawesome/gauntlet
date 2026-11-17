package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
)

// Auditor records account and token events -- the signature of
// mikroview's audit.Store.Record minus its return value (docs/design.md
// §1.2). nil means no audit.
type Auditor interface {
	Record(actor, action, target, detail string)
}

// AdminPasskeyRule says whether every admin account must hold a passkey
// (#82, ADR-0015): Config.AdminPasskey. There is no default, and the
// zero value means "not set", which New refuses: the application's
// admin makes a conscious choice either way, so the application never
// fails silently -- neither running admins without the rule nor
// locking them out by surprise.
type AdminPasskeyRule string

const (
	// AdminPasskeyRequired: every admin account holds at least one
	// passkey usable at this deployment's public URL (an authenticator
	// app may be held as well, never instead). Until it does, Protect
	// holds the account at the passkey door, which still admits
	// registering one. Needs a ready relying party: New refuses this
	// value while Deps.Passkeys is nil or its Status is not
	// gauntlet.PasskeyStatusReady.
	AdminPasskeyRequired AdminPasskeyRule = "required"
	// AdminPasskeyOptional: the application waives the rule, and an
	// admin's second factor may be any kind, as every other account's
	// is. For an application reached over plain http (on any host but
	// localhost) or by IP address, where browsers cannot make a passkey,
	// or one that wires no passkeys at all.
	AdminPasskeyOptional AdminPasskeyRule = "optional"
)

// Config configures a Gate. Everything here is a per-application value
// mikroview hard-coded (CookieName, CSRFHeaderValue) -- docs/design.md
// §1.5. What is NOT here, because it is security behaviour rather than
// taste, is fixed in protect.go and cookie.go: the CSRF header name
// itself, the cookie's HttpOnly/SameSite/path, its __Host- prefix under
// TLS, its Max-Age (the session store's lifetime ceiling), and -- since
// #49 -- the second-factor door, which no longer varies by application.
type Config struct {
	// CookieName is the session cookie's name -- mikroview uses
	// "mikroview_session", birdcage its own equivalent. While
	// SecureCookie is true the cookie is written and read as "__Host-"
	// plus this name (cookie.go's sessionCookieName), so the name must
	// not already carry a "__Host-" or "__Secure-" prefix: New refuses
	// one. No frontend reads the cookie (it is HttpOnly), so the prefix
	// is invisible to both applications' code.
	CookieName string
	// SecureCookie sets the session cookie's Secure attribute, and with
	// it the __Host- prefix. The application decides this from its own
	// listener's TLS state; gate has no way to know it, so New logs one
	// warning when it is left false rather than failing: plain HTTP is
	// what development runs on, and a warning is what birdcage's startup
	// is designed to show (docs/design.md §2.4).
	SecureCookie bool
	// CSRFHeaderValue is the value Protect requires in the
	// X-Requested-With header (the header name itself is fixed, see
	// csrfHeaderName in protect.go) on every unsafe-method request once
	// an account exists. Required: an empty value would make an absent
	// header satisfy the check, since a missing header also reads back
	// as "".
	CSRFHeaderValue string
	// RequireSecondFactor used to gate the forced-enrolment door: a
	// session belonging to a local-password account with no confirmed
	// second factor could reach nothing once this was true. An account
	// stuck at the door can still reach the enrolment routes
	// (protect.go's secondFactorEnrolPaths), so the door was never a
	// lockout for a local account without a factor: it is sent to
	// enrol one.
	//
	// Deprecated: the door is now always shut (#49) and this field is
	// ignored, whatever value is set -- it stays only so applications
	// that already set it still compile. See docs/design.md §1.6 for
	// why: leaving the door optional, off by default, meant an
	// application that forgot to turn it on got 8-character
	// single-factor passwords, which NIST SP 800-63B-4 §3.1.1.2 permits
	// only behind a mandatory second factor; #49 closes that gap by
	// removing the "off" state rather than raising the minimum.
	RequireSecondFactor bool
	// ProductName names the deployment in TOTP enrolment URIs and
	// passkey display names (docs/design.md §1.5's last paragraph).
	// Required: Routes always serves the TOTP enrolment routes, and an
	// empty product name would land in the otpauth:// URI an
	// authenticator app scans, which is worse than refusing to start.
	ProductName string
	// LoginPath is the frontend route the OIDC callback's `?ssoError=`
	// redirect points at on a failed login. Not required: unused unless
	// Deps.OIDC is configured, and an empty value simply redirects to a
	// bare "?ssoError=..." (relative to the current path), which is
	// tolerable degradation rather than a security hole.
	LoginPath string
	// Log receives everything gate logs (nothing is fatal to a request
	// on its own). nil discards it.
	Log *slog.Logger
	// Audit receives account and token events (register, login,
	// password change, user/token create/delete). nil means no audit.
	Audit Auditor
	// Notices is told about every account event this module raises --
	// a password reset, a second factor added or removed, recovery
	// codes regenerated, a lockout or disable, an admin ending every
	// session, an unusual sign-in (#73) -- so the application can tell
	// the account's owner. nil means nobody is told; everything is still
	// shown and audited either way. See AccountNotifier. New refuses a
	// Config with both Notices and the deprecated Notify set.
	Notices AccountNotifier
	// Deprecated: Notify is Notices narrowed to one event (an admin
	// ending another account's sessions). Kept working for a minor
	// release (ADR-0002 decision 2); set Notices instead. See Notifier.
	Notify Notifier
	// DeliverConfirmCode hands an unusual sign-in's confirmation code to
	// the application, synchronously, before the sign-in is answered
	// (#55, #73): nil means the confirm action is unavailable, and New
	// refuses a Config.UnusualSignIns that asks for it. Unlike Notices,
	// a failure here -- an error, a panic, or running past DecideTimeout
	// -- refuses the sign-in: no code reached anyone, so none is owed.
	// See ConfirmCode.
	DeliverConfirmCode func(ctx context.Context, c ConfirmCode) error
	// OnEscapeCode receives the escape code a lone admin refused by the
	// unusual-sign-in policy may type into the refused browser (#66,
	// ADR-0011), synchronously, before the refusal is answered. nil
	// means the code is written to Log as one Warn line, as the setup
	// and unlock codes are; with both nil no code is issued and the
	// refusal is as it always was. See EscapeCodeHandler.
	OnEscapeCode EscapeCodeHandler
	// ClientIP resolves the address the login limiter is keyed on
	// (mikroview's clientIP -- its own trusted-proxy policy is the
	// application's, not gate's). Required.
	ClientIP func(*http.Request) string
	// Country resolves the ISO 3166-1 alpha-2 country code for an
	// address, so a sign-in record and the session it issues can carry
	// where the request came from (#54). Optional: nil means no country
	// is ever recorded. The application passes
	// (*geoip.Manager).Country; ok is false when nothing is known for
	// that address (no data file loaded yet, a private address, or no
	// match), and gate then records no country for it, never an error.
	Country func(address string) (code string, ok bool)
	// Locate resolves an address to a point and accuracy radius, so a
	// sign-in can be judged for impossible travel (#55). Optional: nil
	// means impossible travel is never raised. The application passes
	// (*geoip.Manager).Locate, which answers only from a MaxMind City
	// file (geoip.EditionCity). Coordinates are kept only as the
	// account's last place; no route, notice or record shows them.
	Locate func(address string) (gauntlet.Location, bool)
	// PasskeySignIn offers signing in with a passkey alone, no password
	// first (#77, ADR-0012): POST /api/auth/login/passkey/begin and
	// /api/auth/login/passkey, a passkey that verified the user as the
	// whole sign-in, and the same passkey resuming a timed-out session.
	// Off by default, so an application opts in when its frontend has the
	// button; while it is off, or Deps.Passkeys cannot do it
	// (gauntlet.PasskeySignIn), those routes answer 404, and the
	// passkeys block of the session body does not say signIn. An account
	// keeps its password either way: a passkey replaces it at sign-in,
	// never in the account.
	PasskeySignIn bool
	// AdminPasskey says whether every admin account must hold a passkey
	// (#82, ADR-0015). Required, with no default: New refuses an unset
	// or unknown value, so the application's admin chooses consciously
	// and the application never fails silently. AdminPasskeyRequired
	// also needs a ready relying party (Deps.Passkeys wired, Status
	// ready), or New refuses to start; AdminPasskeyOptional is for an
	// application reached over plain http (on any host but localhost) or
	// by IP address, or one that wires no passkeys. New logs the chosen
	// value.
	AdminPasskey AdminPasskeyRule
	// UnusualSignIns is what a sign-in from a new browser, a new country
	// or an impossible distance away does (#55; unusual.go). The zero
	// value flags each one: the sign-in completes and is marked on the
	// session, the history and the audit record. New refuses a value
	// that is not one of the actions, and impossible travel turned on
	// with no Locate.
	UnusualSignIns UnusualSignInPolicy
	// Now is the clock Protect and every handler read the current time
	// from. nil means time.Now.
	Now func() time.Time
}

// Deps are the stores and clients Protect and Routes call into --
// docs/design.md §1.5. Users, Sessions, Tokens and Limiter are required;
// a Gate with any of them nil fails closed rather than serving requests
// it cannot actually check.
type Deps struct {
	Users    *gauntlet.Store
	Sessions *gauntlet.SessionStore
	Tokens   *gauntlet.TokenStore
	Limiter  *gauntlet.LoginLimiter
	// OIDC being nil means SSO is off: Routes still registers the
	// /api/auth/oidc/* routes, which then answer 404 (docs/design.md
	// §1.5). OIDCState is required whenever OIDC is set -- New refuses
	// the pair otherwise.
	OIDC       *oidc.Client
	OIDCState  *oidc.StateCodec
	OIDCPolicy oidc.Policy
	// Passkeys runs the WebAuthn ceremonies -- in practice
	// gauntlet/passkey's RelyingParty, built by the application from its
	// own public URL (ADR-0004). nil means this application has no
	// passkeys: Routes still registers every passkey route, and each
	// answers 404, the session body leaves out "passkeys", and the
	// password step never offers "passkey" -- the same shape as OIDC
	// being nil. With Config.AdminPasskey set to AdminPasskeyOptional,
	// New does not check it: nil is a valid choice, and a relying party
	// that is not ready is a reported state, not a wiring mistake. With
	// AdminPasskeyRequired, New refuses nil and a relying party that is
	// not ready (#82).
	Passkeys gauntlet.PasskeyCeremony
	// SignIns is the sign-in history (#53): every sign-in attempt is
	// appended to it, and GET /api/auth/sign-ins lets an admin page
	// through it. nil means no history: nothing is appended and the
	// route answers 404. The audit records (Config.Audit) are written
	// either way. Not checked by New; the application opens it
	// (gauntlet.OpenSignInHistory) and closes it at shutdown.
	SignIns *gauntlet.SignInHistory
}

// Gate is the middleware and handler set built by New.
type Gate struct {
	cfg  Config
	deps Deps

	// exempt holds paths added by Exempt, beyond the built-in
	// /api/auth/* set (exemptPaths in protect.go).
	exempt map[string]bool

	// kindHandlers and kindOrder back Handle: a bearer token is tried
	// against each registered kind in the order Handle was called for
	// it (docs/design.md §1.5), and dispatched to that kind's handler.
	// Both are written only by Handle, which -- like Exempt -- is setup
	// state a caller wires before Protect ever serves a request, the
	// same single-goroutine-at-startup convention mikroview's own
	// requireAuth construction follows; neither is guarded by a mutex.
	kindHandlers map[gauntlet.TokenKind]http.Handler
	kindOrder    []gauntlet.TokenKind

	// warns rates the Warn lines refused requests leave (warnrate.go).
	warns warnRater
	// notifying counts Notifier calls still running (notify.go), so a
	// test can wait for them.
	notifying sync.WaitGroup
	// notices rates the unusual-sign-in notices for flag and block: one
	// per account per unusualNoticeInterval (#55).
	notices warnRater

	// signInHook, when set, receives every sign-in attempt recordSignIn
	// handles, after its client and lockout fields are filled, beside
	// Deps.SignIns: a test seam.
	signInHook func(ev gauntlet.SignInEvent, now time.Time)
}

// errMissingDep is New's fail-closed refusal for a Deps field with no
// safe default -- returned rather than panicking, since a missing
// dependency is a wiring mistake the caller's own startup should be able
// to report and exit on, not a crash inside a library.
var errMissingDep = errors.New("gate: missing required dependency")

// errSessionLimits is New's fail-closed refusal for a Deps.Sessions
// store configured outside gauntlet.MaxSessionIdle/MaxSessionLifetime
// (the NIST SP 800-63B-4 AAL2 caps the owner adopted on 2026-10-02,
// gauntlet#51) -- a Gate that started despite a longer-lived session
// store would silently keep a session alive past the limit the rest of
// the module is now built to.
var errSessionLimits = errors.New("gate: Deps.Sessions session limits exceed AAL2 caps")

// New builds a Gate from cfg and deps, failing closed on anything it
// cannot safely default: a Gate that started despite a missing store or
// CSRF value would either panic on the first request or -- worse, for
// CSRFHeaderValue -- silently accept every forged one.
func New(cfg Config, deps Deps) (*Gate, error) {
	if cfg.CookieName == "" {
		return nil, fmt.Errorf("gate: Config.CookieName is required")
	}
	// gate adds the __Host- prefix itself (cookie.go): a name that
	// already carries a browser-reserved prefix would be doubled under
	// TLS and, under plain HTTP, silently dropped by every browser --
	// a deployment that signs nobody in, with nothing in the log.
	if hasReservedCookiePrefix(cfg.CookieName) {
		return nil, fmt.Errorf("gate: Config.CookieName %q must not start with __Host- or __Secure-; gate adds the prefix", cfg.CookieName)
	}
	if cfg.CSRFHeaderValue == "" {
		return nil, fmt.Errorf("gate: Config.CSRFHeaderValue is required")
	}
	if cfg.ClientIP == nil {
		return nil, fmt.Errorf("gate: Config.ClientIP is required")
	}
	if cfg.ProductName == "" {
		return nil, fmt.Errorf("gate: Config.ProductName is required")
	}
	if deps.Users == nil {
		return nil, fmt.Errorf("%w: Deps.Users", errMissingDep)
	}
	if deps.Sessions == nil {
		return nil, fmt.Errorf("%w: Deps.Sessions", errMissingDep)
	}
	idle, ceiling := deps.Sessions.Limits()
	if idle <= 0 {
		return nil, fmt.Errorf("%w: idle %s must be positive", errSessionLimits, idle)
	}
	if idle > gauntlet.MaxSessionIdle {
		return nil, fmt.Errorf("%w: idle %s exceeds MaxSessionIdle %s", errSessionLimits, idle, gauntlet.MaxSessionIdle)
	}
	if ceiling <= 0 {
		return nil, fmt.Errorf("%w: no lifetime ceiling configured (MaxSessionLifetime is %s)", errSessionLimits, gauntlet.MaxSessionLifetime)
	}
	if ceiling > gauntlet.MaxSessionLifetime {
		return nil, fmt.Errorf("%w: ceiling %s exceeds MaxSessionLifetime %s", errSessionLimits, ceiling, gauntlet.MaxSessionLifetime)
	}
	if deps.Tokens == nil {
		return nil, fmt.Errorf("%w: Deps.Tokens", errMissingDep)
	}
	if deps.Limiter == nil {
		return nil, fmt.Errorf("%w: Deps.Limiter", errMissingDep)
	}
	// SSO on means the flow cookie gets sealed on the first click; a nil
	// codec there is a panic on that request, not here.
	if deps.OIDC != nil && deps.OIDCState == nil {
		return nil, fmt.Errorf("%w: Deps.OIDCState (required when Deps.OIDC is set)", errMissingDep)
	}
	// oidc.New checked the issuer against its own Config.Policy, but the
	// policy enforced at every sign-in is this one. A shared issuer
	// without its tenant pinned here would let any account at that
	// provider in, so it is refused at startup (ADR-0014).
	if deps.OIDC != nil {
		if err := oidc.AllowIssuerWithPolicy(deps.OIDC.Issuer(), deps.OIDCPolicy); err != nil {
			return nil, fmt.Errorf("gate: Deps.OIDCPolicy: %w (see docs/adr/0014-shared-issuers.md)", err)
		}
	}
	// A blank allow-list entry (a trailing comma in an app's setting)
	// must not widen access, so it is refused at startup (#91).
	if err := deps.OIDCPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("gate: Deps.OIDCPolicy: %w", err)
	}
	// A group never gives admin (ADR-0013 decision 1): an identity
	// provider that is misconfigured or compromised must not be able to
	// mint an account that skips the local password and second factor
	// every admin keeps (ADR-0010). Refused here, not at the first
	// sign-in, so the mistake shows at startup.
	if err := deps.OIDCPolicy.ValidateRoles(func(role string) bool {
		return role == string(gauntlet.RoleUser) || role == string(gauntlet.RoleViewer)
	}); err != nil {
		return nil, fmt.Errorf("gate: Deps.OIDCPolicy: %w (a group may give only %q or %q; see docs/adr/0013-sso-group-roles.md)",
			err, gauntlet.RoleUser, gauntlet.RoleViewer)
	}
	if cfg.Notify != nil && cfg.Notices != nil {
		return nil, fmt.Errorf("gate: Config.Notify and Config.Notices must not both be set; Notices replaces the deprecated Notify")
	}
	if err := checkUnusualPolicy(cfg); err != nil {
		return nil, err
	}
	if err := checkAdminPasskeyRule(cfg, deps); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	g := &Gate{
		cfg:          cfg,
		deps:         deps,
		exempt:       make(map[string]bool),
		kindHandlers: make(map[gauntlet.TokenKind]http.Handler),
		notices:      warnRater{interval: &unusualNoticeInterval},
	}
	g.logInfo("gate: admin passkey rule: " + string(cfg.AdminPasskey))
	if cfg.PasskeySignIn {
		if _, ok := deps.Passkeys.(gauntlet.PasskeySignIn); !ok {
			g.logWarn("gate: Config.PasskeySignIn is set but Deps.Passkeys is nil or does not implement gauntlet.PasskeySignIn; the passkey sign-in routes answer 404")
		}
	}
	// Not a refusal: plain HTTP is what development runs on, and the
	// application, not gate, knows whether TLS terminates in front of
	// it. One line at startup, naming the setting, is what an operator
	// reading the log needs to notice a production deployment that
	// forgot it (ASVS 3.3.1, SP 800-63B-4 §5.1.1 Secure SHALL).
	if !cfg.SecureCookie {
		g.logWarn("gate: Config.SecureCookie is false: the session cookie is sent over plain HTTP and has no __Host- prefix; set it to true where TLS terminates")
	}
	return g, nil
}

// checkAdminPasskeyRule is New's check of Config.AdminPasskey (#82,
// ADR-0015): set, known, and -- for AdminPasskeyRequired -- backed by a
// ready relying party. A relying party's status is fixed by
// configuration, so refusing here is seen once, by the operator, rather
// than by every admin at a door they cannot pass.
func checkAdminPasskeyRule(cfg Config, deps Deps) error {
	switch cfg.AdminPasskey {
	case AdminPasskeyRequired:
		switch {
		case deps.Passkeys == nil:
			return errors.New("gate: Config.AdminPasskey is required, but Deps.Passkeys is nil; wire gauntlet/passkey or set gate.AdminPasskeyOptional")
		case deps.Passkeys.Status() != gauntlet.PasskeyStatusReady:
			return fmt.Errorf("gate: Config.AdminPasskey is required, but the relying party is not ready (%s); fix the public URL or set gate.AdminPasskeyOptional", deps.Passkeys.Status())
		}
	case AdminPasskeyOptional:
		// nothing to check
	case "":
		return errors.New("gate: Config.AdminPasskey is not set; choose gate.AdminPasskeyRequired or gate.AdminPasskeyOptional")
	default:
		return fmt.Errorf("gate: Config.AdminPasskey %q is not a known value; choose gate.AdminPasskeyRequired or gate.AdminPasskeyOptional", cfg.AdminPasskey)
	}
	return nil
}

// now is the current time as Protect and every handler see it.
func (g *Gate) now() time.Time { return g.cfg.Now() }

// audit records action against target with detail as actor, through
// Config.Audit if one is configured -- a no-op otherwise. The address r
// came from (Config.ClientIP) is appended to detail as from="...",
// quoted because ClientIP may read a header the client set (#45, ASVS
// 16.2.1): every record a request writes says where it came from.
func (g *Gate) audit(r *http.Request, actor, action, target, detail string) {
	from := fmt.Sprintf("from=%q", g.cfg.ClientIP(r))
	if detail == "" {
		detail = from
	} else {
		detail += "; " + from
	}
	g.auditRecord(actor, action, target, detail)
}

// auditRecord is audit for a detail that already names the address:
// the sign-in records (recordSignIn), which name the address the
// limiter counted.
func (g *Gate) auditRecord(actor, action, target, detail string) {
	if g.cfg.Audit == nil {
		return
	}
	g.cfg.Audit.Record(actor, action, target, detail)
}

// auditActorInvariantViolation mirrors mikroview's own marker (see
// auth.go): bracketed and impossible to mistake for a username, so a
// caller reading the audit log sees a defect on sight rather than a
// believable actor.
const auditActorInvariantViolation = "[bug: gate.audit reached with no caller in context]"

func auditActor(r *http.Request) string {
	if u := UserFromContext(r); u != nil {
		return u.Username
	}
	return auditActorInvariantViolation
}

// logInfo, logWarn and logError are nil-safe wrappers around
// Config.Log, the same discard-on-nil convention as
// gauntlet.Options.Log.
func (g *Gate) logInfo(msg string) {
	if g.cfg.Log != nil {
		g.cfg.Log.Info(msg)
	}
}

func (g *Gate) logWarn(msg string) {
	if g.cfg.Log != nil {
		g.cfg.Log.Warn(msg)
	}
}

func (g *Gate) logError(msg string) {
	if g.cfg.Log != nil {
		g.cfg.Log.Error(msg)
	}
}
