package gate

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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

// Config configures a Gate. Everything here is a per-application value
// mikroview hard-coded (CookieName, CSRFHeaderValue) -- docs/design.md
// §1.5. What is NOT here, because it is security behaviour rather than
// taste, is in the constants in protect.go and session.go: the CSRF
// header name itself, the cookie's HttpOnly/SameSite/path/Max-Age, and
// -- since #49 -- the second-factor door, which no longer varies by
// application.
type Config struct {
	// CookieName is the session cookie's name -- mikroview uses
	// "mikroview_session", birdcage its own equivalent.
	CookieName string
	// SecureCookie sets the session cookie's Secure attribute. The
	// application decides this from its own listener's TLS state; gate
	// has no way to know it.
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
	// ClientIP resolves the address the login limiter is keyed on
	// (mikroview's clientIP -- its own trusted-proxy policy is the
	// application's, not gate's). Required.
	ClientIP func(*http.Request) string
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
	// being nil. Not checked by New: nil is a valid choice, and a
	// relying party that is not ready is a reported state, not a wiring
	// mistake.
	Passkeys gauntlet.PasskeyCeremony
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
}

// errMissingDep is New's fail-closed refusal for a Deps field with no
// safe default -- returned rather than panicking, since a missing
// dependency is a wiring mistake the caller's own startup should be able
// to report and exit on, not a crash inside a library.
var errMissingDep = errors.New("gate: missing required dependency")

// New builds a Gate from cfg and deps, failing closed on anything it
// cannot safely default: a Gate that started despite a missing store or
// CSRF value would either panic on the first request or -- worse, for
// CSRFHeaderValue -- silently accept every forged one.
func New(cfg Config, deps Deps) (*Gate, error) {
	if cfg.CookieName == "" {
		return nil, fmt.Errorf("gate: Config.CookieName is required")
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Gate{
		cfg:          cfg,
		deps:         deps,
		exempt:       make(map[string]bool),
		kindHandlers: make(map[gauntlet.TokenKind]http.Handler),
	}, nil
}

// now is the current time as Protect and every handler see it.
func (g *Gate) now() time.Time { return g.cfg.Now() }

// audit records action against target with detail as actor, through
// Config.Audit if one is configured -- a no-op otherwise.
func (g *Gate) audit(actor, action, target, detail string) {
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

// logWarn and logError are nil-safe wrappers around Config.Log, the same
// discard-on-nil convention as gauntlet.Options.Log.
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
