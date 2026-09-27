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

// Config configures a Gate. Everything here is either a per-application
// value mikroview hard-coded (CookieName, CSRFHeaderValue) or a policy
// choice mikroview made once for itself (RequireSecondFactor) --
// docs/design.md §1.5. What is NOT here, because it is security
// behaviour rather than taste, is in the constants in protect.go and
// session.go: the CSRF header name itself, and the cookie's HttpOnly/
// SameSite/path/Max-Age.
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
	// RequireSecondFactor mirrors mikroview's #1253 rule: a session
	// belonging to a local-password account with no confirmed second
	// factor can reach nothing once this is true. Off by default. See
	// docs/design.md §1.6 for why mikroview keeps this on and birdcage
	// is recommended to.
	//
	// The enrolment routes this door expects an account to be able to
	// reach while stuck at it (mikroview's secondFactorEnrolPaths) don't
	// exist in this stage -- see protect.go's "G6 stage 2" TODO. Setting
	// this true before that stage lands is a real lockout for any local
	// account without a factor already on its document.
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
	// OIDC being nil means SSO is off -- unused in this stage; the OIDC
	// routes are not registered by Routes yet (docs/design.md §1.5,
	// route table).
	OIDC       *oidc.Client
	OIDCState  *oidc.StateCodec
	OIDCPolicy oidc.Policy
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
