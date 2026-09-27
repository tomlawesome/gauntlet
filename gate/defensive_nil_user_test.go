// TestSecondFactorHandlersRefuseWithNoCallerInContext covers each new
// handler's defensive "no caller in context" guard directly -- normally
// unreachable through Routes()+Protect (Protect never dispatches to
// Routes' mux without first putting an authenticated user in context,
// except on an exempt path, and none of these are exempt), the same way
// mikroview's own handlers carry this check for a caller that reaches
// them some other way in the future.
package gate

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecondFactorHandlersRefuseWithNoCallerInContext(t *testing.T) {
	g := newTestGate(t)
	handlers := map[string]http.HandlerFunc{
		"handleTOTPEnrol":               g.handleTOTPEnrol,
		"handleTOTPConfirm":             g.handleTOTPConfirm,
		"handleTOTPDelete":              g.handleTOTPDelete,
		"handleRecoveryCodesRegenerate": g.handleRecoveryCodesRegenerate,
		"handleOIDCLinkStart":           g.handleOIDCLinkStart,
	}
	// handleOIDCLinkStart 404s before reaching the caller check unless
	// OIDC is configured.
	g.deps.OIDCState = nil

	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			rec := httptest.NewRecorder()
			h(rec, req)
			if name == "handleOIDCLinkStart" {
				// Covered separately in oidc_handler_test.go once OIDC
				// is configured -- here it 404s (OIDC nil), which is
				// also a legitimate refusal.
				return
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with no caller in context got %d, want 401", name, rec.Code)
			}
		})
	}
}
