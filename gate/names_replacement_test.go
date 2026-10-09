package gate

import (
	"net/http"
	"strings"
	"testing"
)

// U+FFFD is refused in every name a person chooses (#90). A JSON body
// decodes invalid UTF-8 to U+FFFD, so this is how broken text reaches the
// routes; the character itself is also sent as it is.

var replacementNameBodies = []struct{ label, name string }{
	{"alone", "\uFFFD"},
	{"at the start", "\uFFFDKey"},
	{"in the middle", "Yubi\uFFFDKey"},
	{"at the end", "YubiKey\uFFFD"},
}

func TestPasskeyRegisterFinishRefusesTheReplacementCharacterAndLeavesTheCeremonyLive(t *testing.T) {
	for _, tc := range replacementNameBodies {
		t.Run(tc.label, func(t *testing.T) {
			g, ts, _, rec := passkeyNameFixture(t)
			bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
			bilboID := passkeyBilboID(t, g)
			fake := newFake(g)
			creation := passkeyRegisterBegin(t, bilbo, ts)

			wantProblem(t, passkeyRegisterFinishRaw(t, bilbo, ts, fake, creation, tc.name), http.StatusBadRequest, classInvalidRequest)

			if got := storedPasskeys(g, bilboID); got != 0 {
				t.Errorf("a refused name left %d passkeys stored", got)
			}
			if got := auditCount(g, "account.passkey_added"); got != 0 {
				t.Errorf("a refused name wrote %d account.passkey_added audit entries", got)
			}
			if got := noticesOfKind(g, rec, NoticeSecondFactorAdded, passkeyBilboUsername); got != 0 {
				t.Errorf("a refused name sent %d second-factor-added notices", got)
			}

			out := passkeyRegisterFinishOK(t, bilbo, ts, fake, creation, "YubiKey")
			if out.Passkey.Name != "YubiKey" {
				t.Errorf("finishing again stored the name %q, want %q", out.Passkey.Name, "YubiKey")
			}
		})
	}
}

func TestPasskeyRenameRefusesTheReplacementCharacter(t *testing.T) {
	for _, tc := range replacementNameBodies {
		t.Run(tc.label, func(t *testing.T) {
			g, ts, _ := passkeyFixture(t)
			bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
			_, out := registerPasskey(t, bilbo, ts, g, "original")

			resp := doJSON(t, bilbo, http.MethodPatch, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyRenameRequest{Name: tc.name})
			wantProblem(t, resp, http.StatusBadRequest, classInvalidRequest)

			if list := passkeysList(t, bilbo, ts); len(list) != 1 || list[0].Name != "original" {
				t.Errorf("passkey list after a refused rename = %+v, want the name unchanged", list)
			}
		})
	}
}

// The sign-out reason refuses U+FFFD, wherever it sits.
func TestAdminLogoutAllReasonRefusesTheReplacementCharacter(t *testing.T) {
	g, ts, admin, bobs := adminLogoutFixture(t)
	bobID := totpBobID(t, g)

	for _, tc := range []struct{ label, reason string }{
		{"alone", "\uFFFD"},
		{"in the middle", "lost\uFFFDphone"},
		{"at the end", "lost phone\uFFFD"},
		{"within CJK", "鍵\uFFFD鍵"},
	} {
		if status, _, raw := adminLogoutAll(t, admin, ts, bobID, adminLogoutAllRequest{Reason: tc.reason}); status != http.StatusBadRequest {
			t.Errorf("%s: status %d %q, want 400", tc.label, status, raw)
		}
	}
	requireSignedIn(t, ts, bobs, true)
	if n := len(auditEntries(g.cfg.Audit.(*auditRecorder), "user.sessions_ended")); n != 0 {
		t.Errorf("refusals wrote %d user.sessions_ended records", n)
	}
}

// Guard: the reason's limit counts characters, however wide they are.
func TestAdminLogoutAllReasonLimitCountsCharacters(t *testing.T) {
	g, ts, admin, bobs := adminLogoutFixture(t)
	bobID := totpBobID(t, g)

	for _, tc := range []struct{ label, reason string }{
		{"201 CJK characters", strings.Repeat("鍵", MaxSessionEndReason+1)},
		{"201 emoji", strings.Repeat("🔑", MaxSessionEndReason+1)},
	} {
		if status, _, raw := adminLogoutAll(t, admin, ts, bobID, adminLogoutAllRequest{Reason: tc.reason}); status != http.StatusBadRequest {
			t.Errorf("%s: status %d %q, want 400", tc.label, status, raw)
		}
	}
	requireSignedIn(t, ts, bobs, true)

	if status, _, raw := adminLogoutAll(t, admin, ts, bobID, adminLogoutAllRequest{Reason: strings.Repeat("鍵", MaxSessionEndReason)}); status != http.StatusOK {
		t.Errorf("a %d-character reason of CJK: %d %q, want 200", MaxSessionEndReason, status, raw)
	}
}
