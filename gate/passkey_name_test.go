package gate

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tomlawesome/gauntlet/persist"
)

// A passkey's name is plain text (#89): a control or format character,
// or a line or paragraph separator, is refused with 400 invalid-request,
// and a notice about a passkey stored with one before that rule carries
// the name with those characters taken out. Invalid UTF-8 cannot reach
// the routes (a JSON body decodes it to U+FFFD, which is printable), so
// the store's own tests cover it.

// unprintableNameBodies are names no route may accept. Each is an
// ordinary Go string; the JSON body carries it escaped.
var unprintableNameBodies = []struct{ label, name string }{
	{"NUL", "Yubi\x00Key"},
	{"ESC", "Yubi\x1bKey"},
	{"DEL", "Yubi\x7fKey"},
	{"C1 NEL", "Yubi\u0085Key"},
	{"zero-width space", "Yubi\u200bKey"},
	{"right-to-left override", "Yubi\u202eKey"},
	{"left-to-right isolate", "Yubi\u2066Key"},
	{"byte order mark", "Yubi\ufeffKey"},
	{"line separator", "Yubi\u2028Key"},
	{"paragraph separator", "Yubi\u2029Key"},
	{"trailing newline", "YubiKey\n"},
	{"only a newline", "\n"},
}

// storedUnprintableName is how a name holding unprintable characters sits
// in an accounts document written before the rule: JSON-escaped, between
// the quotes. Cleaned, it reads "Work Key 1".
const storedUnprintableName = `Wo\u0000rk\u0007 \u001b\u200bKe\u007f\u0085y\u2028\u2029\ufeff\u202e\u2066\n 1`

const cleanedStoredName = "Work Key 1"

// plantedMarker stands in for a passkey's name until plantPasskeyName
// swaps in storedUnprintableName behind the store's back.
const plantedMarker = "PLANTEDNAMEMARKER"

// passkeyNameFixture is passkeyFixture over a backend the test holds, with
// a notice recorder: the backend is how an old, unchecked name is put
// into the accounts document.
func passkeyNameFixture(t *testing.T) (*Gate, *httptest.Server, *persist.Memory, *noticeRecorder) {
	t.Helper()
	mem := persist.NewMemory()
	g := newTestGateWithUsers(t, openTrackedStore(t, mem))
	g.deps.Passkeys = mustRelyingParty(t, passkeyTestPublicURL)
	g.cfg.Audit = &auditRecorder{}
	rec := &noticeRecorder{}
	g.cfg.Notices = rec
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
	return g, ts, mem, rec
}

// plantPasskeyName rewrites the accounts document so the passkey named
// plantedMarker is named storedUnprintableName instead -- the way a
// hand-edited file, or a store from before the rule, would hold it.
func plantPasskeyName(t *testing.T, mem *persist.Memory) {
	t.Helper()
	snap, err := mem.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	quoted := []byte(`"` + plantedMarker + `"`)
	if n := bytes.Count(snap.Payload, quoted); n == 0 {
		t.Fatalf("no passkey is named %s in the accounts document", plantedMarker)
	}
	planted := bytes.ReplaceAll(snap.Payload, quoted, []byte(`"`+storedUnprintableName+`"`))
	if _, err := mem.Save(t.Context(), planted, snap.Version); err != nil {
		t.Fatal(err)
	}
}

// auditCount is how many entries of action g's audit recorder holds.
func auditCount(g *Gate, action string) int {
	rec := g.cfg.Audit.(*auditRecorder)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for _, e := range rec.entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// noticesOfKind waits for the background notices, then counts those of
// kind about username's account. The fixture's own setup sends notices
// for the admin (registerAdmin enrols it a factor), so the count is
// per account.
func noticesOfKind(g *Gate, rec *noticeRecorder, kind NoticeKind, username string) int {
	g.notifying.Wait()
	n := 0
	for _, notice := range rec.all() {
		if notice.Kind == kind && notice.Username == username {
			n++
		}
	}
	return n
}

func TestPasskeyRegisterFinishRefusesAnUnprintableNameAndLeavesTheCeremonyLive(t *testing.T) {
	for _, tc := range unprintableNameBodies {
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

			// The ceremony was not used up: the same credential finishes
			// with a good name.
			out := passkeyRegisterFinishOK(t, bilbo, ts, fake, creation, "YubiKey")
			if out.Passkey.Name != "YubiKey" {
				t.Errorf("finishing again stored the name %q, want %q", out.Passkey.Name, "YubiKey")
			}
			if got := storedPasskeys(g, bilboID); got != 1 {
				t.Errorf("finishing again left %d passkeys stored, want 1", got)
			}
		})
	}
}

func TestPasskeyRenameRefusesAnUnprintableName(t *testing.T) {
	for _, tc := range unprintableNameBodies {
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

// Letters of any script, accents and emoji stay welcome, and the notice
// carries them as they are (guards behaviour that does not change).
func TestPasskeyNamesKeepNonLatinLettersAccentsAndEmojiInRoutesAndNotices(t *testing.T) {
	g, ts, _, rec := passkeyNameFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	name := "Clé de Zoë 🔑"
	_, out := registerPasskeyHeld(t, bilbo, ts, g, name)
	if out.Passkey.Name != name {
		t.Errorf("registered name = %q, want %q", out.Passkey.Name, name)
	}
	confirmEnrolmentOK(t, bilbo, ts)
	n := lastNotice(t, g, rec, NoticeSecondFactorAdded)
	if n.SecondFactor == nil || n.SecondFactor.Name != name {
		t.Errorf("notice = %+v, want the name %q untouched", n, name)
	}

	for _, renamed := range []string{"鍵", "مفتاح", "Clé de Zoë 🔑"} {
		resp := doJSON(t, bilbo, http.MethodPatch, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyRenameRequest{Name: renamed})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("renaming to %q returned %d, want 200", renamed, resp.StatusCode)
		}
		if list := passkeysList(t, bilbo, ts); len(list) != 1 || list[0].Name != renamed {
			t.Errorf("passkey list after renaming to %q = %+v", renamed, list)
		}
	}
}

// A first passkey is held, then goes live when its recovery codes are
// confirmed; the notice for that is built from the held name, which an
// older store may have kept with unprintable characters in it.
func TestNoticeCleansAnOldUnprintableNameWhenAHeldPasskeyIsConfirmed(t *testing.T) {
	g, ts, mem, rec := passkeyNameFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskeyHeld(t, bilbo, ts, g, plantedMarker)
	plantPasskeyName(t, mem)

	confirmEnrolmentOK(t, bilbo, ts)

	n := lastNotice(t, g, rec, NoticeSecondFactorAdded)
	if n.SecondFactor == nil {
		t.Fatalf("notice = %+v, want a second-factor detail", n)
	}
	if n.SecondFactor.Method != "passkey" || n.SecondFactor.Name != cleanedStoredName {
		t.Errorf("notice detail = %+v, want method passkey and the name %q", *n.SecondFactor, cleanedStoredName)
	}
}

func TestNoticeCleansAnOldUnprintableNameWhenAPasskeyIsRemoved(t *testing.T) {
	g, ts, mem, rec := passkeyNameFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	_, out := registerPasskey(t, bilbo, ts, g, plantedMarker)
	plantPasskeyName(t, mem)

	resp := deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete returned %d, want 200", resp.StatusCode)
	}

	n := lastNotice(t, g, rec, NoticeSecondFactorRemoved)
	if n.SecondFactor == nil {
		t.Fatalf("notice = %+v, want a second-factor detail", n)
	}
	if n.SecondFactor.Method != "passkey" || n.SecondFactor.Name != cleanedStoredName {
		t.Errorf("notice detail = %+v, want method passkey and the name %q", *n.SecondFactor, cleanedStoredName)
	}
}
