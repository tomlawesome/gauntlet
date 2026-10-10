// v0.4.1, #100: DELETE /api/auth/totp and DELETE /api/auth/passkeys/{id}
// re-check the caller's password, then remove the factor. When the
// caller's account is deleted after the password re-check passes but
// before the removal is saved, each answers 401, sign-in-required,
// detail "sign in first" -- the answer POST /api/auth/recovery-codes
// gives in the same window -- with no internal error text and no
// session cookie.
//
// The window is reached the way contractfix99_admingone_test.go reaches
// it: the gate's store sits on a backend that, on the next Save, first
// lets a second store on the same document delete the account.
package gate

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

type v041DeletingBackend struct {
	*persist.Memory
	mu         sync.Mutex
	beforeSave func()
}

func (b *v041DeletingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.mu.Lock()
	f := b.beforeSave
	b.beforeSave = nil
	b.mu.Unlock()
	if f != nil {
		f()
	}
	return b.Memory.Save(ctx, payload, expect)
}

func (b *v041DeletingBackend) arm(f func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.beforeSave = f
}

func (b *v041DeletingBackend) armed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.beforeSave != nil
}

// v041SelfDeleteFixture is a gate on a deleting backend, holding one
// account with either an authenticator app or a passkey, signed in. It
// returns the request to send, the account's ID and the backend.
type v041SelfDeleteFixture struct {
	g       *Gate
	backend *v041DeletingBackend
	client  *http.Client
	url     string
	body    any
	id      string
}

func newV041SelfDeleteFixture(t *testing.T, route string) *v041SelfDeleteFixture {
	t.Helper()
	backend := &v041DeletingBackend{Memory: persist.NewMemory()}
	g := passkeyGate(t)
	g.deps.Users = openTrackedStore(t, backend)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)
	f := &v041SelfDeleteFixture{g: g, backend: backend}
	switch route {
	case "totp":
		_ = postJSON(t, admin, ts.URL+"/api/auth/users",
			createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()
		f.client = loggedInClient(t, ts, totpBobUsername, totpBobPassword)
		totpEnrolAndConfirm(t, f.client, ts)
		f.id = totpBobID(t, g)
		f.url = ts.URL + "/api/auth/totp"
		f.body = totpDeleteRequest{Password: totpBobPassword}
	case "passkey":
		_ = postJSON(t, admin, ts.URL+"/api/auth/users",
			createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
		f.client = loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		_, out := registerPasskey(t, f.client, ts, g, "key")
		f.id = passkeyBilboID(t, g)
		f.url = ts.URL + "/api/auth/passkeys/" + out.Passkey.ID
		f.body = passkeyDeleteRequest{Password: passkeyBilboPassword}
	default:
		t.Fatalf("unknown route %q", route)
	}
	return f
}

var v041SelfDeleteRoutes = []struct{ name, route string }{
	{"turn off authenticator app", "totp"},
	{"remove passkey", "passkey"},
}

func TestV041SelfDeleteOfADeletedAccountIsToldToSignIn(t *testing.T) {
	for _, r := range v041SelfDeleteRoutes {
		t.Run(r.name, func(t *testing.T) {
			f := newV041SelfDeleteFixture(t, r.route)
			other, err := gauntlet.OpenStore(f.backend.Memory, gauntlet.Options{})
			if err != nil {
				t.Fatal(err)
			}
			f.backend.arm(func() {
				if _, err := other.DeleteUser(f.id); err != nil {
					t.Errorf("the other process's DeleteUser: %v", err)
				}
			})

			resp := deleteJSON(t, f.client, f.url, f.body)
			raw, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if f.backend.armed() {
				t.Fatalf("the request saved nothing, so the account was never deleted under it (status %d %s): the window was not reached", resp.StatusCode, raw)
			}
			if _, ok := f.g.deps.Users.Get(f.id); ok {
				t.Fatal("the account survived the other process's delete")
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", resp.StatusCode, raw)
			}
			p := decodeProblem(t, raw)
			if p.Type != problemTypeBase+"sign-in-required" {
				t.Errorf("problem type = %q, want class sign-in-required", p.Type)
			}
			if p.Status != http.StatusUnauthorized {
				t.Errorf("body status = %d, want 401", p.Status)
			}
			if p.Detail != "sign in first" {
				t.Errorf("detail = %q, want %q", p.Detail, "sign in first")
			}
			for _, internal := range []string{"no such user", "gauntlet:", "persist:"} {
				if strings.Contains(string(raw), internal) {
					t.Errorf("body = %s, carries internal error text %q", raw, internal)
				}
			}
			for _, c := range resp.Cookies() {
				if c.Name == testCookieName && c.Value != "" {
					t.Errorf("a session cookie %q was issued on the refusal", c.Name)
				}
			}
		})
	}
}

// The control: the same request with no deletion succeeds, so the test
// above reaches the route it means to.
func TestV041SelfDeleteControlSucceedsWithoutTheDeletion(t *testing.T) {
	for _, r := range v041SelfDeleteRoutes {
		t.Run(r.name, func(t *testing.T) {
			f := newV041SelfDeleteFixture(t, r.route)
			status, raw := readAll(t, deleteJSON(t, f.client, f.url, f.body))
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", status, raw)
			}
			if _, ok := f.g.deps.Users.Get(f.id); !ok {
				t.Fatal("the account is gone without anything deleting it")
			}
		})
	}
}
