// #99, part 4: DELETE /api/auth/users/{id}/totp and DELETE
// /api/auth/users/{id}/passkeys, when the account is deleted after the
// route has found it but before the clear is saved, answer 404
// not-found with a detail free of internal error text.
//
// The window is reached the way mutate_test.go's otherProcessBackend
// reaches it in the root package: the gate's store sits on a backend
// that, on the next Save, first lets a second store on the same
// document (another process) delete the account. The gate's store has
// already found the account and decided the clear; its Save then
// conflicts, it reloads, and the account is gone.
package gate

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

type contractFix99DeletingBackend struct {
	*persist.Memory
	mu         sync.Mutex
	beforeSave func()
}

func (b *contractFix99DeletingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.mu.Lock()
	f := b.beforeSave
	b.beforeSave = nil
	b.mu.Unlock()
	if f != nil {
		f()
	}
	return b.Memory.Save(ctx, payload, expect)
}

func (b *contractFix99DeletingBackend) arm(f func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.beforeSave = f
}

func (b *contractFix99DeletingBackend) armed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.beforeSave != nil
}

func TestContractFix99AdminClearOfADeletedAccountIs404(t *testing.T) {
	routes := []struct{ name, suffix string }{
		{"clear authenticator app", "/totp"},
		{"clear passkeys", "/passkeys"},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			backend := &contractFix99DeletingBackend{Memory: persist.NewMemory()}
			g := passkeyGate(t)
			g.deps.Users = openTrackedStore(t, backend)
			ts := newTestServer(t, g)
			admin := registerAdmin(t, ts, "admin", testAdminPassword)

			var target string
			if route.suffix == "/totp" {
				_ = postJSON(t, admin, ts.URL+"/api/auth/users",
					createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()
				totpEnrolAndConfirm(t, loggedInClient(t, ts, totpBobUsername, totpBobPassword), ts)
				target = totpBobID(t, g)
			} else {
				_ = postJSON(t, admin, ts.URL+"/api/auth/users",
					createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
				registerPasskey(t, loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword), ts, g, "key")
				target = passkeyBilboID(t, g)
			}

			other, err := gauntlet.OpenStore(backend.Memory, gauntlet.Options{})
			if err != nil {
				t.Fatal(err)
			}
			backend.arm(func() {
				if _, err := other.DeleteUser(target); err != nil {
					t.Errorf("the other process's DeleteUser: %v", err)
				}
			})

			status, raw := readAll(t, deleteJSON(t, admin, ts.URL+"/api/auth/users/"+target+route.suffix, adminStepUpRequest{Password: testAdminPassword}))
			if backend.armed() {
				t.Fatalf("the request saved nothing, so the account was never deleted under it (status %d %s): the window was not reached", status, raw)
			}
			if _, ok := g.deps.Users.Get(target); ok {
				t.Fatal("the account survived the other process's delete")
			}
			if status != http.StatusNotFound {
				t.Fatalf("status = %d, want 404: %s", status, raw)
			}
			p := decodeProblem(t, []byte(raw))
			if p.Type != problemTypeBase+classNotFound.anchor {
				t.Errorf("problem type = %q, want class not-found", p.Type)
			}
			for _, internal := range []string{"no such user", "gauntlet:", "persist:"} {
				if strings.Contains(p.Detail, internal) {
					t.Errorf("detail = %q, carries internal error text %q", p.Detail, internal)
				}
			}
		})
	}
}
