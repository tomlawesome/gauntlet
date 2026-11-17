// An account deleted by an admin after a handler's own start-of-request
// read (#95): the store then reports gauntlet.ErrUserNotFound at the
// write. The handler answers it the way it answers an account that is
// gone at the start -- 401, sign-in-required, "sign in first" -- not a
// 500. Other store errors keep their own answers.
//
// The recovery-codes regenerate route has no named error writer to call
// and its mid-request race cannot be driven deterministically from the
// specification alone, so it is not covered here.
package gate

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tomlawesome/gauntlet"
)

type errorWriter func(g *Gate, w http.ResponseWriter, r *http.Request, err error)

var accountGoneWriters = []struct {
	name   string
	path   string
	writer errorWriter
	// conflictErr is a store error this writer answers 409.
	conflictErr error
}{
	{
		name: "passkey register finish",
		path: "/api/auth/passkeys/register/finish",
		writer: func(g *Gate, w http.ResponseWriter, r *http.Request, err error) {
			g.writePasskeyStoreError(w, r, err)
		},
		conflictErr: gauntlet.ErrPasskeyDuplicate,
	},
	{
		name: "totp confirm",
		path: "/api/auth/totp/confirm",
		writer: func(g *Gate, w http.ResponseWriter, r *http.Request, err error) {
			g.writeTOTPConfirmError(w, r, err)
		},
		conflictErr: gauntlet.ErrNoPendingTOTP,
	},
}

func callErrorWriter(g *Gate, path string, write errorWriter, err error) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	write(g, rec, req, err)
	return rec
}

func TestAccountGoneMidRequestIsToldToSignIn(t *testing.T) {
	g := passkeyGate(t)
	errs := map[string]error{
		"bare":    gauntlet.ErrUserNotFound,
		"wrapped": fmt.Errorf("saving the factor: %w", gauntlet.ErrUserNotFound),
	}
	for _, w := range accountGoneWriters {
		for kind, err := range errs {
			t.Run(w.name+"/"+kind, func(t *testing.T) {
				rec := callErrorWriter(g, w.path, w.writer, err)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
				}
				p := decodeProblem(t, rec.Body.Bytes())
				if p.Type != problemTypeBase+"sign-in-required" {
					t.Errorf("type = %q, want sign-in-required", p.Type)
				}
				if p.Status != http.StatusUnauthorized {
					t.Errorf("body status = %d, want 401", p.Status)
				}
				if p.Detail != "sign in first" {
					t.Errorf("detail = %q, want %q", p.Detail, "sign in first")
				}
			})
		}
	}
}

func TestAccountGoneMidRequestLeavesOtherErrorsAlone(t *testing.T) {
	g := passkeyGate(t)
	for _, w := range accountGoneWriters {
		t.Run(w.name+"/conflict", func(t *testing.T) {
			rec := callErrorWriter(g, w.path, w.writer, w.conflictErr)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
			}
		})
		t.Run(w.name+"/unknown", func(t *testing.T) {
			rec := callErrorWriter(g, w.path, w.writer, errors.New("x"))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
			}
		})
	}
}
