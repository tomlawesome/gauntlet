package gate

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
)

type createTokenRequest struct {
	Name string `json:"name"`
	// Kind is optional; omitting it means a read-only API token -- the
	// default is the less privileged of the two, so a caller can never
	// end up with an ingest token by leaving the field out.
	Kind   string `json:"kind"`
	Device string `json:"device"`
}

// tokenResponse mirrors gauntlet.Token but never carries HashedValue --
// used for both the list endpoint and (with Value additionally set) the
// one-time creation response.
type tokenResponse struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Kind       gauntlet.TokenKind `json:"kind"`
	Device     string             `json:"device,omitempty"`
	CreatedAt  time.Time          `json:"createdAt"`
	LastUsedAt time.Time          `json:"lastUsedAt,omitzero"`
	// Value is the raw bearer token, set only by handleTokensCreate's
	// response -- it cannot be recovered afterward, only reissued as a
	// brand new token.
	Value string `json:"value,omitempty"`
}

// handleTokensCreate issues a new bearer token. The raw value is
// returned exactly once, in this response; the store itself never
// retains it, only its SHA-256 hash.
func (g *Gate) handleTokensCreate(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	// Trimmed first because the store trims it: a name of only spaces
	// would pass an untrimmed check and be issued with no name at all.
	if strings.TrimSpace(req.Name) == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "name is required", nil)
		return
	}

	kind := gauntlet.TokenKind(req.Kind)
	if req.Kind == "" {
		kind = gauntlet.TokenKindAPI
	}

	raw, tok, err := g.deps.Tokens.Create(req.Name, kind, req.Device, UserFromContext(r), g.now())
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case gauntlet.ErrTokenNotPersisted:
			// The message gateErrorMessages carries for this says what
			// to do about it; the generic one below does not.
			g.writeAuthError(w, r, err, http.StatusServiceUnavailable, classNotPersisted)
			return
		case gauntlet.ErrTokenKindInvalid, gauntlet.ErrTokenDeviceRequired,
			gauntlet.ErrTokenDeviceNotAllowed, gauntlet.ErrTokenDeviceInvalid,
			gauntlet.ErrTokenNameInvalid:
			// The caller's request is wrong, not the deployment's state,
			// and the message is safe to hand back: it names a field,
			// not anything about existing tokens.
			g.writeAuthError(w, r, err, http.StatusBadRequest, classInvalidRequest)
			return
		}
		g.logWarn(err.Error())
		writeProblem(w, status, classServerError, "unable to create token", nil)
		return
	}

	detail := "id=" + tok.ID + " kind=" + string(tok.Kind)
	if tok.Device != "" {
		detail += " device=" + tok.Device
	}
	g.audit(r, auditActor(r), "token.create", tok.Name, detail)
	writeJSON(w, http.StatusCreated, tokenResponse{
		ID:        tok.ID,
		Name:      tok.Name,
		Kind:      tok.Kind,
		Device:    tok.Device,
		CreatedAt: tok.CreatedAt,
		Value:     raw,
	})
}

// handleTokensList returns every token's metadata -- never the hash or
// raw value.
func (g *Gate) handleTokensList(w http.ResponseWriter, r *http.Request) {
	tokens := g.deps.Tokens.List()
	out := make([]tokenResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, tokenResponse{
			ID:         t.ID,
			Name:       t.Name,
			Kind:       t.Kind,
			Device:     t.Device,
			CreatedAt:  t.CreatedAt,
			LastUsedAt: t.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// handleTokensRevoke permanently deletes a token by ID. A 404 either
// means "already revoked" or "never existed" -- indistinguishable and
// both fine, same as gauntlet.TokenStore.Revoke's own error handling.
func (g *Gate) handleTokensRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := g.deps.Tokens.Revoke(id); err != nil {
		// Only a missing token is a 404. A failed save leaves the token
		// working, so telling the admin it is gone would leave a leaked
		// token live with nobody the wiser; writeAuthError logs it.
		if errors.Is(err, gauntlet.ErrTokenNotFound) {
			writeProblem(w, http.StatusNotFound, classNotFound, "no such token", nil)
			return
		}
		g.writeAuthError(w, r, err, http.StatusInternalServerError, classServerError)
		return
	}
	g.audit(r, auditActor(r), "token.revoke", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}
