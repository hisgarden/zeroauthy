package mgmt

import (
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// GetPasskeyPrerequisites serves the system API's
// GET /api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites
// (D-0062, LR33b-1): whether passkeys are effective on the connection and
// which documented prerequisites are unmet, plus passkey_disabled when the
// connection has passkeys switched off. A connection of another tenant is
// 404, like a missing one.
func (h *Handlers) GetPasskeyPrerequisites(w http.ResponseWriter, r *http.Request, tenantName, id string) {
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	ctx := r.Context()
	tn, err := h.Store.Tenants().GetByName(ctx, tenantName)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "passkey prerequisites", err))
		return
	}
	conn, err := h.Store.Connections().Get(ctx, tn.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errConnectionNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "passkey prerequisites", err))
		return
	}
	var prompts map[string]any
	cfg, err := h.Store.HostedLogins().Get(ctx, tn.ID)
	switch {
	case err == nil:
		prompts = cfg.Prompts
	case !errors.Is(err, store.ErrNotFound):
		Fail(w, internalError(h, r, "passkey prerequisites", err))
		return
	}
	policy, unmet := connrules.Passkeys(conn, prompts)
	out := make([]string, 0, len(unmet)+1)
	for _, u := range unmet {
		out = append(out, string(u))
	}
	if !policy.Enabled {
		out = append(out, string(connrules.UnmetPasskeyDisabled))
	}
	writeJSON(w, http.StatusOK, map[string]any{"effective": policy.Effective, "unmet": out})
}
