package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Security-key user verification (spec section 6.1, LR33b-22). Auth0
// documents this setting only in its Dashboard, so D-0062 freezes the wire
// contract: GET/PUT
// /api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings
// with {"user_verification": "discouraged"|"preferred"|"required"}, kept in
// the Guardian settings store at "webauthn-roaming/settings".
const webauthnRoamingSettingsPath = "webauthn-roaming/settings"

// WebAuthnRoamingUVs are the accepted values, in ascending strictness.
var WebAuthnRoamingUVs = []string{"discouraged", "preferred", "required"}

// GetWebAuthnRoamingSettings answers the operator-only settings read. The
// default is "discouraged" ("Never"), which accepts FIDO-1 keys.
func (h *Handlers) GetWebAuthnRoamingSettings(w http.ResponseWriter, r *http.Request, tenantName string) {
	g, err := h.webauthnRoamingSettings(r, tenantName)
	if err != nil {
		Fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_verification": g})
}

// PutWebAuthnRoamingSettings replaces the setting. Only the three documented
// values are accepted; anything else is a 400.
func (h *Handlers) PutWebAuthnRoamingSettings(w http.ResponseWriter, r *http.Request, tenantName string) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		Fail(w, badBody("invalid body"))
		return
	}
	var body struct {
		UserVerification string `json:"user_verification"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&body) != nil {
		Fail(w, badBody("invalid body"))
		return
	}
	value := body.UserVerification
	if !slices.Contains(WebAuthnRoamingUVs, value) {
		Fail(w, badBody("user_verification must be one of %v", WebAuthnRoamingUVs))
		return
	}
	tn, err := h.Store.Tenants().GetByName(r.Context(), tenantName)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "webauthn roaming settings", err))
		return
	}
	// This is an operator route on the system host, so the request's resolved
	// tenant is the system one; the setting belongs to the tenant named in the
	// path, which is why it is written by ID rather than through
	// guardianWrite (that refuses a reserved tenant by design).
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		g, e := tx.MFA().GetGuardian(r.Context(), tn.ID)
		if e != nil {
			return e
		}
		if g.Stored == nil {
			g.Stored = map[string]json.RawMessage{}
		}
		raw, e := json.Marshal(map[string]any{"user_verification": value})
		if e != nil {
			return e
		}
		g.Stored[webauthnRoamingSettingsPath] = raw
		return tx.MFA().PutGuardian(r.Context(), g, g.Version)
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	h.domainEvent(r, "gd_tenant_update", nil, nil, nil)
	logDetails(r, "update Guardian configuration", "route", webauthnRoamingSettingsPath)
	writeJSON(w, http.StatusOK, map[string]any{"user_verification": value})
}

// webauthnRoamingSettings reads the stored value, defaulting to
// "discouraged" when it was never set.
func (h *Handlers) webauthnRoamingSettings(r *http.Request, tenantName string) (string, error) {
	tn, err := h.Store.Tenants().GetByName(r.Context(), tenantName)
	if errors.Is(err, store.ErrNotFound) {
		return "", errTenantNotFound
	}
	if err != nil {
		return "", internalError(h, r, "webauthn roaming settings", err)
	}
	g, err := h.Store.MFA().GetGuardian(r.Context(), tn.ID)
	if err != nil {
		return "", err
	}
	raw := g.Stored[webauthnRoamingSettingsPath]
	if len(raw) == 0 {
		return "discouraged", nil
	}
	var out struct {
		UserVerification string `json:"user_verification"`
	}
	if json.Unmarshal(raw, &out) != nil || !slices.Contains(WebAuthnRoamingUVs, out.UserVerification) {
		return "discouraged", nil
	}
	return out.UserVerification, nil
}
