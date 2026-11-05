package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// GetWebAuthnRoamingSettings serves the system API's
// GET /api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings
// (D-0062, LR33b-22): the tenant's security-key user-verification setting,
// "discouraged" until one is stored. Auth0 documents the setting only in
// its Dashboard, so there is no /api/v2 route.
func (h *Handlers) GetWebAuthnRoamingSettings(w http.ResponseWriter, r *http.Request, tenantName string) {
	tn, ok := h.roamingTenant(w, r, tenantName)
	if !ok {
		return
	}
	g, err := h.Store.MFA().GetGuardian(r.Context(), tn.ID)
	if err != nil {
		h.roamingFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_verification": mfa.RoamingUV(g)})
}

// PutWebAuthnRoamingSettings serves the system API's
// PUT /api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings:
// it replaces the setting with "discouraged", "preferred" or "required",
// stored in GuardianSettings.Stored["webauthn-roaming/settings"].
func (h *Handlers) PutWebAuthnRoamingSettings(w http.ResponseWriter, r *http.Request, tenantName string) {
	tn, ok := h.roamingTenant(w, r, tenantName)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<10+1))
	if err != nil || len(raw) > 4<<10 {
		Fail(w, badBody("invalid WebAuthn settings"))
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in struct {
		UV *string `json:"user_verification"`
	}
	if dec.Decode(&in) != nil || dec.More() || in.UV == nil || !slices.Contains(mfa.RoamingUVValues, *in.UV) {
		Fail(w, badBody("user_verification must be one of discouraged, preferred or required"))
		return
	}
	stored, _ := json.Marshal(map[string]string{"user_verification": *in.UV})
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		g, err := tx.MFA().GetGuardian(r.Context(), tn.ID)
		if err != nil {
			return err
		}
		if g.Stored == nil {
			g.Stored = map[string]json.RawMessage{}
		}
		g.Stored[mfa.RoamingSettingsKey] = stored
		return tx.MFA().PutGuardian(r.Context(), g, g.Version)
	})
	if err != nil {
		h.roamingFail(w, r, err)
		return
	}
	logDetails(r, "update WebAuthn security-key settings", "tenant", tn.Name, "user_verification", *in.UV)
	writeJSON(w, http.StatusOK, map[string]any{"user_verification": *in.UV})
}

// roamingTenant resolves the route's tenant. The system tenant has no MFA.
func (h *Handlers) roamingTenant(w http.ResponseWriter, r *http.Request, name string) (*store.Tenant, bool) {
	tn, err := h.Store.Tenants().GetByName(r.Context(), name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errTenantNotFound)
		return nil, false
	case err != nil:
		Fail(w, internalError(h, r, "WebAuthn settings", err))
		return nil, false
	case tn.Reserved:
		Fail(w, errSystemTenant)
		return nil, false
	}
	return tn, true
}

func (h *Handlers) roamingFail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrMFAUnavailable):
		Fail(w, errMFAUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errTenantNotFound)
	case errors.Is(err, store.ErrConflict):
		Fail(w, &Error{Status: 409, Code: "conflict", Message: "The MFA resource changed concurrently"})
	default:
		Fail(w, internalError(h, r, "WebAuthn settings", err))
	}
}
