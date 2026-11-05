package mgmt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

// derivedPublicData are allowlisted public data keys the Management API
// does not return under their own names: a passkey's backup_eligible and
// backed_up become credential_device_type and credential_backed_up (spec
// §9.1), and attachment stays internal.
var derivedPublicData = []string{"attachment", "backed_up", "backup_eligible"}

// methodPublicData are the store.AuthenticatorPublicDataKeys the
// Management API accepts and returns as they are.
var methodPublicData = slices.DeleteFunc(slices.Clone(store.AuthenticatorPublicDataKeys), func(k string) bool { return slices.Contains(derivedPublicData, k) })

var errWebAuthnUnavailable = &Error{Status: http.StatusNotImplemented, Code: "webauthn_unavailable", Message: "Passkeys need a storage driver with the webauthn.v1 capability"}

// passkeyUserAgentMax bounds a passkey's user_agent, as hosted enrollment
// does.
const passkeyUserAgentMax = 512

// passkeyHandleMax is the WebAuthn user handle limit (64 bytes).
const passkeyHandleMax = 64

func methodJSON(a store.Authenticator) map[string]any {
	if a.Type == "passkey" {
		return passkeyJSON(a)
	}
	out := map[string]any{}
	if len(a.PublicData) > 0 {
		var data map[string]any
		_ = json.Unmarshal(a.PublicData, &data)
		for _, key := range methodPublicData {
			if v, ok := data[key]; ok {
				out[key] = v
			}
		}
	}
	for k, v := range map[string]any{"id": a.ID, "type": a.Type, "confirmed": a.Confirmed, "name": a.Name, "created_at": userTime(a.CreatedAt)} {
		out[k] = v
	}
	if a.PhoneMethod != "" {
		out["preferred_authentication_method"] = a.PhoneMethod
	}
	if !a.LastAuthAt.IsZero() {
		out["last_auth_at"] = userTime(a.LastAuthAt)
	}
	switch a.Type {
	case "email":
		out["email"] = a.Email
	case "phone":
		out["phone_number"] = a.Phone
		if a.PhoneMethod != "" {
			out["preferred_authentication_method"] = a.PhoneMethod
		}
	case "webauthn-roaming", "webauthn-platform":
		out["key_id"] = base64.RawURLEncoding.EncodeToString(a.CredentialID)
		out["public_key"] = base64.RawURLEncoding.EncodeToString(a.PublicKey)
		out["relying_party_identifier"] = a.RPID
	}
	return out
}

// passkeyJSON is a passkey with exactly the §9.1 members:
// credential_device_type is multi_device iff the credential is backup
// eligible, credential_backed_up its backup state, and there is no
// confirmed (passkeys are always usable).
func passkeyJSON(a store.Authenticator) map[string]any {
	var data map[string]any
	if len(a.PublicData) > 0 {
		_ = json.Unmarshal(a.PublicData, &data)
	}
	device := "single_device"
	if data["backup_eligible"] == true {
		device = "multi_device"
	}
	out := map[string]any{
		"id": a.ID, "type": a.Type, "name": a.Name, "created_at": userTime(a.CreatedAt),
		"key_id": base64.RawURLEncoding.EncodeToString(a.CredentialID), "public_key": base64.RawURLEncoding.EncodeToString(a.PublicKey),
		"relying_party_identifier": a.RPID, "credential_device_type": device, "credential_backed_up": data["backed_up"] == true,
	}
	for _, key := range []string{"aaguid", "identity_user_id", "user_agent", "user_handle", "transports"} {
		if v, ok := data[key]; ok {
			out[key] = v
		}
	}
	if !a.LastAuthAt.IsZero() {
		out["last_auth_at"] = userTime(a.LastAuthAt)
	}
	return out
}

// rpHostname checks a relying_party_identifier: a bare host name, no
// scheme, port, path or wildcard.
func rpHostname(rp string) bool {
	parsed, err := url.Parse("https://" + rp)
	return rp != "" && err == nil && parsed.Host == rp && parsed.Hostname() == rp && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && !strings.ContainsAny(rp, " *@")
}

// defaultPasskeyRPID is the RP ID of a passkey created without
// relying_party_identifier (LR33b-23): the effective RP ID of the tenant's
// default custom domain when that domain resolves to a usable one, else
// the canonical host's.
func (h *Handlers) defaultPasskeyRPID(r *http.Request) (string, error) {
	ctx := r.Context()
	tn := resolved(r)
	p := rpid.Policy{BaseDomain: h.BaseDomain, SystemHost: h.SystemHost, RestrictShared: h.RestrictSharedRPIDs, Store: h.Store}
	if h.Domains != nil {
		p.OriginSuffix = h.Domains.Reserved().OriginSuffix
	}
	id, err := h.Store.CustomDomains().GetDefault(ctx, tn.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCustomDomainRepositoryUnavailable) {
		return "", err
	}
	if id != "" {
		d, err := h.Store.CustomDomains().Get(ctx, tn.ID, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
		if d != nil {
			res, err := p.For(ctx, tenant.Resolved{Tenant: tn, Host: d.Domain})
			if err != nil {
				return "", err
			}
			if res.Valid {
				return res.RPID, nil
			}
		}
	}
	res, err := p.For(ctx, tenant.Resolved{Tenant: tn, Host: tn.CanonicalHost})
	if err != nil {
		return "", err
	}
	if !res.Valid {
		return "", badBody("the tenant has no usable relying party identifier; set relying_party_identifier")
	}
	return res.RPID, nil
}

// newPasskey builds the passkey a POST body describes for u (LR33b-23):
// key_id and a valid COSE public_key are required; relying_party_identifier
// defaults to rp; identity_user_id must name one of u's database
// identities and defaults to its own; user_handle defaults to the handle
// of u's existing passkeys (existing), else 32 new random bytes.
func (h *Handlers) newPasskey(u *store.User, b map[string]any, rp string, existing []store.Authenticator) (*store.Authenticator, error) {
	text := func(k string) string { v, _ := b[k].(string); return v }
	limits := webauthnrules.Limits
	a := &store.Authenticator{TenantID: u.TenantID, UserID: u.UserID, ID: "passkey|dev_" + secrets.RandomString(20), Type: "passkey", Name: text("name"),
		Confirmed: true, LastStep: -1, CreatedAt: h.now(), RPID: rp}
	var err error
	if a.CredentialID, err = decodeMFAKey(text("key_id")); err != nil || len(a.CredentialID) > limits.CredentialIDMax {
		return nil, badBody("key_id must be a base64url credential ID")
	}
	if a.PublicKey, err = decodeMFAKey(text("public_key")); err != nil || len(a.PublicKey) > limits.COSEMax {
		return nil, badBody("public_key must be a base64url COSE key")
	}
	if _, err = webauthn.ParseCOSEKey(a.PublicKey); err != nil {
		return nil, badBody("public_key must be a base64url COSE key")
	}
	if v, ok := b["relying_party_identifier"]; ok {
		a.RPID = strings.TrimSuffix(strings.ToLower(v.(string)), ".")
		if !rpHostname(a.RPID) || len(a.RPID) > limits.RPIDMax {
			return nil, badBody("relying_party_identifier must be a host name")
		}
	}
	if utf8.RuneCountInString(a.Name) > limits.NicknameMax {
		return nil, badBody("name must be at most %d characters", limits.NicknameMax)
	}
	var databases []string
	own := ""
	for _, id := range u.Identities {
		if id.Provider == store.StrategyDatabase {
			databases = append(databases, id.UserID)
			if own == "" && !id.Linked() {
				own = id.UserID
			}
		}
	}
	identityUserID := own
	if v, ok := b["identity_user_id"]; ok {
		identityUserID = v.(string)
		if !slices.Contains(databases, identityUserID) {
			return nil, badBody("identity_user_id must name one of the user's database identities")
		}
	}
	if identityUserID == "" {
		return nil, badBody("passkeys need a database identity")
	}
	handle := passkeyHandle(existing)
	if v, ok := b["user_handle"]; ok {
		h, err := decodeMFAKey(v.(string))
		if err != nil || len(h) > passkeyHandleMax {
			return nil, badBody("user_handle must be a base64url value of at most %d bytes", passkeyHandleMax)
		}
		handle = base64.RawURLEncoding.EncodeToString(h)
	}
	if handle == "" {
		raw := make([]byte, limits.UserHandleBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		handle = base64.RawURLEncoding.EncodeToString(raw)
	}
	if len(text("user_agent")) > passkeyUserAgentMax {
		return nil, badBody("user_agent must be at most %d bytes", passkeyUserAgentMax)
	}
	data := map[string]any{"backup_eligible": b["credential_device_type"] == "multi_device", "backed_up": b["credential_backed_up"] == true,
		"identity_user_id": identityUserID, "user_handle": handle}
	if v, ok := b["aaguid"]; ok {
		data["aaguid"] = strings.ToLower(v.(string))
	}
	for _, key := range []string{"user_agent", "transports"} {
		if v, ok := b[key]; ok {
			data[key] = v
		}
	}
	if a.PublicData, err = json.Marshal(data); err != nil {
		return nil, err
	}
	return a, nil
}

// passkeyHandle is the user handle of the user's first passkey (by
// creation time, then ID), which every later passkey reuses (LR33b-7), or
// "" when the user has none.
func passkeyHandle(list []store.Authenticator) string {
	var first *store.Authenticator
	handle := ""
	for i := range list {
		a := &list[i]
		var data struct {
			UserHandle string `json:"user_handle"`
		}
		if a.Type != "passkey" || json.Unmarshal(a.PublicData, &data) != nil || data.UserHandle == "" {
			continue
		}
		if first == nil || a.CreatedAt.Before(first.CreatedAt) || a.CreatedAt.Equal(first.CreatedAt) && a.ID < first.ID {
			first, handle = a, data.UserHandle
		}
	}
	return handle
}

func decodeMFAKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if v, e := enc.DecodeString(s); e == nil && len(v) > 0 {
			return v, nil
		}
	}
	return nil, store.ErrInvalid
}
func (h *Handlers) newMethod(tid, uid string, b map[string]any) (store.Authenticator, error) {
	text := func(k string) string { v, _ := b[k].(string); return v }
	a := store.Authenticator{TenantID: tid, UserID: uid, Type: text("type"), Name: text("name"), Confirmed: true, LastStep: -1, CreatedAt: h.now(), PhoneMethod: text("preferred_authentication_method")}
	a.ID = a.Type + "|dev_" + secrets.RandomString(20)
	var err error
	switch a.Type {
	case "totp":
		a.SealedSecret, err = mfa.SealTOTPSecret(h.Wrapper, tid, uid, a.ID, text("totp_secret"))
	case "email":
		a.Email = text("email")
		if !mfaEmail(a.Email) {
			err = store.ErrInvalid
		}
	case "phone":
		a.Phone = text("phone_number")
		if len(a.Phone) < 2 {
			err = store.ErrInvalid
		}
	case "webauthn-roaming":
		a.CredentialID, err = decodeMFAKey(text("key_id"))
		if err == nil {
			a.PublicKey, err = decodeMFAKey(text("public_key"))
		}
		a.RPID = text("relying_party_identifier")
		parsed, parseErr := url.Parse("https://" + a.RPID)
		// The stored key goes through the same parser the verifier uses, so
		// a key the Management API accepts is one assertions can be checked
		// against, and private material is refused with everything else.
		_, keyErr := webauthn.ParseCOSEKey(a.PublicKey)
		if a.RPID == "" || parseErr != nil || parsed.Host != a.RPID || parsed.Hostname() != a.RPID || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(a.RPID, " *@") || keyErr != nil {
			err = store.ErrInvalid
		}
	default:
		err = store.ErrInvalid
	}
	if utf8.RuneCountInString(a.Name) > 20 {
		return a, store.ErrInvalid
	}
	public := map[string]any{}
	for _, key := range methodPublicData {
		if v, ok := b[key]; ok {
			public[key] = v
		}
	}
	if len(public) > 0 {
		a.PublicData, _ = json.Marshal(public)
	}
	return a, err
}
func (h *Handlers) userMFA(w http.ResponseWriter, r *http.Request, route mfarules.RouteSchema, uid, id string, body any) {
	u, err := h.getUser(r, uid)
	if err != nil {
		Fail(w, err)
		return
	}
	tid := resolved(r).ID
	passkeyRP := ""
	if b, ok := body.(map[string]any); ok && route.Operation == "CreateAuthenticationMethods" && b["type"] == "passkey" {
		// Passkeys need webauthn.v1 (spec §10); without it the create is
		// 501 whatever the body says.
		supported, e := webauthnStorage(r.Context(), h.Store)
		if e != nil {
			Fail(w, internalError(h, r, "check WebAuthn storage", e))
			return
		}
		if !supported {
			Fail(w, errWebAuthnUnavailable)
			return
		}
		if rp, ok := b["relying_party_identifier"].(string); ok {
			passkeyRP = rp
		} else if passkeyRP, e = h.defaultPasskeyRPID(r); e != nil {
			var apiErr *Error
			if errors.As(e, &apiErr) {
				Fail(w, apiErr)
			} else {
				Fail(w, internalError(h, r, "resolve the default relying party identifier", e))
			}
			return
		}
	}
	switch route.Operation {
	case "GetAuthenticationMethods", "GetUserEnrollments":
		all, e := h.Store.MFA().ListAuthenticators(r.Context(), tid, uid)
		if e != nil {
			h.mfaFail(w, r, e)
			return
		}
		out := []any{}
		if route.Operation == "GetUserEnrollments" {
			// Passkeys are a first factor, not Guardian enrollments.
			for _, a := range all {
				if a.Confirmed && a.Type != "passkey" {
					view := enrollmentJSON(publicPhone(r, a))
					if a.Type == "webauthn-roaming" || a.Type == "webauthn-platform" {
						view["auth_method"] = a.Type
					}
					out = append(out, view)
				}
			}
			writeJSON(w, 200, out)
			return
		}
		page, per, totals, e := pageWithMinimum(r, 0)
		if e != nil {
			Fail(w, e)
			return
		}
		start := min(page*per, len(all))
		end := min(start+per, len(all))
		for _, a := range all[start:end] {
			out = append(out, methodJSON(publicPhone(r, a)))
		}
		if totals {
			writeJSON(w, 200, map[string]any{"authenticators": out, "start": page * per, "limit": per, "total": len(all)})
		} else {
			writeJSON(w, 200, out)
		}
		return
	case "GetAuthenticationMethod":
		a, e := h.Store.MFA().GetAuthenticator(r.Context(), tid, uid, id)
		if e != nil {
			h.mfaFail(w, r, e)
			return
		}
		writeJSON(w, 200, methodJSON(publicPhone(r, *a)))
		return
	}
	var out any
	status := 204
	code := "gd_unenroll"
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		// Same user lock as service enrollment/proof commits: replace-all,
		// regeneration and deletions serialize with concurrent authenticators.
		locked, e := tx.Users().GetForUpdate(r.Context(), tid, uid)
		if e != nil {
			return e
		}
		repo := tx.MFA()
		switch route.Operation {
		case "CreateAuthenticationMethods":
			if b := body.(map[string]any); b["type"] == "passkey" {
				existing, e := repo.ListAuthenticators(r.Context(), tid, uid)
				if e != nil {
					return e
				}
				a, e := h.newPasskey(locked, b, passkeyRP, existing)
				if e != nil {
					return e
				}
				// No user.updated: passkeys are not part of multifactor
				// (LR33b-33).
				switch e = tx.WebAuthn().CreatePasskey(r.Context(), a, webauthnrules.Limits.MaxPasskeys); {
				case errors.Is(e, store.ErrPrecondition):
					return badBody("the user already has the maximum of %d passkeys", webauthnrules.Limits.MaxPasskeys)
				case errors.Is(e, store.ErrConflict):
					return &Error{Status: http.StatusConflict, Code: "conflict", Message: "An authentication method with this key_id already exists"}
				case errors.Is(e, store.ErrWebAuthnUnavailable):
					return errWebAuthnUnavailable
				case e != nil:
					return e
				}
				out = passkeyJSON(*a)
				delete(out.(map[string]any), "last_auth_at")
				status = 201
				code = "gd_enrollment_complete"
				return nil
			}
			a, e := h.newMethod(tid, uid, body.(map[string]any))
			if e != nil {
				return e
			}
			if e = repo.CreateAuthenticator(r.Context(), &a); e != nil {
				return e
			}
			out = methodJSON(publicPhone(r, a))
			delete(out.(map[string]any), "confirmed")
			delete(out.(map[string]any), "last_auth_at")
			status = 201
			code = "gd_enrollment_complete"
		case "SetAuthenticationMethods":
			methods := []store.Authenticator{}
			for _, v := range body.([]any) {
				a, e := h.newMethod(tid, uid, v.(map[string]any))
				if e != nil {
					return e
				}
				methods = append(methods, a)
			}
			if e := repo.DeleteUserAuthenticators(r.Context(), tid, uid, nil); e != nil {
				return e
			}
			list := []any{}
			for _, a := range methods {
				if e := repo.CreateAuthenticator(r.Context(), &a); e != nil {
					return e
				}
				view := methodJSON(publicPhone(r, a))
				delete(view, "confirmed")
				delete(view, "last_auth_at")
				list = append(list, view)
			}
			out = list
			status = 200
			code = "gd_update_device_account"
			if e := repo.BumpRememberEpoch(r.Context(), tid, uid); e != nil {
				return e
			}
		case "UpdateAuthenticationMethod":
			a, e := repo.GetAuthenticator(r.Context(), tid, uid, id)
			if e != nil {
				return e
			}
			patch := body.(map[string]any)
			if _, ok := patch["preferred_authentication_method"]; ok && a.Type == "passkey" {
				return badBody("passkeys have no preferred_authentication_method")
			}
			if v, ok := patch["name"]; ok {
				if utf8.RuneCountInString(v.(string)) > 20 {
					return store.ErrInvalid
				}
				a.Name = v.(string)
			}
			if v, ok := patch["preferred_authentication_method"]; ok {
				a.PhoneMethod = v.(string)
			}
			if e = repo.UpdateAuthenticator(r.Context(), a); e != nil {
				return e
			}
			view := methodJSON(publicPhone(r, *a))
			for _, key := range []string{"credential_device_type", "credential_backed_up", "identity_user_id", "user_agent", "user_handle", "transports", "last_auth_at"} {
				delete(view, key)
			}
			out = view
			status = 200
			code = "gd_update_device_account"
		case "DeleteAuthenticationMethod":
			a, e := repo.GetAuthenticator(r.Context(), tid, uid, id)
			if e != nil {
				return e
			}
			if e := repo.DeleteAuthenticator(r.Context(), tid, uid, id); e != nil {
				return e
			}
			if a.Type == "passkey" {
				// A passkey is not MFA: remembered MFA browsers stay valid.
				return nil
			}
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "DeleteAuthenticationMethods", "DeleteUserAuthenticators":
			if e := repo.DeleteUserAuthenticators(r.Context(), tid, uid, nil); e != nil {
				return e
			}
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "DeleteUserMultifactor":
			types := []string{}
			switch id {
			case "google-authenticator":
				types = []string{"totp"}
			case "duo":
				types = []string{"duo"}
			default:
				return badBody("invalid multifactor provider")
			}
			if e := repo.DeleteUserAuthenticators(r.Context(), tid, uid, types); e != nil {
				return e
			}
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "CreateUserRememberBrowser":
			code = "gd_update_device_account"
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "CreateUserRecoveryCode":
			all, e := repo.ListAuthenticators(r.Context(), tid, uid)
			if e != nil {
				return e
			}
			old := ""
			hasFactor := false
			for _, a := range all {
				if a.Confirmed && a.Type != "recovery-code" && a.Type != "passkey" {
					hasFactor = true
				}
				if a.Type == "recovery-code" {
					old = a.CodeHash
				}
			}
			if !hasFactor {
				return badBody("A confirmed authentication method is required")
			}
			raw := mfa.NewRecoveryCode()
			if e = repo.ReplaceRecoveryCode(r.Context(), tid, uid, old, secrets.HashToken(raw), h.now()); e != nil {
				return e
			}
			out = map[string]any{"recovery_code": raw}
			status = 200
			code = "gd_update_device_account"
		default:
			return errMFAMissing
		}
		return nil
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	h.domainEvent(r, code, u, nil, nil)
	logDetails(r, "manage user authentication methods", "user_id", uid, "operation", route.Operation)
	if status == 204 {
		w.WriteHeader(status)
	} else {
		writeJSON(w, status, out)
	}
}
func enrollmentJSON(a store.Authenticator) map[string]any {
	id := a.ID
	if _, v, ok := strings.Cut(id, "|"); ok {
		id = v
	}
	out := map[string]any{"id": id, "status": "confirmed", "identifier": a.Email, "enrolled_at": userTime(a.CreatedAt)}
	if a.Name != "" {
		out["name"] = a.Name
	}
	if a.Phone != "" {
		out["phone_number"] = a.Phone
		out["identifier"] = a.Phone
	}
	if !a.LastAuthAt.IsZero() {
		out["last_auth"] = userTime(a.LastAuthAt)
	}
	return out
}
func (h *Handlers) guardianEnrollment(w http.ResponseWriter, r *http.Request, id string, remove bool) {
	// An indexed tenant-scoped lookup by enrollment ID; never an unscoped search
	// or a walk over the tenant's users.
	tid := resolved(r).ID
	a, err := h.Store.MFA().GetAuthenticatorByEnrollmentID(r.Context(), tid, id)
	if err == nil && (!a.Confirmed || a.Type == "passkey") {
		// Passkeys are a first factor, never Guardian enrollments.
		err = store.ErrNotFound
	}
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	if !remove {
		writeJSON(w, 200, enrollmentJSON(publicPhone(r, *a)))
		return
	}
	var u *store.User
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		var e error
		if u, e = tx.Users().GetForUpdate(r.Context(), tid, a.UserID); e != nil {
			return e
		}
		if e = tx.MFA().DeleteAuthenticator(r.Context(), tid, a.UserID, a.ID); e != nil {
			return e
		}
		return tx.MFA().BumpRememberEpoch(r.Context(), tid, a.UserID)
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	h.domainEvent(r, "gd_unenroll", u, nil, nil)
	logDetails(r, "delete Guardian enrollment", "user_id", a.UserID)
	w.WriteHeader(204)
}

func publicPhone(r *http.Request, a store.Authenticator) store.Authenticator {
	if !tenantrules.PhoneSettingsOf(resolved(r)).DisableSMSObfuscation && a.Phone != "" {
		a.Phone = phone.Mask(a.Phone)
	}
	return a
}
