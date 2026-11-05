package mgmt_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// oldWebAuthnPlugin is a storage plugin without webauthn.v1: the gRPC
// client answers ErrWebAuthnUnavailable and drops the new fields (Task 6).
type oldWebAuthnPlugin struct{ store.Store }

func (oldWebAuthnPlugin) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }
func (oldWebAuthnPlugin) CheckWebAuthnSupport(context.Context) error {
	return store.ErrWebAuthnUnavailable
}
func (oldWebAuthnPlugin) WebAuthnSupported() bool { return false }

func TestClientMobileAndPasskeyGrant(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	fp := strings.TrimSuffix(strings.Repeat("0A:", 32), ":")
	mobile := map[string]any{
		"ios":     map[string]any{"team_id": "A1B2C3D4E5", "app_bundle_identifier": "com.acme.app"},
		"android": map[string]any{"app_package_name": "com.acme.app", "sha256_cert_fingerprints": []any{fp}},
	}
	out := e.mustCreate(t, map[string]any{"name": "Native", "app_type": "native", "grant_types": []string{clientrules.GrantPasskey, clientrules.GrantRefreshToken}, "mobile": mobile})
	id := out["client_id"].(string)
	if !jsonEqual(out["mobile"], mobile) || !jsonEqual(out["grant_types"], []any{clientrules.GrantPasskey, clientrules.GrantRefreshToken}) {
		t.Fatalf("created = %v", out)
	}
	c, err := e.st.Clients().Get(ctx, e.tn.ID, id)
	if err != nil || c.Mobile == nil || c.Mobile.IOS == nil || c.Mobile.IOS.TeamID != "A1B2C3D4E5" || c.Mobile.IOS.AppBundleIdentifier != "com.acme.app" ||
		c.Mobile.Android == nil || c.Mobile.Android.AppPackageName != "com.acme.app" || len(c.Mobile.Android.SHA256CertFingerprints) != 1 {
		t.Fatalf("stored = %+v, %v", c, err)
	}
	get := func() map[string]any {
		t.Helper()
		_, out := e.call(t, e.tn, m2mCaller("read:clients"), "GET", "/api/v2/clients/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.GetClient(w, r, id, mgmtapi.GetClientParams{})
		})
		return out.(map[string]any)
	}
	if got := get(); !jsonEqual(got["mobile"], mobile) {
		t.Fatalf("get mobile = %v", got["mobile"])
	}
	// PATCH replaces mobile; null clears it.
	ios := map[string]any{"ios": map[string]any{"team_id": "Z9Y8X7W6V5", "app_bundle_identifier": "com.acme.other"}}
	if rec, out := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"mobile": ios}); rec.Code != 200 || !jsonEqual(out["mobile"], ios) {
		t.Fatalf("patch mobile = %d %s", rec.Code, rec.Body)
	}
	if rec, out := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"name": "Renamed"}); rec.Code != 200 || !jsonEqual(out["mobile"], ios) {
		t.Fatalf("unrelated patch lost mobile = %d %s", rec.Code, rec.Body)
	}
	if rec, out := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"mobile": nil}); rec.Code != 200 || out["mobile"] != nil {
		t.Fatalf("clear mobile = %d %s", rec.Code, rec.Body)
	}
	if c, _ := e.st.Clients().Get(ctx, e.tn.ID, id); c.Mobile != nil {
		t.Fatalf("cleared mobile stored: %+v", c.Mobile)
	}
	// Validation per ClientMobile*.
	for name, m := range map[string]any{
		"not an object":    "ios",
		"unknown member":   map[string]any{"windows": map[string]any{}},
		"unknown ios key":  map[string]any{"ios": map[string]any{"team": "A1B2C3D4E5"}},
		"bad team id":      map[string]any{"ios": map[string]any{"team_id": "abc"}},
		"bad bundle id":    map[string]any{"ios": map[string]any{"app_bundle_identifier": "no spaces allowed"}},
		"bad package":      map[string]any{"android": map[string]any{"app_package_name": "1acme"}},
		"bad fingerprint":  map[string]any{"android": map[string]any{"sha256_cert_fingerprints": []any{"0A:0B"}}},
		"no fingerprints":  map[string]any{"android": map[string]any{"sha256_cert_fingerprints": []any{}}},
		"fingerprint type": map[string]any{"android": map[string]any{"sha256_cert_fingerprints": "0A"}},
	} {
		rec, _ := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Bad " + name, "app_type": "native", "mobile": m})
		if rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// The passkey grant is for first-party applications.
	rec, _ := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Partner", "app_type": "native", "is_first_party": false,
		"third_party_security_mode": "permissive", "grant_types": []string{clientrules.GrantPasskey}})
	wantError(t, rec, 400, "invalid_body")

	// An old plugin keeps mobile ignored: accepted, not validated, not
	// returned, so the response matches what a later read shows.
	e.h.Store = oldWebAuthnPlugin{e.st}
	rec, old := e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Old", "app_type": "native", "mobile": mobile})
	if rec.Code != 201 || old["mobile"] != nil {
		t.Fatalf("old plugin create = %d %s", rec.Code, rec.Body)
	}
	if c, _ := e.st.Clients().Get(ctx, e.tn.ID, old["client_id"].(string)); c.Mobile != nil {
		t.Fatalf("old plugin stored mobile: %+v", c.Mobile)
	}
	rec, _ = e.create(t, m2mCaller(allClientScopes...), map[string]any{"name": "Old invalid", "app_type": "native", "mobile": map[string]any{"ios": map[string]any{"team_id": "abc"}}})
	if rec.Code != 201 {
		t.Fatalf("old plugin validated mobile: %d %s", rec.Code, rec.Body)
	}
	oid := old["client_id"].(string)
	rec, patched := e.call(t, e.tn, m2mCaller(allClientScopes...), "PATCH", "/api/v2/clients/"+oid, map[string]any{"mobile": mobile}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClient(w, r, oid) })
	if rec.Code != 200 || patched.(map[string]any)["mobile"] != nil {
		t.Fatalf("old plugin patch = %d %s", rec.Code, rec.Body)
	}
}
