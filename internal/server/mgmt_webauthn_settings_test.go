package server

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

// TestRoamingUVSettingRouteWired checks the Plan 33b security-key setting
// route through the generated system router: operators only, no /api/v2
// counterpart, and the hosted WebAuthn MFA paths are registered.
func TestRoamingUVSettingRouteWired(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, _ := operatorToken(t, st, "op@example.test")
	path := "https://" + mgmtSystemHost + "/api/system/tenants/acme/guardian/factors/webauthn-roaming/settings"
	if rec, out := sendRaw(h, "GET", path, op, nil); rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"user_verification": "discouraged"}) {
		t.Fatalf("GET = %d %v", rec.Code, out)
	}
	if rec, out := sendRaw(h, "PUT", path, op, map[string]any{"user_verification": "preferred"}); rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"user_verification": "preferred"}) {
		t.Fatalf("PUT = %d %v", rec.Code, out)
	}
	if rec, out := sendRaw(h, "PUT", path, op, map[string]any{"user_verification": "sometimes"}); rec.Code != 400 {
		t.Fatalf("bad PUT = %d %v", rec.Code, out)
	}
	tok := m2mToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/")
	if rec, out := sendRaw(h, "GET", path, tok, nil); rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("tenant token = %d %v", rec.Code, out)
	}
	if rec, _ := sendRaw(h, "GET", "https://acme.example.test/api/v2/guardian/factors/webauthn-roaming/settings", tok, nil); rec.Code != 404 {
		t.Fatalf("an /api/v2 route exists: %d", rec.Code)
	}
	for _, p := range []string{"/u/mfa-detect-browser-capabilities", "/u/mfa-webauthn-roaming-enrollment", "/u/mfa-webauthn-roaming-challenge", "/u/mfa-webauthn-change-key-nickname", "/u/mfa-webauthn-enrollment-success"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "https://acme.example.test"+p+"?state=missing", nil))
		if rec.Code == 404 || rec.Code == 405 {
			t.Fatalf("%s not routed: %d", p, rec.Code)
		}
	}
}
