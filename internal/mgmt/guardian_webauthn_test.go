package mgmt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

func TestRoamingUVSettingRoute(t *testing.T) {
	e := newClientsEnv(t)
	operator := mgmt.Caller{Kind: mgmt.Operator, UserID: "auth0|op"}
	call := func(caller mgmt.Caller, method, tenantName string, body any) (int, map[string]any) {
		t.Helper()
		path := "/api/system/tenants/" + tenantName + "/guardian/factors/webauthn-roaming/settings"
		w, _ := e.call(t, e.sys, caller, method, path, body, mgmt.RequireOperator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if method == "GET" {
				e.h.GetWebAuthnRoamingSettings(w, r, tenantName)
			} else {
				e.h.PutWebAuthnRoamingSettings(w, r, tenantName)
			}
		})).ServeHTTP)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := call(operator, "GET", "acme", nil); code != 200 || out["user_verification"] != "discouraged" || len(out) != 1 {
		t.Fatalf("default = %d %v", code, out)
	}
	for _, uv := range mfa.RoamingUVValues {
		if code, out := call(operator, "PUT", "acme", map[string]any{"user_verification": uv}); code != 200 || out["user_verification"] != uv {
			t.Fatalf("PUT %s = %d %v", uv, code, out)
		}
		if code, out := call(operator, "GET", "acme", nil); code != 200 || out["user_verification"] != uv {
			t.Fatalf("GET after %s = %d %v", uv, code, out)
		}
	}
	g, err := e.st.MFA().GetGuardian(context.Background(), e.tn.ID)
	if err != nil || string(g.Stored["webauthn-roaming/settings"]) != `{"user_verification":"required"}` || mfa.RoamingUV(g) != "required" {
		t.Fatalf("stored %s %v", g.Stored["webauthn-roaming/settings"], err)
	}
	for name, body := range map[string]any{
		"never":         map[string]any{"user_verification": "never"},
		"missing":       map[string]any{},
		"extra field":   map[string]any{"user_verification": "required", "other": true},
		"not a string":  map[string]any{"user_verification": true},
		"not an object": "[]",
	} {
		if code, out := call(operator, "PUT", "acme", body); code != 400 {
			t.Fatalf("%s = %d %v", name, code, out)
		}
	}
	if code, _ := call(operator, "GET", "nobody", nil); code != 404 {
		t.Fatalf("unknown tenant = %d", code)
	}
	if code, _ := call(operator, "PUT", e.sys.Name, map[string]any{"user_verification": "required"}); code != 403 {
		t.Fatalf("system tenant = %d", code)
	}
	if code, _ := call(m2mCaller("update:guardian_factors", "read:guardian_factors"), "GET", "acme", nil); code != 403 {
		t.Fatalf("tenant token = %d", code)
	}
}
