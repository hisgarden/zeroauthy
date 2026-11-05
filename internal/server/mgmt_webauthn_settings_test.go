package server

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// TestRoamingUVSettingRoute checks the operator-only security-key
// user-verification setting: the default, the accepted values, where it is
// stored, and the routes that must not reach it (spec section 6.1, LR33b-22).
func TestRoamingUVSettingRoute(t *testing.T) {
	// The Guardian settings write refuses a reserved tenant, so the setting is
	// exercised on a regular one.
	seed := mgmtSeed + `  - name: globex
    domains: [globex.example.test]
`
	h, st := newMgmtEnvSeed(t, seed, nil)
	ctx := context.Background()
	op, _ := operatorToken(t, st, "uv-op@example.test")
	path := "https://" + mgmtSystemHost + "/api/system/tenants/globex/guardian/factors/webauthn-roaming/settings"

	// Unset reads as the documented default.
	rec, out := sendRaw(h, "GET", path, op, nil)
	if rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"user_verification": "discouraged"}) {
		t.Fatalf("default = %d %v", rec.Code, out)
	}

	// Each accepted value round-trips.
	for _, value := range []string{"discouraged", "preferred", "required"} {
		rec, out := sendRaw(h, "PUT", path, op, map[string]any{"user_verification": value})
		if rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"user_verification": value}) {
			t.Fatalf("put %q = %d %v", value, rec.Code, out)
		}
		if rec, out := sendRaw(h, "GET", path, op, nil); rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"user_verification": value}) {
			t.Fatalf("get %q = %d %v", value, rec.Code, out)
		}
	}

	// The value lives in the Guardian settings store.
	tn, err := st.Tenants().GetByName(ctx, "globex")
	if err != nil {
		t.Fatal(err)
	}
	g, err := st.MFA().GetGuardian(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := g.Stored["webauthn-roaming/settings"]
	if !ok || !strings.Contains(string(raw), "required") {
		t.Fatalf("stored = %q", raw)
	}

	// Anything else is a 400 and leaves the value alone.
	for _, bad := range []string{"always", "", "Required"} {
		if rec, _ := sendRaw(h, "PUT", path, op, map[string]any{"user_verification": bad}); rec.Code != 400 {
			t.Fatalf("put %q = %d, want 400", bad, rec.Code)
		}
	}
	if rec, out := sendRaw(h, "GET", path, op, nil); rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"user_verification": "required"}) {
		t.Fatalf("value changed by a refused write: %d %v", rec.Code, out)
	}

	// Operator only: a tenant token and no token are refused.
	tok := m2mToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/")
	if rec, _ := sendRaw(h, "GET", path, tok, nil); rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("tenant token = %d", rec.Code)
	}
	if rec, _ := sendRaw(h, "GET", path, "", nil); rec.Code != 401 {
		t.Fatalf("no token = %d", rec.Code)
	}

	// Unknown tenant is 404.
	if rec, _ := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/nope/guardian/factors/webauthn-roaming/settings", op, nil); rec.Code != 404 {
		t.Fatalf("unknown tenant = %d", rec.Code)
	}
}

// TestRoamingUVNoV2Route: the setting is a zeroauthy extension on the system
// API only; no /api/v2 route exists for it.
func TestRoamingUVNoV2Route(t *testing.T) {
	h, _ := newMgmtEnv(t)
	tok := m2mToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/")
	path := "https://acme.example.test/api/v2/guardian/factors/webauthn-roaming/settings"
	if rec, _ := sendRaw(h, "GET", path, tok, nil); rec.Code == 200 {
		t.Fatal("/api/v2 route exists")
	}
}
