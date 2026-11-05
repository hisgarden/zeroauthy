package server

import (
	"context"
	"reflect"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestPasskeyPrerequisitesRoute checks the system route is wired through the
// generated router: operators read it on the system host, a tenant token
// does not reach it, and an unknown connection is 404.
func TestPasskeyPrerequisitesRoute(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Connection{TenantID: tn.ID, ID: "con_passkeys", Name: "passkeys", Strategy: store.StrategyDatabase,
		Extra: map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}}
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	op, _ := operatorToken(t, st, "op@example.test")
	path := "https://" + mgmtSystemHost + "/api/system/tenants/acme/connections/con_passkeys/passkey-prerequisites"
	rec, out := sendRaw(h, "GET", path, op, nil)
	if rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"effective": false, "unmet": []any{"identifier_first"}}) {
		t.Fatalf("operator = %d %v", rec.Code, out)
	}
	if rec, out := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/acme/connections/con_missing/passkey-prerequisites", op, nil); rec.Code != 404 {
		t.Fatalf("missing connection = %d %v", rec.Code, out)
	}
	tok := m2mToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/")
	if rec, out := sendRaw(h, "GET", path, tok, nil); rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("tenant token = %d %v", rec.Code, out)
	}
	if rec, _ := sendRaw(h, "GET", path, "", nil); rec.Code != 401 {
		t.Fatalf("no token = %d", rec.Code)
	}
}
