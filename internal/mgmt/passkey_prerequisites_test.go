package mgmt_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

func TestPasskeyPrerequisitesRoute(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	mk := func(tn *store.Tenant, id string, passkey bool) {
		c := &store.Connection{TenantID: tn.ID, ID: id, Name: id[4:], Strategy: store.StrategyDatabase, CreatedAt: now,
			Extra: map[string]any{"authentication_methods": map[string]any{
				"password": map[string]any{"enabled": true}, "passkey": map[string]any{"enabled": passkey}}}}
		if err := e.st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	mk(e.tn, "con_passkeys", true)
	mk(e.tn, "con_passwords", false)
	globex, err := tenantsetup.UpsertTenant(ctx, e.st, "globex", now, func(tn *store.Tenant) error {
		tn.Domains, tn.CanonicalHost = []string{"login.globex.test"}, "login.globex.test"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mk(globex, "con_foreign", true)
	operator := mgmt.Caller{Kind: mgmt.Operator, UserID: "auth0|op"}
	get := func(caller mgmt.Caller, tenantName, id string) (int, map[string]any) {
		t.Helper()
		w, _ := e.call(t, e.sys, caller, "GET", "/api/system/tenants/"+tenantName+"/connections/"+id+"/passkey-prerequisites", nil,
			mgmt.RequireOperator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h.GetPasskeyPrerequisites(w, r, tenantName, id) })).ServeHTTP)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	want := func(body string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if code, out := get(operator, "acme", "con_passkeys"); code != 200 || !reflect.DeepEqual(out, want(`{"effective":false,"unmet":["identifier_first"]}`)) {
		t.Fatalf("default prompts = %d %v", code, out)
	}
	if err := e.st.HostedLogins().Put(ctx, &store.HostedLoginConfig{TenantID: e.tn.ID, Prompts: map[string]any{"identifier_first": true}}, 0); err != nil {
		t.Fatal(err)
	}
	if code, out := get(operator, "acme", "con_passkeys"); code != 200 || !reflect.DeepEqual(out, want(`{"effective":true,"unmet":[]}`)) {
		t.Fatalf("identifier first on = %d %v", code, out)
	}
	if code, out := get(operator, "acme", "con_passwords"); code != 200 || !reflect.DeepEqual(out, want(`{"effective":false,"unmet":["passkey_disabled"]}`)) {
		t.Fatalf("passkeys off = %d %v", code, out)
	}
	for _, tc := range []struct {
		name, tenant, id string
		caller           mgmt.Caller
		status           int
	}{
		{"foreign tenant's connection", "acme", "con_foreign", operator, 404},
		{"unknown connection", "acme", "con_missing", operator, 404},
		{"unknown tenant", "nobody", "con_passkeys", operator, 404},
		{"malformed connection ID", "acme", "nope", operator, 400},
		{"not an operator", "acme", "con_passkeys", m2mCaller("read:connections"), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, out := get(tc.caller, tc.tenant, tc.id); code != tc.status {
				t.Fatalf("status = %d %v, want %d", code, out, tc.status)
			}
		})
	}
}

// TestCustomDomainSharedRPID runs the R1 rule on POST and PATCH
// /custom-domains: a parent of the base domain is accepted by default and
// refused as 400 invalid_body under security.webauthn.restrict_shared_rp_ids.
func TestCustomDomainSharedRPID(t *testing.T) {
	for _, restrict := range []bool{false, true} {
		e := newClientsEnv(t)
		e.h.BaseDomain = "id.customer.example"
		e.h.RestrictSharedRPIDs = restrict
		e.h.Domains = customdomain.NewService(e.st, managementDNS{customdomain.ErrDNSNotFound}, customdomain.ServiceConfig{BaseDomain: "id.customer.example", OriginDomain: "origin.example.test", ManagedEnabled: true}, func() time.Time { return now }, rand.Reader)
		create := func(body string) (int, map[string]any) {
			w, out := e.call(t, e.tn, m2mCaller("create:custom_domains"), "POST", "/api/v2/custom-domains", body, e.h.CreateCustomDomain)
			m, _ := out.(map[string]any)
			return w.Code, m
		}
		code, out := create(`{"domain":"login.customer.example","type":"auth0_managed_certs","relying_party_identifier":"customer.example"}`)
		if restrict {
			if code != 400 || out["errorCode"] != "invalid_body" {
				t.Fatalf("restricted create = %d %v, want 400 invalid_body", code, out)
			}
		} else if code != 201 || out["relying_party_identifier"] != "customer.example" {
			t.Fatalf("default create = %d %v", code, out)
		}
		code, out = create(`{"domain":"auth.customer.example","type":"auth0_managed_certs"}`)
		if code != 201 {
			t.Fatalf("create without RP ID = %d %v", code, out)
		}
		id, _ := out["custom_domain_id"].(string)
		patch := func(body string) (int, map[string]any) {
			w, out := e.call(t, e.tn, m2mCaller("update:custom_domains"), "PATCH", "/api/v2/custom-domains/"+id, body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateCustomDomain(w, r, id) })
			m, _ := out.(map[string]any)
			return w.Code, m
		}
		code, out = patch(`{"relying_party_identifier":"customer.example"}`)
		if restrict {
			if code != 400 || out["errorCode"] != "invalid_body" {
				t.Fatalf("restricted patch = %d %v, want 400 invalid_body", code, out)
			}
		} else if code != 200 || out["relying_party_identifier"] != "customer.example" {
			t.Fatalf("default patch = %d %v", code, out)
		}
		for _, rp := range []string{"co.uk", "other.example", "example"} {
			if code, out := patch(`{"relying_party_identifier":"` + rp + `"}`); code != 400 || out["errorCode"] != "invalid_body" {
				t.Fatalf("restrict=%v patch %q = %d %v, want 400 invalid_body", restrict, rp, code, out)
			}
		}
		if code, out := patch(`{"relying_party_identifier":"auth.customer.example"}`); code != 200 {
			t.Fatalf("restrict=%v RP ID equal to the domain = %d %v", restrict, code, out)
		}
		if code, out := patch(`{"relying_party_identifier":null}`); code != 200 {
			t.Fatalf("restrict=%v null RP ID = %d %v", restrict, code, out)
		}
	}
}
