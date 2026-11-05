package seed

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// TestSeedDomainRPID: domains entries are a host or {host,
// relying_party_identifier} (Plan 33b R2), checked with the R1 rule.
func TestSeedDomainRPID(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	apply := func(raw string, opts ...Options) error {
		f, err := Parse([]byte(raw))
		if err != nil {
			return err
		}
		if err = f.CheckManagementAPI("id.example.test"); err != nil {
			return err
		}
		return Apply(ctx, st, f, fixedNow, testWrapper(t), opts...)
	}
	rpids := func(name string) map[string]string {
		tn, err := st.Tenants().GetByName(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		return tn.DomainRPIDs
	}
	seeded := `tenants:
  - name: acme
    domains:
      - plain.acme.test
      - {host: Login.Acme.Test., relying_party_identifier: ACME.test}
      - {host: "sdk.e2e.test:9543", relying_party_identifier: e2e.test}
      - {host: self.acme.test, relying_party_identifier: self.acme.test}
      - host: only-host.acme.test
`
	if err := apply(seeded); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	for _, h := range []string{"plain.acme.test", "login.acme.test", "sdk.e2e.test:9543", "self.acme.test", "only-host.acme.test"} {
		if b, err := st.CustomDomains().GetHost(ctx, h); err != nil || b.TenantID != tn.ID || b.Kind != store.HostOperator {
			t.Errorf("alias %s = %+v, %v", h, b, err)
		}
	}
	if got, want := rpids("acme"), map[string]string{"login.acme.test": "acme.test", "sdk.e2e.test:9543": "e2e.test"}; !maps.Equal(got, want) {
		t.Fatalf("DomainRPIDs = %v, want %v", got, want)
	}
	if err := apply("tenants: [{name: acme, friendly_name: Renamed}]"); err != nil {
		t.Fatal(err)
	}
	if got := rpids("acme"); len(got) != 2 {
		t.Fatalf("omitted domains dropped RP IDs: %v", got)
	}
	if err := apply("tenants: [{name: acme, domains: [plain.acme.test, login.acme.test]}]"); err != nil {
		t.Fatal(err)
	}
	if got := rpids("acme"); len(got) != 0 {
		t.Fatalf("plain domains kept RP IDs: %v", got)
	}

	for name, raw := range map[string]string{
		"not an ancestor":   `{host: login.acme.test, relying_party_identifier: other.test}`,
		"public suffix":     `{host: login.acme.co.uk, relying_party_identifier: co.uk}`,
		"IP alias":          `{host: "127.0.0.1:8443", relying_party_identifier: 127.0.0.1}`,
		"too long":          `{host: login.acme.test, relying_party_identifier: ` + strings.Repeat("a", 256) + `}`,
		"unknown key":       `{host: login.acme.test, rp_id: acme.test}`,
		"no host":           `{relying_party_identifier: acme.test}`,
		"sequence":          `[login.acme.test]`,
		"empty RP ID":       `{host: login.acme.test, relying_party_identifier: ""}`,
		"duplicate by case": `{host: PLAIN.acme.test, relying_party_identifier: acme.test}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte("tenants: [{name: other, domains: [plain.acme.test, " + raw + "]}]"))
			if err == nil {
				t.Fatalf("accepted %s", raw)
			}
			t.Log(err)
		})
	}
	t.Run("canonical host keeps its own RP ID", func(t *testing.T) {
		f, err := Parse([]byte("tenants: [{name: beta, domains: [{host: login.beta.test, relying_party_identifier: beta.test}]}]"))
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, memory.New(), f, fixedNow, testWrapper(t)); err == nil || !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("RP ID on the canonical host = %v, want invalid", err)
		}
	})
	t.Run("strict rule", func(t *testing.T) {
		shared := `tenants:
  - name: gamma
    domains:
      - gamma.alias.test
      - {host: login.gamma.test, relying_party_identifier: gamma.test}
      - {host: login.partner.test, relying_party_identifier: partner.test}
  - name: delta
    domains: [delta.alias.test, app.partner.test]
`
		strict := Options{RPIDs: rpid.Policy{BaseDomain: "id.example.test", RestrictShared: true}}
		if err := apply(shared, strict); err == nil || !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("RP ID covering another tenant's alias under the strict rule = %v", err)
		}
		if _, err := st.Tenants().GetByName(ctx, "gamma"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("failed seed left tenant gamma: %v", err)
		}
		if err := apply(shared); err != nil {
			t.Fatalf("default rule: %v", err)
		}
		if got := rpids("gamma"); got["login.partner.test"] != "partner.test" || got["login.gamma.test"] != "gamma.test" {
			t.Fatalf("gamma RP IDs = %v", got)
		}
		base := "tenants: [{name: gamma, domains: [gamma.alias.test, {host: login.gamma.test, relying_party_identifier: gamma.test}, {host: auth.example.test, relying_party_identifier: example.test}]}]"
		if err := apply(base, strict); err == nil {
			t.Fatal("RP ID covering the base domain accepted under the strict rule")
		}
		if err := apply(base); err != nil {
			t.Fatalf("parent of the base domain by default: %v", err)
		}
	})
}
