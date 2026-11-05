package rpid_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// fixture is two tenants on a shared deployment: acme with a canonical
// host, two operator aliases (one with an RP ID override) and three active
// custom domains; globex with its canonical host and one alias.
type fixture struct {
	st           store.Store
	acme, globex *store.Tenant
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	acme := &store.Tenant{
		ID: "ten_acme", Name: "acme", CanonicalHost: "acme.id.example.com",
		Domains:     []string{"acme.id.example.com", "alias.acme.test", "plain.acme.test", "x.mine.test"},
		DomainRPIDs: map[string]string{"alias.acme.test": "acme.test"},
	}
	globex := &store.Tenant{ID: "ten_globex", Name: "globex", CanonicalHost: "globex.id.example.com", Domains: []string{"globex.id.example.com", "app.partner.test"}}
	for _, tn := range []*store.Tenant{acme, globex} {
		if err := st.Tenants().Create(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []*store.CustomDomain{
		{TenantID: acme.ID, ID: "cd_login", Domain: "login.example.com"},
		{TenantID: acme.ID, ID: "cd_auth", Domain: "auth.example.org", RelyingPartyIdentifier: "example.org"},
		{TenantID: acme.ID, ID: "cd_bad", Domain: "bad.example.net", RelyingPartyIdentifier: "other.example"},
		{TenantID: acme.ID, ID: "cd_partner", Domain: "login.partner.test", RelyingPartyIdentifier: "partner.test"},
	} {
		d.Type, d.Generation, d.Status = "auth0_managed_certs", 1, "ready"
		if err := st.CustomDomains().Create(ctx, d); err != nil {
			t.Fatal(err)
		}
		if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: d.TenantID, DomainID: d.ID, Generation: 1, Kind: store.HostPublic, Active: true}); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	if acme, err = st.Tenants().Get(ctx, acme.ID); err != nil {
		t.Fatal(err)
	}
	if globex, err = st.Tenants().Get(ctx, globex.ID); err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, acme: acme, globex: globex}
}

func (f *fixture) policy(restrict bool) rpid.Policy {
	return rpid.Policy{BaseDomain: "id.example.com", SystemHost: "system.id.example.com", OriginSuffix: "origin.example.net", RestrictShared: restrict, Store: f.st}
}

// warnings captures slog's default logger for the test.
type warnings struct {
	mu      sync.Mutex
	records []slog.Record
}

func (w *warnings) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, r.Clone())
	return nil
}
func (w *warnings) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnings) WithGroup(string) slog.Handler      { return w }
func (w *warnings) warns() []map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []map[string]string
	for _, r := range w.records {
		if r.Level != slog.LevelWarn {
			continue
		}
		m := map[string]string{"msg": r.Message}
		r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
		out = append(out, m)
	}
	return out
}

func captureWarnings(t *testing.T) *warnings {
	t.Helper()
	w := &warnings{}
	prev := slog.Default()
	slog.SetDefault(slog.New(w))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return w
}

func TestRPIDFor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		tn   *store.Tenant
		host string
		want rpid.Result
	}{
		{"canonical", f.acme, "acme.id.example.com", rpid.Result{RPID: "acme.id.example.com", Origin: "https://acme.id.example.com", Kind: rpid.KindCanonical, Valid: true}},
		{"custom without override", f.acme, "login.example.com", rpid.Result{RPID: "login.example.com", Origin: "https://login.example.com", Kind: rpid.KindCustom, Valid: true}},
		{"custom with override", f.acme, "auth.example.org", rpid.Result{RPID: "example.org", Origin: "https://auth.example.org", Kind: rpid.KindCustom, Valid: true}},
		{"operator alias", f.acme, "plain.acme.test", rpid.Result{RPID: "plain.acme.test", Origin: "https://plain.acme.test", Kind: rpid.KindOperator, Valid: true}},
		{"operator alias with override", f.acme, "alias.acme.test", rpid.Result{RPID: "acme.test", Origin: "https://alias.acme.test", Kind: rpid.KindOperator, Valid: true}},
		{"shared parent allowed by default", f.acme, "login.partner.test", rpid.Result{RPID: "partner.test", Origin: "https://login.partner.test", Kind: rpid.KindCustom, Valid: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := captureWarnings(t)
			got, err := f.policy(false).For(ctx, tenant.Resolved{Tenant: tc.tn, Host: tc.host})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("For(%s) = %+v, want %+v", tc.host, got, tc.want)
			}
			if n := len(w.warns()); n != 0 {
				t.Fatalf("valid resolution logged %d warnings", n)
			}
		})
	}
	t.Run("stored RP ID not a suffix fails closed", func(t *testing.T) {
		w := captureWarnings(t)
		got, err := f.policy(false).For(ctx, tenant.Resolved{Tenant: f.acme, Host: "bad.example.net"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Valid || got.Problem == "" || got.Kind != rpid.KindCustom || got.RPID != "other.example" || got.Origin != "https://bad.example.net" {
			t.Fatalf("For(bad) = %+v, want invalid with a problem and the stored RP ID", got)
		}
		warns := w.warns()
		if len(warns) != 1 || warns[0]["tenant"] != f.acme.ID || warns[0]["host"] != "bad.example.net" {
			t.Fatalf("warnings = %v, want one WARN with tenant and host", warns)
		}
		for k, v := range warns[0] {
			if strings.Contains(strings.ToLower(k), "challenge") || strings.Contains(strings.ToLower(v), "challenge") {
				t.Fatalf("warning names a challenge: %v", warns[0])
			}
		}
	})
	t.Run("strict rule fails closed", func(t *testing.T) {
		w := captureWarnings(t)
		got, err := f.policy(true).For(ctx, tenant.Resolved{Tenant: f.acme, Host: "login.partner.test"})
		if err != nil {
			t.Fatal(err)
		}
		if got.Valid || got.Problem == "" {
			t.Fatalf("RP ID covering another tenant's host = %+v, want invalid", got)
		}
		if len(w.warns()) != 1 {
			t.Fatalf("warnings = %v", w.warns())
		}
	})
	t.Run("canonical stays its own host under the strict rule", func(t *testing.T) {
		got, err := f.policy(true).For(ctx, tenant.Resolved{Tenant: f.globex, Host: "globex.id.example.com"})
		if err != nil || !got.Valid || got.RPID != "globex.id.example.com" || got.Kind != rpid.KindCanonical {
			t.Fatalf("For(globex canonical) = %+v, %v", got, err)
		}
	})
	t.Run("host of another tenant", func(t *testing.T) {
		captureWarnings(t)
		got, err := f.policy(false).For(ctx, tenant.Resolved{Tenant: f.acme, Host: "app.partner.test"})
		if err != nil || got.Valid {
			t.Fatalf("For(foreign host) = %+v, %v, want invalid", got, err)
		}
	})
	t.Run("unknown host", func(t *testing.T) {
		captureWarnings(t)
		got, err := f.policy(false).For(ctx, tenant.Resolved{Tenant: f.acme, Host: "nowhere.example"})
		if err != nil || got.Valid {
			t.Fatalf("For(unknown) = %+v, %v, want invalid", got, err)
		}
	})
	t.Run("no tenant", func(t *testing.T) {
		got, err := f.policy(false).For(ctx, tenant.Resolved{Host: "acme.id.example.com"})
		if err != nil || got.Valid {
			t.Fatalf("For(no tenant) = %+v, %v, want invalid", got, err)
		}
	})
}

func TestRPIDHostWithPort(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "ten_sdk", Name: "sdk", CanonicalHost: "sdk.e2e.test:9543", Domains: []string{"sdk.e2e.test:9543", "alias.e2e.test:9543", "plain.e2e.test"},
		DomainRPIDs: map[string]string{"alias.e2e.test:9543": "e2e.test"}}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	tn, _ = st.Tenants().Get(ctx, tn.ID)
	p := rpid.Policy{Store: st}
	for _, tc := range []struct{ host, rpID, origin string }{
		{"SDK.e2e.test.:9543", "sdk.e2e.test", "https://sdk.e2e.test:9543"},
		{"sdk.e2e.test:9543", "sdk.e2e.test", "https://sdk.e2e.test:9543"},
		{"Alias.E2E.test:9543", "e2e.test", "https://alias.e2e.test:9543"},
		{"plain.e2e.test", "plain.e2e.test", "https://plain.e2e.test"},
		{"PLAIN.e2e.test.:443", "plain.e2e.test", "https://plain.e2e.test"},
	} {
		got, err := p.For(ctx, tenant.Resolved{Tenant: tn, Host: tc.host})
		if err != nil {
			t.Fatal(err)
		}
		if !got.Valid || got.RPID != tc.rpID || got.Origin != tc.origin {
			t.Errorf("For(%q) = %+v, want RP ID %q and origin %q", tc.host, got, tc.rpID, tc.origin)
		}
	}
}

func TestRPIDValidateShared(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name, host, rpID      string
		defaultOK, restrictOK bool
	}{
		{"parent of the base domain", "login.example.com", "example.com", true, false},
		{"the host itself", "login.example.com", "login.example.com", true, true},
		{"covers another tenant's host", "login.partner.test", "partner.test", true, false},
		{"covers only own hosts", "x.mine.test", "mine.test", true, true},
		{"covers the system host", "id.example.com", "id.example.com", true, false},
		{"covers the origin suffix", "a.origin.example.net", "example.net", true, false},
		{"public suffix", "login.example.co.uk", "co.uk", false, false},
		{"top-level domain", "login.example.com", "com", false, false},
		{"not an ancestor", "login.example.com", "other.example", false, false},
		{"sibling", "login.example.com", "auth.example.com", false, false},
		{"too long", "login.example.com", strings.Repeat("a", 250) + ".example.com", false, false},
		{"IP host", "127.0.0.1:8443", "127.0.0.1", false, false},
		{"empty", "login.example.com", "", false, false},
		{"host with port", "app.example.com:8443", "example.com", true, false},
		{"localhost alias", "localhost:8080", "localhost", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, restrict := range []bool{false, true} {
				err := f.policy(restrict).Validate(ctx, f.acme.ID, tc.host, tc.rpID)
				want := tc.defaultOK
				if restrict {
					want = tc.restrictOK
				}
				if (err == nil) != want {
					t.Fatalf("restrict=%v Validate(%q, %q) = %v, want ok=%v", restrict, tc.host, tc.rpID, err, want)
				}
				if err != nil && (!errors.Is(err, rpid.ErrInvalid) || !errors.Is(err, store.ErrInvalid)) {
					t.Fatalf("error %v is not rpid.ErrInvalid wrapping store.ErrInvalid", err)
				}
				if err != nil && err.Error() != rpid.ErrInvalid.Error() {
					t.Fatalf("error message %q is not the fixed message", err)
				}
			}
		})
	}
	t.Run("the strict rule fails closed without the store capability", func(t *testing.T) {
		p := f.policy(true)
		p.Store = unavailable{f.st}
		if err := p.Validate(ctx, f.acme.ID, "login.example.org", "example.org"); err == nil {
			t.Fatal("accepted without HostTenantsUnder")
		}
	})
}

type unavailable struct{ store.Store }

func (unavailable) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }
