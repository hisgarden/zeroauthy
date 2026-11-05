package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

// The storetest suite skips a driver without WebAuthn; sqlstore must not be one.
func TestWebAuthnConformance(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			if ws, ok := any(s).(store.WebAuthnSupporter); !ok || !ws.WebAuthnSupported() || ws.CheckWebAuthnSupport(t.Context()) != nil {
				t.Fatal("sqlstore does not report WebAuthn support")
			}
			if _, err := s.WebAuthn().GetSnooze(t.Context(), "t", "u", store.SnoozePasskeyProgressive, "rp", time.Now()); errors.Is(err, store.ErrWebAuthnUnavailable) {
				t.Fatal("sqlstore WebAuthn is unavailable")
			}
			storetest.WebAuthn(t, func(t *testing.T) store.Store { return fresh(t) })
		})
	}
}

// HostTenantsUnder builds a LIKE pattern from the suffix; LIKE wildcards in
// the suffix must stay literal, and only whole labels match.
func TestWebAuthnHostTenantsUnderWildcards(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			ctx := t.Context()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t1", Name: "t1", Domains: []string{"login.example.com"}}))
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t2", Name: "t2", Domains: []string{"loginxexample.com"}}))
			mustExec(t, s, `INSERT INTO host_bindings (host,tenant_id,domain_id,generation,kind,active) VALUES ('a_b!c.example.org','t2','',0,'origin',false)`)
			for _, tc := range []struct {
				suffix string
				want   []string
			}{
				{"example.com", []string{"t1"}},
				{"_xample.com", []string{}},
				{"%.com", []string{}},
				{"%", []string{}},
				{"_", []string{}},
				{"example_com", []string{}},
				{"xexample.com", []string{}},
				{"loginxexample.com", []string{"t2"}},
				{"a_b!c.example.org", []string{"t2"}},
				{"b!c.example.org", []string{}},
				{"example.org", []string{"t2"}},
				{"!c.example.org", []string{}},
			} {
				got, err := s.WebAuthn().HostTenantsUnder(ctx, tc.suffix, 0)
				mustEvent(t, err)
				if got == nil || !slices.Equal(got, tc.want) {
					t.Errorf("HostTenantsUnder(%q) = %#v, want %#v", tc.suffix, got, tc.want)
				}
			}
		})
	}
}

// snapshotRows returns every row of table ordered by order, as column→value
// with byte slices turned into strings. phase goes into a comment so the
// query text differs across a migration (pgx caches plans by text, and a
// cached "SELECT *" must not change its result columns).
func snapshotRows(t *testing.T, s *Store, phase, table, order string) []map[string]any {
	t.Helper()
	rows, err := s.query(context.Background(), `SELECT * /* `+phase+` */ FROM `+table+` ORDER BY `+order)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		for i, c := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			m[strings.ToLower(c)] = v
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Catches a 0035 migration that rewrites existing rows: every column of the
// seeded sessions, clients, tenants and MFA rows keeps its value, and the
// only new columns are NULL.
func TestWebAuthnMigrationLeavesRows(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 34)
			mustExec(t, s, `INSERT INTO tenants (id,name,friendly_name,default_audience,allowed_logout_urls,enabled_locales,custom_text,session_lifetime,idle_session_lifetime,logo_url,primary_color,default_directory,created_at) VALUES ('t','t','Legacy','','["https://example.test/out"]','[]','{}',3600,600,'','','',1)`)
			mustExec(t, s, `INSERT INTO tenant_domains (domain,tenant_id,position) VALUES ('login.example.test','t',0)`)
			insertLegacyUser(t, s, &store.User{TenantID: "t", UserID: "auth0|u", Email: "u@example.test", Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "u"}}})
			mustExec(t, s, `INSERT INTO sessions (tenant_id,id,token_hash,user_id,connection,authenticated_at,client_ids,expires_at,idle_expires_at,created_at,updated_at,last_interacted_at,initial_ip,initial_user_agent,last_ip,last_user_agent,cookie_mode,origin,mfa_at) VALUES ('t','s1','h1','auth0|u','Database',5,'["spa"]',9999999999999,9999999999999,5,6,7,'198.51.100.1','ua','198.51.100.2','ua2','persistent','',8)`)
			mustExec(t, s, `INSERT INTO sessions (tenant_id,id,token_hash,user_id,connection,authenticated_at,client_ids,expires_at,idle_expires_at,created_at,updated_at,last_interacted_at,initial_ip,initial_user_agent,last_ip,last_user_agent,cookie_mode,origin) VALUES ('t','s2','h2','auth0|u','Database',5,'[]',9999999999999,9999999999999,5,6,7,'','','','','','')`)
			for _, id := range []string{"c1", "c2"} {
				c := &store.Client{TenantID: "t", ClientID: id, Name: "app " + id, AppType: "native", Callbacks: []string{"com.example.app://callback"}, CreatedAt: time.UnixMicro(42).UTC()}
				args, err := clientArgs(c)
				mustEvent(t, err)
				mustExec(t, s, `INSERT INTO clients (`+clientCols+`) VALUES (`+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+`)`, args...)
			}
			mustExec(t, s, `INSERT INTO mfa_authenticators (`+authCols+`,recovery_user) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				"t", "auth0|u", "webauthn-roaming|dev_1", "webauthn-roaming", "key", true, false, nil, 0, "", "", "", []byte("cred-1"), []byte("cose"), "example.test", 3, 9, 10, "", []byte(`{"aaguid":"x"}`), nil)
			mustExec(t, s, `INSERT INTO mfa_challenges (tenant_id,id,user_id,data,attempts,expires_at) VALUES ('t','ch1','auth0|u','{"TenantID":"t","ID":"ch1","UserID":"auth0|u","Kind":"webauthn","Challenge":"Y2hhbA=="}',1,9999999999999)`)

			tables := []struct{ name, order string }{
				{"tenants", "id"}, {"tenant_domains", "domain"}, {"users", "user_id"}, {"sessions", "id"}, {"clients", "client_id"},
				{"mfa_authenticators", "id"}, {"mfa_challenges", "id"}, {"host_bindings", "host"},
			}
			added := map[string]string{"tenants": "domain_rp_ids", "sessions": "auth_methods", "clients": "mobile"}
			before := map[string][]map[string]any{}
			for _, tb := range tables {
				before[tb.name] = snapshotRows(t, s, "before", tb.name, tb.order)
				if len(before[tb.name]) == 0 && tb.name != "host_bindings" {
					t.Fatalf("%s: nothing seeded", tb.name)
				}
			}
			mustEvent(t, s.Migrate(ctx))
			if v, err := s.SchemaVersion(ctx); err != nil || v != 35 {
				t.Fatalf("version %d err %v", v, err)
			}
			for _, tb := range tables {
				after := snapshotRows(t, s, "after", tb.name, tb.order)
				if len(after) != len(before[tb.name]) {
					t.Fatalf("%s: %d rows became %d", tb.name, len(before[tb.name]), len(after))
				}
				for i, row := range after {
					old := before[tb.name][i]
					for col, v := range row {
						if _, existed := old[col]; existed {
							continue
						}
						if col != added[tb.name] || v != nil {
							t.Fatalf("%s: new column %s = %v", tb.name, col, v)
						}
						delete(row, col)
					}
					if !reflect.DeepEqual(old, row) {
						t.Fatalf("%s row changed by migration:\n%v\n%v", tb.name, old, row)
					}
				}
			}
			var n int
			mustEvent(t, s.queryRow(ctx, `SELECT COUNT(*) FROM webauthn_snoozes`).Scan(&n))
			if n != 0 {
				t.Fatalf("%d snoozes after migration", n)
			}

			// The repositories read the old rows with the new fields absent.
			session, err := s.Sessions().Get(ctx, "t", "s1")
			mustEvent(t, err)
			if session.AuthMethods != nil || session.MFAAt.IsZero() || len(session.ClientIDs) != 1 {
				t.Fatalf("session = %+v", session)
			}
			client, err := s.Clients().Get(ctx, "t", "c1")
			mustEvent(t, err)
			if client.Mobile != nil || client.Name != "app c1" {
				t.Fatalf("client = %+v", client)
			}
			tenant, err := s.Tenants().Get(ctx, "t")
			mustEvent(t, err)
			if tenant.DomainRPIDs != nil || !slices.Equal(tenant.Domains, []string{"login.example.test"}) || tenant.FriendlyName != "Legacy" {
				t.Fatalf("tenant = %+v", tenant)
			}
			challenge, err := s.MFA().GetChallenge(ctx, "t", "ch1", time.UnixMicro(1))
			mustEvent(t, err)
			if challenge.Binding != nil || string(challenge.Challenge) != "chal" || challenge.Attempts != 1 {
				t.Fatalf("challenge = %+v", challenge)
			}
			got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "t", []byte("cred-1"))
			mustEvent(t, err)
			if got.ID != "webauthn-roaming|dev_1" || got.SignCount != 3 {
				t.Fatalf("authenticator = %+v", got)
			}
			// And the migrated schema takes the new writes.
			mustEvent(t, s.WebAuthn().CreatePasskey(ctx, &store.Authenticator{TenantID: "t", UserID: "auth0|u", ID: "passkey|dev_1", Type: "passkey", CredentialID: []byte("cred-2")}, 20))
			mustEvent(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "t", UserID: "auth0|u", Kind: store.SnoozePasskeyProgressive, ScopeKey: "example.test", Until: time.UnixMicro(99).UTC()}))
			client.Mobile = &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "ABCDE12345", AppBundleIdentifier: "com.example.app"}}
			mustEvent(t, s.Clients().Update(ctx, client))
			tenant.DomainRPIDs = map[string]string{"login.example.test": "example.test"}
			mustEvent(t, s.Tenants().Update(ctx, tenant))
		})
	}
}

// MySQL commits DDL implicitly: a process that died part way through 0035
// leaves version 34, and the next Migrate finishes it.
func TestWebAuthnMySQLMigrationResume35(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		if name != "mysql" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			s := openAtVersion(t, mk(t), 34)
			ms, err := s.migrations()
			mustEvent(t, err)
			for _, m := range ms {
				if m.version == 35 {
					for _, stmt := range m.statements[:4] {
						_, err = s.exec(t.Context(), stmt)
						mustEvent(t, err)
					}
				}
			}
			mustEvent(t, s.Migrate(t.Context()))
			mustEvent(t, s.Migrate(t.Context()))
			version, err := s.SchemaVersion(t.Context())
			mustEvent(t, err)
			if version != 35 {
				t.Fatal(version)
			}
			mustEvent(t, s.CheckSchema(t.Context()))
		})
	}
}

// Ten writers race for the last free passkey slot on separate pool
// connections (PostgreSQL and MySQL run them concurrently); the locked user
// row admits exactly one.
func TestWebAuthnCreatePasskeyLimitAcrossConnections(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			s := mustOpen(t, dsn)
			other := mustOpenRaw(t, dsn)
			ctx := t.Context()
			mustEvent(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			mustEvent(t, s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
			passkey := func(i string) *store.Authenticator {
				return &store.Authenticator{TenantID: "t", UserID: "u", ID: "passkey|dev_" + i, Type: "passkey", CredentialID: []byte("cred-" + i)}
			}
			for i := range 19 {
				mustEvent(t, s.WebAuthn().CreatePasskey(ctx, passkey(fmt.Sprint(i)), 20))
			}
			errs := make(chan error, 10)
			for i := range 10 {
				w := s.WebAuthn()
				if i%2 == 1 {
					w = other.WebAuthn()
				}
				go func() { errs <- w.CreatePasskey(ctx, passkey(fmt.Sprintf("race-%d", i)), 20) }()
			}
			wins := 0
			deadline := time.After(30 * time.Second)
			for range 10 {
				select {
				case err := <-errs:
					switch {
					case err == nil:
						wins++
					case !errors.Is(err, store.ErrPrecondition):
						t.Fatal(err)
					}
				case <-deadline:
					t.Fatal("concurrent CreatePasskey calls did not all return")
				}
			}
			var n int
			mustEvent(t, s.queryRow(ctx, `SELECT COUNT(*) FROM mfa_authenticators WHERE tenant_id='t' AND user_id='u' AND type='passkey'`).Scan(&n))
			if wins != 1 || n != 20 {
				t.Fatalf("wins=%d passkeys=%d", wins, n)
			}
		})
	}
}
