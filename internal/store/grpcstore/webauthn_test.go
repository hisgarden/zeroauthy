package grpcstore

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

var _ store.WebAuthnSupporter = (*Client)(nil)

func TestWebAuthnCapabilityNegotiated(t *testing.T) {
	c := inProcess(t)
	if err := c.CheckWebAuthnSupport(context.Background()); err != nil || !c.WebAuthnSupported() {
		t.Fatalf("webauthn.v1 not negotiated: %v", err)
	}
	// The storetest WebAuthn suite passes over gRPC (it skips only for a
	// driver that has not negotiated the capability, asserted above).
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "WebAuthn")
}

// webauthnFixture is a passkey whose opaque bytes are not valid UTF-8.
func webauthnFixture(tid, uid string, now time.Time) *store.Authenticator {
	return &store.Authenticator{TenantID: tid, UserID: uid, ID: "passkey|dev_k1", Type: "passkey", Name: "key", Confirmed: true,
		CredentialID: []byte{0x00, 0xff, 'C', 'R', 'E', 'D', '-', 'I', 'D', 0x80}, PublicKey: []byte{0xa5, 0x01, 0x02}, RPID: "a.example.test",
		PublicData: []byte(`{"backup_eligible":true,"backed_up":false,"user_handle":"USER-HANDLE-b64"}`), CreatedAt: now}
}

func TestOldPluginWebAuthnUnavailable(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	backing := memory.New()
	c := serveEventsFaults(t, backing, &eventsFaults{webauthnMissing: true})
	if c.WebAuthnSupported() {
		t.Fatal("old plugin reports WebAuthn support")
	}
	if err := c.CheckWebAuthnSupport(ctx); !errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("probe: %v", err)
	}

	// Every WebAuthn method answers ErrWebAuthnUnavailable.
	w := c.WebAuthn()
	u := &store.User{TenantID: "t", UserID: "p"}
	calls := map[string]func() error{
		"GetAuthenticatorByCredentialID": func() error { _, err := w.GetAuthenticatorByCredentialID(ctx, "t", []byte("c")); return err },
		"CreatePasskey":                  func() error { return w.CreatePasskey(ctx, webauthnFixture("t", "u", now), 20) },
		"CreateUserWithPasskey":          func() error { return w.CreateUserWithPasskey(ctx, u, webauthnFixture("t", "p", now)) },
		"AcceptAssertion":                func() error { return w.AcceptAssertion(ctx, "t", "u", "passkey|dev_k1", 1, true, now) },
		"MovePasskeys":                   func() error { return w.MovePasskeys(ctx, "t", "u", "v", "") },
		"PutSnooze": func() error {
			return w.PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "t", UserID: "u", Kind: store.SnoozePasskeyLocal, ScopeKey: "k", Until: now})
		},
		"GetSnooze":        func() error { _, err := w.GetSnooze(ctx, "t", "u", store.SnoozePasskeyLocal, "k", now); return err },
		"HostTenantsUnder": func() error { _, err := w.HostTenantsUnder(ctx, "example.test", 0); return err },
		"PurgeWebAuthn":    func() error { _, err := w.PurgeWebAuthn(ctx, now, 0); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, store.ErrWebAuthnUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A transaction handle shares the latched answer.
	if err := c.WithTx(ctx, func(tx store.Store) error {
		if _, err := tx.WebAuthn().GetSnooze(ctx, "t", "u", store.SnoozePasskeyLocal, "k", now); !errors.Is(err, store.ErrWebAuthnUnavailable) {
			t.Fatalf("tx get snooze: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The new record fields are dropped on write: the plugin never sees
	// them, and the caller's value is left as it was.
	tenant := &store.Tenant{ID: "t", Name: "t", Domains: []string{"login.example.test"}, DomainRPIDs: map[string]string{"login.example.test": "example.test"}}
	if err := c.Tenants().Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if tenant.DomainRPIDs == nil {
		t.Fatal("caller's tenant was modified")
	}
	for _, uid := range []string{"u", "v"} {
		if err := c.Users().Create(ctx, &store.User{TenantID: "t", UserID: uid}); err != nil {
			t.Fatal(err)
		}
	}
	client := &store.Client{TenantID: "t", ClientID: "app", Name: "app", Mobile: &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "ABCDE12345", AppBundleIdentifier: "com.example.app"}}}
	if err := c.Clients().Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	session := &store.LoginSession{TenantID: "t", ID: "s", TokenHash: "h", UserID: "u", CreatedAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
		AuthMethods: []store.AuthMethod{{Name: "pwd", At: now}}}
	if err := c.Sessions().Create(ctx, session); err != nil {
		t.Fatal(err)
	}
	challenge := &store.MFAChallenge{TenantID: "t", ID: "ch", UserID: "u", Kind: "webauthn", Challenge: []byte("chal"), Binding: []byte(`{"purpose":"webauthn-assert"}`), ExpiresAt: now.Add(time.Minute)}
	if err := c.MFA().CreateChallenge(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if bt, err := backing.Tenants().Get(ctx, "t"); err != nil || bt.DomainRPIDs != nil {
		t.Fatalf("plugin tenant = %+v, %v", bt, err)
	}
	if bc, err := backing.Clients().Get(ctx, "t", "app"); err != nil || bc.Mobile != nil {
		t.Fatalf("plugin client = %+v, %v", bc, err)
	}
	if bs, err := backing.Sessions().Get(ctx, "t", "s"); err != nil || bs.AuthMethods != nil {
		t.Fatalf("plugin session = %+v, %v", bs, err)
	}
	if bch, err := backing.MFA().GetChallenge(ctx, "t", "ch", now); err != nil || bch.Binding != nil {
		t.Fatalf("plugin challenge = %+v, %v", bch, err)
	}

	// The fields are absent on read, even when the plugin returns them.
	if err := backing.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err := backing.Clients().Update(ctx, client); err != nil {
		t.Fatal(err)
	}
	session2 := *session
	session2.ID, session2.TokenHash = "s2", "h2"
	if err := backing.Sessions().Create(ctx, &session2); err != nil {
		t.Fatal(err)
	}
	challenge2 := *challenge
	challenge2.ID = "ch2"
	if err := backing.MFA().CreateChallenge(ctx, &challenge2); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func() (bool, error){
		"tenant get": func() (bool, error) {
			v, err := c.Tenants().Get(ctx, "t")
			return v != nil && v.DomainRPIDs != nil, err
		},
		"tenant by name": func() (bool, error) {
			v, err := c.Tenants().GetByName(ctx, "t")
			return v != nil && v.DomainRPIDs != nil, err
		},
		"tenant by domain": func() (bool, error) {
			v, err := c.Tenants().GetByDomain(ctx, "login.example.test")
			return v != nil && v.DomainRPIDs != nil, err
		},
		"tenant list": func() (bool, error) {
			v, err := c.Tenants().List(ctx)
			return len(v) != 1 || v[0].DomainRPIDs != nil, err
		},
		"client get": func() (bool, error) {
			v, err := c.Clients().Get(ctx, "t", "app")
			return v != nil && v.Mobile != nil, err
		},
		"client list": func() (bool, error) {
			v, _, err := c.Clients().List(ctx, "t", store.ClientFilter{}, store.Page{})
			return len(v) != 1 || v[0].Mobile != nil, err
		},
		"client page": func() (bool, error) {
			v, _, err := c.Clients().List(ctx, "t", store.ClientFilter{}, store.Page{Limit: 5})
			return len(v) != 1 || v[0].Mobile != nil, err
		},
		"session get": func() (bool, error) {
			v, err := c.Sessions().Get(ctx, "t", "s2")
			return v != nil && v.AuthMethods != nil, err
		},
		"session by hash": func() (bool, error) {
			v, err := c.Sessions().GetByTokenHash(ctx, "t", "h2")
			return v != nil && v.AuthMethods != nil, err
		},
		"session list": func() (bool, error) {
			v, err := c.Sessions().ListByUser(ctx, "t", "u")
			return len(v) != 2 || v[0].AuthMethods != nil || v[1].AuthMethods != nil, err
		},
		"challenge get": func() (bool, error) {
			v, err := c.MFA().GetChallenge(ctx, "t", "ch2", now)
			return v != nil && v.Binding != nil, err
		},
	} {
		if leaked, err := read(); err != nil || leaked {
			t.Errorf("%s: leaked=%v err=%v", name, leaked, err)
		}
	}

	// Existing MFA and phone calls keep working against the old plugin.
	if err := c.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "t", UserID: "u", ID: "totp|dev_1", Type: "totp", Name: "otp", SealedSecret: []byte("s"), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if list, err := c.MFA().ListAuthenticators(ctx, "t", "u"); err != nil || len(list) != 1 {
		t.Fatalf("authenticators = %v, %v", list, err)
	}
	if err := c.MFA().ConsumeChallenge(ctx, "t", "ch", now); err != nil {
		t.Fatal(err)
	}
	if err := c.Sessions().MarkMFA(ctx, "t", "s", now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Phone().ListPhoneProviders(ctx, "t"); err != nil {
		t.Fatalf("phone: %v", err)
	}
	if !c.PhoneSupported() || !c.MFASupported() {
		t.Fatal("MFA or phone support lost")
	}
}

// Passkeys are MFA rows: a plugin without MFA v1 has no WebAuthn either,
// even when it answers WebAuthnCapabilities.
func TestWebAuthnRequiresMFA(t *testing.T) {
	c := serveEventsFaults(t, memory.New(), &eventsFaults{mfaMissing: true})
	if c.WebAuthnSupported() {
		t.Fatal("WebAuthn advertised without MFA")
	}
	if _, err := c.WebAuthn().GetSnooze(context.Background(), "t", "u", store.SnoozePasskeyLocal, "k", time.Now()); !errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("get snooze: %v", err)
	}
}

// A transient probe failure is reported, not latched, and never silently
// drops the fields; the next call negotiates.
func TestWebAuthnFieldsTransientProbe(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	faults := &eventsFaults{}
	c := serveEventsFaults(t, memory.New(), faults)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	s := &store.LoginSession{TenantID: "t", ID: "s", TokenHash: "h", UserID: "u", CreatedAt: now, ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
		AuthMethods: []store.AuthMethod{{Name: "passkey", At: now}}}
	faults.webauthnProbe.Store(int32(codes.Unavailable))
	if err := c.Sessions().Create(ctx, s); err == nil || errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("create during probe failure: %v", err)
	}
	if err := c.Sessions().Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := c.Sessions().Get(ctx, "t", "s")
	if err != nil || len(got.AuthMethods) != 1 || got.AuthMethods[0].Name != "passkey" || !got.AuthMethods[0].At.Equal(now) {
		t.Fatalf("session = %+v, %v", got, err)
	}
}

// Challenge bytes, bindings, credential IDs and user handles cross the wire
// unchanged and never appear in the log output.
func TestWebAuthnCodecNotLogged(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	now := time.Now().UTC().Truncate(time.Microsecond)
	c := inProcess(t)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Users().Create(ctx, &store.User{TenantID: "a", UserID: "u"}); err != nil {
		t.Fatal(err)
	}
	pk := webauthnFixture("a", "u", now)
	if err := c.WebAuthn().CreatePasskey(ctx, pk, 20); err != nil {
		t.Fatal(err)
	}
	got, err := c.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", pk.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.CredentialID, pk.CredentialID) || !bytes.Equal(got.PublicKey, pk.PublicKey) || string(got.PublicData) != string(pk.PublicData) || !got.CreatedAt.Equal(now) || got.Type != "passkey" {
		t.Fatalf("passkey changed on the wire: %+v", got)
	}
	// The same credential ID in the tenant conflicts, over the wire too.
	if err := c.WebAuthn().CreatePasskey(ctx, pk, 20); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	signup := webauthnFixture("a", "new", now)
	signup.ID, signup.CredentialID = "passkey|dev_k2", []byte{0xfe, 'S', 'I', 'G', 'N', 'U', 'P', 0x01}
	if err := c.WebAuthn().CreateUserWithPasskey(ctx, &store.User{TenantID: "a", UserID: "new"}, signup); err != nil {
		t.Fatal(err)
	}
	if got, err := c.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", signup.CredentialID); err != nil || got.UserID != "new" {
		t.Fatalf("signup passkey = %+v, %v", got, err)
	}
	raw := []byte{0x00, 0x01, 0xfe, 0xff, 'R', 'A', 'W', '-', 'C', 'H', 'A', 'L', 'L', 'E', 'N', 'G', 'E'}
	binding := []byte(`{"purpose":"passkey-login","rp_id":"a.example.test","cookie_hash":"COOKIE-HASH-xyz"}`)
	if err := c.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "a", ID: "ch", UserID: "u", Kind: "webauthn-assert", Challenge: raw, Binding: binding, ExpiresAt: now.Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ch, err := c.MFA().GetChallenge(ctx, "a", "ch", now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ch.Challenge, raw) || !bytes.Equal(ch.Binding, binding) {
		t.Fatalf("challenge changed on the wire: %+v", ch)
	}
	if err := c.WebAuthn().AcceptAssertion(ctx, "a", "u", pk.ID, 5, true, now); err != nil {
		t.Fatal(err)
	}
	if err := c.WebAuthn().AcceptAssertion(ctx, "a", "u", pk.ID, 5, true, now); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("replayed counter: %v", err)
	}
	for _, secret := range []string{"RAW-CHALLENGE", "CRED-ID", "SIGNUP", "USER-HANDLE", "COOKIE-HASH"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("log output contains %q:\n%s", secret, logs.String())
		}
	}
}
