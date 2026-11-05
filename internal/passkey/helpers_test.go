package passkey_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const (
	tid    = "ten_acme"
	host   = "acme.id.example.com"
	origin = "https://" + host
	dbConn = "Username-Password-Authentication"
)

// clock is an injected, settable clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

type env struct {
	ctx   context.Context
	st    store.Store
	clock *clock
	svc   *passkey.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: tid, Name: "acme", CanonicalHost: host, Domains: []string{host}}
	if err := st.Tenants().Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	clk := &clock{now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	policy := rpid.Policy{BaseDomain: "id.example.com", SystemHost: "system.id.example.com", Store: st}
	return &env{ctx: ctx, st: st, clock: clk, svc: passkey.New(st, policy, clk.Now)}
}

// user creates a database user u<n> with an email.
func (e *env) user(t *testing.T, id string) *store.User {
	t.Helper()
	u := &store.User{TenantID: tid, UserID: "auth0|" + id, Email: id + "@example.com", Identities: []store.Identity{{Connection: dbConn, Provider: store.StrategyDatabase, UserID: id}}}
	if err := e.st.Users().Create(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := e.st.Users().Get(e.ctx, tid, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func hosted(p passkey.Purpose, uid string) passkey.Binding {
	return passkey.Binding{Purpose: p, RPID: host, Origins: []string{origin}, TxnID: "txn-1", CookieHash: "cookie-hash-1", UserID: uid}
}

func native(p passkey.Purpose, uid string) passkey.Binding {
	return passkey.Binding{Purpose: p, RPID: host, Origins: []string{origin, "android:apk-key-hash:abc"}, ClientID: "client-1", Realm: dbConn, Organization: "org_1", UserID: uid}
}

func (e *env) issue(t *testing.T, b passkey.Binding) *passkey.Issued {
	t.Helper()
	iss, err := e.svc.Issue(e.ctx, tid, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func (e *env) take(t *testing.T, iss *passkey.Issued, b passkey.Binding) []byte {
	t.Helper()
	ch, err := e.svc.Take(e.ctx, tid, iss.ID, b)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// enroll registers a new passkey for u with auth through the service and
// returns the stored row.
func (e *env) enroll(t *testing.T, u *store.User, auth *webauthntest.Authenticator) *store.Authenticator {
	t.Helper()
	b := hosted(passkey.PurposePasskeyRegister, u.UserID)
	iss := e.issue(t, b)
	opts, err := e.svc.CreationOptions(e.ctx, tid, u, passkey.Display(u, nil), host, passkey.Progressive, iss.Challenge, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := auth.Create(opts, origin)
	ch := e.take(t, iss, b)
	a, err := e.svc.Enroll(e.ctx, tid, u, u.Identities[0].UserID, raw, ch, b, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// assertion runs a passkey-login challenge through auth and returns the
// response and the taken challenge.
func (e *env) assertion(t *testing.T, auth *webauthntest.Authenticator, b passkey.Binding) ([]byte, []byte) {
	t.Helper()
	iss := e.issue(t, b)
	opts := e.svc.RequestOptions(b.RPID, iss.Challenge, 0)
	raw := auth.Get(opts, origin)
	return raw, e.take(t, iss, b)
}

func publicData(t *testing.T, a *store.Authenticator) map[string]any {
	t.Helper()
	m := map[string]any{}
	if len(a.PublicData) > 0 {
		if err := json.Unmarshal(a.PublicData, &m); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func handleOf(t *testing.T, a *store.Authenticator) []byte {
	t.Helper()
	s, _ := publicData(t, a)["user_handle"].(string)
	h, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("user_handle %q: %v", s, err)
	}
	return h
}

// storedPasskey inserts a passkey row for uid directly.
func (e *env) storedPasskey(t *testing.T, uid, id, rp string, cred []byte) *store.Authenticator {
	t.Helper()
	a := &store.Authenticator{TenantID: tid, UserID: uid, ID: "passkey|dev_" + id, Type: "passkey", Confirmed: true, CredentialID: cred, PublicKey: webauthntest.New(webauthntest.Options{}).PublicKeyCOSE(), RPID: rp, CreatedAt: e.clock.Now(),
		PublicData: []byte(`{"user_handle":"` + base64.RawURLEncoding.EncodeToString([]byte("handle-"+uid)) + `","transports":["internal","hybrid"]}`)}
	if err := e.st.WebAuthn().CreatePasskey(e.ctx, a, 0); err != nil {
		t.Fatal(err)
	}
	return a
}

func reason(err error) string { return webauthn.Reason(err) }
