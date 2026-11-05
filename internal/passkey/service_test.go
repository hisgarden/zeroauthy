package passkey_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

func TestLoginResolvesCredentialUser(t *testing.T) {
	e := newEnv(t)
	u1 := e.user(t, "u1")
	e.user(t, "u2")
	auth := webauthntest.New(webauthntest.Options{BE: true, BS: true, Attachment: "cross-platform"})
	enrolled := e.enroll(t, u1, auth)

	// LR33b-16: the service never sees a typed identifier; the hosted page
	// may have shown u2's email, the credential's user is the user.
	b := hosted(passkey.PurposePasskeyLogin, "")
	auth.SignCount = 7
	raw, ch := e.assertion(t, auth, b)
	e.clock.Set(e.clock.Now().Add(time.Minute))
	res, err := e.svc.Login(e.ctx, tid, raw, ch, b)
	if err != nil {
		t.Fatal(err)
	}
	if res.User.UserID != u1.UserID || res.Method.ID != enrolled.ID || res.Assertion.SignCount != 7 || res.Assertion.Attachment != "cross-platform" {
		t.Fatalf("login = %+v / %+v / %+v", res.User, res.Method, res.Assertion)
	}
	stored, err := e.st.MFA().GetAuthenticator(e.ctx, tid, u1.UserID, enrolled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SignCount != 7 || !stored.LastAuthAt.Equal(e.clock.Now()) || publicData(t, stored)["backed_up"] != true {
		t.Fatalf("stored after login = %+v %s", stored, stored.PublicData)
	}
	if res.Method.SignCount != 7 || !res.Method.LastAuthAt.Equal(e.clock.Now()) {
		t.Fatalf("returned method not refreshed: %+v", res.Method)
	}

	// Native logins carry the realm: the user must have an identity there.
	nb := native(passkey.PurposePasskeyLogin, "")
	auth.SignCount = 8
	raw, ch = e.assertion(t, auth, nb)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, nb); err != nil {
		t.Fatalf("native login: %v", err)
	}
	nb.Realm = "other-db"
	auth.SignCount = 9
	raw, ch = e.assertion(t, auth, nb)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, nb); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("other realm = %v", err)
	}

	// Sign-count regression: ErrCeremony with reason sign_count.
	auth.SignCount = 3
	raw, ch = e.assertion(t, auth, b)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, b); !errors.Is(err, passkey.ErrCeremony) || reason(err) != webauthn.ReasonSignCount {
		t.Fatalf("regression = %v (%s)", err, reason(err))
	}

	// A credential stored under another RP ID is refused.
	other := webauthntest.New(webauthntest.Options{})
	e.storedPasskey(t, u1.UserID, "elsewhere", "login.example.com", other.CredentialID())
	raw, ch = e.assertion(t, other, b)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, b); !errors.Is(err, passkey.ErrCeremony) || reason(err) != webauthn.ReasonRPID {
		t.Fatalf("other rp_id = %v (%s)", err, reason(err))
	}

	// Unknown credentials and non-passkey WebAuthn credentials are the
	// generic failure.
	unknown := webauthntest.New(webauthntest.Options{})
	raw, ch = e.assertion(t, unknown, b)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("unknown credential = %v", err)
	}
	roaming := webauthntest.New(webauthntest.Options{})
	if err := e.st.MFA().CreateAuthenticator(e.ctx, &store.Authenticator{TenantID: tid, UserID: u1.UserID, ID: "webauthn-roaming|dev_k", Type: "webauthn-roaming", Confirmed: true, CredentialID: roaming.CredentialID(), PublicKey: roaming.PublicKeyCOSE(), RPID: host}); err != nil {
		t.Fatal(err)
	}
	raw, ch = e.assertion(t, roaming, b)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("MFA key as passkey = %v", err)
	}
	if _, err := e.svc.Login(e.ctx, tid, []byte(`{"id":`), ch, b); !errors.Is(err, passkey.ErrCeremony) || reason(err) != webauthn.ReasonParse {
		t.Fatalf("malformed = %v", err)
	}

	// A blocked user gets identity.ErrUserBlocked once the passkey verifies.
	blocked, _ := e.st.Users().Get(e.ctx, tid, u1.UserID)
	blocked.Blocked = true
	if err := e.st.Users().Update(e.ctx, blocked); err != nil {
		t.Fatal(err)
	}
	auth.SignCount = 20
	raw, ch = e.assertion(t, auth, b)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, b); !errors.Is(err, identity.ErrUserBlocked) || errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("blocked = %v", err)
	}
}

func TestEnrollLimitAndExclude(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "u1")
	var here, there [][]byte
	for i := range webauthnrules.Limits.MaxPasskeys {
		cred := []byte{byte(i), 'c', 'r', 'e', 'd'}
		rp := host
		if i%5 == 0 {
			rp = "login.example.com"
			there = append(there, cred)
		} else {
			here = append(here, cred)
		}
		e.storedPasskey(t, u.UserID, string(rune('a'+i)), rp, cred)
	}
	mfaKey := []byte("roaming-key")
	if err := e.st.MFA().CreateAuthenticator(e.ctx, &store.Authenticator{TenantID: tid, UserID: u.UserID, ID: "webauthn-roaming|dev_k", Type: "webauthn-roaming", Confirmed: true, CredentialID: mfaKey, PublicKey: []byte("cose"), RPID: host}); err != nil {
		t.Fatal(err)
	}
	b := hosted(passkey.PurposePasskeyRegister, u.UserID)
	iss := e.issue(t, b)
	opts, err := e.svc.CreationOptions(e.ctx, tid, u, passkey.Display(u, nil), host, passkey.Progressive, iss.Challenge, 0)
	if err != nil {
		t.Fatal(err)
	}
	var excluded [][]byte
	for _, d := range opts.Exclude {
		excluded = append(excluded, d.ID)
		if !bytes.Equal(d.ID, mfaKey) && !slices.Equal(d.Transports, []string{"internal", "hybrid"}) {
			t.Fatalf("transports = %v", d.Transports)
		}
	}
	want := append(slices.Clone(here), mfaKey)
	if len(excluded) != len(want) {
		t.Fatalf("excluded %d credentials, want %d", len(excluded), len(want))
	}
	for _, c := range want {
		if !slices.ContainsFunc(excluded, func(x []byte) bool { return bytes.Equal(x, c) }) {
			t.Fatalf("credential %q not excluded", c)
		}
	}
	for _, c := range there {
		if slices.ContainsFunc(excluded, func(x []byte) bool { return bytes.Equal(x, c) }) {
			t.Fatalf("credential %q of another RP ID excluded", c)
		}
	}

	// The 21st passkey is refused with the documented error key.
	raw := webauthntest.New(webauthntest.Options{}).Create(opts, origin)
	_, err = e.svc.Enroll(e.ctx, tid, u, "u1", raw, e.take(t, iss, b), b, "")
	if !errors.Is(err, passkey.ErrMaxPasskeys) || passkey.ErrorKey(err) != "passkey-enrollment-max-allowed-reached" {
		t.Fatalf("21st = %v (%q)", err, passkey.ErrorKey(err))
	}
	list, _ := e.st.MFA().ListAuthenticators(e.ctx, tid, u.UserID)
	count := 0
	for _, a := range list {
		if a.Type == "passkey" {
			count++
		}
	}
	if count != webauthnrules.Limits.MaxPasskeys {
		t.Fatalf("%d passkeys stored", count)
	}

	// Below the limit: a new passkey is stored with its public metadata,
	// and registering a credential the tenant already holds fails.
	v := e.user(t, "u2")
	auth := webauthntest.New(webauthntest.Options{BE: true, Attachment: "platform", Transports: []string{"internal"}, AAGUID: [16]byte{0xad, 0xce, 0x00, 0x02}})
	a := e.enroll(t, v, auth)
	pd := publicData(t, a)
	if a.Type != "passkey" || !a.Confirmed || a.RPID != host || !bytes.Equal(a.CredentialID, auth.CredentialID()) || !bytes.Equal(a.PublicKey, auth.PublicKeyCOSE()) ||
		pd["identity_user_id"] != "u2" || pd["backup_eligible"] != true || pd["backed_up"] != false || pd["attachment"] != "platform" ||
		pd["aaguid"] != "adce0002-0000-0000-0000-000000000000" || pd["user_agent"] == nil || !slices.Equal(anyStrings(pd["transports"]), []string{"internal"}) {
		t.Fatalf("enrolled = %+v %s", a, a.PublicData)
	}
	for k := range pd {
		if !slices.Contains(store.AuthenticatorPublicDataKeys, k) {
			t.Fatalf("public data key %q outside the allowlist", k)
		}
	}
	b = hosted(passkey.PurposePasskeyRegister, v.UserID)
	iss = e.issue(t, b)
	opts, _ = e.svc.CreationOptions(e.ctx, tid, v, passkey.Display(v, nil), host, passkey.Progressive, iss.Challenge, 0)
	raw = auth.Create(opts, origin)
	if _, err := e.svc.Enroll(e.ctx, tid, v, "u2", raw, e.take(t, iss, b), b, ""); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("duplicate credential = %v", err)
	}
	// Enrollment is bound to the challenge's user.
	b = hosted(passkey.PurposePasskeyRegister, u.UserID)
	iss = e.issue(t, b)
	raw = webauthntest.New(webauthntest.Options{}).Create(opts, origin)
	if _, err := e.svc.Enroll(e.ctx, tid, v, "u2", raw, e.take(t, iss, b), b, ""); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("other user's challenge = %v", err)
	}
}

func anyStrings(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func TestUserHandleReused(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "u1")
	b := hosted(passkey.PurposePasskeyRegister, u.UserID)
	iss := e.issue(t, b)
	opts, err := e.svc.CreationOptions(e.ctx, tid, u, passkey.Display(u, nil), host, passkey.Progressive, iss.Challenge, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.UserID) != webauthnrules.Limits.UserHandleBytes || bytes.Contains(opts.UserID, []byte("u1")) {
		t.Fatalf("new user's handle = %x", opts.UserID)
	}
	first := webauthntest.New(webauthntest.Options{})
	a1, err := e.svc.Enroll(e.ctx, tid, u, "u1", first.Create(opts, origin), e.take(t, iss, b), b, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handleOf(t, a1), opts.UserID) {
		t.Fatal("stored handle differs from the one the authenticator holds")
	}
	second := webauthntest.New(webauthntest.Options{})
	a2 := e.enroll(t, u, second)
	if !bytes.Equal(handleOf(t, a2), handleOf(t, a1)) || !bytes.Equal(second.UserHandle(), opts.UserID) {
		t.Fatal("second passkey did not reuse the user's handle")
	}
	// Both passkeys log in (the stored handles match the authenticators').
	for _, auth := range []*webauthntest.Authenticator{first, second} {
		b := hosted(passkey.PurposePasskeyLogin, "")
		raw, ch := e.assertion(t, auth, b)
		if _, err := e.svc.Login(e.ctx, tid, raw, ch, b); err != nil {
			t.Fatal(err)
		}
	}
	// Another user gets their own handle.
	v := e.user(t, "u2")
	other := e.enroll(t, v, webauthntest.New(webauthntest.Options{}))
	if bytes.Equal(handleOf(t, other), handleOf(t, a1)) || len(handleOf(t, other)) != webauthnrules.Limits.UserHandleBytes {
		t.Fatal("users share a handle")
	}
}

func TestCreationOptionsUserNames(t *testing.T) {
	full := &store.User{UserID: "auth0|u", Email: "ann@example.com", PhoneNumber: "+15551234567", Username: "ann"}
	conn := func(extra map[string]any, requiresUsername bool) *store.Connection {
		return &store.Connection{Name: dbConn, Strategy: store.StrategyDatabase, RequiresUsername: requiresUsername, Extra: extra}
	}
	flexible := func(email, phone, username bool) map[string]any {
		attr := func(on bool) map[string]any { return map[string]any{"identifier": map[string]any{"active": on}} }
		return map[string]any{"attributes": map[string]any{"email": attr(email), "phone_number": attr(phone), "username": attr(username)}}
	}
	cases := []struct {
		name string
		u    *store.User
		c    *store.Connection
		want passkey.UserDisplay
	}{
		{"email first", full, conn(nil, true), passkey.UserDisplay{Name: "ann@example.com", DisplayName: "ann@example.com"}},
		{"no connection", full, nil, passkey.UserDisplay{Name: "ann@example.com", DisplayName: "ann@example.com"}},
		{"phone before username", full, conn(flexible(false, true, true), false), passkey.UserDisplay{Name: "+15551234567", DisplayName: "+15551234567"}},
		{"username only", full, conn(flexible(false, false, true), false), passkey.UserDisplay{Name: "ann", DisplayName: "ann"}},
		{"missing email value", &store.User{PhoneNumber: "+15551234567", Username: "ann"}, conn(flexible(true, true, true), false), passkey.UserDisplay{Name: "+15551234567", DisplayName: "+15551234567"}},
		{"name wins display", &store.User{Email: "ann@example.com", Name: "Ann Example", Username: "ann"}, conn(nil, true), passkey.UserDisplay{Name: "ann@example.com", DisplayName: "Ann Example"}},
		{"legacy username connection", &store.User{Username: "ann", Name: "Ann"}, conn(nil, true), passkey.UserDisplay{Name: "ann", DisplayName: "Ann"}},
	}
	for _, c := range cases {
		if got := passkey.Display(c.u, c.c); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}

	e := newEnv(t)
	u := e.user(t, "u1")
	u.Name = "Una"
	ch := bytes.Repeat([]byte{7}, webauthnrules.Limits.ChallengeBytes)
	for _, tc := range []struct {
		kind       passkey.EnrollKind
		attachment string
	}{{passkey.Signup, ""}, {passkey.Progressive, ""}, {passkey.Local, "platform"}} {
		user := u
		if tc.kind == passkey.Signup {
			user = &store.User{TenantID: tid, Email: "new@example.com"}
		}
		opts, err := e.svc.CreationOptions(e.ctx, tid, user, passkey.Display(user, conn(nil, false)), host, tc.kind, ch, 0)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := opts.JSON()
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Challenge string `json:"challenge"`
			RP        struct{ ID, Name string }
			User      struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			}
			PubKeyCredParams []struct {
				Alg int64 `json:"alg"`
			} `json:"pubKeyCredParams"`
			Timeout                int64  `json:"timeout"`
			Attestation            string `json:"attestation"`
			AuthenticatorSelection struct {
				Attachment       string `json:"authenticatorAttachment"`
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		}
		if err := json.Unmarshal(doc, &got); err != nil {
			t.Fatal(err)
		}
		wantName, wantDisplay := "u1@example.com", "Una"
		if tc.kind == passkey.Signup {
			wantName, wantDisplay = "new@example.com", "new@example.com"
		}
		var algs []int64
		for _, p := range got.PubKeyCredParams {
			algs = append(algs, p.Alg)
		}
		if got.RP.ID != host || got.RP.Name != host || got.User.Name != wantName || got.User.DisplayName != wantDisplay ||
			got.Challenge != base64.RawURLEncoding.EncodeToString(ch) || !slices.Equal(algs, []int64{-8, -7, -257}) || got.Attestation != "none" ||
			got.Timeout != webauthnrules.Limits.HostedChallengeTTL.Milliseconds() || got.AuthenticatorSelection.ResidentKey != "required" ||
			got.AuthenticatorSelection.UserVerification != "preferred" || got.AuthenticatorSelection.Attachment != tc.attachment {
			t.Fatalf("kind %d: %s", tc.kind, doc)
		}
	}
	// An empty display is filled from the user.
	opts, err := e.svc.CreationOptions(e.ctx, tid, u, passkey.UserDisplay{}, host, passkey.Progressive, ch, time.Minute)
	if err != nil || opts.UserName != "u1@example.com" || opts.DisplayName != "Una" || opts.Timeout != time.Minute {
		t.Fatalf("defaulted display: %+v, %v", opts, err)
	}
	// Request options: discoverable, preferred UV, frozen native timeout.
	req := e.svc.RequestOptions(host, ch, webauthnrules.Limits.NativeTimeout)
	if req.RPID != host || len(req.Allow) != 0 || req.UserVerification != "preferred" || req.Timeout != webauthnrules.Limits.NativeTimeout || !bytes.Equal(req.Challenge, ch) {
		t.Fatalf("request options = %+v", req)
	}
}

func TestEffective(t *testing.T) {
	e := newEnv(t)
	tn, _ := e.st.Tenants().Get(e.ctx, tid)
	conn := &store.Connection{TenantID: tid, ID: "con_1", Name: dbConn, Strategy: store.StrategyDatabase,
		Extra: map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}, "password": map[string]any{"enabled": true}}}}
	res := tenant.Resolved{Tenant: tn, Host: host}
	policy, rp, ok, err := e.svc.Effective(e.ctx, tid, res, conn)
	if err != nil || ok || policy.Effective {
		t.Fatalf("identifier_first off: %+v %v %v", policy, ok, err)
	}
	if err := e.st.HostedLogins().Put(e.ctx, &store.HostedLoginConfig{TenantID: tid, Prompts: map[string]any{"universal_login_experience": "new", "identifier_first": true}}, 0); err != nil {
		t.Fatal(err)
	}
	policy, rp, ok, err = e.svc.Effective(e.ctx, tid, res, conn)
	if err != nil || !ok || !policy.Effective || policy.ChallengeUI != "both" || rp.RPID != host || rp.Origin != origin || !rp.Valid {
		t.Fatalf("effective: %+v %+v %v %v", policy, rp, ok, err)
	}
	if _, rp, ok, _ = e.svc.Effective(e.ctx, tid, tenant.Resolved{Tenant: tn, Host: "unknown.example.org"}, conn); ok || rp.Valid {
		t.Fatalf("unknown host effective: %+v", rp)
	}
	if _, _, ok, _ = e.svc.Effective(e.ctx, "ten_other", res, conn); ok {
		t.Fatal("another tenant's request effective")
	}
}
