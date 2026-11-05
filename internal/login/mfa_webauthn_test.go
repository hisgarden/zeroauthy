package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const webauthnOrigin = "https://acme.example.test"

type webauthnFixture struct {
	*mfaFixture
	events *eventRecorder
}

// newWebAuthnFixture is the MFA fixture with WebAuthn ceremonies wired (the
// memory store's RP IDs: acme.example.test) and the WebAuthn MFA paths
// served. A nil st uses a plain memory store.
func newWebAuthnFixture(t *testing.T, st store.Store) *webauthnFixture {
	t.Helper()
	e := newEnv(t)
	if st != nil {
		e = newEnvWithStore(t, st)
	}
	f := newMFAFixtureWithEnv(t, e)
	policy := rpid.Policy{Store: f.st}
	f.h.MFA.Passkeys = passkey.New(f.st, policy, func() time.Time { return *f.clock })
	f.h.MFA.RPIDs = policy
	f.h.Authz.MFA = f.h.MFA
	capture := &eventRecorder{}
	f.h.Recorder = capture
	mux := http.NewServeMux()
	for _, p := range MFAWebAuthnPaths {
		mux.HandleFunc("GET "+p, f.h.MFAPage)
		mux.HandleFunc("POST "+p, f.h.MFASubmit)
	}
	mux.Handle("/", f.srv)
	f.srv = tenant.NewResolver(f.st.Tenants(), "", false).Middleware(mux)
	return &webauthnFixture{mfaFixture: f, events: capture}
}

var webauthnDocument = regexp.MustCompile(`(?s)<script type="application/json" id="za-webauthn">(.*?)</script>`)

// webauthnPage is the za-webauthn document of a hosted page.
type webauthnPage struct {
	Mode      string `json:"mode"`
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		RPID string `json:"rpId"`
		User struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"user"`
		Selection        map[string]any `json:"authenticatorSelection"`
		Allow            []struct{ ID string } `json:"allowCredentials"`
		Exclude          []struct{ ID string } `json:"excludeCredentials"`
		UserVerification string         `json:"userVerification"`
		Timeout          int64          `json:"timeout"`
	} `json:"publicKey"`
}

func webauthnDoc(t *testing.T, body string) webauthnPage {
	t.Helper()
	m := webauthnDocument.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no za-webauthn document in %s", body)
	}
	var out webauthnPage
	if err := json.Unmarshal([]byte(m[1]), &out); err != nil {
		t.Fatalf("za-webauthn %q: %v", m[1], err)
	}
	return out
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (p webauthnPage) creation(t *testing.T) webauthn.CreationOptions {
	return webauthn.CreationOptions{Challenge: b64(t, p.PublicKey.Challenge), RPID: p.PublicKey.RP.ID, UserID: b64(t, p.PublicKey.User.ID)}
}

func (p webauthnPage) request(t *testing.T) webauthn.RequestOptions {
	return webauthn.RequestOptions{Challenge: b64(t, p.PublicKey.Challenge), RPID: p.PublicKey.RPID}
}

// detect answers the capability page as a browser with WebAuthn (and a
// platform authenticator when platform is set), or without script.
func (f *webauthnFixture) detect(t *testing.T, webauthnOK, platform bool) {
	t.Helper()
	v := url.Values{}
	if webauthnOK {
		v.Set("webauthn", "yes")
	}
	if platform {
		v.Set("platform", "yes")
	}
	r := f.post(t, mfaDetectPath, v)
	if loc, _ := url.Parse(r.Header().Get("Location")); r.Code != 303 || loc.Path != "/u/mfa" {
		t.Fatalf("detect = %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
}

// key enrolls a security key directly through the service.
func (f *webauthnFixture) key(t *testing.T) *webauthntest.Authenticator {
	t.Helper()
	ctx := context.Background()
	rp := rpid.Result{RPID: "acme.example.test", Origin: webauthnOrigin, Valid: true}
	svc := f.h.MFA.WithHostedBinding("txn_direct", "cookie")
	e, opts, err := svc.BeginWebAuthnEnroll(ctx, f.tn.ID, f.uid, mfa.FactorRoaming, rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	k := webauthntest.New(webauthntest.Options{Attachment: "cross-platform"})
	if _, err = svc.ConfirmWebAuthnEnroll(ctx, f.tn.ID, f.uid, e, k.Create(opts, webauthnOrigin), "", ""); err != nil {
		t.Fatal(err)
	}
	return k
}

func (f *webauthnFixture) roaming(t *testing.T) []store.Authenticator {
	t.Helper()
	list, err := f.st.MFA().ListAuthenticators(context.Background(), f.tn.ID, f.uid)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.Authenticator
	for _, a := range list {
		if a.Type == mfa.FactorRoaming {
			out = append(out, a)
		}
	}
	return out
}

func follow(t *testing.T, b *browser, r *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	loc, err := url.Parse(r.Header().Get("Location"))
	if r.Code != 303 || err != nil {
		t.Fatalf("want 303, got %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
	return b.do(t, "GET", loc.RequestURI(), nil)
}

func TestHostedRoamingEnrollAndChallenge(t *testing.T) {
	st := events.Wrap(memory.New(), events.Config{})
	f := newWebAuthnFixture(t, st)
	f.policy(t, "otp", mfa.FactorRoaming)
	ctx := context.Background()
	// A foreign RP ID's key and a passkey on this RP ID are not the user's
	// security keys here (LR33b-5).
	for _, a := range []store.Authenticator{
		{TenantID: f.tn.ID, UserID: f.uid, ID: "webauthn-roaming|dev_foreignkey000000000", Type: mfa.FactorRoaming, Confirmed: true, CredentialID: []byte("foreign-credential"), PublicKey: []byte{1}, RPID: "login.other.test", CreatedAt: *f.clock},
	} {
		if err := f.st.MFA().CreateAuthenticator(ctx, &a); err != nil {
			t.Fatal(err)
		}
	}

	// /u/mfa first asks the browser what it can do.
	_, s, c := f.b.begin(t)
	r := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ := url.Parse(r.Header().Get("Location"))
	f.state = loc.Query().Get("state")
	detect := f.page(t, "/u/mfa")
	if !strings.Contains(detect.Body.String(), `action="`+mfaDetectPath+`"`) || webauthnDoc(t, detect.Body.String()).Mode != "detect" {
		t.Fatalf("no detection page first: %s", detect.Body)
	}
	nonce := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(detect.Header().Get("Content-Security-Policy"))
	if nonce == nil || !strings.Contains(detect.Body.String(), `<script nonce="`+nonce[1]+`">`) || strings.Contains(detect.Body.String(), "fetch(") {
		t.Fatalf("page script not inline with the CSP nonce: %s", detect.Header().Get("Content-Security-Policy"))
	}
	f.detect(t, true, false)

	// Enrollment: the factor list offers the security key.
	options := f.page(t, "/u/mfa")
	if !strings.Contains(options.Body.String(), `value="webauthn-roaming"`) || !strings.Contains(options.Body.String(), "Security key") {
		t.Fatalf("security key not offered: %s", options.Body)
	}
	r = f.post(t, "/u/mfa", url.Values{"factor": {mfa.FactorRoaming}})
	page := follow(t, f.b, r)
	if page.Code != 200 || !strings.Contains(page.Body.String(), `action="/u/mfa-webauthn-roaming-enrollment"`) {
		t.Fatalf("enrollment page %d %s", page.Code, page.Body)
	}
	doc := webauthnDoc(t, page.Body.String())
	sel := doc.PublicKey.Selection
	if doc.Mode != "create" || sel["authenticatorAttachment"] != "cross-platform" || sel["residentKey"] != "discouraged" || sel["userVerification"] != "discouraged" || doc.PublicKey.RP.ID != "acme.example.test" || doc.PublicKey.Timeout != 300000 {
		t.Fatalf("creation options %+v", doc)
	}
	if strings.Contains(page.Body.String(), "challenge_id") {
		t.Fatal("the challenge ID belongs in the sealed page state, not the page")
	}
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform", Transports: []string{"usb"}})
	f.csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	r = f.post(t, "/u/mfa-webauthn-roaming-enrollment", url.Values{"credential": {string(key.Create(doc.creation(t), webauthnOrigin))}})
	recovery := regexp.MustCompile(`<code id="recovery-code">([A-Z0-9]{24})</code>`).FindStringSubmatch(r.Body.String())
	if r.Code != 200 || recovery == nil {
		t.Fatalf("first enrollment shows no recovery code: %d %s", r.Code, r.Body)
	}
	if got := f.events.typed("gd_enrollment_complete"); len(got) != 1 || got[0].Details["authenticator"].(map[string]any)["type"] != mfa.FactorRoaming {
		t.Fatalf("gd_enrollment_complete %+v", got)
	}
	f.csrf = csrfField.FindStringSubmatch(r.Body.String())[1]
	nickname := follow(t, f.b, f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}}))
	if nickname.Code != 200 || !strings.Contains(nickname.Body.String(), `name="nickname"`) || !strings.Contains(nickname.Body.String(), `value="Security key"`) {
		t.Fatalf("nickname screen %d %s", nickname.Code, nickname.Body)
	}
	f.csrf = csrfField.FindStringSubmatch(nickname.Body.String())[1]
	for name, want := range map[string]string{"": "Enter a name.", strings.Repeat("k", 21): "at most 20"} {
		r = f.post(t, mfaWebAuthnNicknamePath, url.Values{"nickname": {name}})
		if r.Code != 400 || !strings.Contains(r.Body.String(), want) {
			t.Fatalf("nickname %q = %d %s", name, r.Code, r.Body)
		}
		f.csrf = csrfField.FindStringSubmatch(r.Body.String())[1]
	}
	success := follow(t, f.b, f.post(t, mfaWebAuthnNicknamePath, url.Values{"nickname": {strings.Repeat("k", 20)}}))
	if success.Code != 200 || !strings.Contains(success.Body.String(), "Security key added") {
		t.Fatalf("success screen %d %s", success.Code, success.Body)
	}
	f.csrf = csrfField.FindStringSubmatch(success.Body.String())[1]
	if r = f.post(t, mfaWebAuthnSuccessPath, url.Values{}); r.Code != 302 || !strings.HasPrefix(r.Header().Get("Location"), "https://app.acme.test/cb?") {
		t.Fatalf("finish %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
	keys := f.roaming(t)
	var enrolled store.Authenticator
	for _, a := range keys {
		if a.RPID == "acme.example.test" {
			enrolled = a
		}
	}
	if enrolled.Name != strings.Repeat("k", 20) || !enrolled.Confirmed || string(enrolled.CredentialID) != string(key.CredentialID()) {
		t.Fatalf("stored key %+v", enrolled)
	}
	rows, err := st.Events().EventsAfter(ctx, f.tn.ID, 0, []string{"user.updated"}, 100, time.Now().Add(time.Hour))
	if err != nil || len(rows) == 0 {
		t.Fatalf("user.updated for the multifactor change: %d %v", len(rows), err)
	}

	// Challenge in a new browser: only this RP ID's security keys.
	f.b = f.env.browser("acme.example.test")
	*f.clock = f.clock.Add(time.Minute)
	f.begin(t)
	f.detect(t, true, false)
	challenge := f.page(t, "/u/mfa")
	if !strings.Contains(challenge.Body.String(), `action="/u/mfa-webauthn-roaming-challenge"`) || !strings.Contains(challenge.Body.String(), `name="remember"`) {
		t.Fatalf("challenge page %s", challenge.Body)
	}
	doc = webauthnDoc(t, challenge.Body.String())
	if doc.Mode != "get" || len(doc.PublicKey.Allow) != 1 || string(b64(t, doc.PublicKey.Allow[0].ID)) != string(key.CredentialID()) || doc.PublicKey.UserVerification != "discouraged" {
		t.Fatalf("request options %+v", doc)
	}
	key.SignCount = 7
	r = f.post(t, "/u/mfa-webauthn-roaming-challenge", url.Values{"credential": {string(key.Get(doc.request(t), webauthnOrigin))}, "remember": {"yes"}})
	if r.Code != 302 || !strings.HasPrefix(r.Header().Get("Location"), "https://app.acme.test/cb?") {
		t.Fatalf("challenge %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
	remember := false
	for _, c := range r.Result().Cookies() {
		remember = remember || c.Name == session.MFARememberCookie
	}
	if !remember {
		t.Fatal("remember browser not set after a security key challenge")
	}
	if a, _ := f.st.MFA().GetAuthenticator(ctx, f.tn.ID, f.uid, enrolled.ID); a.SignCount != 7 || a.LastAuthAt.IsZero() {
		t.Fatalf("sign count not written: %+v", a)
	}

	// The remembered browser skips MFA as it does for OTP.
	b := f.env.browser("acme.example.test")
	b.cookies[session.MFARememberCookie] = f.b.cookies[session.MFARememberCookie]
	_, s, c = b.begin(t)
	r = b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
	if r.Code != 302 || !strings.HasPrefix(r.Header().Get("Location"), "https://app.acme.test/cb?") {
		t.Fatalf("remembered browser %d %s", r.Code, r.Header().Get("Location"))
	}

	// A browser without WebAuthn (or script) gets the recovery code instead.
	f.b = f.env.browser("acme.example.test")
	f.begin(t)
	f.detect(t, false, false)
	r = f.b.do(t, "GET", "/u/mfa?state="+f.state, nil)
	if loc, _ := url.Parse(r.Header().Get("Location")); r.Code != 303 || loc.Path != "/u/mfa-recovery-code-challenge" {
		t.Fatalf("no WebAuthn browser = %d %s", r.Code, r.Header().Get("Location"))
	}
	if r = f.b.do(t, "GET", "/u/mfa-webauthn-roaming-challenge?state="+f.state, nil); r.Code != 400 {
		t.Fatalf("security key page without WebAuthn = %d", r.Code)
	}
}

func TestRoamingUVSettingHosted(t *testing.T) {
	f := newWebAuthnFixture(t, nil)
	f.policy(t, mfa.FactorRoaming)
	g, _ := f.st.MFA().GetGuardian(context.Background(), f.tn.ID)
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	g.Stored[mfa.RoamingSettingsKey] = json.RawMessage(`{"user_verification":"required"}`)
	if err := f.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
		t.Fatal(err)
	}
	f.begin(t)
	f.detect(t, true, false)
	page := follow(t, f.b, f.b.do(t, "GET", "/u/mfa?state="+f.state, nil))
	doc := webauthnDoc(t, page.Body.String())
	if doc.PublicKey.Selection["userVerification"] != "required" {
		t.Fatalf("UV setting not applied: %+v", doc.PublicKey.Selection)
	}
	// A FIDO-1-style key (no UV) cannot register.
	f.csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform"})
	r := f.post(t, "/u/mfa-webauthn-roaming-enrollment", url.Values{"credential": {string(key.Create(doc.creation(t), webauthnOrigin))}})
	if r.Code != 400 || !strings.Contains(r.Body.String(), "could not be added") || len(f.roaming(t)) != 0 {
		t.Fatalf("UV-less registration = %d %s", r.Code, r.Body)
	}
	// The page stays usable with a fresh challenge.
	if next := webauthnDoc(t, r.Body.String()); next.PublicKey.Challenge == doc.PublicKey.Challenge {
		t.Fatal("failed ceremony reused its challenge")
	}
}

func TestWebAuthnTicketAndActions(t *testing.T) {
	f := newWebAuthnFixture(t, nil)
	f.policy(t, "otp", mfa.FactorRoaming)
	ctx := context.Background()
	raw := "ticket-" + secrets.RandomString(20)
	if err := f.st.MFA().CreateTicket(ctx, &store.EnrollmentTicket{TenantID: f.tn.ID, UserID: f.uid, Hash: secrets.HashToken(raw), Factor: mfa.FactorRoaming, ExpiresAt: f.clock.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+url.QueryEscape(raw), nil)
	loc, _ := url.Parse(r.Header().Get("Location"))
	if r.Code != 303 || loc.Path != "/u/mfa" {
		t.Fatalf("ticket %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	f.detect(t, true, false)
	page := follow(t, f.b, f.b.do(t, "GET", "/u/mfa?state="+f.state, nil))
	if !strings.Contains(page.Body.String(), `action="/u/mfa-webauthn-roaming-enrollment"`) {
		t.Fatalf("ticket enrollment page %s", page.Body)
	}
	f.csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform"})
	r = f.post(t, "/u/mfa-webauthn-roaming-enrollment", url.Values{"credential": {string(key.Create(webauthnDoc(t, page.Body.String()).creation(t), webauthnOrigin))}})
	f.csrf = csrfField.FindStringSubmatch(r.Body.String())[1]
	nickname := follow(t, f.b, f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}}))
	f.csrf = csrfField.FindStringSubmatch(nickname.Body.String())[1]
	success := follow(t, f.b, f.post(t, mfaWebAuthnNicknamePath, url.Values{"nickname": {"Desk key"}}))
	f.csrf = csrfField.FindStringSubmatch(success.Body.String())[1]
	if r = f.post(t, mfaWebAuthnSuccessPath, url.Values{}); r.Code != 200 {
		t.Fatalf("ticket result %d %s", r.Code, r.Body)
	}
	if keys := f.roaming(t); len(keys) != 1 || keys[0].Name != "Desk key" {
		t.Fatalf("ticket enrollment %+v", keys)
	}
	// The ticket enrolls once.
	if r = f.env.browser("acme.example.test").do(t, "GET", "/u/mfa-enroll-ticket?ticket="+url.QueryEscape(raw), nil); r.Code != 400 {
		t.Fatalf("ticket reuse = %d", r.Code)
	}

	// "Try another method" lists the other factors and the recovery code.
	f.enrolled(t, "otp", false)
	keys := f.roaming(t)
	keys[0].Preferred = true
	if err := f.st.MFA().UpdateAuthenticator(ctx, &keys[0]); err != nil {
		t.Fatal(err)
	}
	f.b = f.env.browser("acme.example.test")
	f.begin(t)
	f.detect(t, true, false)
	challenge := f.page(t, "/u/mfa")
	another := regexp.MustCompile(`href="(/u/mfa\?[^"]*action=another)"`).FindStringSubmatch(challenge.Body.String())
	if !strings.Contains(challenge.Body.String(), `action="/u/mfa-webauthn-roaming-challenge"`) || another == nil {
		t.Fatalf("challenge page %s", challenge.Body)
	}
	list := f.b.do(t, "GET", strings.ReplaceAll(another[1], "&amp;", "&"), nil)
	for _, v := range []string{`value="webauthn-roaming"`, `value="otp"`, `value="recovery-code"`} {
		if !strings.Contains(list.Body.String(), v) {
			t.Fatalf("another method list lacks %s: %s", v, list.Body)
		}
	}
}

// typed returns the recorded events of one type.
func (c *eventRecorder) typed(kind string) []eventRecord {
	var out []eventRecord
	for _, e := range c.events {
		if e.Type == kind {
			out = append(out, eventRecord{Type: e.Type, Details: e.Details})
		}
	}
	return out
}

type eventRecord struct {
	Type    string
	Details map[string]any
}
