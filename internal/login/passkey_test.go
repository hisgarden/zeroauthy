package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const (
	pkHost   = "acme.example.test"
	pkOrigin = "https://" + pkHost
	pkDB     = "Username-Password-Authentication"
)

// syncEvents is a goroutine-safe log recorder.
type syncEvents struct {
	mu     sync.Mutex
	events []logs.Event
}

func (s *syncEvents) Record(_ context.Context, e logs.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *syncEvents) of(code string) []logs.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []logs.Event
	for _, e := range s.events {
		if e.Type == code {
			out = append(out, e)
		}
	}
	return out
}

func (s *syncEvents) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

// captureDeferred hands the Plan 33b WebAuthn log codes, disabled in the
// log inventory until Task 19, to the recorder as well.
func captureDeferred(t *testing.T) {
	t.Helper()
	old := emitEvent
	t.Cleanup(func() { emitEvent = old })
	emitEvent = func(ctx context.Context, rec logs.Recorder, e logs.Event) {
		if strings.HasPrefix(e.Type, "gd_webauthn_") && rec != nil {
			rec.Record(ctx, e)
			return
		}
		logs.RecordEvent(ctx, rec, e)
	}
}

// pkEnv is a login env with identifier-first prompts, passkeys enabled on
// the database connection and alice holding one passkey.
type pkEnv struct {
	*env
	tn     *store.Tenant
	alice  *store.User
	auth   *webauthntest.Authenticator
	events *syncEvents
}

func newPasskeyEnv(t *testing.T) *pkEnv {
	t.Helper()
	return withPasskeys(t, newEnv(t))
}

// withPasskeys turns passkeys on for e and serves the passkey routes in
// front of e's existing ones.
func withPasskeys(t *testing.T, e *env) *pkEnv {
	t.Helper()
	ctx := context.Background()
	enableIdentifier(t, e)
	tn := mustTenant(t, e, "acme")
	setPasskeys(t, e, pkDB, map[string]any{"enabled": true}, nil)
	e.h.Passkeys = passkey.New(e.st, rpid.Policy{Store: e.st}, func() time.Time { return e.h.now() })
	old := e.srv
	mux := http.NewServeMux()
	routePasskeys(mux, e.h)
	mux.Handle("/", old)
	e.srv = tenant.NewResolver(e.st.Tenants(), "", false).Middleware(mux)
	events := &syncEvents{}
	e.h.Recorder = events
	captureDeferred(t)
	alice, err := e.st.Users().FindByLogin(ctx, tn.ID, pkDB, aliceLogin)
	if err != nil {
		t.Fatal(err)
	}
	p := &pkEnv{env: e, tn: tn, alice: alice, events: events, auth: webauthntest.New(webauthntest.Options{})}
	p.enroll(t, alice, p.auth, pkHost)
	return p
}

// routePasskeys is extended by the later passkey tasks' routes.
func routePasskeys(mux *http.ServeMux, h *Handlers) {
	mux.HandleFunc("POST /u/login/passkey", h.LoginPasskey)
}

// setPasskeys writes the connection's passkey method and options.
func setPasskeys(t *testing.T, e *env, name string, method, options map[string]any) {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	conn, err := e.st.Connections().GetByName(ctx, tn.ID, name)
	if err != nil {
		t.Fatal(err)
	}
	if conn.Extra == nil {
		conn.Extra = map[string]any{}
	}
	conn.Extra["authentication_methods"] = map[string]any{"passkey": method, "password": map[string]any{"enabled": true}}
	if options != nil {
		conn.Extra["passkey_options"] = options
	} else {
		delete(conn.Extra, "passkey_options")
	}
	if err := e.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
}

// enroll stores a passkey of u made by auth on rp through the service.
func (p *pkEnv) enroll(t *testing.T, u *store.User, auth *webauthntest.Authenticator, rp string) *store.Authenticator {
	t.Helper()
	ctx := context.Background()
	svc := p.h.Passkeys
	b := passkey.Binding{Purpose: passkey.PurposePasskeyRegister, RPID: rp, Origins: []string{"https://" + rp}, TxnID: "seed", CookieHash: "seed", UserID: u.UserID}
	iss, err := svc.Issue(ctx, p.tn.ID, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := svc.CreationOptions(ctx, p.tn.ID, u, passkey.Display(u, nil), rp, passkey.Progressive, iss.Challenge, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := auth.Create(opts, "https://"+rp)
	ch, err := svc.Take(ctx, p.tn.ID, iss.ID, b)
	if err != nil {
		t.Fatal(err)
	}
	a, err := svc.Enroll(ctx, p.tn.ID, u, "", raw, ch, b, "")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var pkConfigField = regexp.MustCompile(`(?s)<script type="application/json" id="za-webauthn">(.*?)</script>`)

// pkConfig is the page's za-webauthn document.
type pkConfig struct {
	Mode        string          `json:"mode"`
	ChallengeID string          `json:"challenge_id"`
	Mediation   string          `json:"mediation"`
	Button      bool            `json:"button"`
	PublicKey   json.RawMessage `json:"publicKey"`
}

func parsePasskey(t *testing.T, body string) *pkConfig {
	t.Helper()
	m := pkConfigField.FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	var c pkConfig
	if err := json.Unmarshal([]byte(m[1]), &c); err != nil {
		t.Fatalf("za-webauthn %q: %v", m[1], err)
	}
	return &c
}

func (c *pkConfig) request(t *testing.T) webauthn.RequestOptions {
	t.Helper()
	var o struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		Allow            []any  `json:"allowCredentials"`
	}
	if err := json.Unmarshal(c.PublicKey, &o); err != nil {
		t.Fatal(err)
	}
	ch, err := base64.RawURLEncoding.DecodeString(o.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	return webauthn.RequestOptions{Challenge: ch, RPID: o.RPID, UserVerification: o.UserVerification}
}

// start begins a login on b and returns the login-id page's passkey
// document with the transaction.
func (p *pkEnv) start(t *testing.T, b *browser, extra ...string) (string, string, *pkConfig) {
	t.Helper()
	page, state, csrf := b.begin(t, extra...)
	c := parsePasskey(t, page.Body.String())
	if c == nil {
		t.Fatalf("no passkey document on login-id: %s", page.Body)
	}
	return state, csrf, c
}

func (p *pkEnv) post(t *testing.T, b *browser, state, csrf string, c *pkConfig, credential string) *httptest.ResponseRecorder {
	t.Helper()
	return b.do(t, "POST", "/u/login/passkey", url.Values{"state": {state}, "csrf": {csrf}, "challenge_id": {c.ChallengeID}, "credential": {credential}})
}

// login runs a passkey login of auth on a new browser.
func (p *pkEnv) login(t *testing.T, auth *webauthntest.Authenticator, extra ...string) (*browser, *httptest.ResponseRecorder) {
	t.Helper()
	b := p.browser(pkHost)
	state, csrf, c := p.start(t, b, extra...)
	return b, p.post(t, b, state, csrf, c, string(auth.Get(c.request(t), pkOrigin)))
}

func (p *pkEnv) session(t *testing.T, b *browser) *store.LoginSession {
	t.Helper()
	c := b.cookies[session.CookieName]
	if c == nil {
		return nil
	}
	r := httptest.NewRequest("GET", pkOrigin+"/", nil)
	r.AddCookie(c)
	s, err := p.h.Sessions.Lookup(context.Background(), r, p.tn)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pageText is a catalog string as html/template writes it in a page.
func pageText(key string) string {
	return html.EscapeString(i18n.Default().T(key))
}

func genericFailure() string { return pageText(keyPasskeyFailed) }

func TestLoginIDPasskeyMarkup(t *testing.T) {
	for _, tc := range []struct {
		ui                 string
		autofill, button   bool
		mediation, absence string
	}{
		{ui: "both", autofill: true, button: true, mediation: "conditional"},
		{ui: "autofill", autofill: true, mediation: "conditional", absence: `id="za-passkey-button"`},
		{ui: "button", button: true, absence: "username webauthn"},
	} {
		t.Run(tc.ui, func(t *testing.T) {
			p := newPasskeyEnv(t)
			setPasskeys(t, p.env, pkDB, map[string]any{"enabled": true}, map[string]any{"challenge_ui": tc.ui})
			page, _, _ := p.browser(pkHost).begin(t)
			body := page.Body.String()
			c := parsePasskey(t, body)
			if c == nil || c.Mode != "login" || c.ChallengeID == "" || c.Mediation != tc.mediation || c.Button != tc.button {
				t.Fatalf("passkey document = %+v", c)
			}
			var opts map[string]any
			if err := json.Unmarshal(c.PublicKey, &opts); err != nil {
				t.Fatal(err)
			}
			if allow, ok := opts["allowCredentials"].([]any); !ok || len(allow) != 0 || opts["rpId"] != pkHost || opts["userVerification"] != "preferred" || opts["timeout"] != float64(300000) {
				t.Fatalf("request options = %v", opts)
			}
			if tc.autofill != strings.Contains(body, `autocomplete="username webauthn"`) {
				t.Errorf("autofill token present=%v, want %v", !tc.autofill, tc.autofill)
			}
			label := pageText("login-id.login-id.passkeyButtonText")
			if tc.button != (strings.Contains(body, `id="za-passkey-button"`) && strings.Contains(body, label)) {
				t.Errorf("button present=%v, want %v", !tc.button, tc.button)
			}
			if tc.absence != "" && strings.Contains(body, tc.absence) {
				t.Errorf("%q rendered for challenge_ui %s", tc.absence, tc.ui)
			}
			// The one in-tree script is inline with the response's nonce.
			nonce := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(page.Header().Get("Content-Security-Policy"))
			if nonce == nil || !strings.Contains(body, `<script nonce="`+nonce[1]+`">`) || !strings.Contains(body, "za-webauthn") || strings.Contains(body, "fetch(") {
				t.Fatalf("script not inline with the page nonce")
			}
			if strings.Count(body, "<script") != 2 {
				t.Errorf("want the options document and one script, got %d script elements", strings.Count(body, "<script"))
			}
			if !strings.Contains(body, `action="/u/login/passkey"`) || !strings.Contains(body, `name="challenge_id" value="`+c.ChallengeID+`"`) {
				t.Errorf("passkey form missing")
			}
		})
	}

	// Passkeys switched off: the same page without any passkey markup and
	// the same CSP shape.
	p := newPasskeyEnv(t)
	on, _, _ := p.browser(pkHost).begin(t)
	setPasskeys(t, p.env, pkDB, map[string]any{"enabled": false}, nil)
	off, _, _ := p.browser(pkHost).begin(t)
	assertNoPasskey(t, off)
	nonceless := regexp.MustCompile(`'nonce-[^']+'`)
	if a, b := nonceless.ReplaceAllString(on.Header().Get("Content-Security-Policy"), "N"), nonceless.ReplaceAllString(off.Header().Get("Content-Security-Policy"), "N"); a != b || strings.Contains(a, "connect-src") {
		t.Fatalf("CSP changed by passkeys:\n%s\n%s", a, b)
	}
	if on.Header().Get("Permissions-Policy") != off.Header().Get("Permissions-Policy") {
		t.Fatal("Permissions-Policy changed by passkeys")
	}

	// Prerequisites unmet (Task 7 table): identifier-first off and a
	// username-only connection without flexible identifiers.
	t.Run("identifier first off", func(t *testing.T) {
		p := newPasskeyEnv(t)
		c, err := p.st.HostedLogins().Get(context.Background(), p.tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		c.Prompts = map[string]any{"identifier_first": false}
		if err := p.st.HostedLogins().Put(context.Background(), c, c.Revision); err != nil {
			t.Fatal(err)
		}
		page, _, _ := p.browser(pkHost).begin(t)
		assertNoPasskey(t, page)
	})
	t.Run("requires username", func(t *testing.T) {
		p := newPasskeyEnv(t)
		conn, _ := p.st.Connections().GetByName(context.Background(), p.tn.ID, pkDB)
		conn.RequiresUsername = true
		if err := p.st.Connections().Update(context.Background(), conn); err != nil {
			t.Fatal(err)
		}
		page, _, _ := p.browser(pkHost).begin(t)
		assertNoPasskey(t, page)
	})
}

func assertNoPasskey(t *testing.T, page *httptest.ResponseRecorder) {
	t.Helper()
	body := page.Body.String()
	for _, s := range []string{"za-webauthn", "webauthn", "/u/login/passkey", "challenge_id", "za-passkey-button"} {
		if strings.Contains(body, s) {
			t.Fatalf("passkey markup %q without effective passkeys (%d): %s", s, page.Code, body)
		}
	}
}

func TestHostedPasskeyLogin(t *testing.T) {
	p := newPasskeyEnv(t)
	b, rec := p.login(t, p.auth)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" {
		t.Fatalf("passkey login = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	s := p.session(t, b)
	if s == nil || s.UserID != p.alice.UserID || s.Connection != pkDB || len(s.AuthMethods) != 1 || s.AuthMethods[0].Name != "passkey" || s.AuthMethods[0].Type != "" || !s.MFAAt.IsZero() {
		t.Fatalf("session = %+v", s)
	}
	// MFAAt stays zero, so the ID token minter adds no amr (LR33b-12).
	ok := p.events.of("s")
	if len(ok) != 1 {
		t.Fatalf("s events = %+v", ok)
	}
	prompts, _ := json.Marshal(ok[0].Details["prompts"])
	if string(prompts) != `[{"name":"login-id","performed_amr":["phr"]}]` || ok[0].UserID != p.alice.UserID {
		t.Fatalf("s details = %s (%+v)", prompts, ok[0])
	}
	u, _ := p.st.Users().Get(context.Background(), p.tn.ID, p.alice.UserID)
	if u.LoginsCount != p.alice.LoginsCount+1 {
		t.Fatalf("login not recorded: %d", u.LoginsCount)
	}
	aa, _ := p.st.MFA().ListAuthenticators(context.Background(), p.tn.ID, p.alice.UserID)
	if len(aa) != 1 || aa[0].LastAuthAt.IsZero() {
		t.Fatalf("passkey use not recorded: %+v", aa)
	}

	// A password login records pwd and its s carries no passkey prompt.
	p.events.reset()
	pw := p.browser(pkHost)
	page, state, csrf := pw.begin(t)
	step := pw.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {aliceLogin}})
	pwPage := pw.do(t, "GET", step.Header().Get("Location"), nil)
	done := pw.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, pwPage.Body.String())}, "password": {"alice password 1"}})
	if done.Code != http.StatusFound {
		t.Fatalf("password login = %d %s", done.Code, done.Body)
	}
	if s := p.session(t, pw); s == nil || len(s.AuthMethods) != 1 || s.AuthMethods[0].Name != "pwd" {
		t.Fatalf("password session = %+v", s)
	}
	if ok := p.events.of("s"); len(ok) != 1 || ok[0].Details["prompts"] != nil {
		t.Fatalf("password s = %+v", ok)
	}
}

func TestHostedPasskeyLoginMFA(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", true)
	p := withPasskeys(t, f.env)
	b, rec := p.login(t, p.auth)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("passkey with MFA policy = %d %s", rec.Code, loc)
	}
	f.b = b
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	f.page(t, "/u/mfa-otp-challenge")
	done := f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	if !strings.Contains(done.Header().Get("Location"), "code=") {
		t.Fatalf("otp = %d %s %s", done.Code, done.Header().Get("Location"), done.Body)
	}
	s := p.session(t, b)
	if s == nil || s.MFAAt.IsZero() || len(s.AuthMethods) != 2 || s.AuthMethods[0].Name != "passkey" || s.AuthMethods[1].Name != "mfa" || s.AuthMethods[1].Type != "otp" {
		t.Fatalf("session after MFA = %+v", s)
	}
	if ok := p.events.of("s"); len(ok) != 1 || ok[0].Details["prompts"] == nil {
		t.Fatalf("s after MFA = %+v", ok)
	}
}

func TestHostedPasskeyLoginConsentAndOrganization(t *testing.T) {
	t.Run("consent", func(t *testing.T) {
		p := newPasskeyEnv(t)
		b := p.browser(pkHost)
		auth := b.do(t, "GET", "/authorize?"+partnerQ("partner", "https://partner.example/cb").Encode(), nil)
		start, _ := url.Parse(auth.Header().Get("Location"))
		page := b.do(t, "GET", start.RequestURI(), nil)
		c := parsePasskey(t, page.Body.String())
		if c == nil {
			t.Fatalf("no passkey on partner login: %s", page.Body)
		}
		rec := p.post(t, b, start.Query().Get("state"), csrfField.FindStringSubmatch(page.Body.String())[1], c, string(p.auth.Get(c.request(t), pkOrigin)))
		if loc, _ := url.Parse(rec.Header().Get("Location")); loc.Path != "/u/consent" {
			t.Fatalf("third-party passkey login = %d %s", rec.Code, loc)
		}
	})
	t.Run("organization membership", func(t *testing.T) {
		e := newEnv(t)
		org, _, user := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, false)
		p := withPasskeys(t, e)
		_, rec := p.login(t, p.auth, "organization", org.ID)
		if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "code=") {
			t.Fatalf("organization passkey login = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
		}
		member, err := e.st.Organizations().IsMember(context.Background(), org.TenantID, org.ID, user.UserID)
		if err != nil || !member {
			t.Fatalf("membership = %v, %v", member, err)
		}
	})
}

// gateStore holds every GetChallenge until n callers arrive, so the
// concurrent submissions reach the single-use consume together.
type gateStore struct {
	store.Store
	gate *gate
}

type gate struct {
	mu      sync.Mutex
	waiting int
	n       int
	open    chan struct{}
}

func (g *gate) wait() {
	g.mu.Lock()
	g.waiting++
	if g.waiting == g.n {
		close(g.open)
	}
	g.mu.Unlock()
	select {
	case <-g.open:
	case <-time.After(10 * time.Second):
	}
}

type gateMFA struct {
	store.MFA
	gate *gate
}

func (s gateStore) MFA() store.MFA { return gateMFA{s.Store.MFA(), s.gate} }
func (m gateMFA) GetChallenge(ctx context.Context, tid, id string, now time.Time) (*store.MFAChallenge, error) {
	m.gate.wait()
	return m.MFA.GetChallenge(ctx, tid, id, now)
}

// TestHostedPasskeyDoubleSubmit is Review Focus 2.
func TestHostedPasskeyDoubleSubmit(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
	}{{"double submit", 2}, {"autofill and button", 2}, {"many tabs", 6}} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPasskeyEnv(t)
			b := p.browser(pkHost)
			state, csrf, c := p.start(t, b)
			opts := c.request(t)
			creds := make([]string, tc.n)
			for i := range creds {
				// Every submission is a valid assertion of the same challenge
				// (the autofill and the button ceremony each sign it).
				p.auth.SignCount = uint32(i + 1)
				creds[i] = string(p.auth.Get(opts, pkOrigin))
			}
			g := &gate{n: tc.n, open: make(chan struct{})}
			svc := passkey.New(gateStore{p.st, g}, rpid.Policy{Store: p.st}, func() time.Time { return p.h.now() })
			p.h.Passkeys = svc
			form := func(cred string) url.Values {
				return url.Values{"state": {state}, "csrf": {csrf}, "challenge_id": {c.ChallengeID}, "credential": {cred}, "hosted_revision": {b.formRevisions[state]}}
			}
			cookies := map[string]*http.Cookie{}
			for k, v := range b.cookies {
				cookies[k] = v
			}
			recs := make([]*httptest.ResponseRecorder, tc.n)
			var wg sync.WaitGroup
			for i := range tc.n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					tab := &browser{e: p.env, host: pkHost, cookies: map[string]*http.Cookie{}}
					for k, v := range cookies {
						tab.cookies[k] = v
					}
					recs[i] = tab.send("POST", "/u/login/passkey", form(creds[i]))
				}()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("submissions did not return")
			}
			winners := 0
			for _, rec := range recs {
				switch {
				case rec.Code == http.StatusFound && strings.Contains(rec.Header().Get("Location"), "code="):
					winners++
				case rec.Code >= 500:
					t.Fatalf("loser got %d", rec.Code)
				default:
					body := rec.Body.String()
					again := parsePasskey(t, body)
					if !strings.Contains(body, genericFailure()) || again == nil || again.ChallengeID == c.ChallengeID || !strings.Contains(body, `action="/u/login"`) {
						t.Fatalf("loser page = %d %s", rec.Code, body)
					}
				}
			}
			if winners != 1 {
				t.Fatalf("winners = %d", winners)
			}
			list, err := p.st.Sessions().ListByUser(context.Background(), p.tn.ID, p.alice.UserID)
			if err != nil || len(list) != 1 {
				t.Fatalf("sessions = %d, %v", len(list), err)
			}
			if n := len(p.events.of("gd_webauthn_challenge_failed")); n != tc.n-1 {
				t.Fatalf("failure logs = %d", n)
			}
		})
	}
}

// TestHostedPasskeyStaleCredential is Review Focus 3.
func TestHostedPasskeyStaleCredential(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, p *pkEnv)
	}{
		{"credential deleted", func(t *testing.T, p *pkEnv) {
			aa, _ := p.st.MFA().ListAuthenticators(ctx, p.tn.ID, p.alice.UserID)
			for _, a := range aa {
				if err := p.st.MFA().DeleteAuthenticator(ctx, p.tn.ID, p.alice.UserID, a.ID); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"passkeys disabled on the connection", func(t *testing.T, p *pkEnv) {
			setPasskeys(t, p.env, pkDB, map[string]any{"enabled": false}, nil)
		}},
		{"connection disabled for the client", func(t *testing.T, p *pkEnv) {
			// The page's transaction now uses another database connection
			// with passkeys; the passkey's user is not on it.
			other := &store.Connection{TenantID: p.tn.ID, ID: "con_alt0000000000001", Name: "Alt-DB", Strategy: store.StrategyDatabase, EnabledClients: []string{"spa"}}
			if err := p.st.Connections().Create(ctx, other); err != nil {
				t.Fatal(err)
			}
			setPasskeys(t, p.env, "Alt-DB", map[string]any{"enabled": true}, nil)
			conn, _ := p.st.Connections().GetByName(ctx, p.tn.ID, pkDB)
			conn.EnabledClients = slices.DeleteFunc(conn.EnabledClients, func(c string) bool { return c == "spa" })
			if err := p.st.Connections().Update(ctx, conn); err != nil {
				t.Fatal(err)
			}
		}},
		{"credential of another RP ID", func(t *testing.T, p *pkEnv) {
			p.auth = webauthntest.New(webauthntest.Options{})
			p.enroll(t, p.alice, p.auth, "other.example.test")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPasskeyEnv(t)
			b := p.browser(pkHost)
			state, csrf, c := p.start(t, b)
			tc.prepare(t, p)
			rec := p.post(t, b, state, csrf, c, string(p.auth.Get(c.request(t), pkOrigin)))
			body := rec.Body.String()
			if rec.Code != http.StatusUnauthorized || !strings.Contains(body, genericFailure()) || !strings.Contains(body, `action="/u/login"`) || b.cookies[session.CookieName] != nil {
				t.Fatalf("stale = %d %s", rec.Code, body)
			}
			failed := p.events.of("gd_webauthn_challenge_failed")
			if len(failed) != 1 || failed[0].Details["first_factor"] != true {
				t.Fatalf("failure log = %+v", failed)
			}
			fd, _ := failed[0].Details["failure_details"].(map[string]any)
			if code, _ := fd["errorCode"].(string); code == "" || len(code) > 32 || len(fd) != 1 {
				t.Fatalf("failure_details = %v", fd)
			}
		})
	}
	t.Run("blocked user", func(t *testing.T) {
		p := newPasskeyEnv(t)
		u, _ := p.st.Users().Get(ctx, p.tn.ID, p.alice.UserID)
		u.Blocked = true
		if err := p.st.Users().Update(ctx, u); err != nil {
			t.Fatal(err)
		}
		b, rec := p.login(t, p.auth)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), pageText(i18n.KeyUserBlocked)) || b.cookies[session.CookieName] != nil {
			t.Fatalf("blocked = %d %s", rec.Code, rec.Body)
		}
	})
}

func TestHostedPasskeyBinding(t *testing.T) {
	ctx := context.Background()
	fails := func(t *testing.T, p *pkEnv, b *browser, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), genericFailure()) || b.cookies[session.CookieName] != nil {
			t.Fatalf("binding = %d %s", rec.Code, rec.Body)
		}
	}
	t.Run("another transaction", func(t *testing.T) {
		p := newPasskeyEnv(t)
		b := p.browser(pkHost)
		_, _, other := p.start(t, b)
		state, csrf, _ := p.start(t, b)
		fails(t, p, b, p.post(t, b, state, csrf, other, string(p.auth.Get(other.request(t), pkOrigin))))
	})
	t.Run("another browser cookie", func(t *testing.T) {
		p := newPasskeyEnv(t)
		victim := p.browser(pkHost)
		_, _, theirs := p.start(t, victim)
		b := p.browser(pkHost)
		state, csrf, _ := p.start(t, b)
		fails(t, p, b, p.post(t, b, state, csrf, theirs, string(p.auth.Get(theirs.request(t), pkOrigin))))
	})
	t.Run("forged origin", func(t *testing.T) {
		p := newPasskeyEnv(t)
		b := p.browser(pkHost)
		state, csrf, c := p.start(t, b)
		fails(t, p, b, p.post(t, b, state, csrf, c, string(p.auth.Get(c.request(t), "https://evil.example.test"))))
	})
	t.Run("another tenant host", func(t *testing.T) {
		p := newPasskeyEnv(t)
		b := p.browser(pkHost)
		state, csrf, c := p.start(t, b)
		other := &browser{e: p.env, host: "globex.example.test", cookies: b.cookies}
		rec := other.do(t, "POST", "/u/login/passkey", url.Values{"state": {state}, "csrf": {csrf}, "challenge_id": {c.ChallengeID}, "credential": {string(p.auth.Get(c.request(t), pkOrigin))}})
		if rec.Code != http.StatusBadRequest || b.cookies[session.CookieName] != nil {
			t.Fatalf("other tenant = %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("another custom domain", func(t *testing.T) {
		p := newPasskeyEnv(t)
		alias := "login.acme.test"
		tn, _ := p.st.Tenants().Get(ctx, p.tn.ID)
		tn.Domains = append(tn.Domains, alias)
		if err := p.st.Tenants().Update(ctx, tn); err != nil {
			t.Fatal(err)
		}
		a := p.browser(alias)
		_, _, onAlias := p.start(t, a)
		b := p.browser(pkHost)
		state, csrf, _ := p.start(t, b)
		// The alias's challenge, signed for the alias, posted on the
		// canonical host: another RP ID and origin.
		rec := p.post(t, b, state, csrf, onAlias, string(p.auth.Get(onAlias.request(t), "https://"+alias)))
		fails(t, p, b, rec)
	})
	t.Run("invalid stored RP ID", func(t *testing.T) {
		p := newPasskeyEnv(t)
		alias := "login.acme.test"
		tn, _ := p.st.Tenants().Get(ctx, p.tn.ID)
		tn.Domains = append(tn.Domains, alias)
		tn.DomainRPIDs = map[string]string{alias: "unrelated.example"}
		if err := p.st.Tenants().Update(ctx, tn); err != nil {
			t.Fatal(err)
		}
		b := p.browser(alias)
		page, state, csrf := b.begin(t)
		assertNoPasskey(t, page)
		rec := b.do(t, "POST", "/u/login/passkey", url.Values{"state": {state}, "csrf": {csrf}, "challenge_id": {"x"}, "credential": {"{}"}})
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), `action="/u/login"`) || b.cookies[session.CookieName] != nil {
			t.Fatalf("invalid RP ID = %d %s", rec.Code, rec.Body)
		}
	})
}

// TestHostedPasskeyAttackProtection pins R3.
func TestHostedPasskeyAttackProtection(t *testing.T) {
	ctx := context.Background()
	t.Run("brute-force block refuses a valid passkey", func(t *testing.T) {
		p := newPasskeyEnv(t)
		setProtectionLimits(t, p.st, 3, 50, 50)
		pw := p.browser(pkHost)
		for range 3 {
			_, state, csrf := pw.begin(t)
			rec := pw.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}})
			pwd := pw.do(t, "GET", rec.Header().Get("Location"), nil)
			pw.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, pwd.Body.String())}, "password": {"wrong"}})
		}
		p.events.reset()
		b, rec := p.login(t, p.auth)
		if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), pageText(i18n.KeyTooManyAttempts)) || b.cookies[session.CookieName] != nil {
			t.Fatalf("blocked passkey = %d %s", rec.Code, rec.Body)
		}
		if len(p.events.of("limit_wc")) == 0 {
			t.Fatalf("no block log: %+v", p.events.events)
		}
		if list, _ := p.st.Sessions().ListByUser(ctx, p.tn.ID, p.alice.UserID); len(list) != 0 {
			t.Fatalf("sessions = %d", len(list))
		}
	})
	t.Run("success resets the failure counter", func(t *testing.T) {
		p := newPasskeyEnv(t)
		setProtectionLimits(t, p.st, 3, 50, 50)
		pw := p.browser(pkHost)
		wrong := func() {
			_, state, csrf := pw.begin(t)
			rec := pw.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}})
			pwd := pw.do(t, "GET", rec.Header().Get("Location"), nil)
			pw.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, pwd.Body.String())}, "password": {"wrong"}})
		}
		wrong()
		wrong()
		if _, rec := p.login(t, p.auth); rec.Code != http.StatusFound {
			t.Fatalf("passkey = %d %s", rec.Code, rec.Body)
		}
		wrong()
		wrong()
		// Two more failures after the reset: still below the limit.
		p.auth.SignCount = 9
		if _, rec := p.login(t, p.auth); rec.Code != http.StatusFound {
			t.Fatalf("counter not reset: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("failed assertions spend the IP login budget", func(t *testing.T) {
		p := newPasskeyEnv(t)
		setProtectionLimits(t, p.st, 50, 3, 50)
		stranger := webauthntest.New(webauthntest.Options{})
		stranger.Create(webauthn.CreationOptions{UserID: []byte("nobody")}, pkOrigin)
		var last int
		for range 4 {
			_, rec := p.login(t, stranger)
			last = rec.Code
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("IP budget not spent: last = %d", last)
		}
		// The block is store-backed: a valid passkey from that IP is refused too.
		if _, rec := p.login(t, p.auth); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("valid passkey from blocked IP = %d", rec.Code)
		}
		blocks, err := p.st.Protection().Blocks(ctx, p.tn.ID, store.ProtectionFilter{Kind: store.ProtectionSuspiciousIPLogin}, p.h.now())
		if err != nil || len(blocks) == 0 {
			t.Fatalf("store block = %+v, %v", blocks, err)
		}
	})
}

func TestWebAuthnErrorNames(t *testing.T) {
	for _, name := range []string{"NotAllowedError", "InvalidStateError", "NotSupportedError", "SecurityError", "AbortError", "ConstraintError", "UnknownError"} {
		if got := webauthnErrorName(name); got != name {
			t.Errorf("%s -> %s", name, got)
		}
	}
	for _, name := range []string{"", "TypeError", "notallowederror", "<script>alert(1)</script>", strings.Repeat("A", 4096)} {
		if got := webauthnErrorName(name); got != "UnknownError" {
			t.Errorf("%q -> %s", name, got)
		}
	}
	p := newPasskeyEnv(t)
	for _, name := range []string{"NotAllowedError", "EvilMarker<b>Error"} {
		b := p.browser(pkHost)
		state, csrf, c := p.start(t, b)
		p.events.reset()
		rec := b.do(t, "POST", "/u/login/passkey", url.Values{"state": {state}, "csrf": {csrf}, "challenge_id": {c.ChallengeID}, "webauthn_error": {name}})
		body := rec.Body.String()
		again := parsePasskey(t, body)
		if rec.Code != http.StatusOK || again == nil || again.ChallengeID == c.ChallengeID || strings.Contains(body, "EvilMarker") || strings.Contains(body, name) {
			t.Fatalf("%s = %d %s", name, rec.Code, body)
		}
		if len(p.events.events) != 0 {
			t.Fatalf("logged %+v", p.events.events)
		}
	}
}
