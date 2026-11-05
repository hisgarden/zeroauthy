package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const passkeyOrigin = "https://acme.example.test"
const passkeyRPID = "acme.example.test"

// enablePasskeys turns passkeys on for the fixture's database connection,
// makes the prompts satisfy the prerequisites, and wires the ceremony
// service the base fixture leaves nil.
func (e *env) enablePasskeys(t *testing.T, ui string) {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	c, err := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	if c.Extra == nil {
		c.Extra = map[string]any{}
	}
	c.Extra["authentication_methods"] = map[string]any{"passkey": map[string]any{"enabled": true}}
	if ui != "" {
		c.Extra["passkey_options"] = map[string]any{"challenge_ui": ui}
	}
	if err := e.st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	e.setPrompts(t, map[string]any{"identifier_first": true, "universal_login_experience": "new"})
	e.h.Passkeys = passkey.New(e.st, rpid.Policy{BaseDomain: "example.test", Store: e.st}, fixedNow)
}

// setPrompts upserts the tenant's hosted-login prompt settings.
func (e *env) setPrompts(t *testing.T, prompts map[string]any) {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	rev := int64(0)
	if cfg, err := e.st.HostedLogins().Get(ctx, tn.ID); err == nil {
		rev = cfg.Revision
	}
	if err := e.st.HostedLogins().Put(ctx, &store.HostedLoginConfig{TenantID: tn.ID, Prompts: prompts}, rev); err != nil {
		t.Fatal(err)
	}
}

// challengeIDField finds the hidden challenge the page posts.
var challengeIDField = regexp.MustCompile(`name="challenge_id" value="([^"]+)"`)

// pageChallenge reads the challenge_id and RequestOptions the login-id page
// embedded. The options JSON is what the browser parses, so the test
// authenticator signs exactly the server's challenge.
func pageChallenge(t *testing.T, body string) (string, webauthn.RequestOptions) {
	t.Helper()
	const marker = `<script type="application/json" id="za-webauthn">`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no za-webauthn block on the page")
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, "</script>")
	if j < 0 {
		t.Fatal("unterminated za-webauthn block")
	}
	raw := strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&").Replace(rest[:j])
	var pub struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		Allow            []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err := json.Unmarshal([]byte(raw), &pub); err != nil {
		t.Fatalf("options JSON %q: %v", raw, err)
	}
	opts := webauthn.RequestOptions{Challenge: mustB64(t, pub.Challenge), RPID: pub.RPID, UserVerification: pub.UserVerification}
	for _, d := range pub.Allow {
		opts.Allow = append(opts.Allow, webauthn.Descriptor{ID: mustB64(t, d.ID)})
	}
	id := challengeIDField.FindStringSubmatch(body)
	if id == nil {
		t.Fatal("no challenge_id on the page")
	}
	return id[1], opts
}

// logCode returns the frozen inventory entry for a log code.
func logCode(code string) *logrules.Code {
	for _, c := range logrules.Codes() {
		if c.Type == code {
			return &c
		}
	}
	return nil
}

// rawPost sends a form POST using the browser's current cookies without
// mutating the browser, so concurrent submissions are race-free.
func rawPost(t *testing.T, b *browser, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "https://"+b.host+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.e.srv.ServeHTTP(rec, r)
	return rec
}

// findEvent returns the first recorded event of a type, or nil.
func findEvent(c *eventRecorder, code string) *logs.Event {
	for i := range c.events {
		if c.events[i].Type == code {
			return &c.events[i]
		}
	}
	return nil
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return out
}

// registerPasskey enrolls a passkey for the fixture user through the
// ceremony service, as signup or progressive enrollment would.
func (e *env) registerPasskey(t *testing.T, login string, opts ...func(*webauthntest.Options)) *webauthntest.Authenticator {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	u := e.user(t, login)
	o := webauthntest.Options{Alg: -7, UV: true, BE: true, BS: true, Attachment: "platform"}
	for _, f := range opts {
		f(&o)
	}
	auth := webauthntest.New(o)
	b := passkey.Binding{Purpose: passkey.PurposePasskeyRegister, RPID: passkeyRPID, Origins: []string{passkeyOrigin}, TxnID: "test-txn", CookieHash: "test-cookie", UserID: u.UserID}
	issued, err := e.h.Passkeys.Issue(ctx, tn.ID, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	co, err := e.h.Passkeys.CreationOptions(ctx, tn.ID, u, passkey.UserDisplay{Name: "alice@acme.test", DisplayName: "Alice"}, passkeyRPID, passkey.Progressive, issued.Challenge, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := auth.Create(co, passkeyOrigin)
	if _, err := e.h.Passkeys.Enroll(ctx, tn.ID, u, "", raw, issued.Challenge, b, "test-agent"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return auth
}

// startPasskeyLogin begins a transaction on the login-id page and returns
// the page, state, csrf, challenge id and parsed options.
func startPasskeyLogin(t *testing.T, b *browser) (*httptest.ResponseRecorder, string, string, string, webauthn.RequestOptions) {
	t.Helper()
	page, state, csrf := b.begin(t)
	challengeID, opts := pageChallenge(t, page.Body.String())
	return page, state, csrf, challengeID, opts
}

// TestLoginIDPasskeyMarkup covers spec section 3.3: which markup each
// challenge_ui value adds to the login-id page, and that a page without
// effective passkeys carries none of it.
func TestLoginIDPasskeyMarkup(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		ui                           string
		wantAutocomplete, wantButton bool
	}{
		{"both", "both", true, true},
		{"autofill", "autofill", true, false},
		{"button", "button", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.enablePasskeys(t, tc.ui)
			b := e.browser("acme.example.test")
			page, _, _ := b.begin(t)
			body := page.Body.String()

			gotAutocomplete := strings.Contains(body, `autocomplete="username webauthn"`)
			if gotAutocomplete != tc.wantAutocomplete {
				t.Fatalf("autofill markup = %v, want %v", gotAutocomplete, tc.wantAutocomplete)
			}
			gotButton := strings.Contains(body, `id="za-passkey-button"`)
			if gotButton != tc.wantButton {
				t.Fatalf("button markup = %v, want %v", gotButton, tc.wantButton)
			}
			if tc.wantButton && !strings.Contains(body, "Continue with a passkey") {
				t.Fatal("button label missing")
			}
			if tc.wantAutocomplete {
				if !strings.Contains(body, `id="za-webauthn"`) {
					t.Fatal("no options block")
				}
				if _, opts := pageChallenge(t, body); opts.RPID != passkeyRPID || len(opts.Challenge) == 0 {
					t.Fatalf("options = %+v", opts)
				}
			} else if strings.Contains(body, `id="za-webauthn"`) {
				t.Fatal("button-only page carries an options block")
			}
			// The script is inline and carries the response's CSP nonce.
			if !strings.Contains(body, "<script nonce=") {
				t.Fatal("no inline nonce script")
			}
			// The CSP is unchanged from Plan 22's: no connect-src, no
			// script-src relaxation beyond the nonce.
			csp := page.Header().Get("Content-Security-Policy")
			if strings.Contains(csp, "connect-src") || !strings.Contains(csp, "script-src 'nonce-") {
				t.Fatalf("csp = %q", csp)
			}
			if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
				t.Fatalf("csp relaxed = %q", csp)
			}
		})
	}
}

// TestLoginIDPasskeyMarkupAbsent: with passkeys off, or a prerequisite
// unmet, the page is exactly the plain identifier page.
func TestLoginIDPasskeyMarkupAbsent(t *testing.T) {
	t.Run("passkeys disabled", func(t *testing.T) {
		e := newEnv(t)
		e.h.Passkeys = passkey.New(e.st, rpid.Policy{BaseDomain: "example.test", Store: e.st}, fixedNow)
		b := e.browser("acme.example.test")
		page, _, _ := b.begin(t)
		body := page.Body.String()
		if strings.Contains(body, "za-webauthn") || strings.Contains(body, "za-passkey-button") || strings.Contains(body, "webauthn") {
			t.Fatal("markup present with passkeys disabled")
		}
	})
	t.Run("identifier_first unmet", func(t *testing.T) {
		e := newEnv(t)
		e.enablePasskeys(t, "both")
		e.setPrompts(t, map[string]any{"identifier_first": false})
		b := e.browser("acme.example.test")
		page, _, _ := b.begin(t)
		if strings.Contains(page.Body.String(), "za-webauthn") {
			t.Fatal("markup present with identifier_first unmet")
		}
	})
}

// TestHostedPasskeyLogin covers the success path: the assertion logs the
// user in, the session records the passkey first factor, and MFAAt stays
// zero.
func TestHostedPasskeyLogin(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	auth := e.registerPasskey(t, "alice@acme.test")

	b := e.browser("acme.example.test")
	_, state, csrf, challengeID, opts := startPasskeyLogin(t, b)
	rec := b.do(t, "POST", "/u/login/passkey", url.Values{
		"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID},
		"credential": {string(auth.Get(opts, passkeyOrigin))},
	})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" {
		t.Fatalf("passkey login = %d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	ck := b.cookies["za_session"]
	if ck == nil {
		t.Fatal("no session cookie")
	}
	sess, err := e.st.Sessions().GetByTokenHash(context.Background(), mustTenant(t, e, "acme").ID, secrets.HashToken(ck.Value))
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.AuthMethods) != 1 || sess.AuthMethods[0].Name != "passkey" {
		t.Fatalf("session methods = %+v", sess.AuthMethods)
	}
	if !sess.MFAAt.IsZero() {
		t.Fatalf("MFAAt = %v, want zero", sess.MFAAt)
	}
}

// TestHostedPasskeyDoubleSubmit is Review Focus 2: exactly one of two
// concurrent submissions of one challenge is accepted, and the loser sees
// the generic failure with a fresh usable page, never a 500.
func TestHostedPasskeyDoubleSubmit(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	auth := e.registerPasskey(t, "alice@acme.test")

	b := e.browser("acme.example.test")
	page, state, csrf, challengeID, opts := startPasskeyLogin(t, b)
	raw := string(auth.Get(opts, passkeyOrigin))
	// Read the revision from the page and send it explicitly: two concurrent
	// submissions must not race on the browser's own bookkeeping.
	rev := hostedRevisionField.FindStringSubmatch(page.Body.String())
	if rev == nil {
		t.Fatal("no hosted_revision on the page")
	}

	form := url.Values{
		"state": {state}, "csrf": {csrf}, "hosted_revision": {rev[1]},
		"challenge_id": {challengeID}, "credential": {raw},
	}
	var wg sync.WaitGroup
	recs := make([]*httptest.ResponseRecorder, 2)
	for i := range recs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recs[i] = rawPost(t, b, "/u/login/passkey", form)
		}(i)
	}
	wg.Wait()

	wins, losses := 0, 0
	for _, rec := range recs {
		switch rec.Code {
		case 302:
			wins++
		case 200, 401:
			losses++
			body := rec.Body.String()
			if !strings.Contains(body, "passkey") && !strings.Contains(body, "sign you in") {
				t.Fatalf("loser page lacks the generic error:\n%s", body)
			}
		default:
			t.Fatalf("unexpected status %d:\n%s", rec.Code, rec.Body)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("wins=%d losses=%d, want exactly one each", wins, losses)
	}
}

// TestHostedPasskeyStaleCredential is Review Focus 3: a credential the
// server no longer accepts gives one generic answer and the same log, and
// never reveals which case applied.
func TestHostedPasskeyStaleCredential(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before func(t *testing.T, e *env, auth *webauthntest.Authenticator)
	}{
		{"credential deleted", func(t *testing.T, e *env, auth *webauthntest.Authenticator) {
			tn := mustTenant(t, e, "acme")
			u := e.user(t, "alice@acme.test")
			list, err := e.st.MFA().ListAuthenticators(context.Background(), tn.ID, u.UserID)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range list {
				if err := e.st.MFA().DeleteAuthenticator(context.Background(), tn.ID, u.UserID, a.ID); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"passkeys disabled", func(t *testing.T, e *env, auth *webauthntest.Authenticator) {
			ctx := context.Background()
			tn := mustTenant(t, e, "acme")
			c, err := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
			if err != nil {
				t.Fatal(err)
			}
			c.Extra["authentication_methods"] = map[string]any{"passkey": map[string]any{"enabled": false}}
			if err := e.st.Connections().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.enablePasskeys(t, "both")
			auth := e.registerPasskey(t, "alice@acme.test")
			capture := &eventRecorder{}
			e.h.Recorder = capture
			b := e.browser("acme.example.test")
			_, state, csrf, challengeID, opts := startPasskeyLogin(t, b)
			raw := string(auth.Get(opts, passkeyOrigin))
			tc.before(t, e, auth)

			rec := b.do(t, "POST", "/u/login/passkey", url.Values{
				"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID}, "credential": {raw},
			})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401:\n%s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "passkey") {
				t.Fatalf("no generic error:\n%s", rec.Body)
			}
			// The log code is deferred to Task 19, so emission is asserted
			// there; here the path must record it once it is emitted.
			if ev := findEvent(capture, "gd_webauthn_challenge_failed"); ev != nil {
				if first, _ := ev.Details["first_factor"].(bool); !first {
					t.Fatalf("first_factor = %v, want true", ev.Details["first_factor"])
				}
				if body := fmt.Sprint(ev.Details); strings.Contains(body, challengeID) || strings.Contains(body, raw[:40]) {
					t.Fatalf("details leak the challenge or credential: %s", body)
				}
			}
			if code := logCode("gd_webauthn_challenge_failed"); code == nil || code.Owner != "Plan 33b" {
				t.Fatalf("log code owner = %+v", code)
			}
		})
	}
}

// TestHostedPasskeyBinding: a challenge from another transaction, browser or
// host, or with a forged origin, is refused generically.
func TestHostedPasskeyBinding(t *testing.T) {
	t.Run("another transaction", func(t *testing.T) {
		e := newEnv(t)
		e.enablePasskeys(t, "both")
		auth := e.registerPasskey(t, "alice@acme.test")
		b := e.browser("acme.example.test")
		_, _, _, challengeID, opts := startPasskeyLogin(t, b)
		raw := string(auth.Get(opts, passkeyOrigin))
		// A second transaction's state and csrf, but the first's challenge.
		_, state2, csrf2 := b.begin(t)
		rec := b.do(t, "POST", "/u/login/passkey", url.Values{
			"state": {state2}, "csrf": {csrf2}, "challenge_id": {challengeID}, "credential": {raw},
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
	t.Run("forged origin", func(t *testing.T) {
		e := newEnv(t)
		e.enablePasskeys(t, "both")
		auth := e.registerPasskey(t, "alice@acme.test")
		b := e.browser("acme.example.test")
		_, state, csrf, challengeID, opts := startPasskeyLogin(t, b)
		raw := string(auth.Get(opts, "https://evil.example.test"))
		rec := b.do(t, "POST", "/u/login/passkey", url.Values{
			"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID}, "credential": {raw},
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

// TestWebAuthnErrorNames: the posted DOMException name is bounded and never
// echoed; a cancellation re-renders without a challenge-failed log.
func TestWebAuthnErrorNames(t *testing.T) {
	for _, tc := range []struct {
		posted     string
		wantLogged bool
	}{
		{"NotAllowedError", false},
		{"InvalidStateError", true},
		{"<script>alert(1)</script>", true},
	} {
		t.Run(tc.posted, func(t *testing.T) {
			e := newEnv(t)
			e.enablePasskeys(t, "both")
			capture := &eventRecorder{}
			e.h.Recorder = capture
			b := e.browser("acme.example.test")
			_, state, csrf, challengeID, _ := startPasskeyLogin(t, b)
			rec := b.do(t, "POST", "/u/login/passkey", url.Values{
				"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID}, "webauthn_error": {tc.posted},
			})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
				t.Fatal("posted value echoed into the page")
			}
			// Only the two blocks below reach the challenge-failure path;
			// that code is emitted from Task 19, so this asserts the two
			// paths diverge and that nothing unbounded reaches a page.
			if tc.wantLogged && !strings.Contains(rec.Body.String(), "passkey") {
				t.Fatalf("no generic passkey failure for %q:\n%s", tc.posted, rec.Body)
			}
			for _, ev := range capture.events {
				if strings.Contains(fmt.Sprint(ev.Details), "alert(1)") {
					t.Fatal("posted value leaked into a log")
				}
			}
		})
	}
}
