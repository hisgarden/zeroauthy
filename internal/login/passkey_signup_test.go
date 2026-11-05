package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

// creationOptionsJSON mirrors webauthn's creationOptionsJSON document.
type creationOptionsJSON struct {
	RP struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Challenge string `json:"challenge"`
	Timeout   int64  `json:"timeout"`
	Selection struct {
		Attachment       string `json:"authenticatorAttachment"`
		ResidentKey      string `json:"residentKey"`
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Attestation string `json:"attestation"`
}

func jsonUnmarshal(raw string, v any) error { return json.Unmarshal([]byte(raw), v) }

func b64u(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return out
}

// toCreationOptions converts the page document into the options the test
// authenticator signs, so the ceremony uses the server's own challenge.
func toCreationOptions(t *testing.T, o creationOptionsJSON) webauthn.CreationOptions {
	t.Helper()
	return webauthn.CreationOptions{
		Challenge: b64u(t, o.Challenge), RPID: o.RP.ID, RPName: o.RP.Name,
		UserID: b64u(t, o.User.ID), UserName: o.User.Name, DisplayName: o.User.DisplayName,
		Attachment: o.Selection.Attachment, ResidentKey: o.Selection.ResidentKey,
		UserVerification: o.Selection.UserVerification,
	}
}

// signupBegin starts a signup transaction and walks the split flow to the
// passkey-enrollment step. b.begin already follows the entry redirect, so
// the page it returns is the split flow's identifier step.
func signupBegin(t *testing.T, b *browser, email string) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	ident, state, _ := b.begin(t, "screen_hint", "signup")
	if ident.Code != http.StatusOK {
		t.Fatalf("identifier page = %d %s", ident.Code, ident.Body)
	}
	m := csrfField.FindStringSubmatch(ident.Body.String())
	if m == nil {
		t.Fatalf("no csrf on the identifier page:\n%s", ident.Body)
	}
	rec := b.do(t, "POST", "/u/signup/identifier", url.Values{
		"state": {state}, "csrf": {m[1]}, "email": {email},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("identifier step = %d %s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/signup/passkey" {
		t.Fatalf("identifier redirect = %q", rec.Header().Get("Location"))
	}
	enroll := b.do(t, "GET", loc.RequestURI(), nil)
	if enroll.Code != http.StatusOK {
		t.Fatalf("enrollment page = %d %s", enroll.Code, enroll.Body)
	}
	em := csrfField.FindStringSubmatch(enroll.Body.String())
	if em == nil {
		t.Fatalf("no csrf on the enrollment page:\n%s", enroll.Body)
	}
	return enroll, state, em[1]
}

// enrollmentChallenge reads the creation challenge and options from the
// passkey-enrollment page.
func enrollmentChallenge(t *testing.T, body string) (string, creationOptionsJSON) {
	t.Helper()
	const marker = `<script type="application/json" id="za-webauthn-create">`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no za-webauthn-create block on the page")
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, "</script>")
	if j < 0 {
		t.Fatal("unterminated za-webauthn-create block")
	}
	raw := strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&").Replace(rest[:j])
	var opts creationOptionsJSON
	if err := jsonUnmarshal(raw, &opts); err != nil {
		t.Fatalf("creation options %q: %v", raw, err)
	}
	id := challengeIDField.FindStringSubmatch(body)
	if id == nil {
		t.Fatal("no challenge_id on the enrollment page")
	}
	return id[1], opts
}

// TestPasskeySignup covers the whole split flow (spec section 3.4): the
// identifier step, the enrollment choice, and an account created with a
// passkey and no password.
func TestPasskeySignup(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	b := e.browser("acme.example.test")
	enroll, state, csrf := signupBegin(t, b, "bob@acme.test")

	body := enroll.Body.String()
	if !strings.Contains(body, "bob@acme.test") || !strings.Contains(body, "passkey") {
		t.Fatalf("enrollment page lacks the collected email or the passkey offer:\n%s", body)
	}
	// The screen offers both choices.
	if !strings.Contains(body, "create a password") && !strings.Contains(body, "Create a password") {
		t.Fatalf("no password choice:\n%s", body)
	}
	challengeID, opts := enrollmentChallenge(t, body)
	auth := webauthntest.New(webauthntest.Options{Alg: -7, UV: true, BE: true, BS: true, Attachment: "platform"})
	raw := auth.Create(toCreationOptions(t, opts), passkeyOrigin)

	rec := b.do(t, "POST", "/u/signup/passkey", url.Values{
		"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID}, "credential": {string(raw)},
	})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" {
		t.Fatalf("passkey signup = %d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}

	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	u, err := e.st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "bob@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	// The account was created with no password.
	if len(u.Identities) != 1 || u.Identities[0].PasswordHash != "" {
		t.Fatalf("password hash = %+v, want empty", u.Identities)
	}
	// The passkey exists and belongs to that user.
	creds, err := e.st.MFA().ListAuthenticators(ctx, tn.ID, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].Type != "passkey" {
		t.Fatalf("authenticators = %+v", creds)
	}
	// The session records the passkey first factor.
	ck := b.cookies["za_session"]
	if ck == nil {
		t.Fatal("no session cookie")
	}
	sess, err := e.st.Sessions().GetByTokenHash(ctx, tn.ID, secrets.HashToken(ck.Value))
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.AuthMethods) != 1 || sess.AuthMethods[0].Name != "passkey" {
		t.Fatalf("session methods = %+v", sess.AuthMethods)
	}
}

// TestPasskeySignupWithoutScript is Review Focus 4: the enrollment page
// without JavaScript still renders a plain form whose "create a password"
// submit reaches the password step and completes signup.
func TestPasskeySignupWithoutScript(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	b := e.browser("acme.example.test")
	enroll, state, _ := signupBegin(t, b, "nina@acme.test")
	if !strings.Contains(enroll.Body.String(), "/u/signup/password") {
		t.Fatalf("no plain password form:\n%s", enroll.Body)
	}
	step := b.do(t, "GET", "/u/signup/password?state="+url.QueryEscape(state), nil)
	if step.Code != http.StatusOK {
		t.Fatalf("password page = %d %s", step.Code, step.Body)
	}
	pm := csrfField.FindStringSubmatch(step.Body.String())
	if pm == nil {
		t.Fatalf("no csrf on the password page:\n%s", step.Body)
	}
	rec := b.do(t, "POST", "/u/signup/password", url.Values{
		"state": {state}, "csrf": {pm[1]}, "password": {"a long enough password"},
	})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" {
		t.Fatalf("password step = %d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	u, err := e.st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "carol@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if u.Identities[0].PasswordHash == "" {
		t.Fatal("password signup stored no password")
	}
	ck := b.cookies["za_session"]
	sess, err := e.st.Sessions().GetByTokenHash(ctx, tn.ID, secrets.HashToken(ck.Value))
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.AuthMethods) != 1 || sess.AuthMethods[0].Name != "pwd" {
		t.Fatalf("session methods = %+v, want pwd", sess.AuthMethods)
	}
}

// TestPasskeySignupRules: without effective passkeys the single Plan 22 page
// stays (LR33b-15), and a passkey-only user's password login gets the normal
// wrong-credentials answer (LR33b-36).
func TestPasskeySignupRules(t *testing.T) {
	t.Run("single page without passkeys", func(t *testing.T) {
		e := newEnv(t)
		e.h.Passkeys = nil
		b := e.browser("acme.example.test")
		page, state, _ := b.begin(t, "screen_hint", "signup")
		if page.Code != 200 {
			t.Fatalf("signup page = %d", page.Code)
		}
		// The single page renders the password field itself, and posting it
		// still reaches the ordinary signup handler.
		if !strings.Contains(page.Body.String(), `name="password"`) {
			t.Fatalf("no password field on the single page:\n%s", page.Body)
		}
		rec := b.do(t, "GET", "/u/signup?state="+url.QueryEscape(state), nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="password"`) {
			t.Fatalf("single signup page = %d\n%s", rec.Code, rec.Body)
		}
	})
	t.Run("passkey-only user cannot use a password", func(t *testing.T) {
		e := newEnv(t)
		e.enablePasskeys(t, "both")
		b := e.browser("acme.example.test")
		enroll, state, csrf := signupBegin(t, b, "dave@acme.test")
		challengeID, opts := enrollmentChallenge(t, enroll.Body.String())
		auth := webauthntest.New(webauthntest.Options{Alg: -7, UV: true})
		raw := auth.Create(toCreationOptions(t, opts), passkeyOrigin)
		if rec := b.do(t, "POST", "/u/signup/passkey", url.Values{
			"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID}, "credential": {string(raw)},
		}); rec.Code != 302 {
			t.Fatalf("passkey signup = %d %s", rec.Code, rec.Body)
		}
		// A new login attempt with a password gets the ordinary refusal.
		b2 := e.browser("acme.example.test")
		_, state2, csrf2 := b2.begin(t)
		// identifier_first moves the login to its password step first.
		rec := b2.do(t, "POST", "/u/login", url.Values{
			"state": {state2}, "csrf": {csrf2}, "username": {"dave@acme.test"},
		})
		if rec.Code == http.StatusSeeOther {
			pw := b2.do(t, "GET", rec.Header().Get("Location"), nil)
			pm := csrfField.FindStringSubmatch(pw.Body.String())
			if pm == nil {
				t.Fatalf("no csrf on the password step:\n%s", pw.Body)
			}
			rec = b2.do(t, "POST", "/u/login/password", url.Values{
				"state": {state2}, "csrf": {pm[1]}, "password": {"anything at all"},
			})
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("password login = %d, want 401:\n%s", rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), "Incorrect email/username or password") {
			t.Fatalf("not the wrong-credentials answer:\n%s", rec.Body)
		}
	})
}

// TestPasskeySignupIdentifierStored: the password step cannot change the
// identifier the first step collected.
func TestPasskeySignupIdentifierStored(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	b := e.browser("acme.example.test")
	_, state, _ := signupBegin(t, b, "erin@acme.test")
	// Posting a different email must not create that account.
	step := b.do(t, "GET", "/u/signup/password?state="+url.QueryEscape(state), nil)
	pm := csrfField.FindStringSubmatch(step.Body.String())
	if pm == nil {
		t.Fatalf("no csrf on the password page:\n%s", step.Body)
	}
	rec := b.do(t, "POST", "/u/signup/password", url.Values{
		"state": {state}, "csrf": {pm[1]}, "email": {"mallory@acme.test"}, "password": {"a long enough password"},
	})
	if rec.Code != 302 {
		t.Fatalf("password step = %d %s", rec.Code, rec.Body)
	}
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	if _, err := e.st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "erin@acme.test"); err != nil {
		t.Fatalf("stored identifier was not used: %v", err)
	}
	if _, err := e.st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "mallory@acme.test"); err == nil {
		t.Fatal("posted identifier overrode the stored one")
	}
}
