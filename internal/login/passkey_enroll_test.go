package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

// passwordLogin signs in with a password and returns the redirect response
// and the transaction state the login used.
func passwordLogin(t *testing.T, b *browser, login, password string) *httptest.ResponseRecorder {
	t.Helper()
	_, state, csrf := b.begin(t)
	ident := b.do(t, "POST", "/u/login", url.Values{
		"state": {state}, "csrf": {csrf}, "username": {login},
	})
	if ident.Code == http.StatusSeeOther {
		pw := b.do(t, "GET", ident.Header().Get("Location"), nil)
		m := csrfField.FindStringSubmatch(pw.Body.String())
		if m == nil {
			t.Fatalf("no csrf on the password step:\n%s", pw.Body)
		}
		return b.do(t, "POST", "/u/login/password", url.Values{
			"state": {state}, "csrf": {m[1]}, "password": {password},
		})
	}
	return b.do(t, "POST", "/u/login", url.Values{
		"state": {state}, "csrf": {csrf}, "username": {login}, "password": {password},
	})
}

// enrollmentFromRedirect follows a 303 the login produced to the enrollment
// prompt, if that is where it went.
func enrollmentFromRedirect(t *testing.T, b *browser, rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
		return nil
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(loc.Path, "/u/passkey-enrollment") {
		return nil
	}
	page := b.do(t, "GET", rec.Header().Get("Location"), nil)
	if page.Code != http.StatusOK {
		t.Fatalf("enrollment page = %d %s", page.Code, page.Body)
	}
	return page
}

// TestProgressiveEnrollmentOffered covers the progressive offer: it appears
// after a password login when the connection enables it, and the skip and
// snooze choices behave as the spec says.
func TestProgressiveEnrollmentOffered(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	b := e.browser("acme.example.test")
	rec := passwordLogin(t, b, "alice@acme.test", "alice password 1")
	page := enrollmentFromRedirect(t, b, rec)
	if page == nil {
		t.Fatalf("no progressive prompt after a password login: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	body := page.Body.String()
	if !strings.Contains(body, "/u/passkey-enrollment") || !strings.Contains(body, "za-webauthn-create") {
		t.Fatalf("prompt page lacks the registration markup:\n%s", body)
	}
	if !strings.Contains(body, "checkbox") {
		t.Fatal("prompt has no don't-show-again checkbox")
	}

	// Skipping continues the login for this time only.
	state := stateFromPage(t, body)
	m := csrfField.FindStringSubmatch(body)
	skip := b.do(t, "POST", "/u/passkey-enrollment?decision=skip", url.Values{
		"state": {state}, "csrf": {m[1]},
	})
	loc, _ := url.Parse(skip.Header().Get("Location"))
	if skip.Code != http.StatusFound && skip.Code != http.StatusSeeOther {
		t.Fatalf("skip = %d %s", skip.Code, skip.Body)
	}
	if loc.Host != "app.acme.test" || loc.Query().Get("code") == "" {
		t.Fatalf("skip did not complete the login: %q", skip.Header().Get("Location"))
	}
	// No snooze was stored, so the next login offers it again.
	tn := mustTenant(t, e, "acme")
	u := e.user(t, "alice@acme.test")
	if _, err := e.st.WebAuthn().GetSnooze(ctx, tn.ID, u.UserID, store.SnoozePasskeyProgressive, "acme.example.test", fixedNow()); err == nil {
		t.Fatal("a plain skip stored a snooze")
	}
}

// TestProgressiveEnrollmentSnooze: the checkbox stores a 30-day snooze for
// this RP ID, and the prompt is offered again after it expires.
func TestProgressiveEnrollmentSnooze(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	b := e.browser("acme.example.test")
	rec := passwordLogin(t, b, "alice@acme.test", "alice password 1")
	page := enrollmentFromRedirect(t, b, rec)
	if page == nil {
		t.Fatal("no progressive prompt")
	}
	state := stateFromPage(t, page.Body.String())
	m := csrfField.FindStringSubmatch(page.Body.String())
	skip := b.do(t, "POST", "/u/passkey-enrollment?decision=skip", url.Values{
		"state": {state}, "csrf": {m[1]}, "checkbox": {"on"},
	})
	if skip.Code != http.StatusFound && skip.Code != http.StatusSeeOther {
		t.Fatalf("skip = %d %s", skip.Code, skip.Body)
	}
	tn := mustTenant(t, e, "acme")
	u := e.user(t, "alice@acme.test")
	sn, err := e.st.WebAuthn().GetSnooze(ctx, tn.ID, u.UserID, store.SnoozePasskeyProgressive, "acme.example.test", fixedNow())
	if err != nil {
		t.Fatalf("no snooze stored: %v", err)
	}
	if want := fixedNow().Add(30 * 24 * time.Hour); !sn.Until.Equal(want) {
		t.Fatalf("snooze until = %v, want %v", sn.Until, want)
	}
	// The window is live until its instant: a day before is snoozed, the
	// instant itself and later are not.
	if _, err := e.st.WebAuthn().GetSnooze(ctx, tn.ID, u.UserID, store.SnoozePasskeyProgressive, "acme.example.test", fixedNow().AddDate(0, 0, 29)); err != nil {
		t.Fatalf("day 29 should still be snoozed: %v", err)
	}
	if _, err := e.st.WebAuthn().GetSnooze(ctx, tn.ID, u.UserID, store.SnoozePasskeyProgressive, "acme.example.test", fixedNow().AddDate(0, 0, 30)); err == nil {
		t.Fatal("day 30 (the expiry instant) should no longer be snoozed")
	}
}

// TestProgressiveEnrollmentNotOffered: every condition that suppresses the
// offer.
func TestProgressiveEnrollmentNotOffered(t *testing.T) {
	t.Run("progressive disabled", func(t *testing.T) {
		e := newEnv(t)
		e.enablePasskeys(t, "both")
		e.setPasskeyOptions(t, map[string]any{"progressive_enrollment_enabled": false})
		b := e.browser("acme.example.test")
		if p := enrollmentFromRedirect(t, b, passwordLogin(t, b, "alice@acme.test", "alice password 1")); p != nil {
			t.Fatal("prompt offered with progressive enrollment disabled")
		}
	})
	t.Run("user already has a passkey", func(t *testing.T) {
		e := newEnv(t)
		e.enablePasskeys(t, "both")
		e.registerPasskey(t, "alice@acme.test")
		b := e.browser("acme.example.test")
		if p := enrollmentFromRedirect(t, b, passwordLogin(t, b, "alice@acme.test", "alice password 1")); p != nil {
			t.Fatal("prompt offered with an existing passkey for this RP ID")
		}
	})
	t.Run("snoozed", func(t *testing.T) {
		e := newEnv(t)
		e.enablePasskeys(t, "both")
		tn := mustTenant(t, e, "acme")
		u := e.user(t, "alice@acme.test")
		if err := e.st.WebAuthn().PutSnooze(context.Background(), &store.WebAuthnSnooze{
			TenantID: tn.ID, UserID: u.UserID, Kind: store.SnoozePasskeyProgressive,
			ScopeKey: "acme.example.test", Until: fixedNow().AddDate(0, 0, 10),
		}); err != nil {
			t.Fatal(err)
		}
		b := e.browser("acme.example.test")
		if p := enrollmentFromRedirect(t, b, passwordLogin(t, b, "alice@acme.test", "alice password 1")); p != nil {
			t.Fatal("prompt offered while snoozed")
		}
	})
}

// TestLocalEnrollmentOffered: a cross-platform passkey assertion on a
// browser that reports a platform authenticator offers the local prompt.
func TestLocalEnrollmentOffered(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	auth := e.registerPasskey(t, "alice@acme.test", func(o *webauthntest.Options) { o.Attachment = "cross-platform" })

	b := e.browser("acme.example.test")
	_, state, csrf, challengeID, opts := startPasskeyLogin(t, b)
	rec := b.do(t, "POST", "/u/login/passkey", url.Values{
		"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID},
		"credential":             {string(auth.Get(opts, passkeyOrigin))},
		"platform_authenticator": {"1"},
	})
	page := enrollmentFromRedirect(t, b, rec)
	if page == nil {
		t.Fatalf("no local prompt after a cross-platform passkey login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/passkey-enrollment-local" {
		t.Fatalf("prompt path = %q, want the local variant", loc.Path)
	}
	if !strings.Contains(page.Body.String(), "za-webauthn-create") {
		t.Fatalf("local prompt lacks the registration markup:\n%s", page.Body)
	}
}

// TestLocalEnrollmentNotOfferedWithoutAttachment is Review Focus 5: an
// assertion with no authenticatorAttachment offers no local prompt.
func TestLocalEnrollmentNotOfferedWithoutAttachment(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	auth := e.registerPasskey(t, "alice@acme.test", func(o *webauthntest.Options) { o.Attachment = "" })

	b := e.browser("acme.example.test")
	_, state, csrf, challengeID, opts := startPasskeyLogin(t, b)
	rec := b.do(t, "POST", "/u/login/passkey", url.Values{
		"state": {state}, "csrf": {csrf}, "challenge_id": {challengeID},
		"credential":             {string(auth.Get(opts, passkeyOrigin))},
		"platform_authenticator": {"1"},
	})
	if p := enrollmentFromRedirect(t, b, rec); p != nil {
		t.Fatal("local prompt offered without authenticatorAttachment")
	}
}

// TestEnrollmentPromptBinding: the prompt cannot be skipped or forged. A
// direct GET without a pending prompt, or for the other variant, is the
// session-expired page.
func TestEnrollmentPromptBinding(t *testing.T) {
	e := newEnv(t)
	e.enablePasskeys(t, "both")
	b := e.browser("acme.example.test")
	rec := passwordLogin(t, b, "alice@acme.test", "alice password 1")
	page := enrollmentFromRedirect(t, b, rec)
	if page == nil {
		t.Fatal("no progressive prompt")
	}
	state := stateFromPage(t, page.Body.String())

	// The other variant is refused.
	other := b.do(t, "GET", "/u/passkey-enrollment-local?state="+url.QueryEscape(state), nil)
	if other.Code != http.StatusBadRequest {
		t.Fatalf("local variant of a progressive prompt = %d, want the session-expired page", other.Code)
	}
	// Another browser cannot answer this prompt.
	other2 := e.browser("acme.example.test")
	forged := other2.do(t, "POST", "/u/passkey-enrollment?decision=skip", url.Values{
		"state": {state}, "csrf": {csrfOf(t, page)},
	})
	if forged.Code != http.StatusBadRequest {
		t.Fatalf("another browser answered the prompt = %d", forged.Code)
	}
}

// setPasskeyOptions replaces the connection's passkey_options.
func (e *env) setPasskeyOptions(t *testing.T, opts map[string]any) {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	c, err := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	c.Extra["passkey_options"] = opts
	if err := e.st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
}

var stateRe = regexp.MustCompile(`name="state" value="([^"]+)"`)

func stateFromPage(t *testing.T, body string) string {
	t.Helper()
	m := stateRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no state on the page:\n%s", body)
	}
	return m[1]
}

func csrfOf(t *testing.T, page *httptest.ResponseRecorder) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("no csrf on the page:\n%s", page.Body)
	}
	return m[1]
}

var _ = authz.StagePasskeyPrompt
var _ = passkey.PromptProgressive
var _ = webauthn.ReasonRPID
