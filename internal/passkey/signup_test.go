package passkey_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

func TestSignupCreatesPasswordlessUser(t *testing.T) {
	e := newEnv(t)
	signup := func(draft *store.User, auth *webauthntest.Authenticator) (*store.User, *store.Authenticator, error) {
		t.Helper()
		b := hosted(passkey.PurposePasskeyRegister, "")
		iss := e.issue(t, b)
		opts, err := e.svc.CreationOptions(e.ctx, tid, draft, passkey.Display(draft, nil), host, passkey.Signup, iss.Challenge, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(opts.Exclude) != 0 || len(opts.UserID) != webauthnrules.Limits.UserHandleBytes {
			t.Fatalf("signup options = %+v", opts)
		}
		return e.svc.Signup(e.ctx, tid, draft, auth.Create(opts, origin), e.take(t, iss, b), b, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
	}
	draft := func(email string) *store.User {
		return &store.User{TenantID: tid, Email: email, Identities: []store.Identity{{Connection: dbConn, Provider: store.StrategyDatabase}}}
	}

	auth := webauthntest.New(webauthntest.Options{BE: true, BS: true})
	u, a, err := signup(draft("new@example.com"), auth)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.UserID, store.StrategyDatabase+"|") || u.Identities[0].UserID != strings.TrimPrefix(u.UserID, store.StrategyDatabase+"|") {
		t.Fatalf("user ID = %q / %+v", u.UserID, u.Identities)
	}
	stored, err := e.st.Users().Get(e.ctx, tid, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Identities[0].PasswordHash != "" || stored.Identities[0].ImportedHash != "" || stored.Email != "new@example.com" {
		t.Fatalf("stored user = %+v", stored)
	}
	pk, err := e.st.MFA().GetAuthenticator(e.ctx, tid, u.UserID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pk.Type != "passkey" || !bytes.Equal(pk.CredentialID, auth.CredentialID()) || publicData(t, pk)["identity_user_id"] != u.Identities[0].UserID || !bytes.Equal(handleOf(t, pk), auth.UserHandle()) {
		t.Fatalf("passkey = %+v %s", pk, pk.PublicData)
	}
	// The new user logs in with the passkey.
	b := hosted(passkey.PurposePasskeyLogin, "")
	raw, ch := e.assertion(t, auth, b)
	if res, err := e.svc.Login(e.ctx, tid, raw, ch, b); err != nil || res.User.UserID != u.UserID {
		t.Fatalf("login after signup = %v", err)
	}

	// One transaction: a credential the tenant already holds leaves no user.
	dup := webauthntest.New(webauthntest.Options{CredentialID: auth.CredentialID()})
	if _, _, err := signup(draft("other@example.com"), dup); err == nil {
		t.Fatal("duplicate credential signed up")
	}
	if users, _ := e.st.Users().FindByEmail(e.ctx, tid, "other@example.com"); len(users) != 0 {
		t.Fatalf("user created without its passkey: %+v", users)
	}
	// A taken email leaves no passkey behind.
	fresh := webauthntest.New(webauthntest.Options{})
	if _, _, err := signup(draft("new@example.com"), fresh); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("taken email = %v", err)
	}
	if _, err := e.st.WebAuthn().GetAuthenticatorByCredentialID(e.ctx, tid, fresh.CredentialID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("passkey stored without its user: %v", err)
	}

	// A draft carrying a password, a registration that fails verification,
	// and a challenge bound to a user are refused.
	withPassword := draft("pw@example.com")
	withPassword.Identities[0].PasswordHash = "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"
	if _, _, err := signup(withPassword, webauthntest.New(webauthntest.Options{})); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("draft with password = %v", err)
	}
	tampered := webauthntest.New(webauthntest.Options{TamperRPIDHash: true})
	if _, _, err := signup(draft("t@example.com"), tampered); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("tampered = %v", err)
	}
	owner := e.user(t, "u1")
	bound := hosted(passkey.PurposePasskeyRegister, owner.UserID)
	iss := e.issue(t, bound)
	opts, _ := e.svc.CreationOptions(e.ctx, tid, draft("x@example.com"), passkey.UserDisplay{}, host, passkey.Signup, iss.Challenge, 0)
	if _, _, err := e.svc.Signup(e.ctx, tid, draft("x@example.com"), webauthntest.New(webauthntest.Options{}).Create(opts, origin), e.take(t, iss, bound), bound, ""); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("user-bound challenge = %v", err)
	}
}
