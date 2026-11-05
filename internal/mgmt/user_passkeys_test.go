package mgmt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Plan 33b Task 14: passkeys on /users/{id}/authentication-methods (spec
// §9.1), linking (LR33b-24), the session view (§5.4) and client mobile.

const passkeyHost = "login.acme.test"

var passkeyIDPattern = regexp.MustCompile(`^passkey\|dev_[A-Za-z0-9]{20}$`)

// passkeyFields are the §9.1 members of a listed passkey.
var passkeyFields = []string{"id", "type", "name", "created_at", "last_auth_at", "key_id", "public_key", "relying_party_identifier",
	"credential_device_type", "credential_backed_up", "aaguid", "identity_user_id", "user_agent", "user_handle", "transports"}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// passkeys is the tenant's passkey ceremony service over the env's store,
// on the canonical host.
func (e *usersEnv) passkeys() *passkey.Service {
	return passkey.New(e.st, rpid.Policy{Store: e.st}, func() time.Time { return now })
}

func hostedBinding(p passkey.Purpose, uid string) passkey.Binding {
	return passkey.Binding{Purpose: p, RPID: passkeyHost, Origins: []string{"https://" + passkeyHost}, TxnID: "txn-1", CookieHash: "cookie-1", UserID: uid}
}

// enrollPasskey registers a passkey for uid through the ceremony service
// with auth, as a hosted enrollment would.
func (e *usersEnv) enrollPasskey(t *testing.T, uid string, auth *webauthntest.Authenticator) *store.Authenticator {
	t.Helper()
	ctx := context.Background()
	svc := e.passkeys()
	u, err := e.st.Users().Get(ctx, e.tn.ID, uid)
	if err != nil {
		t.Fatal(err)
	}
	b := hostedBinding(passkey.PurposePasskeyRegister, uid)
	iss, err := svc.Issue(ctx, e.tn.ID, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := svc.CreationOptions(ctx, e.tn.ID, u, passkey.Display(u, nil), passkeyHost, passkey.Progressive, iss.Challenge, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := auth.Create(opts, "https://"+passkeyHost)
	ch, err := svc.Take(ctx, e.tn.ID, iss.ID, b)
	if err != nil {
		t.Fatal(err)
	}
	a, err := svc.Enroll(ctx, e.tn.ID, u, "", raw, ch, b, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// passkeyLogin runs a hosted passkey login with auth and returns the user
// the credential resolved to.
func (e *usersEnv) passkeyLogin(t *testing.T, auth *webauthntest.Authenticator) (*passkey.LoginResult, error) {
	t.Helper()
	ctx := context.Background()
	svc := e.passkeys()
	b := hostedBinding(passkey.PurposePasskeyLogin, "")
	iss, err := svc.Issue(ctx, e.tn.ID, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := auth.Get(svc.RequestOptions(passkeyHost, iss.Challenge, 0), "https://"+passkeyHost)
	ch, err := svc.Take(ctx, e.tn.ID, iss.ID, b)
	if err != nil {
		t.Fatal(err)
	}
	return svc.Login(ctx, e.tn.ID, raw, ch, b)
}

func newPasskeyBody(auth *webauthntest.Authenticator) map[string]any {
	return map[string]any{"type": "passkey", "key_id": b64u(auth.CredentialID()), "public_key": b64u(auth.PublicKeyCOSE())}
}

func (e *usersEnv) dbIdentity(t *testing.T, uid string) string {
	t.Helper()
	u, err := e.st.Users().Get(context.Background(), e.tn.ID, uid)
	if err != nil {
		t.Fatal(err)
	}
	return u.Identities[0].UserID
}

func methodByID(t *testing.T, list any, id string) map[string]any {
	t.Helper()
	for _, v := range list.([]any) {
		if m := v.(map[string]any); m["id"] == id {
			return m
		}
	}
	t.Fatalf("method %s not listed in %v", id, list)
	return nil
}

func userPasskeys(t *testing.T, e *usersEnv, uid string) []store.Authenticator {
	t.Helper()
	all, err := e.st.MFA().ListAuthenticators(context.Background(), e.tn.ID, uid)
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(all, func(a store.Authenticator) bool { return a.Type != "passkey" })
}

func TestPasskeyMethodsList(t *testing.T) {
	e, uid := mfaUser(t)
	ctx := context.Background()
	synced := webauthntest.New(webauthntest.Options{BE: true, BS: true, Attachment: "platform", Transports: []string{"internal", "hybrid"}})
	pk := e.enrollPasskey(t, uid, synced)
	if err := e.st.WebAuthn().AcceptAssertion(ctx, e.tn.ID, uid, pk.ID, 1, true, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A device-bound passkey stored for another RP ID is listed too.
	bound := webauthntest.New(webauthntest.Options{})
	other := &store.Authenticator{TenantID: e.tn.ID, UserID: uid, ID: "passkey|dev_AbCdEfGhIjKlMnOpQrSt", Type: "passkey", Confirmed: true,
		CredentialID: bound.CredentialID(), PublicKey: bound.PublicKeyCOSE(), RPID: "other.example.test", CreatedAt: now,
		PublicData: []byte(`{"backup_eligible":false,"backed_up":false,"identity_user_id":"` + e.dbIdentity(t, uid) + `","user_handle":"aGFuZGxl"}`)}
	if err := e.st.WebAuthn().CreatePasskey(ctx, other, 0); err != nil {
		t.Fatal(err)
	}
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": testCOSEKey, "relying_party_identifier": "example.test"}, "")
	if r.Code != 201 {
		t.Fatalf("roaming: %d %s", r.Code, r.Body)
	}
	roamingID := out.(map[string]any)["id"].(string)

	r, out = mfaCall(t, e.clientsEnv, "GetAuthenticationMethods", uid, "", nil, "")
	if r.Code != 200 || len(out.([]any)) != 3 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	for _, tc := range []struct {
		a              *store.Authenticator
		auth           *webauthntest.Authenticator
		device, rp     string
		backedUp, used bool
	}{{pk, synced, "multi_device", passkeyHost, true, true}, {other, bound, "single_device", "other.example.test", false, false}} {
		m := methodByID(t, out, tc.a.ID)
		if !passkeyIDPattern.MatchString(tc.a.ID) {
			t.Errorf("passkey ID %q", tc.a.ID)
		}
		for k := range m {
			if !slices.Contains(passkeyFields, k) {
				t.Errorf("%s: unexpected member %q in %v", tc.a.ID, k, m)
			}
		}
		if m["type"] != "passkey" || m["credential_device_type"] != tc.device || m["credential_backed_up"] != tc.backedUp || m["relying_party_identifier"] != tc.rp ||
			m["key_id"] != b64u(tc.auth.CredentialID()) || m["public_key"] != b64u(tc.auth.PublicKeyCOSE()) || m["identity_user_id"] != e.dbIdentity(t, uid) {
			t.Errorf("%s = %v", tc.a.ID, m)
		}
		if _, ok := m["last_auth_at"]; ok != tc.used {
			t.Errorf("%s last_auth_at present=%v", tc.a.ID, ok)
		}
	}
	m := methodByID(t, out, pk.ID)
	if m["aaguid"] != "00000000-0000-0000-0000-000000000000" || m["user_agent"] == nil || !jsonEqual(m["transports"], []any{"internal", "hybrid"}) {
		t.Errorf("passkey metadata = %v", m)
	}
	if h, err := base64.RawURLEncoding.DecodeString(m["user_handle"].(string)); err != nil || len(h) != webauthnrules.Limits.UserHandleBytes {
		t.Errorf("user_handle %v: %v", m["user_handle"], err)
	}
	// WebAuthn MFA keeps its Plan 33 shape.
	roaming := methodByID(t, out, roamingID)
	if roaming["key_id"] != "AQID" || roaming["relying_party_identifier"] != "example.test" || roaming["confirmed"] != true {
		t.Errorf("roaming = %v", roaming)
	}
	r, one := mfaCall(t, e.clientsEnv, "GetAuthenticationMethod", uid, pk.ID, nil, "")
	if r.Code != 200 || !jsonEqual(one, m) {
		t.Errorf("get one = %d %v, want %v", r.Code, one, m)
	}
	// Internal public data never leaves storage under its own name.
	for _, k := range []string{"backup_eligible", "backed_up", "attachment"} {
		if strings.Contains(r.Body.String(), `"`+k+`"`) {
			t.Errorf("%s returned: %s", k, r.Body)
		}
	}
}

type noWebAuthn struct{ store.Store }

func (noWebAuthn) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }

func TestPasskeyMethodsCreate(t *testing.T) {
	e, uid := mfaUser(t)
	ctx := context.Background()
	identityID := e.dbIdentity(t, uid)

	auth := webauthntest.New(webauthntest.Options{})
	r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", newPasskeyBody(auth), "")
	if r.Code != 201 {
		t.Fatalf("create: %d %s", r.Code, r.Body)
	}
	first := out.(map[string]any)
	// Defaults (LR33b-23): the canonical host's RP ID, the database identity
	// and a new 32-byte user handle.
	if !passkeyIDPattern.MatchString(first["id"].(string)) || first["type"] != "passkey" || first["relying_party_identifier"] != passkeyHost ||
		first["identity_user_id"] != identityID || first["credential_device_type"] != "single_device" || first["credential_backed_up"] != false {
		t.Fatalf("created = %v", first)
	}
	handle, err := base64.RawURLEncoding.DecodeString(first["user_handle"].(string))
	if err != nil || len(handle) != webauthnrules.Limits.UserHandleBytes {
		t.Fatalf("user_handle %v: %v", first["user_handle"], err)
	}
	stored, err := e.st.MFA().GetAuthenticator(ctx, e.tn.ID, uid, first["id"].(string))
	if err != nil || !stored.Confirmed || stored.RPID != passkeyHost || string(stored.PublicKey) != string(auth.PublicKeyCOSE()) || string(stored.CredentialID) != string(auth.CredentialID()) {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	// The second passkey reuses the user's handle (LR33b-7); given values
	// are stored as sent.
	given := webauthntest.New(webauthntest.Options{})
	body := newPasskeyBody(given)
	for k, v := range map[string]any{"name": "Work phone", "relying_party_identifier": "acme.test", "aaguid": "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
		"credential_device_type": "multi_device", "credential_backed_up": true, "user_agent": "Imported/1.0", "transports": []string{"internal", "hybrid"}} {
		body[k] = v
	}
	r, out = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", body, "")
	if r.Code != 201 {
		t.Fatalf("create with values: %d %s", r.Code, r.Body)
	}
	second := out.(map[string]any)
	if second["user_handle"] != first["user_handle"] || second["relying_party_identifier"] != "acme.test" || second["credential_device_type"] != "multi_device" ||
		second["credential_backed_up"] != true || second["aaguid"] != body["aaguid"] || second["user_agent"] != "Imported/1.0" || second["name"] != "Work phone" ||
		!jsonEqual(second["transports"], []any{"internal", "hybrid"}) {
		t.Fatalf("created = %v", second)
	}

	// The default RP ID follows the default custom domain's effective RP ID.
	d := &store.CustomDomain{TenantID: e.tn.ID, ID: "cd_login", Domain: "id.acme.example", RelyingPartyIdentifier: "acme.example", Type: "auth0_managed_certs", Generation: 1, Status: "ready"}
	if err := e.st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: e.tn.ID, DomainID: d.ID, Generation: 1, Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CustomDomains().SetDefault(ctx, e.tn.ID, d.ID); err != nil {
		t.Fatal(err)
	}
	r, out = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", newPasskeyBody(webauthntest.New(webauthntest.Options{})), "")
	if r.Code != 201 || out.(map[string]any)["relying_party_identifier"] != "acme.example" {
		t.Fatalf("default custom domain: %d %s", r.Code, r.Body)
	}

	// Refusals.
	missingKey := newPasskeyBody(auth)
	delete(missingKey, "key_id")
	missingPublic := newPasskeyBody(auth)
	delete(missingPublic, "public_key")
	badCOSE := newPasskeyBody(webauthntest.New(webauthntest.Options{}))
	badCOSE["public_key"] = "AQID"
	otherIdentity := newPasskeyBody(webauthntest.New(webauthntest.Options{}))
	otherIdentity["identity_user_id"] = "not-an-identity"
	badHandle := newPasskeyBody(webauthntest.New(webauthntest.Options{}))
	badHandle["user_handle"] = "***"
	for name, b := range map[string]map[string]any{"no key_id": missingKey, "no public_key": missingPublic, "bad COSE": badCOSE, "foreign identity": otherIdentity, "bad handle": badHandle} {
		r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", b, "")
		wantError(t, r, 400, "invalid_body")
		_ = name
	}
	// A duplicate key_id in the tenant, even for another user, is 409.
	other := e.mustCreate(t, map[string]any{"email": "other-passkey@example.test"})["user_id"].(string)
	r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", other, "", newPasskeyBody(auth), "")
	if r.Code != 409 {
		t.Fatalf("duplicate key_id: %d %s", r.Code, r.Body)
	}

	// The 21st passkey is 400 invalid_body (LR33b-29).
	for len(userPasskeys(t, e, uid)) < webauthnrules.Limits.MaxPasskeys {
		r, _ := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", newPasskeyBody(webauthntest.New(webauthntest.Options{})), "")
		if r.Code != 201 {
			t.Fatalf("fill: %d %s", r.Code, r.Body)
		}
	}
	r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", newPasskeyBody(webauthntest.New(webauthntest.Options{})), "")
	wantError(t, r, 400, "invalid_body")
	if n := len(userPasskeys(t, e, uid)); n != webauthnrules.Limits.MaxPasskeys {
		t.Fatalf("%d passkeys after the refused 21st", n)
	}

	// Without webauthn.v1 a passkey create is 501; other types still work.
	e.h.Store = noWebAuthn{e.st}
	r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", other, "", newPasskeyBody(webauthntest.New(webauthntest.Options{})), "")
	wantError(t, r, 501, "webauthn_unavailable")
	r, _ = mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", other, "", map[string]any{"type": "email", "email": "other-passkey@example.test"}, "")
	if r.Code != 201 {
		t.Fatalf("email without webauthn.v1: %d %s", r.Code, r.Body)
	}
}

func TestPasskeyMethodsPatchDelete(t *testing.T) {
	e, uid := mfaUser(t)
	ctx := context.Background()
	e.h.Store = events.Wrap(e.st, events.Config{})
	userUpdated := func() int {
		t.Helper()
		rows, err := e.h.Store.Events().EventsAfter(ctx, e.tn.ID, 0, []string{"user.updated"}, 100, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	create := func(b map[string]any) string {
		t.Helper()
		r, out := mfaCall(t, e.clientsEnv, "CreateAuthenticationMethods", uid, "", b, "")
		if r.Code != 201 {
			t.Fatalf("create %v: %d %s", b["type"], r.Code, r.Body)
		}
		return out.(map[string]any)["id"].(string)
	}
	a := create(newPasskeyBody(webauthntest.New(webauthntest.Options{})))
	b := create(newPasskeyBody(webauthntest.New(webauthntest.Options{})))
	r, out := mfaCall(t, e.clientsEnv, "UpdateAuthenticationMethod", uid, a, map[string]any{"name": "Laptop"}, "")
	if r.Code != 200 || out.(map[string]any)["name"] != "Laptop" || out.(map[string]any)["type"] != "passkey" {
		t.Fatalf("rename: %d %s", r.Code, r.Body)
	}
	if got, _ := e.st.MFA().GetAuthenticator(ctx, e.tn.ID, uid, a); got == nil || got.Name != "Laptop" {
		t.Fatalf("stored name = %+v", got)
	}
	if r, _ = mfaCall(t, e.clientsEnv, "DeleteAuthenticationMethod", uid, a, nil, ""); r.Code != 204 {
		t.Fatalf("delete: %d %s", r.Code, r.Body)
	}
	if _, err := e.st.MFA().GetAuthenticator(ctx, e.tn.ID, uid, a); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted passkey still stored: %v", err)
	}
	// Passkeys are not MFA: no multifactor, no enrollment, no recovery code,
	// no guardian enrollment, and no user.updated (LR33b-33).
	if n := userUpdated(); n != 0 {
		t.Fatalf("passkey changes fired %d user.updated events", n)
	}
	if _, u := e.get(t, uid, ""); len(u["multifactor"].([]any)) != 0 {
		t.Fatalf("multifactor with passkeys only = %v", u["multifactor"])
	}
	if r, out = mfaCall(t, e.clientsEnv, "GetUserEnrollments", uid, "", nil, ""); r.Code != 200 || len(out.([]any)) != 0 {
		t.Fatalf("enrollments with passkeys only: %d %s", r.Code, r.Body)
	}
	if r, _ = mfaCall(t, e.clientsEnv, "CreateUserRecoveryCode", uid, "", nil, ""); r.Code != 400 {
		t.Fatalf("recovery code with passkeys only: %d %s", r.Code, r.Body)
	}
	if r, _ = mfaCall(t, e.clientsEnv, "GetGuardianEnrollment", strings.TrimPrefix(b, "passkey|"), "", nil, ""); r.Code != 404 {
		t.Fatalf("guardian enrollment of a passkey: %d %s", r.Code, r.Body)
	}

	// WebAuthn MFA is MFA.
	roaming := map[string]any{"type": "webauthn-roaming", "key_id": "AQID", "public_key": testCOSEKey, "relying_party_identifier": "example.test"}
	create(roaming)
	if _, u := e.get(t, uid, ""); !jsonEqual(u["multifactor"], []any{"guardian"}) {
		t.Fatalf("multifactor with WebAuthn MFA = %v", u["multifactor"])
	}
	r, out = mfaCall(t, e.clientsEnv, "GetUserEnrollments", uid, "", nil, "")
	if list, _ := out.([]any); r.Code != 200 || len(list) != 1 || list[0].(map[string]any)["auth_method"] != "webauthn-roaming" {
		t.Fatalf("enrollments: %d %s", r.Code, r.Body)
	}
	kinds := func() []string {
		all, err := e.st.MFA().ListAuthenticators(ctx, e.tn.ID, uid)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range all {
			out = append(out, a.Type)
		}
		slices.Sort(out)
		return out
	}
	// DELETE /authenticators and DELETE /authentication-methods keep
	// passkeys; PUT keeps them too.
	if r, _ = mfaCall(t, e.clientsEnv, "DeleteUserAuthenticators", uid, "", nil, ""); r.Code != 204 || !slices.Equal(kinds(), []string{"passkey"}) {
		t.Fatalf("delete authenticators: %d %v", r.Code, kinds())
	}
	create(roaming)
	if r, _ = mfaCall(t, e.clientsEnv, "DeleteAuthenticationMethods", uid, "", nil, ""); r.Code != 204 || !slices.Equal(kinds(), []string{"passkey"}) {
		t.Fatalf("delete authentication methods: %d %v", r.Code, kinds())
	}
	create(roaming)
	if r, _ = mfaCall(t, e.clientsEnv, "SetAuthenticationMethods", uid, "", []any{map[string]any{"type": "email", "email": "mfa@example.test"}}, ""); r.Code != 200 || !slices.Equal(kinds(), []string{"email", "passkey"}) {
		t.Fatalf("replace authentication methods: %d %v", r.Code, kinds())
	}
	if got := userPasskeys(t, e, uid); len(got) != 1 || got[0].ID != b {
		t.Fatalf("passkeys after the MFA resets = %v", got)
	}
}

// linkFailure makes Users().Delete fail inside a transaction, after
// recording whether the user still held passkeys at that moment.
type linkFailure struct {
	store.Store
	heldAtDelete *int
}

func (s linkFailure) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(linkFailure{tx, s.heldAtDelete}) })
}
func (s linkFailure) Users() store.Users { return linkFailureUsers{s.Store.Users(), s} }

type linkFailureUsers struct {
	store.Users
	s linkFailure
}

func (u linkFailureUsers) Delete(ctx context.Context, tid, uid string) error {
	all, _ := u.s.Store.MFA().ListAuthenticators(ctx, tid, uid)
	*u.s.heldAtDelete = len(slices.DeleteFunc(all, func(a store.Authenticator) bool { return a.Type != "passkey" }))
	return errors.New("injected failure")
}

func TestLinkMovesPasskeys(t *testing.T) {
	e := newUsersEnv(t)
	primary := e.mustCreate(t, map[string]any{"email": "primary-pk@example.test"})["user_id"].(string)
	secondary := e.mustCreate(t, map[string]any{"email": "secondary-pk@example.test"})["user_id"].(string)
	secondaryIdentity := e.dbIdentity(t, secondary)
	own := webauthntest.New(webauthntest.Options{})
	ownPasskey := e.enrollPasskey(t, primary, own)
	moved := webauthntest.New(webauthntest.Options{BE: true, BS: true})
	movedPasskey := e.enrollPasskey(t, secondary, moved)
	if res, err := e.passkeyLogin(t, moved); err != nil || res.User.UserID != secondary {
		t.Fatalf("login before linking: %v %v", res, err)
	}

	// Moving and deleting happen in one transaction: the passkeys have
	// left the secondary when it is deleted, and a failed link keeps them.
	held := -1
	plain := e.h.Store
	e.h.Store = linkFailure{plain, &held}
	if rec, _ := e.link(t, primary, map[string]any{"provider": "auth0", "user_id": strings.TrimPrefix(secondary, "auth0|")}); rec.Code != 500 {
		t.Fatalf("injected failure: %d %s", rec.Code, rec.Body)
	}
	if held != 0 {
		t.Fatalf("secondary held %d passkeys when deleted", held)
	}
	if got := userPasskeys(t, e, secondary); len(got) != 1 || got[0].ID != movedPasskey.ID {
		t.Fatalf("failed link moved passkeys: %v", got)
	}
	e.h.Store = plain

	e.mustLink(t, primary, secondary)
	got := userPasskeys(t, e, primary)
	ids := []string{}
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	slices.Sort(ids)
	want := []string{ownPasskey.ID, movedPasskey.ID}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("primary passkeys after linking = %v, want %v", ids, want)
	}
	for _, a := range got {
		if a.ID == movedPasskey.ID {
			var data map[string]any
			_ = json.Unmarshal(a.PublicData, &data)
			if data["identity_user_id"] != secondaryIdentity || a.RPID != movedPasskey.RPID || string(a.CredentialID) != string(movedPasskey.CredentialID) {
				t.Fatalf("moved passkey changed: %+v", a)
			}
		}
	}
	// A passkey login with the secondary's credential is the primary's.
	if res, err := e.passkeyLogin(t, moved); err != nil || res.User.UserID != primary {
		t.Fatalf("login after linking: %v %v", res, err)
	}

	// Unlinking moves the identity's passkeys back; the primary keeps its own.
	if rec, _ := e.unlink(t, primary, "auth0", strings.TrimPrefix(secondary, "auth0|")); rec.Code != 200 {
		t.Fatalf("unlink: %d %s", rec.Code, rec.Body)
	}
	if back := userPasskeys(t, e, secondary); len(back) != 1 || back[0].ID != movedPasskey.ID {
		t.Fatalf("secondary passkeys after unlinking = %v", back)
	}
	if kept := userPasskeys(t, e, primary); len(kept) != 1 || kept[0].ID != ownPasskey.ID {
		t.Fatalf("primary passkeys after unlinking = %v", kept)
	}
	if res, err := e.passkeyLogin(t, moved); err != nil || res.User.UserID != secondary {
		t.Fatalf("login after unlinking: %v %v", res, err)
	}
	if res, err := e.passkeyLogin(t, own); err != nil || res.User.UserID != primary {
		t.Fatalf("primary login after unlinking: %v %v", res, err)
	}
}

func TestSessionAuthMethodsView(t *testing.T) {
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "methods@x.test"})["user_id"].(string)
	created := now.Add(-time.Hour)
	e.addSession(t, "sess_legacy", u, created)
	e.addSession(t, "sess_passkey", u, created.Add(time.Second), func(s *store.LoginSession) {
		s.AuthMethods = []store.AuthMethod{{Name: "passkey", At: created}, {Name: "mfa", Type: "webauthn-roaming", At: created.Add(time.Minute)}}
	})
	ts := "2026-10-18T11:00:00.000Z"
	for id, want := range map[string]any{
		"sess_legacy":  []any{map[string]any{"name": "pwd", "timestamp": ts}},
		"sess_passkey": []any{map[string]any{"name": "passkey", "timestamp": ts}, map[string]any{"name": "mfa", "type": "webauthn-roaming", "timestamp": "2026-10-18T11:01:00.000Z"}},
	} {
		code, one := e.call2(t, "read:sessions", "GET", "/api/v2/sessions/"+id, func(w http.ResponseWriter, r *http.Request) { e.h.GetSession(w, r, id) })
		if code != 200 || !jsonEqual(one["authentication"], map[string]any{"methods": want}) {
			t.Errorf("%s authentication = %d %v, want %v", id, code, one["authentication"], want)
		}
	}
	code, out := e.sessions(t, u, "")
	if code != 200 || len(out["sessions"].([]any)) != 2 {
		t.Fatalf("list = %d %v", code, out)
	}
}
