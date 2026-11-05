package actions_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestWebAuthnMFACommands: the WebAuthn factors are accepted by every
// Actions MFA member (Plan 33b spec 6.2), and a passkey is never an
// enrolled factor.
func TestWebAuthnMFACommands(t *testing.T) {
	for call, want := range map[string]struct {
		mode    string
		factors [][]string
	}{
		`authentication.challengeWith({type:'webauthn-roaming'})`:                                     {"challenge", [][]string{{"webauthn-roaming"}}},
		`authentication.challengeWith({type:'otp'},{additionalFactors:[{type:'webauthn-platform'}]})`: {"challenge", [][]string{{"otp", "webauthn-platform"}}},
		`authentication.challengeWithAny([{type:'webauthn-roaming'},{type:'webauthn-platform'}])`:     {"challenge", [][]string{{"webauthn-roaming", "webauthn-platform"}}},
		`authentication.enrollWith({type:'webauthn-roaming'})`:                                        {"enroll", [][]string{{"webauthn-roaming"}}},
		`authentication.enrollWithAny([{type:'webauthn-platform'},{type:'otp'}])`:                     {"enroll", [][]string{{"webauthn-platform", "otp"}}},
	} {
		t.Run(call, func(t *testing.T) {
			r, err, _ := runMFAAction(t, `api.`+call+`;`, true)
			if err != nil || r.Effects.MFA == nil || r.Effects.MFA.Mode != want.mode || !reflect.DeepEqual(r.Effects.MFA.Factors, want.factors) {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	for _, p := range []string{"any", "guardian"} {
		r, err, _ := runMFAAction(t, `api.multifactor.enable('`+p+`');`, false)
		if err != nil || r.Effects.MFA == nil || r.Effects.MFA.Provider != p {
			t.Fatalf("enable %s = %+v %v", p, r, err)
		}
	}
	h := newHarness(t)
	for _, a := range []store.Authenticator{
		{TenantID: "t1", UserID: "auth0|u1", ID: "webauthn-roaming|dev_1", Type: "webauthn-roaming", Confirmed: true, CredentialID: []byte{1}},
		{TenantID: "t1", UserID: "auth0|u1", ID: "passkey|dev_1", Type: "passkey", Confirmed: true, CredentialID: []byte{2}},
	} {
		if err := h.st.MFA().CreateAuthenticator(context.Background(), &a); err != nil {
			t.Fatal(err)
		}
	}
	a := h.action("t1", trigLogin, "event", `exports.onExecutePostLogin=(event,api)=>api.idToken.setCustomClaim('urn:factors',event.user.enrolledFactors);`, nil, false)
	h.bind("t1", trigLogin, a)
	got := fmt.Sprint(h.mustPostLogin("t1").Effects.IDClaims["urn:factors"])
	if !strings.Contains(got, "webauthn-roaming") || strings.Contains(got, "passkey") {
		t.Fatalf("enrolledFactors %s", got)
	}
}
