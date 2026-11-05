package mfa

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const (
	testRPID   = "login.acme.test"
	testOrigin = "https://login.acme.test"
	iPhoneUA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	macUA      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
)

var testRP = rpid.Result{RPID: testRPID, Origin: testOrigin, Kind: rpid.KindCanonical, Valid: true}

// webauthnEvents captures the WebAuthn MFA outcomes before the log catalog
// gate (gd_webauthn_* are deferred until Task 19).
func webauthnEvents(t *testing.T) *[]logs.Event {
	t.Helper()
	var got []logs.Event
	observeWebAuthnEvent = func(e logs.Event) { got = append(got, e) }
	t.Cleanup(func() { observeWebAuthnEvent = nil })
	return &got
}

// webauthn turns the fixture's WebAuthn factors on and returns the service
// bound to a hosted transaction.
func (f *serviceFixture) webauthn(t *testing.T, uv string) *Service {
	t.Helper()
	g, err := f.st.MFA().GetGuardian(f.ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	g.Factors[FactorRoaming] = true
	g.Factors[FactorPlatform] = true
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	if uv != "" {
		g.Stored[RoamingSettingsKey] = json.RawMessage(`{"user_verification":"` + uv + `"}`)
	}
	if err = f.st.MFA().PutGuardian(f.ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	f.svc.Passkeys = passkey.New(f.st, rpid.Policy{}, func() time.Time { return f.now })
	return f.svc.WithHostedBinding("txn_1", "cookie-hash")
}

func (f *serviceFixture) enrollKey(t *testing.T, svc *Service, factor, ua string, key *webauthntest.Authenticator) *Confirmed {
	t.Helper()
	e, opts, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", factor, testRP, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(opts, testOrigin), "", ua)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *serviceFixture) assert(t *testing.T, svc *Service, factor, ua string, key *webauthntest.Authenticator) error {
	t.Helper()
	device := webauthn.DeviceOf(ua)
	c, opts, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", factor, testRP, device)
	if err != nil {
		t.Fatal(err)
	}
	return svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, key.Get(opts, testOrigin))
}

func TestDecideWebAuthnFilters(t *testing.T) {
	enabled := map[string]bool{"otp": true, FactorRoaming: true, FactorPlatform: true, "recovery-code": true}
	settings := &store.GuardianSettings{Factors: enabled, Policies: []string{"all-applications"}}
	data := func(ua string) []byte { b, _ := json.Marshal(map[string]any{"user_agent": ua}); return b }
	here := store.Authenticator{ID: "r1", Type: FactorRoaming, Confirmed: true, CredentialID: []byte{1}, RPID: testRPID}
	foreign := store.Authenticator{ID: "r2", Type: FactorRoaming, Confirmed: true, CredentialID: []byte{2}, RPID: "login.other.test"}
	phone := store.Authenticator{ID: "p1", Type: FactorPlatform, Confirmed: true, CredentialID: []byte{3}, RPID: testRPID, PublicData: data(iPhoneUA)}
	recovery := store.Authenticator{ID: "rc", Type: "recovery-code", Confirmed: true}
	capable := WebAuthnInput{Available: true, Platform: true, RPID: testRPID, Device: webauthn.DeviceOf(iPhoneUA)}
	for _, tc := range []struct {
		name     string
		list     []store.Authenticator
		w        WebAuthnInput
		enroll   bool
		factors  []string
		noFactor bool
	}{
		{name: "only foreign RP ID enrolls (LR33b-5)", list: []store.Authenticator{foreign}, w: capable, enroll: true, factors: []string{"otp", FactorRoaming}},
		{name: "security key on this RP ID", list: []store.Authenticator{here, recovery}, w: capable, factors: []string{FactorRoaming, "recovery-code"}},
		{name: "no capability result offers no WebAuthn enrollment", w: WebAuthnInput{RPID: testRPID}, enroll: true, factors: []string{"otp"}},
		{name: "no script falls back to recovery", list: []store.Authenticator{here, recovery}, w: WebAuthnInput{RPID: testRPID}, factors: []string{"recovery-code"}},
		{name: "no script without recovery fails closed", list: []store.Authenticator{here}, w: WebAuthnInput{RPID: testRPID}, noFactor: true},
		{name: "grant without WebAuthn fails closed", list: []store.Authenticator{here}, noFactor: true},
		{name: "platform on its device", list: []store.Authenticator{phone, recovery}, w: capable, factors: []string{FactorPlatform, "recovery-code"}},
		{name: "platform on another device", list: []store.Authenticator{phone, recovery}, w: WebAuthnInput{Available: true, Platform: true, RPID: testRPID, Device: webauthn.DeviceOf(macUA)}, factors: []string{"recovery-code"}},
		{name: "platform without a platform authenticator", list: []store.Authenticator{phone, recovery}, w: WebAuthnInput{Available: true, RPID: testRPID, Device: webauthn.DeviceOf(iPhoneUA)}, factors: []string{"recovery-code"}},
		{name: "biometrics are never a first enrollment", w: capable, enroll: true, factors: []string{"otp", FactorRoaming}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decide(DecideInput{Settings: settings, Authenticators: tc.list, WebAuthn: tc.w})
			if tc.noFactor {
				if !errors.Is(err, ErrNoFactor) {
					t.Fatalf("got %+v %v, want ErrNoFactor", got, err)
				}
				return
			}
			if err != nil || !got.Required || got.Enroll != tc.enroll || !reflect.DeepEqual(got.Factors, tc.factors) {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
	// The MFA API requires MFA for a user enrolled only in WebAuthn.
	got, err := Decide(DecideInput{Settings: &store.GuardianSettings{Factors: enabled}, Authenticators: []store.Authenticator{here, recovery}, MFAAPI: true})
	if err != nil || !got.Required || got.Enroll || !reflect.DeepEqual(got.Factors, []string{"recovery-code"}) {
		t.Fatalf("MFA API = %+v %v", got, err)
	}
}

func TestWebAuthnDecideActions(t *testing.T) {
	enabled := map[string]bool{"otp": true, FactorRoaming: true, "recovery-code": true}
	key := store.Authenticator{Type: FactorRoaming, Confirmed: true, CredentialID: []byte{1}, RPID: testRPID}
	otp := store.Authenticator{Type: "totp", Confirmed: true}
	w := WebAuthnInput{Available: true, Platform: true, RPID: testRPID}
	for _, tc := range []struct {
		name    string
		effects *actionresult.MFAEffects
		list    []store.Authenticator
		enroll  bool
		factors []string
	}{
		{"challengeWith security key", &actionresult.MFAEffects{Mode: "challenge", Factors: [][]string{{FactorRoaming}}}, []store.Authenticator{key, otp}, false, []string{FactorRoaming}},
		{"enrollWith security key", &actionresult.MFAEffects{Mode: "enroll", Factors: [][]string{{FactorRoaming}}}, []store.Authenticator{otp}, true, []string{FactorRoaming}},
		{"enable any", &actionresult.MFAEffects{Provider: "any"}, []store.Authenticator{key}, false, []string{FactorRoaming}},
		{"enable guardian", &actionresult.MFAEffects{Provider: "guardian"}, []store.Authenticator{key, otp}, false, []string{"otp", FactorRoaming}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decide(DecideInput{Settings: &store.GuardianSettings{Factors: enabled}, Effects: tc.effects, Authenticators: tc.list, CustomizeInActions: true, RememberValid: true, WebAuthn: w})
			if err != nil || !got.Required || got.Enroll != tc.enroll || !reflect.DeepEqual(got.Factors, tc.factors) {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
	// A remembered browser satisfies a policy challenge but never
	// challengeWith.
	got, _ := Decide(DecideInput{Settings: &store.GuardianSettings{Factors: enabled, Policies: []string{"all-applications"}}, Authenticators: []store.Authenticator{key}, RememberValid: true, WebAuthn: w})
	if got.Required {
		t.Fatalf("remember did not satisfy policy: %+v", got)
	}
}

func TestWebAuthnRoamingEnrollAndVerify(t *testing.T) {
	f := newServiceFixture(t)
	svc := f.webauthn(t, "")
	seen := webauthnEvents(t)
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform", Transports: []string{"usb", "nfc"}})
	e, opts, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", FactorRoaming, testRP, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Attachment != "cross-platform" || opts.ResidentKey != "discouraged" || opts.UserVerification != "discouraged" || opts.RPName != testRPID || len(opts.UserID) != 32 || e.AuthenticatorID != "" {
		t.Fatalf("options %+v enrollment %+v", opts, e)
	}
	c, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(opts, testOrigin), "", "")
	if err != nil || c.RecoveryCode == "" {
		t.Fatalf("confirm %+v %v", c, err)
	}
	a, err := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", c.AuthenticatorID)
	if err != nil || a.Type != FactorRoaming || !a.Confirmed || a.Name != DefaultRoamingName || a.RPID != testRPID || !strings.HasPrefix(a.ID, "webauthn-roaming|dev_") {
		t.Fatalf("stored %+v %v", a, err)
	}
	// The same challenge cannot confirm twice.
	if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(opts, testOrigin), "", ""); !errors.Is(err, ErrWebAuthn) {
		t.Fatalf("replay = %v", err)
	}
	// A second enrollment excludes the first key.
	_, opts, err = svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", FactorRoaming, testRP, passkey.UserDisplay{})
	if err != nil || len(opts.Exclude) != 1 || string(opts.Exclude[0].ID) != string(key.CredentialID()) || !slices.Equal(opts.Exclude[0].Transports, []string{"usb", "nfc"}) {
		t.Fatalf("exclude %+v %v", opts.Exclude, err)
	}
	key.SignCount = 1
	if err = f.assert(t, svc, FactorRoaming, "", key); err != nil {
		t.Fatal(err)
	}
	if f.events.count("gd_auth_succeed") != 1 || f.events.count("gd_start_auth") != 1 {
		t.Fatalf("events %+v", f.events.events)
	}
	// Another origin or a challenge bound to another transaction fails.
	ch, ropts, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", FactorRoaming, testRP, webauthn.Device{})
	if err != nil {
		t.Fatal(err)
	}
	key.SignCount = 2
	other := f.svc.WithHostedBinding("txn_2", "cookie-hash")
	if err = other.VerifyWebAuthn(f.ctx, "tenant", "user", ch, key.Get(ropts, testOrigin)); !errors.Is(err, ErrWebAuthn) {
		t.Fatalf("foreign transaction = %v", err)
	}
	ch, ropts, _ = svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", FactorRoaming, testRP, webauthn.Device{})
	if err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", ch, key.Get(ropts, "https://evil.test")); !errors.Is(err, ErrWebAuthn) {
		t.Fatalf("foreign origin = %v", err)
	}
	var failed []logs.Event
	for _, e := range *seen {
		if e.Type == "gd_webauthn_challenge_failed" {
			failed = append(failed, e)
		}
	}
	if len(failed) != 2 || failed[1].Details["first_factor"] != false || failed[1].Details["failure_details"].(map[string]any)["errorCode"] != "challenge" && failed[1].Details["failure_details"].(map[string]any)["errorCode"] != "origin" {
		t.Fatalf("challenge failures %+v", failed)
	}
	if f.events.count("gd_auth_failed") != 2 {
		t.Fatalf("gd_auth_failed = %d", f.events.count("gd_auth_failed"))
	}
	// Nothing logged carries ceremony secrets.
	raw, _ := json.Marshal(*seen)
	for _, secret := range []string{ch.ID, string(key.CredentialID())} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("event leaks %q", secret)
		}
	}
	// Nicknames are 1–20 characters.
	for _, name := range []string{"", " ", strings.Repeat("x", 21), "bad\x00name"} {
		if err = svc.RenameWebAuthn(f.ctx, "tenant", "user", a.ID, name); !errors.Is(err, ErrNickname) {
			t.Fatalf("nickname %q = %v", name, err)
		}
	}
	if err = svc.RenameWebAuthn(f.ctx, "tenant", "user", a.ID, strings.Repeat("é", 20)); err != nil {
		t.Fatal(err)
	}
}

func TestRoamingUVRequired(t *testing.T) {
	f := newServiceFixture(t)
	svc := f.webauthn(t, "required")
	seen := webauthnEvents(t)
	// A FIDO-1-style key (no user verification) cannot register.
	fido1 := webauthntest.New(webauthntest.Options{Attachment: "cross-platform"})
	e, opts, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", FactorRoaming, testRP, passkey.UserDisplay{})
	if err != nil || opts.UserVerification != "required" {
		t.Fatalf("options %+v %v", opts, err)
	}
	if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, fido1.Create(opts, testOrigin), "", ""); !errors.Is(err, ErrWebAuthn) || webauthn.Reason(err) != webauthn.ReasonUserVerified {
		t.Fatalf("UV-less registration = %v (%s)", err, webauthn.Reason(err))
	}
	if len(*seen) != 1 || (*seen)[0].Type != "gd_webauthn_enrollment_failed" || (*seen)[0].Details["authenticator"].(map[string]any)["type"] != FactorRoaming {
		t.Fatalf("enrollment failure event %+v", *seen)
	}
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform", UV: true})
	f.enrollKey(t, svc, FactorRoaming, "", key)
	key.UV = false
	key.SignCount = 1
	if err = f.assert(t, svc, FactorRoaming, "", key); !errors.Is(err, ErrWebAuthn) {
		t.Fatalf("UV-less assertion = %v", err)
	}
	last := (*seen)[len(*seen)-1]
	if last.Type != "gd_webauthn_challenge_failed" || last.Details["first_factor"] != false || last.Details["failure_details"].(map[string]any)["errorCode"] != webauthn.ReasonUserVerified || f.events.count("gd_auth_failed") != 1 {
		t.Fatalf("challenge failure %+v", last)
	}
	key.UV = true
	key.SignCount = 2
	if err = f.assert(t, svc, FactorRoaming, "", key); err != nil {
		t.Fatal(err)
	}
	// "discouraged" (the default) accepts a UV-less assertion.
	svc = f.webauthn(t, "discouraged")
	key.UV = false
	key.SignCount = 3
	if err = f.assert(t, svc, FactorRoaming, "", key); err != nil {
		t.Fatalf("discouraged = %v", err)
	}
	if RoamingUV(&store.GuardianSettings{}) != "discouraged" || RoamingUV(&store.GuardianSettings{Stored: map[string]json.RawMessage{RoamingSettingsKey: json.RawMessage(`{"user_verification":"other"}`)}}) != "discouraged" {
		t.Fatal("RoamingUV default")
	}
}

func TestWebAuthnThrottle(t *testing.T) {
	f := newServiceFixture(t)
	svc := f.webauthn(t, "")
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform"})
	f.enrollKey(t, svc, FactorRoaming, "", key)
	key.TamperRPIDHash = true
	for i := 1; i <= 10; i++ {
		f.now = f.now.Add(time.Minute)
		if err := f.assert(t, svc, FactorRoaming, "", key); !errors.Is(err, ErrWebAuthn) {
			t.Fatalf("failure %d = %v", i, err)
		}
	}
	key.TamperRPIDHash = false
	key.SignCount = 1
	if err := f.assert(t, svc, FactorRoaming, "", key); !errors.Is(err, ErrThrottled) {
		t.Fatalf("11th attempt within 15 minutes = %v", err)
	}
	if f.events.count("gd_otp_rate_limit_exceed") != 1 {
		t.Fatalf("rate limit event = %d", f.events.count("gd_otp_rate_limit_exceed"))
	}
	// The window is per factor: an OTP proof is not throttled by it.
	if _, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "otp", ""); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(15 * time.Minute)
	if err := f.assert(t, svc, FactorRoaming, "", key); err != nil {
		t.Fatalf("after the window = %v", err)
	}
}

func TestWebAuthnPlatformDevice(t *testing.T) {
	f := newServiceFixture(t)
	svc := f.webauthn(t, "")
	key := webauthntest.New(webauthntest.Options{Attachment: "platform", UV: true})
	c := f.enrollKey(t, svc, FactorPlatform, iPhoneUA, key)
	a, _ := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", c.AuthenticatorID)
	if a.Name != "Safari on iOS" || DeviceKey(*a) != webauthn.DeviceOf(iPhoneUA).Key() {
		t.Fatalf("platform row %+v", a)
	}
	if _, _, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", FactorPlatform, testRP, webauthn.DeviceOf(macUA)); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("other device = %v", err)
	}
	key.SignCount = 1
	if err := f.assert(t, svc, FactorPlatform, iPhoneUA, key); err != nil {
		t.Fatal(err)
	}
	// Biometrics always require user verification.
	key.UV = false
	key.SignCount = 2
	if err := f.assert(t, svc, FactorPlatform, iPhoneUA, key); !errors.Is(err, ErrWebAuthn) {
		t.Fatalf("platform without UV = %v", err)
	}
}
