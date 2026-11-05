package webauthnrules_test

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// The §2 evidence list; every rule must cite one of these pages.
var evidenceURLs = []string{
	"https://auth0.com/docs/authenticate/database-connections/passkeys",
	"https://auth0.com/docs/authenticate/database-connections/passkeys/configure-passkey-policy",
	"https://auth0.com/docs/authenticate/database-connections/passkeys/monitor-passkey-events-in-tenant-logs",
	"https://auth0.com/docs/authenticate/database-connections/passkeys/passkey-apis",
	"https://auth0.com/docs/api/authentication/passkey/register",
	"https://auth0.com/docs/api/authentication/passkey/challenge",
	"https://auth0.com/docs/customize/custom-domains/multiple-custom-domains/passkeys",
	"https://auth0.com/docs/customize/custom-domains/multiple-custom-domains",
	"https://auth0.com/docs/secure/multi-factor-authentication/fido-authentication-with-webauthn",
	"https://auth0.com/docs/secure/multi-factor-authentication/fido-authentication-with-webauthn/configure-webauthn-security-keys-for-mfa",
	"https://auth0.com/docs/secure/multi-factor-authentication/fido-authentication-with-webauthn/configure-webauthn-device-biometrics-for-mfa",
	"https://auth0.com/docs/authenticate/login/auth0-universal-login/passwordless-login/webauthn-device-biometrics",
	"https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors",
	"https://auth0.com/docs/customize/actions/explore-triggers/post-login",
	"https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-api-object",
	"https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-event-object",
	"https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements",
	"https://auth0.com/docs/authenticate/login/auth0-universal-login/identifier-first",
	"https://auth0.com/docs/oas/management/v2/management-api-oas.json",
	"https://auth0.com/docs/secure/multi-factor-authentication/manage-mfa-auth0-apis/manage-authentication-methods-with-management-api",
	"https://auth0.com/docs/oas/authentication/authentication-api-oas.json",
	"https://auth0.com/docs/oas/tenant-logs/logs-schema.json",
	"https://www.npmjs.com/package/@auth0/auth0-auth-js/v/1.16.1",
	"https://www.w3.org/TR/webauthn-2/",
	"https://www.w3.org/TR/webauthn-3/",
	"https://www.rfc-editor.org/rfc/rfc8949",
	"https://www.rfc-editor.org/rfc/rfc9052",
	"https://www.rfc-editor.org/rfc/rfc9053",
	"https://www.rfc-editor.org/rfc/rfc8230",
	"https://www.rfc-editor.org/rfc/rfc8032",
	"https://csrc.nist.gov/pubs/fips/186-4/final",
	"https://developer.apple.com/documentation/xcode/supporting-associated-domains",
	"https://developers.google.com/digital-asset-links/v1/getting-started",
}

var nineScreens = []string{
	"mfa-detect-browser-capabilities",
	"mfa-webauthn-roaming-enrollment", "mfa-webauthn-platform-enrollment",
	"mfa-webauthn-roaming-challenge", "mfa-webauthn-platform-challenge",
	"mfa-webauthn-change-key-nickname", "mfa-webauthn-enrollment-success",
	"mfa-webauthn-error", "mfa-webauthn-not-available-error",
}

func TestWebAuthnInventory(t *testing.T) {
	inv := webauthnrules.Inventory()
	if inv.Decision != "D-0062" || inv.FetchedAt == "" || inv.ReviewedAt == "" {
		t.Errorf("decision/dates: %+v", inv.Decision)
	}
	for _, u := range evidenceURLs {
		found := false
		for _, v := range inv.Evidence {
			found = found || v == u
		}
		if !found {
			t.Errorf("evidence missing %s", u)
		}
	}
	rules := webauthnrules.Rules()
	if len(rules) < 60 {
		t.Fatalf("only %d rules frozen", len(rules))
	}
	ids := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || r.Statement == "" || !strings.HasPrefix(r.Source, "https://") {
			t.Errorf("incomplete rule %+v", r)
		}
		if !slices.Contains(evidenceURLs, r.Source) {
			t.Errorf("rule %s cites a source outside §2: %s", r.ID, r.Source)
		}
		if ids[r.ID] {
			t.Errorf("duplicate rule %s", r.ID)
		}
		ids[r.ID] = true
	}
	for _, id := range []string{"policy.limit", "rpid.per-host", "login.challenge-ui", "signup.no-password", "enroll.progressive", "enroll.local", "verify.sign-count", "ceremony.challenge", "mfa.security-keys-uv", "mfa.biometrics-not-alone", "native.grant", "native.origins", "actions.methods", "logs.details", "mgmt.passkey-create", "store.capability"} {
		if !ids[id] {
			t.Errorf("rule %s missing", id)
		}
	}

	screens := webauthnrules.Screens()
	if got := screens["passkeys"]; !reflect.DeepEqual(got, []string{"passkey-enrollment", "passkey-enrollment-local"}) {
		t.Errorf("passkeys screens = %v", got)
	}
	want := append(slices.Clone(nineScreens), "reset-password-mfa-webauthn-platform-challenge", "reset-password-mfa-webauthn-roaming-challenge")
	if got := screens["mfa-webauthn"]; !reflect.DeepEqual(got, want) {
		t.Errorf("mfa-webauthn screens = %v", got)
	}
	if !reflect.DeepEqual(screens["login-id"], []string{"login-id"}) || !reflect.DeepEqual(screens["mfa"], []string{"mfa-detect-browser-capabilities"}) {
		t.Errorf("login-id/mfa screens: %v %v", screens["login-id"], screens["mfa"])
	}
	for screen, prompt := range map[string]string{"passkey-enrollment": "passkeys", "mfa-detect-browser-capabilities": "mfa", "mfa-webauthn-error": "mfa-webauthn", "reset-password-mfa-webauthn-roaming-challenge": "reset-password", "login-id": "login-id"} {
		if webauthnrules.Prompt(screen) != prompt {
			t.Errorf("prompt of %s = %q", screen, webauthnrules.Prompt(screen))
		}
	}
	// Every screen the plan renders has frozen text keys, and the branding
	// inventory (Plan 22 custom text) lists it, including the two
	// reset-password WebAuthn screens Task 1 adds.
	var branding struct {
		Prompts []string `json:"custom_text_prompts"`
		Screens []string `json:"custom_text_screens"`
	}
	raw, err := os.ReadFile("../brandingrules/inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &branding); err != nil {
		t.Fatal(err)
	}
	for family, list := range screens {
		for _, s := range list {
			if len(webauthnrules.TextKeys(s)) == 0 && !strings.HasPrefix(s, "signup-") {
				t.Errorf("screen %s (%s) has no text keys", s, family)
			}
			if !slices.Contains(branding.Screens, s) {
				t.Errorf("branding inventory lacks screen %s", s)
			}
			if p := webauthnrules.Prompt(s); p == "" || (!slices.Contains(branding.Prompts, p) && p != "mfa" && p != "reset-password") {
				t.Errorf("screen %s prompt %q not documented", s, p)
			}
		}
	}
	if keys := webauthnrules.TextKeys("login-id"); !slices.Contains(keys, "passkeyButtonText") {
		t.Errorf("login-id keys %v", keys)
	}
	// §3.3 hosted login error keys and the §3.1 limit key.
	for _, k := range []string{"passkey-not-allowed", "no-passkey", "passkey-authentication-failed", "invalid-passkey", "conflict-password-passkey", "password-not-allowed"} {
		if !slices.Contains(webauthnrules.TextKeys("login-id"), k) {
			t.Errorf("login-id lacks error key %s", k)
		}
	}
	for _, k := range []string{"passkey-enrollment-max-allowed-reached", "createButtonText", "usePasswordButtonText", "backButtonText", "continueButtonText", "checkboxText", "email-in-use", "auth0-users-validation", "passkey-enrollment-failure"} {
		if !slices.Contains(webauthnrules.TextKeys("passkey-enrollment"), k) {
			t.Errorf("passkey-enrollment lacks key %s", k)
		}
	}
	for screen, keys := range map[string][]string{
		"passkey-enrollment-local":                       {"createButtonText", "continueButtonText", "checkboxText", "error_passkey-enrollment-max-allowed-reached"},
		"mfa-webauthn-platform-enrollment":               {"continueButtonText", "snoozeEnrollmentButtonText", "refuseAddingDeviceText", "skipAddingDeviceText"},
		"mfa-webauthn-roaming-challenge":                 {"rememberMeText", "too-many-webauthn-challenge-attempts-error"},
		"mfa-webauthn-platform-challenge":                {"rememberMeText", "too-many-webauthn-challenge-attempts-error", "usePasswordText"},
		"mfa-webauthn-change-key-nickname":               {"nickname", "nicknamePlatform", "no-nickname", "nickname-too-short", "nickname-too-long"},
		"reset-password-mfa-webauthn-platform-challenge": {"continueButtonText", "webauthn-platform-challenge-error"},
		"reset-password-mfa-webauthn-roaming-challenge":  {"continueButtonText", "webauthn-challenge-error"},
		"mfa-detect-browser-capabilities":                {"reloadButtonText", "noJSErrorTitle"},
	} {
		for _, k := range keys {
			if !slices.Contains(webauthnrules.TextKeys(screen), k) {
				t.Errorf("%s lacks key %s", screen, k)
			}
		}
	}

	l := webauthnrules.Limits
	wantLimits := webauthnrules.LimitSet{
		MaxPasskeys: 20, HostedChallengeTTL: 5 * time.Minute, NativeTimeout: 60 * time.Second, NativeGrace: 10 * time.Second,
		ProgressiveSnooze: 30 * 24 * time.Hour, LocalSnooze: 30 * 24 * time.Hour, PlatformRemind: 14 * 24 * time.Hour, PlatformRefuse: 365 * 24 * time.Hour,
		NicknameMin: 1, NicknameMax: 20, ChallengeBytes: 32, UserHandleBytes: 32, AttestationMax: 64 << 10, ClientDataMax: 16 << 10,
		CredentialIDMax: 1023, COSEMax: 16 << 10, CBORDepth: 16, CBORItems: 1024, RPIDMax: 255,
	}
	if l != wantLimits {
		t.Errorf("limits %+v, want %+v", l, wantLimits)
	}
	if !reflect.DeepEqual(inv.PubKeyCredParams, []int64{-8, -7, -257}) || inv.Attestation != "none" {
		t.Errorf("ceremony params: %v %s", inv.PubKeyCredParams, inv.Attestation)
	}
	for _, c := range []string{"passkey-register", "passkey-login"} {
		if webauthnrules.Ceremonies()[c].UserVerification != "preferred" {
			t.Errorf("%s userVerification %+v", c, webauthnrules.Ceremonies()[c])
		}
	}
	if len(inv.Rulings) != 37 || inv.Rulings[0] != "LR33b-1" || inv.Rulings[36] != "LR33b-37" {
		t.Errorf("rulings %v", inv.Rulings)
	}
	if len(inv.ObserveLater) != 12 || len(inv.ControllerCalls) != 17 {
		t.Errorf("observe later %v / calls %v", inv.ObserveLater, inv.ControllerCalls)
	}
	for _, k := range []string{"authn_response", "auth_session", "attestationObject", "authenticatorData", "clientDataJSON", "signature", "userHandle", "user_handle", "challenge_id"} {
		if !slices.Contains(webauthnrules.ScrubKeys(), k) {
			t.Errorf("scrub key %s missing", k)
		}
	}
	// The Guardian factor inventory and the Actions factor lists are flipped
	// in the same freeze (§6, §9.2).
	for _, f := range mfarules.Factors() {
		if strings.HasPrefix(f.Name, "webauthn-") && f.Status != "enforced" {
			t.Errorf("factor %s status %s, want enforced", f.Name, f.Status)
		}
	}
}

var plan33bCodes = []string{"gd_webauthn_enrollment_failed", "gd_webauthn_challenge_failed", "passkey_challenge_started", "passkey_challenge_failed", "sepkotpft", "sepkoobft", "sepkrcft", "seotpft", "seoobft", "sercft"}

func TestPlan33bLogCodes(t *testing.T) {
	codes := map[string]logrules.Code{}
	for _, c := range logrules.Codes() {
		codes[c.Type] = c
	}
	for _, code := range plan33bCodes {
		c, ok := codes[code]
		if !ok {
			t.Errorf("missing code %s", code)
			continue
		}
		if c.Owner != "Plan 33b" || !strings.HasPrefix(c.Source, "https://auth0.com/docs/tenant-logs/") {
			t.Errorf("%s owner/source: owner=%q plan=%d source=%s", code, c.Owner, c.Plan, c.Source)
		}
		if !strings.Contains(webauthnrules.LogCodes()[code], " ") {
			t.Errorf("%s has no frozen Plan 33b emission rule", code)
		}
	}
	if c := codes["gd_auth_rejected"]; c.Status != "not_planned" || c.Emitted || c.Owner == "Plan 33b" {
		t.Errorf("gd_auth_rejected must be not_planned (push decline): %+v", c)
	}
	// §8.2 detail allowlists, exactly.
	for code, want := range map[string][]string{
		"gd_webauthn_enrollment_failed": {"authentication_methods", "authenticator", "failure_details"},
		"gd_webauthn_challenge_failed":  {"first_factor", "authenticator", "failure_details"},
		"passkey_challenge_started":     {"purpose"},
		"passkey_challenge_failed":      {"purpose", "error"},
		"s":                             {"prompts"},
		"ss":                            {"authentication_methods"},
		"gd_enrollment_complete":        {"authenticator"},
	} {
		if got := webauthnrules.LogDetails(code); !reflect.DeepEqual(got, want) {
			t.Errorf("LogDetails(%s) = %v, want %v", code, got, want)
		}
	}
	for _, code := range []string{"sepkotpft", "sepkoobft", "sepkrcft", "seotpft", "seoobft", "sercft"} {
		if got := webauthnrules.LogDetails(code); len(got) != 0 {
			t.Errorf("LogDetails(%s) = %v, want none", code, got)
		}
	}
	all := map[string]bool{}
	for _, code := range append(slices.Clone(plan33bCodes), "s", "ss", "gd_enrollment_complete") {
		for _, f := range webauthnrules.LogDetails(code) {
			all[f] = true
		}
	}
	for _, f := range []string{"first_factor", "failure_details", "purpose", "authentication_methods", "authenticator", "prompts"} {
		if !all[f] {
			t.Errorf("§8.2 detail field %s not frozen", f)
		}
	}
	// The frozen logrules allowlists carry the same fields per code.
	for code, want := range webauthnrules.Inventory().LogDetails {
		if got := logrules.BodyAllowlist("details:" + code); !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("logrules details allowlist for %s = %v, want %v", code, got, want)
		}
	}
	t.Skip("flipped in Task 19")
	for _, code := range plan33bCodes {
		c := codes[code]
		if !c.Emitted || c.Status != "emitted" || len(c.Triggers) == 0 {
			t.Errorf("%s not emitted by Plan 33b", code)
		}
	}
}
