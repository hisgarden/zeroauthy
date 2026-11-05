package ui

import (
	_ "embed"
	"html/template"
	"net/http"
)

type MFAOption struct{ Factor, Label string }
type MFAData struct {
	State, CSRF, Action, Error, Secret, RecoveryCode, AnotherURL, Prefix string
	// RedirectURI is the validated OAuth callback, as on other hosted forms.
	RedirectURI                                        string
	PhoneNumber                                        string
	PhoneMethod                                        string
	PhoneMethods                                       []string
	PhoneCountries                                     []string
	PhoneEnroll, SwitchPhone                           bool
	Revision                                           int64
	QR                                                 template.HTML
	Options                                            []MFAOption
	AllowRemember, Email, Recovery, Enroll, CodeScreen bool
	WebAuthn                                           *WebAuthnView
}

// WebAuthnView is the Plan 33b WebAuthn MFA part of a page: View selects
// the template section ("detect", "ceremony", "nickname", "success",
// "error" or "not-available"); Keys maps logical text names (title,
// description, continueButtonText, …) to the screen's catalog keys, present
// only for the keys the screen documents; Options is the za-webauthn JSON
// document the page script reads ({"mode": …, "publicKey": …}).
type WebAuthnView struct {
	View                          string
	Keys                          map[string]string
	Instructions                  []string
	Options                       any
	Nickname, RetryURL, DetectURL string
	NicknameMax                   int
	// Script is the page script, set by RenderMFA.
	Script template.JS
}

//go:embed webauthn_mfa.js
var webauthnMFAScript string

func MFAScreen(page string) (string, string) {
	switch page {
	case "mfa_phone_enroll":
		return "mfa-phone", "mfa-phone-enrollment"
	case "mfa_sms_challenge":
		return "mfa-sms", "mfa-sms-challenge"
	case "mfa_voice_challenge":
		return "mfa-voice", "mfa-voice-challenge"
	case "mfa_options":
		return "mfa", "mfa-login-options"
	case "mfa_enroll_options":
		return "mfa", "mfa-begin-enroll-options"
	case "mfa_otp_enroll":
		return "mfa-otp", "mfa-otp-enrollment-qr"
	case "mfa_otp_enroll_code":
		return "mfa-otp", "mfa-otp-enrollment-code"
	case "mfa_otp_challenge":
		return "mfa-otp", "mfa-otp-challenge"
	case "mfa_email_challenge":
		return "mfa-email", "mfa-email-challenge"
	case "mfa_email_list":
		return "mfa-email", "mfa-email-list"
	case "mfa_recovery_enroll":
		return "mfa-recovery-code", "mfa-recovery-code-enrollment"
	case "mfa_recovery_challenge":
		return "mfa-recovery-code", "mfa-recovery-code-challenge"
	// Plan 33b WebAuthn MFA (hosted).
	case "mfa_detect":
		return "mfa", "mfa-detect-browser-capabilities"
	case "mfa_webauthn_roaming_enroll":
		return "mfa-webauthn", "mfa-webauthn-roaming-enrollment"
	case "mfa_webauthn_platform_enroll":
		return "mfa-webauthn", "mfa-webauthn-platform-enrollment"
	case "mfa_webauthn_roaming_challenge":
		return "mfa-webauthn", "mfa-webauthn-roaming-challenge"
	case "mfa_webauthn_platform_challenge":
		return "mfa-webauthn", "mfa-webauthn-platform-challenge"
	case "mfa_webauthn_reset_roaming_challenge":
		return "reset-password", "reset-password-mfa-webauthn-roaming-challenge"
	case "mfa_webauthn_reset_platform_challenge":
		return "reset-password", "reset-password-mfa-webauthn-platform-challenge"
	case "mfa_webauthn_nickname":
		return "mfa-webauthn", "mfa-webauthn-change-key-nickname"
	case "mfa_webauthn_success":
		return "mfa-webauthn", "mfa-webauthn-enrollment-success"
	case "mfa_webauthn_error":
		return "mfa-webauthn", "mfa-webauthn-error"
	case "mfa_webauthn_not_available":
		return "mfa-webauthn", "mfa-webauthn-not-available-error"
	default:
		return "mfa", "mfa-enroll-result"
	}
}
func RenderMFA(w http.ResponseWriter, status int, t Tenant, page string, d MFAData) {
	p, s := MFAScreen(page)
	d.Prefix = p + "." + s + "."
	if d.WebAuthn != nil {
		v := *d.WebAuthn
		v.Script = template.JS(webauthnMFAScript)
		d.WebAuthn = &v
	}
	render(w, status, page, t, d, formActionFor(d.RedirectURI))
}
func init() {
	for page, file := range map[string]string{"mfa_phone_enroll": "phone", "mfa_sms_challenge": "phone", "mfa_voice_challenge": "phone", "mfa_options": "options", "mfa_enroll_options": "options", "mfa_otp_enroll": "otp_enroll", "mfa_otp_enroll_code": "otp_enroll", "mfa_otp_challenge": "otp_challenge", "mfa_email_challenge": "email_challenge", "mfa_email_list": "options", "mfa_recovery_enroll": "recovery_enroll", "mfa_recovery_challenge": "recovery_challenge", "mfa_result": "result"} {
		pages[page] = parsePage("templates/layout.html", "templates/mfa_"+file+".html")
	}
	// Plan 33b WebAuthn MFA (hosted).
	pages["mfa_detect"] = parsePage("templates/layout.html", "templates/mfa_detect.html")
	for _, page := range []string{"mfa_webauthn_roaming_enroll", "mfa_webauthn_platform_enroll", "mfa_webauthn_roaming_challenge", "mfa_webauthn_platform_challenge", "mfa_webauthn_reset_roaming_challenge", "mfa_webauthn_reset_platform_challenge", "mfa_webauthn_nickname", "mfa_webauthn_success", "mfa_webauthn_error", "mfa_webauthn_not_available"} {
		pages[page] = parsePage("templates/layout.html", "templates/mfa_webauthn.html")
	}
}
