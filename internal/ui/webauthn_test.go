package ui

import (
	"strings"
	"testing"
)

// TestPasskeyScriptNoNetwork pins section 5.2: the one hosted WebAuthn
// script posts ordinary forms and opens no network channel of its own, so
// the page CSP keeps connect-src 'none'.
func TestPasskeyScriptNoNetwork(t *testing.T) {
	js := string(WebAuthnScript())
	for _, banned := range []string{"fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "eval(", "new Function", "innerHTML", "<script", "</script"} {
		if strings.Contains(js, banned) {
			t.Errorf("script contains %q", banned)
		}
	}
	for _, want := range []string{`getElementById("za-webauthn")`, `getElementById("za-webauthn-form")`, "form.submit()", `mediation: "conditional"`, "abort()", "webauthn_error", "parseRequestOptionsFromJSON", "parseCreationOptionsFromJSON"} {
		if !strings.Contains(js, want) {
			t.Errorf("script lacks %q", want)
		}
	}
}
