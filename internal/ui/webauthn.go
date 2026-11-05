package ui

import (
	_ "embed"
	"encoding/json"
	"html/template"
)

// webauthnJS is the one in-tree hosted WebAuthn script (Plan 33b spec
// section 5.2). Pages inline it with their CSP nonce.
//
//go:embed webauthn.js
var webauthnJS string

// WebAuthnScript is the hosted WebAuthn script, for inlining in a nonce'd
// script element.
func WebAuthnScript() template.JS { return template.JS(webauthnJS) }

// WebAuthnDoc is the page's za-webauthn options document. html/template
// renders it as JSON inside <script type="application/json">, escaped for
// that context.
type WebAuthnDoc struct {
	// Mode is "login" (navigator.credentials.get) or "create".
	Mode        string `json:"mode"`
	ChallengeID string `json:"challenge_id"`
	// Mediation is "conditional" for autofill and empty otherwise.
	Mediation string `json:"mediation,omitempty"`
	// Button offers the explicit passkey button (login mode).
	Button bool `json:"button,omitempty"`
	// PublicKey is the WebAuthn options JSON (webauthn.RequestOptions or
	// CreationOptions).
	PublicKey json.RawMessage `json:"publicKey"`
}

// PasskeyLogin is the passkey part of the login-id page: present only when
// passkeys are effective for the transaction's connection.
type PasskeyLogin struct {
	Doc WebAuthnDoc
	// Autofill adds the webauthn autocomplete token to the identifier
	// input; Button shows the passkey button.
	Autofill, Button bool
	Script           template.JS
}
