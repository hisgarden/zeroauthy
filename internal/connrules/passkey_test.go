package connrules

import (
	"reflect"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func passkeyConn(mut func(c *store.Connection)) *store.Connection {
	c := &store.Connection{
		ID: "con_pk", Name: "db", Strategy: store.StrategyDatabase,
		Extra: map[string]any{
			"authentication_methods": map[string]any{
				"password": map[string]any{"enabled": true, "api_behavior": "required"},
				"passkey":  map[string]any{"enabled": true},
			},
		},
	}
	if mut != nil {
		mut(c)
	}
	return c
}

func methods(c *store.Connection) map[string]any {
	return c.Extra["authentication_methods"].(map[string]any)
}

func TestPasskeyPolicy(t *testing.T) {
	ready := map[string]any{"universal_login_experience": "new", "identifier_first": true}
	defaults := PasskeyPolicy{Enabled: true, Effective: true, ChallengeUI: "both", Progressive: true, Local: true}
	for _, tc := range []struct {
		name    string
		conn    *store.Connection
		prompts map[string]any
		want    PasskeyPolicy
		unmet   []Unmet
	}{
		{"all met, D-0042 defaults", passkeyConn(nil), ready, defaults, nil},
		{"strategy not auth0", passkeyConn(func(c *store.Connection) { c.Strategy = "google-oauth2" }), ready,
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetStrategy}},
		{"classic experience", passkeyConn(nil), map[string]any{"universal_login_experience": "classic", "identifier_first": true},
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetUniversalLogin}},
		{"identifier first off", passkeyConn(nil), map[string]any{"universal_login_experience": "new", "identifier_first": false},
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetIdentifierFirst}},
		{"no prompt settings", passkeyConn(nil), nil,
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetIdentifierFirst}},
		{"requires username without attributes", passkeyConn(func(c *store.Connection) { c.RequiresUsername = true }), ready,
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetRequiresUsername}},
		{"requires username with flexible identifiers", passkeyConn(func(c *store.Connection) {
			c.RequiresUsername = true
			c.Extra["attributes"] = map[string]any{"email": map[string]any{"identifier": map[string]any{"active": true}}}
		}), ready, defaults, nil},
		{"custom database without import", passkeyConn(func(c *store.Connection) { c.EnabledDatabaseCustomization = true }), ready,
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetImportMode}},
		{"custom database in import mode", passkeyConn(func(c *store.Connection) { c.EnabledDatabaseCustomization, c.ImportMode = true, true }), ready, defaults, nil},
		{"passwords disabled", passkeyConn(func(c *store.Connection) { methods(c)["password"] = map[string]any{"enabled": false} }), ready,
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetPassword}},
		{"password method omitted counts as enabled", passkeyConn(func(c *store.Connection) { delete(methods(c), "password") }), ready, defaults, nil},
		{"passkeys off", passkeyConn(func(c *store.Connection) { methods(c)["passkey"] = map[string]any{"enabled": false} }), ready,
			PasskeyPolicy{ChallengeUI: "both", Progressive: true, Local: true}, nil},
		{"no authentication methods", passkeyConn(func(c *store.Connection) { c.Extra = nil }), ready,
			PasskeyPolicy{ChallengeUI: "both", Progressive: true, Local: true}, nil},
		{"stored options", passkeyConn(func(c *store.Connection) {
			c.Extra["passkey_options"] = map[string]any{"challenge_ui": "autofill", "progressive_enrollment_enabled": false, "local_enrollment_enabled": false}
		}), ready, PasskeyPolicy{Enabled: true, Effective: true, ChallengeUI: "autofill"}, nil},
		{"button only", passkeyConn(func(c *store.Connection) {
			c.Extra["passkey_options"] = map[string]any{"challenge_ui": "button"}
		}), ready, PasskeyPolicy{Enabled: true, Effective: true, ChallengeUI: "button", Progressive: true, Local: true}, nil},
		{"unknown challenge_ui keeps the default", passkeyConn(func(c *store.Connection) {
			c.Extra["passkey_options"] = map[string]any{"challenge_ui": "popup", "local_enrollment_enabled": "yes"}
		}), ready, defaults, nil},
		{"several unmet in a fixed order", passkeyConn(func(c *store.Connection) {
			c.RequiresUsername, c.EnabledDatabaseCustomization = true, true
			methods(c)["password"] = map[string]any{"enabled": false}
		}), map[string]any{"universal_login_experience": "classic"},
			PasskeyPolicy{Enabled: true, ChallengeUI: "both", Progressive: true, Local: true},
			[]Unmet{UnmetUniversalLogin, UnmetIdentifierFirst, UnmetRequiresUsername, UnmetImportMode, UnmetPassword}},
		{"no connection", nil, ready, PasskeyPolicy{ChallengeUI: "both", Progressive: true, Local: true}, []Unmet{UnmetStrategy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, unmet := Passkeys(tc.conn, tc.prompts)
			if got != tc.want {
				t.Errorf("policy = %+v, want %+v", got, tc.want)
			}
			if !reflect.DeepEqual(unmet, tc.unmet) {
				t.Errorf("unmet = %q, want %q", unmet, tc.unmet)
			}
		})
	}
	// The wire names are the frozen API enum (api/management.yaml).
	for u, want := range map[Unmet]string{UnmetUniversalLogin: "universal_login", UnmetIdentifierFirst: "identifier_first",
		UnmetRequiresUsername: "requires_username", UnmetImportMode: "import_mode", UnmetPassword: "password",
		UnmetStrategy: "strategy", UnmetPasskeyDisabled: "passkey_disabled"} {
		if string(u) != want {
			t.Errorf("Unmet %q, want %q", u, want)
		}
	}
}
