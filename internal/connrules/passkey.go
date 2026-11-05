package connrules

import "github.com/zeroauthy/zeroauthy/internal/store"

// PasskeyPolicy is a connection's passkey settings as the server applies
// them (spec section 3.1, LR33b-1). Enabled is
// authentication_methods.passkey.enabled as stored; Effective is true only
// when it is enabled and every documented prerequisite holds. ChallengeUI
// ("both", "autofill" or "button"), Progressive and Local are
// passkey_options with the D-0042 defaults (both, true, true) for absent or
// unrecognized values.
type PasskeyPolicy struct {
	Enabled, Effective bool
	ChallengeUI        string
	Progressive, Local bool
}

// Unmet names a documented passkey prerequisite that does not hold. The
// values are the frozen wire enum of
// GET /api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites.
type Unmet string

const (
	UnmetUniversalLogin   Unmet = "universal_login"   // prompt universal_login_experience is not "new"
	UnmetIdentifierFirst  Unmet = "identifier_first"  // prompt identifier_first is not true
	UnmetRequiresUsername Unmet = "requires_username" // requires_username without flexible identifiers (attributes)
	UnmetImportMode       Unmet = "import_mode"       // a custom database without import mode
	UnmetPassword         Unmet = "password"          // authentication_methods.password.enabled is false
	UnmetStrategy         Unmet = "strategy"          // not a database (auth0) connection
	// UnmetPasskeyDisabled is not a prerequisite and Passkeys never returns
	// it; the prerequisites route adds it when passkeys are switched off.
	UnmetPasskeyDisabled Unmet = "passkey_disabled"
)

// Passkeys evaluates conn's passkey policy against the tenant's prompt
// settings (store.HostedLoginConfig.Prompts; nil means the defaults:
// universal_login_experience "new", identifier_first false). The unmet list
// is in the order of the constants above and nil when every prerequisite
// holds. zeroauthy has no classic custom login page (D-0039), so that
// prerequisite always holds. The connection prerequisites are not checked
// on a connection that is not a database connection.
func Passkeys(conn *store.Connection, prompts map[string]any) (PasskeyPolicy, []Unmet) {
	p := PasskeyPolicy{ChallengeUI: "both", Progressive: true, Local: true}
	var unmet []Unmet
	if ule, ok := prompts["universal_login_experience"]; ok && ule != "new" {
		unmet = append(unmet, UnmetUniversalLogin)
	}
	if prompts["identifier_first"] != true {
		unmet = append(unmet, UnmetIdentifierFirst)
	}
	if conn == nil {
		return p, append(unmet, UnmetStrategy)
	}
	methods, _ := conn.Extra["authentication_methods"].(map[string]any)
	passkey, _ := methods["passkey"].(map[string]any)
	p.Enabled = passkey["enabled"] == true
	if opts, ok := conn.Extra["passkey_options"].(map[string]any); ok {
		switch ui := opts["challenge_ui"]; ui {
		case "both", "autofill", "button":
			p.ChallengeUI = ui.(string)
		}
		if v, ok := opts["progressive_enrollment_enabled"].(bool); ok {
			p.Progressive = v
		}
		if v, ok := opts["local_enrollment_enabled"].(bool); ok {
			p.Local = v
		}
	}
	if conn.Strategy != store.StrategyDatabase {
		unmet = append(unmet, UnmetStrategy)
	} else {
		if conn.RequiresUsername && conn.Extra["attributes"] == nil {
			unmet = append(unmet, UnmetRequiresUsername)
		}
		if conn.EnabledDatabaseCustomization && !conn.ImportMode {
			unmet = append(unmet, UnmetImportMode)
		}
		if password, _ := methods["password"].(map[string]any); password["enabled"] == false {
			unmet = append(unmet, UnmetPassword)
		}
	}
	p.Effective = p.Enabled && len(unmet) == 0
	return p, unmet
}
