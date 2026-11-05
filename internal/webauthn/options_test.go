package webauthn_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

type jsoner interface{ JSON() ([]byte, error) }

func decodeJSON(t *testing.T, o jsoner) map[string]any {
	t.Helper()
	raw, err := o.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestOptionsJSON(t *testing.T) {
	t.Run("creation", func(t *testing.T) {
		o := creation()
		o.Exclude = []webauthn.Descriptor{{ID: []byte{1, 2, 3}, Transports: []string{"usb"}}, {ID: []byte{4}}}
		m := decodeJSON(t, o)
		rp := m["rp"].(map[string]any)
		if rp["id"] != testRPID || rp["name"] != testRPID {
			t.Fatalf("rp %v", rp)
		}
		user := m["user"].(map[string]any)
		if user["id"] != b64(testHandle) || user["name"] != "u@example.test" || user["displayName"] != "U" {
			t.Fatalf("user %v", user)
		}
		if m["challenge"] != b64(testChallenge) || m["attestation"] != "none" || m["timeout"] != float64(300000) {
			t.Fatalf("%v", m)
		}
		params := m["pubKeyCredParams"].([]any)
		if len(params) != 3 {
			t.Fatalf("params %v", params)
		}
		for i, alg := range []float64{-8, -7, -257} {
			p := params[i].(map[string]any)
			if p["type"] != "public-key" || p["alg"] != alg {
				t.Fatalf("param %d: %v", i, p)
			}
		}
		sel := m["authenticatorSelection"].(map[string]any)
		if sel["residentKey"] != "required" || sel["requireResidentKey"] != true || sel["userVerification"] != "preferred" {
			t.Fatalf("selection %v", sel)
		}
		if _, ok := sel["authenticatorAttachment"]; ok {
			t.Fatalf("attachment emitted: %v", sel)
		}
		exclude := m["excludeCredentials"].([]any)
		first := exclude[0].(map[string]any)
		if len(exclude) != 2 || first["type"] != "public-key" || first["id"] != "AQID" || first["transports"].([]any)[0] != "usb" {
			t.Fatalf("exclude %v", exclude)
		}
		if _, ok := exclude[1].(map[string]any)["transports"]; ok {
			t.Fatalf("empty transports emitted: %v", exclude)
		}
		for _, key := range []string{"rp", "user", "challenge", "pubKeyCredParams", "timeout", "excludeCredentials", "authenticatorSelection", "attestation"} {
			if _, ok := m[key]; !ok {
				t.Fatalf("missing %s", key)
			}
		}
		if len(m) != 8 {
			t.Fatalf("unexpected members: %v", m)
		}
	})
	t.Run("creation rp name and custom algs", func(t *testing.T) {
		o := creation()
		o.RPName = "Example"
		o.Algs = []int64{-7}
		o.Attachment = "platform"
		m := decodeJSON(t, o)
		if m["rp"].(map[string]any)["name"] != "Example" || len(m["pubKeyCredParams"].([]any)) != 1 {
			t.Fatalf("%v", m)
		}
		if m["authenticatorSelection"].(map[string]any)["authenticatorAttachment"] != "platform" {
			t.Fatalf("%v", m)
		}
		if m["excludeCredentials"].([]any) == nil {
			t.Fatal("exclude list must be an empty array")
		}
	})
	t.Run("ceremony rows", func(t *testing.T) {
		for _, row := range []struct {
			name, uv, rk, attachment string
		}{
			{"passkey signup", "preferred", "required", ""},
			{"local enrollment", "preferred", "required", "platform"},
			{"roaming never", "discouraged", "discouraged", "cross-platform"},
			{"roaming if supported", "preferred", "discouraged", "cross-platform"},
			{"roaming required", "required", "discouraged", "cross-platform"},
			{"platform", "required", "discouraged", "platform"},
		} {
			o := creation()
			o.UserVerification, o.ResidentKey, o.Attachment = row.uv, row.rk, row.attachment
			sel := decodeJSON(t, o)["authenticatorSelection"].(map[string]any)
			if sel["userVerification"] != row.uv || sel["residentKey"] != row.rk {
				t.Fatalf("%s: %v", row.name, sel)
			}
			if got, _ := sel["authenticatorAttachment"].(string); got != row.attachment {
				t.Fatalf("%s: attachment %q", row.name, got)
			}
			if (sel["requireResidentKey"] == true) != (row.rk == "required") {
				t.Fatalf("%s: requireResidentKey %v", row.name, sel["requireResidentKey"])
			}
		}
	})
	t.Run("request", func(t *testing.T) {
		o := request()
		m := decodeJSON(t, o)
		if m["challenge"] != b64(testChallenge) || m["rpId"] != testRPID || m["timeout"] != float64(60000) || m["userVerification"] != "preferred" {
			t.Fatalf("%v", m)
		}
		allow, ok := m["allowCredentials"].([]any)
		if !ok || len(allow) != 0 {
			t.Fatalf("allow %v", m["allowCredentials"])
		}
		if len(m) != 5 {
			t.Fatalf("unexpected members: %v", m)
		}
		o.Allow = []webauthn.Descriptor{{ID: []byte{9}, Transports: []string{"usb", "nfc"}}}
		o.UserVerification = "required"
		o.Timeout = 5 * time.Minute
		m = decodeJSON(t, o)
		allow = m["allowCredentials"].([]any)
		if len(allow) != 1 || allow[0].(map[string]any)["id"] != "CQ" || m["userVerification"] != "required" || m["timeout"] != float64(300000) {
			t.Fatalf("%v", m)
		}
	})
	t.Run("defaults and validation", func(t *testing.T) {
		o := creation()
		o.UserVerification, o.ResidentKey = "", ""
		sel := decodeJSON(t, o)["authenticatorSelection"].(map[string]any)
		if sel["userVerification"] != "preferred" {
			t.Fatalf("%v", sel)
		}
		if _, ok := sel["residentKey"]; ok {
			t.Fatalf("empty residentKey emitted: %v", sel)
		}
		for name, mutate := range map[string]func(*webauthn.CreationOptions){
			"no challenge":       func(o *webauthn.CreationOptions) { o.Challenge = nil },
			"no rp id":           func(o *webauthn.CreationOptions) { o.RPID = "" },
			"no user id":         func(o *webauthn.CreationOptions) { o.UserID = nil },
			"user id too long":   func(o *webauthn.CreationOptions) { o.UserID = make([]byte, 65) },
			"no user name":       func(o *webauthn.CreationOptions) { o.UserName = "" },
			"bad attachment":     func(o *webauthn.CreationOptions) { o.Attachment = "remote" },
			"bad resident key":   func(o *webauthn.CreationOptions) { o.ResidentKey = "maybe" },
			"bad uv":             func(o *webauthn.CreationOptions) { o.UserVerification = "always" },
			"empty exclude id":   func(o *webauthn.CreationOptions) { o.Exclude = []webauthn.Descriptor{{}} },
			"negative timeout":   func(o *webauthn.CreationOptions) { o.Timeout = -time.Second },
			"unsupported alg":    func(o *webauthn.CreationOptions) { o.Algs = []int64{-65535} },
			"no display name ok": func(o *webauthn.CreationOptions) { o.DisplayName = "" },
		} {
			o := creation()
			mutate(&o)
			_, err := o.JSON()
			if name == "no display name ok" {
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("%s: accepted", name)
			}
		}
		r := request()
		r.Challenge = nil
		if _, err := r.JSON(); err == nil {
			t.Fatal("request without challenge accepted")
		}
		r = request()
		r.RPID = ""
		if _, err := r.JSON(); err == nil {
			t.Fatal("request without rp id accepted")
		}
		r = request()
		r.UserVerification = "maybe"
		if _, err := r.JSON(); err == nil {
			t.Fatal("request with bad uv accepted")
		}
	})
}
