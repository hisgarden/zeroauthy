package logscrub_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// TestScrubWebAuthnKeys pins the Plan 33b §8.2 key names: each is hidden at
// any depth and in any casing or separator style, and a representative
// value never survives the scrubber.
func TestScrubWebAuthnKeys(t *testing.T) {
	want := []string{"authn_response", "auth_session", "attestationObject", "authenticatorData", "clientDataJSON", "signature", "userHandle", "user_handle", "challenge_id"}
	keys := webauthnrules.ScrubKeys()
	for _, k := range want {
		found := false
		for _, x := range keys {
			found = found || x == k
		}
		if !found {
			t.Fatalf("webauthnrules.ScrubKeys() lacks %q", k)
		}
	}
	variants := func(k string) []string {
		return []string{k, strings.ToUpper(k), strings.ToLower(k), strings.ReplaceAll(k, "_", "-"), strings.ReplaceAll(k, "_", "")}
	}
	const secret = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0-representative-value"
	for _, key := range keys {
		for _, name := range variants(key) {
			if !logscrub.SensitiveKey(name) {
				t.Errorf("%q is not sensitive", name)
			}
			doc := map[string]any{
				name:     secret,
				"public": "visible",
				"nested": map[string]any{"response": map[string]any{name: secret}, "list": []any{map[string]any{name: map[string]any{"x": secret}}}},
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			out, err := logscrub.Scrub(raw)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), secret) || !strings.Contains(string(out), `"public":"visible"`) {
				t.Errorf("%q: %s", name, out)
			}
			// A JSON document carried in a string (a form body logged as
			// text) is scrubbed too.
			embedded, _ := json.Marshal(map[string]any{"body": string(raw)})
			out, err = logscrub.Scrub(embedded)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), secret) {
				t.Errorf("%q embedded: %s", name, out)
			}
		}
	}
	// The names are exact: unrelated keys sharing a fragment stay public.
	for _, key := range []string{"auth", "session", "response", "user", "handle", "signature_alg", "client_data", "user_id"} {
		if logscrub.SensitiveKey(key) {
			t.Errorf("unrelated key %q became sensitive", key)
		}
	}
}
