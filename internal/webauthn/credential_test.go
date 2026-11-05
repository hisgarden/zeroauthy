package webauthn_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

// TestParseLevel2Shapes pins Review Focus 5: responses from browsers that
// implement only WebAuthn Level 2 parse, and the Level 3 members are simply
// absent.
func TestParseLevel2Shapes(t *testing.T) {
	id := b64([]byte{1, 2, 3})
	t.Run("assertion without level 3 members", func(t *testing.T) {
		raw := `{"id":"` + id + `","rawId":"` + id + `","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA","userHandle":null}}`
		c, err := webauthn.ParseCredentialJSON([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if c.Attachment != "" || c.Transports != nil || c.UserHandle != nil || c.Type != "public-key" {
			t.Fatalf("%+v", c)
		}
		if !bytes.Equal(c.ID, []byte{1, 2, 3}) || !bytes.Equal(c.RawID, []byte{1, 2, 3}) || string(c.ClientDataJSON) != "{}" || len(c.AuthenticatorData) != 3 || len(c.Signature) != 3 {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("userHandle omitted", func(t *testing.T) {
		raw := `{"id":"` + id + `","rawId":"` + id + `","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA"}}`
		c, err := webauthn.ParseCredentialJSON([]byte(raw))
		if err != nil || c.UserHandle != nil {
			t.Fatalf("%v %+v", err, c)
		}
	})
	t.Run("registration without level 3 members", func(t *testing.T) {
		raw := `{"id":"` + id + `","rawId":"` + id + `","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`
		c, err := webauthn.ParseCredentialJSON([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if c.Attachment != "" || c.Transports != nil || len(c.AttestationObject) != 1 || c.AuthenticatorData != nil {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("level 3 members", func(t *testing.T) {
		raw := `{"id":"` + id + `","rawId":"` + id + `","type":"public-key","authenticatorAttachment":"cross-platform","response":{"clientDataJSON":"e30","attestationObject":"oA","transports":["usb","nfc"]},"clientExtensionResults":{"credProps":{"rk":true}}}`
		c, err := webauthn.ParseCredentialJSON([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if c.Attachment != "cross-platform" || len(c.Transports) != 2 || c.Transports[1] != "nfc" {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("padded base64url accepted", func(t *testing.T) {
		raw := `{"id":"AQI=","rawId":"AQI=","type":"public-key","response":{"clientDataJSON":"e30=","attestationObject":"oA=="}}`
		c, err := webauthn.ParseCredentialJSON([]byte(raw))
		if err != nil || !bytes.Equal(c.RawID, []byte{1, 2}) || string(c.ClientDataJSON) != "{}" {
			t.Fatalf("%v %+v", err, c)
		}
	})
	t.Run("unknown members ignored", func(t *testing.T) {
		raw := `{"id":"` + id + `","rawId":"` + id + `","type":"public-key","extra":1,"response":{"clientDataJSON":"e30","attestationObject":"oA","publicKeyAlgorithm":-7,"publicKey":"AAAA","authenticatorData":"AAAA"}}`
		if _, err := webauthn.ParseCredentialJSON([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		name, raw, reason string
	}{
		{"id differs from rawId", `{"id":"AQID","rawId":"AQIE","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "parse"},
		{"missing rawId", `{"id":"AQID","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "parse"},
		{"empty id", `{"id":"","rawId":"","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "parse"},
		{"wrong type", `{"id":"AQID","rawId":"AQID","type":"public-key-x","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "type"},
		{"missing type", `{"id":"AQID","rawId":"AQID","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "type"},
		{"standard base64", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"+/+/"}}`, "parse"},
		{"not json", `{`, "parse"},
		{"json array", `[]`, "parse"},
		{"trailing json", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}} {}`, "parse"},
		{"no response", `{"id":"AQID","rawId":"AQID","type":"public-key"}`, "parse"},
		{"no client data", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"attestationObject":"oA"}}`, "parse"},
		{"neither attestation nor assertion", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30"}}`, "parse"},
		{"both attestation and signature", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA","authenticatorData":"AAAA","signature":"AAAA"}}`, "parse"},
		{"assertion without signature", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA"}}`, "parse"},
		{"unknown attachment", `{"id":"AQID","rawId":"AQID","type":"public-key","authenticatorAttachment":"remote","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "parse"},
		{"attachment not a string", `{"id":"AQID","rawId":"AQID","type":"public-key","authenticatorAttachment":1,"response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "parse"},
		{"transports not strings", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA","transports":[1]}}`, "parse"},
		{"user handle not a string", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA","userHandle":7}}`, "parse"},
		{"credential id too long", `{"id":"` + b64(bytes.Repeat([]byte{1}, 1024)) + `","rawId":"` + b64(bytes.Repeat([]byte{1}, 1024)) + `","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`, "too_large"},
		{"client data too long", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"` + b64(bytes.Repeat([]byte{' '}, webauthn.ClientDataMax+1)) + `","attestationObject":"oA"}}`, "too_large"},
		{"user handle too long", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA","userHandle":"` + b64(bytes.Repeat([]byte{1}, 65)) + `"}}`, "too_large"},
		{"too many transports", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA","transports":[` + strings.Repeat(`"usb",`, 16) + `"usb"]}}`, "parse"},
		{"document too long", `{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA","x":"` + strings.Repeat("a", 2*webauthn.AttestationMax) + `"}}`, "too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := webauthn.ParseCredentialJSON([]byte(tc.raw))
			wantReason(t, err, tc.reason)
		})
	}
	t.Run("authenticator output has level 2 shape without attachment", func(t *testing.T) {
		auth := webauthntest.New(webauthntest.Options{})
		var m map[string]json.RawMessage
		if err := json.Unmarshal(auth.Create(creation(), testOrigin), &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["authenticatorAttachment"]; ok {
			t.Fatal("attachment emitted although unset")
		}
	})
}

func FuzzParseCredentialJSON(f *testing.F) {
	auth := webauthntest.New(webauthntest.Options{Alg: -7, UV: true, Attachment: "platform", Transports: []string{"internal"}})
	f.Add(auth.Create(creation(), testOrigin))
	f.Add(auth.Get(request(), testOrigin))
	f.Add(webauthntest.New(webauthntest.Options{Alg: -8, Format: "packed"}).Create(creation(), testOrigin))
	f.Add([]byte(`{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA","userHandle":null}}`))
	f.Add([]byte(`{"id":"AQI=","rawId":"AQI=","type":"public-key","response":{"clientDataJSON":"e30=","attestationObject":"oA=="}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`[]`))
	_, stored := enroll(f, webauthntest.Options{})
	e := expect()
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := webauthn.ParseCredentialJSON(raw)
		if err != nil {
			switch webauthn.Reason(err) {
			case "parse", "type", "too_large":
			default:
				t.Fatalf("reason %q", webauthn.Reason(err))
			}
			return
		}
		if !bytes.Equal(c.ID, c.RawID) || len(c.RawID) == 0 || len(c.RawID) > webauthn.CredentialIDMax || c.Type != "public-key" {
			t.Fatalf("invariant: %+v", c)
		}
		if len(c.ClientDataJSON) == 0 || len(c.ClientDataJSON) > webauthn.ClientDataMax || len(c.AttestationObject) > webauthn.AttestationMax || len(c.AuthenticatorData) > webauthn.AttestationMax {
			t.Fatalf("bounds: %+v", c)
		}
		if (len(c.AttestationObject) == 0) == (len(c.Signature) == 0) {
			t.Fatalf("neither or both shapes: %+v", c)
		}
		// Verification must never panic on any parsed shape.
		r, err := webauthn.VerifyRegistration(c, e)
		if (r == nil) == (err == nil) {
			t.Fatal("registration result and error disagree")
		}
		a, err := webauthn.VerifyAssertion(c, e, stored)
		if (a == nil) == (err == nil) {
			t.Fatal("assertion result and error disagree")
		}
	})
}
