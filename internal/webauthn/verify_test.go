package webauthn_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const (
	testRPID   = "example.test"
	testOrigin = "https://example.test"
)

var (
	testChallenge = bytes.Repeat([]byte{7}, 32)
	testHandle    = bytes.Repeat([]byte{9}, 32)
)

func creation() webauthn.CreationOptions {
	return webauthn.CreationOptions{Challenge: testChallenge, RPID: testRPID, UserID: testHandle, UserName: "u@example.test", DisplayName: "U", ResidentKey: "required", UserVerification: "preferred", Timeout: 5 * time.Minute}
}

func request() webauthn.RequestOptions {
	return webauthn.RequestOptions{Challenge: testChallenge, RPID: testRPID, UserVerification: "preferred", Timeout: time.Minute}
}

func expect() webauthn.Expect {
	return webauthn.Expect{Challenge: testChallenge, RPID: testRPID, Origins: []string{testOrigin}}
}

func parse(t testing.TB, raw []byte) *webauthn.Credential {
	t.Helper()
	c, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if reason == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("accepted, want reason %q", reason)
	}
	if got := webauthn.Reason(err); got != reason {
		t.Fatalf("reason %q want %q (%v)", got, reason, err)
	}
}

func TestVerifyRegistration(t *testing.T) {
	other := append([]byte(nil), testChallenge...)
	other[0] ^= 1
	for _, tc := range []struct {
		name   string
		auth   webauthntest.Options
		opts   func(*webauthn.CreationOptions)
		origin string
		expect func(*webauthn.Expect)
		raw    func([]byte) []byte
		reason string
		check  func(*testing.T, *webauthn.Registration)
	}{
		{name: "eddsa", auth: webauthntest.Options{Alg: -8}, check: func(t *testing.T, r *webauthn.Registration) {
			if r.Alg != -8 {
				t.Fatalf("alg %d", r.Alg)
			}
		}},
		{name: "es256", auth: webauthntest.Options{Alg: -7}, check: func(t *testing.T, r *webauthn.Registration) {
			if r.Alg != -7 || r.Format != "none" || r.SignCount != 0 || r.UV || r.BE || r.BS || r.Attachment != "" || len(r.CredentialID) != 32 {
				t.Fatalf("%+v", r)
			}
			if _, err := webauthn.ParseCOSEKey(r.PublicKeyCOSE); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "rs256", auth: webauthntest.Options{Alg: -257}, check: func(t *testing.T, r *webauthn.Registration) {
			if r.Alg != -257 {
				t.Fatalf("alg %d", r.Alg)
			}
		}},
		{name: "es384 refused at registration", auth: webauthntest.Options{Alg: -35}, reason: "alg"},
		{name: "es512 refused at registration", auth: webauthntest.Options{Alg: -36}, reason: "alg"},
		{name: "ps256 refused at registration", auth: webauthntest.Options{Alg: -37}, reason: "alg"},
		{name: "es384 accepted when offered", auth: webauthntest.Options{Alg: -35}, expect: func(e *webauthn.Expect) { e.Algs = []int64{-35} }},
		{name: "default alg", auth: webauthntest.Options{}, check: func(t *testing.T, r *webauthn.Registration) {
			if r.Alg != -7 {
				t.Fatalf("alg %d", r.Alg)
			}
		}},
		{name: "flags and attachment", auth: webauthntest.Options{UV: true, BE: true, BS: true, Attachment: "platform", SignCount: 3, Transports: []string{"internal", "hybrid"}}, check: func(t *testing.T, r *webauthn.Registration) {
			if !r.UV || !r.BE || !r.BS || r.Attachment != "platform" || r.SignCount != 3 || len(r.Transports) != 2 || r.Transports[0] != "internal" {
				t.Fatalf("%+v", r)
			}
		}},
		{name: "aaguid kept", auth: webauthntest.Options{AAGUID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}, check: func(t *testing.T, r *webauthn.Registration) {
			if r.AAGUID != [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} {
				t.Fatalf("aaguid %x", r.AAGUID)
			}
		}},
		{name: "all-zero aaguid allowed", auth: webauthntest.Options{}, check: func(t *testing.T, r *webauthn.Registration) {
			if r.AAGUID != [16]byte{} {
				t.Fatalf("aaguid %x", r.AAGUID)
			}
		}},
		{name: "wrong type", auth: webauthntest.Options{}, raw: func(b []byte) []byte { return bytes.Replace(b, []byte(`"public-key"`), []byte(`"public-key2"`), 1) }, reason: "type"},
		{name: "wrong client data type", auth: webauthntest.Options{ClientDataType: "webauthn.get"}, reason: "type"},
		{name: "wrong challenge", auth: webauthntest.Options{}, expect: func(e *webauthn.Expect) { e.Challenge = other }, reason: "challenge"},
		{name: "short challenge", auth: webauthntest.Options{}, opts: func(o *webauthn.CreationOptions) { o.Challenge = testChallenge[:31] }, reason: "challenge"},
		{name: "wrong origin", auth: webauthntest.Options{}, origin: "https://example.test:8443", reason: "origin"},
		{name: "origin scheme", auth: webauthntest.Options{}, origin: "http://example.test", reason: "origin"},
		{name: "origin among several", auth: webauthntest.Options{}, origin: "https://login.example.test", expect: func(e *webauthn.Expect) { e.Origins = []string{"https://a.example.test", "https://login.example.test"} }},
		{name: "cross origin", auth: webauthntest.Options{CrossOrigin: true}, reason: "cross_origin"},
		{name: "top origin", auth: webauthntest.Options{TopOrigin: "https://example.test"}, reason: "cross_origin"},
		{name: "wrong rp id hash", auth: webauthntest.Options{TamperRPIDHash: true}, reason: "rp_id"},
		{name: "rp id differs", auth: webauthntest.Options{}, expect: func(e *webauthn.Expect) { e.RPID = "other.test" }, reason: "rp_id"},
		{name: "user not present", auth: webauthntest.Options{NoUP: true}, reason: "user_present"},
		{name: "uv required and clear", auth: webauthntest.Options{}, expect: func(e *webauthn.Expect) { e.RequireUV = true }, reason: "user_verified"},
		{name: "uv required and set", auth: webauthntest.Options{UV: true}, expect: func(e *webauthn.Expect) { e.RequireUV = true }},
		{name: "backed up without eligibility", auth: webauthntest.Options{BS: true}, reason: "backup_state"},
		{name: "unparsed tail", auth: webauthntest.Options{AuthDataTail: []byte{0}}, reason: "parse"},
		{name: "extensions parsed and ignored", auth: webauthntest.Options{Extensions: map[string]any{"credProtect": int64(2)}}},
		{name: "format packed", auth: webauthntest.Options{Format: "packed"}, check: func(t *testing.T, r *webauthn.Registration) {
			if r.Format != "none" {
				t.Fatalf("format %q", r.Format)
			}
		}},
		{name: "format tpm", auth: webauthntest.Options{Format: "tpm"}},
		{name: "format android-key", auth: webauthntest.Options{Format: "android-key"}},
		{name: "format android-safetynet", auth: webauthntest.Options{Format: "android-safetynet"}},
		{name: "format fido-u2f", auth: webauthntest.Options{Format: "fido-u2f"}},
		{name: "format apple", auth: webauthntest.Options{Format: "apple"}},
		{name: "format unknown", auth: webauthntest.Options{Format: "custom"}, reason: "attestation"},
		{name: "format none with statement", auth: webauthntest.Options{Format: "none", AttStmt: map[string]any{"alg": int64(-7)}}, reason: "attestation"},
		{name: "credential id 1023", auth: webauthntest.Options{CredentialID: bytes.Repeat([]byte{1}, 1023)}, check: func(t *testing.T, r *webauthn.Registration) {
			if len(r.CredentialID) != 1023 {
				t.Fatalf("id length %d", len(r.CredentialID))
			}
		}},
		{name: "credential id 1024", auth: webauthntest.Options{CredentialID: bytes.Repeat([]byte{1}, 1024)}, reason: "too_large"},
		{name: "raw id differs from attested id", auth: webauthntest.Options{}, raw: func(b []byte) []byte {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				panic(err)
			}
			m["id"], m["rawId"] = "AQID", "AQID"
			out, _ := json.Marshal(m)
			return out
		}, reason: "parse"},
		{name: "attestation object too large", auth: webauthntest.Options{AuthDataTail: bytes.Repeat([]byte{0}, webauthn.AttestationMax)}, reason: "too_large"},
		{name: "client data too large", auth: webauthntest.Options{ClientDataPadding: webauthn.ClientDataMax}, reason: "too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := webauthntest.New(tc.auth)
			opts := creation()
			if tc.opts != nil {
				tc.opts(&opts)
			}
			origin := testOrigin
			if tc.origin != "" {
				origin = tc.origin
			}
			raw := auth.Create(opts, origin)
			if tc.raw != nil {
				raw = tc.raw(raw)
			}
			e := expect()
			if tc.expect != nil {
				tc.expect(&e)
			}
			c, err := webauthn.ParseCredentialJSON(raw)
			if err != nil {
				wantReason(t, err, tc.reason)
				return
			}
			r, err := webauthn.VerifyRegistration(c, e)
			wantReason(t, err, tc.reason)
			if tc.reason != "" {
				if r != nil {
					t.Fatal("result returned with error")
				}
				return
			}
			if !bytes.Equal(r.CredentialID, auth.CredentialID()) || !bytes.Equal(r.PublicKeyCOSE, auth.PublicKeyCOSE()) {
				t.Fatal("credential or key differs from the authenticator's")
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
	t.Run("nil credential", func(t *testing.T) {
		if _, err := webauthn.VerifyRegistration(nil, expect()); err == nil {
			t.Fatal("nil accepted")
		}
	})
}

// enroll registers a fresh software authenticator and returns it with the
// Stored record a store would keep for it.
func enroll(t testing.TB, o webauthntest.Options) (*webauthntest.Authenticator, webauthn.Stored) {
	t.Helper()
	auth := webauthntest.New(o)
	e := expect()
	if o.Alg != 0 {
		e.Algs = []int64{o.Alg}
	}
	r, err := webauthn.VerifyRegistration(parse(t, auth.Create(creation(), testOrigin)), e)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return auth, webauthn.Stored{PublicKeyCOSE: r.PublicKeyCOSE, SignCount: r.SignCount, BE: r.BE, UserHandle: testHandle}
}

func TestVerifyAssertion(t *testing.T) {
	t.Run("every key type", func(t *testing.T) {
		for _, alg := range []int64{-8, -7, -35, -36, -257, -37} {
			auth, stored := enroll(t, webauthntest.Options{Alg: alg, UV: true})
			c := parse(t, auth.Get(request(), testOrigin))
			a, err := webauthn.VerifyAssertion(c, expect(), stored)
			if err != nil {
				t.Fatalf("alg %d: %v", alg, err)
			}
			if !bytes.Equal(a.CredentialID, auth.CredentialID()) || !bytes.Equal(a.UserHandle, testHandle) || !a.UV || a.BE || a.BS || a.SignCount != 0 {
				t.Fatalf("alg %d: %+v", alg, a)
			}
			// The signature covers authenticatorData || SHA-256(clientDataJSON):
			// touching either side, or the signature, fails.
			for name, mutate := range map[string]func(*webauthn.Credential){
				"signature":          func(c *webauthn.Credential) { c.Signature[len(c.Signature)/2] ^= 1 },
				"authenticator data": func(c *webauthn.Credential) { c.AuthenticatorData[36] ^= 1 },
				"client data": func(c *webauthn.Credential) {
					c.ClientDataJSON = append(c.ClientDataJSON[:len(c.ClientDataJSON)-1], ' ', '}')
				},
				"other key": func(c *webauthn.Credential) {},
			} {
				c := parse(t, auth.Get(request(), testOrigin))
				mutate(c)
				s := stored
				if name == "other key" {
					_, s = enroll(t, webauthntest.Options{Alg: alg})
				}
				_, err := webauthn.VerifyAssertion(c, expect(), s)
				wantReason(t, err, "signature")
			}
		}
	})
	t.Run("client data and flags", func(t *testing.T) {
		other := append([]byte(nil), testChallenge...)
		other[31] ^= 1
		for _, tc := range []struct {
			name   string
			auth   webauthntest.Options
			origin string
			expect func(*webauthn.Expect)
			raw    func([]byte) []byte
			reason string
		}{
			{name: "wrong type", raw: func(b []byte) []byte { return bytes.Replace(b, []byte(`"public-key"`), []byte(`"public-key2"`), 1) }, reason: "type"},
			{name: "create type on assertion", auth: webauthntest.Options{ClientDataType: "webauthn.create"}, reason: "type"},
			{name: "wrong challenge", expect: func(e *webauthn.Expect) { e.Challenge = other }, reason: "challenge"},
			{name: "wrong origin", origin: "https://other.test", reason: "origin"},
			{name: "cross origin", auth: webauthntest.Options{CrossOrigin: true}, reason: "cross_origin"},
			{name: "top origin", auth: webauthntest.Options{TopOrigin: "https://parent.test"}, reason: "cross_origin"},
			{name: "wrong rp id hash", auth: webauthntest.Options{TamperRPIDHash: true}, reason: "rp_id"},
			{name: "user not present", auth: webauthntest.Options{NoUP: true}, reason: "user_present"},
			{name: "uv required and clear", expect: func(e *webauthn.Expect) { e.RequireUV = true }, reason: "user_verified"},
			{name: "uv required and set", auth: webauthntest.Options{UV: true}, expect: func(e *webauthn.Expect) { e.RequireUV = true }},
			{name: "backed up without eligibility", auth: webauthntest.Options{BS: true}, reason: "backup_state"},
			{name: "rfu flags ignored", auth: webauthntest.Options{RFUFlags: 0x22}},
			{name: "unparsed tail", auth: webauthntest.Options{AuthDataTail: []byte{1}}, reason: "parse"},
			{name: "authenticator data too large", auth: webauthntest.Options{AuthDataTail: bytes.Repeat([]byte{0}, webauthn.AttestationMax)}, reason: "too_large"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				o := tc.auth
				o.BS = false // registration must succeed; flags apply to the assertion only
				o.AuthDataTail, o.ClientDataType, o.CrossOrigin, o.TopOrigin, o.TamperRPIDHash, o.NoUP, o.RFUFlags = nil, "", false, "", false, false, 0
				auth, stored := enroll(t, o)
				auth.Options = tc.auth
				origin := testOrigin
				if tc.origin != "" {
					origin = tc.origin
				}
				raw := auth.Get(request(), origin)
				if tc.raw != nil {
					raw = tc.raw(raw)
				}
				e := expect()
				if tc.expect != nil {
					tc.expect(&e)
				}
				c, err := webauthn.ParseCredentialJSON(raw)
				if err != nil {
					wantReason(t, err, tc.reason)
					return
				}
				_, err = webauthn.VerifyAssertion(c, e, stored)
				wantReason(t, err, tc.reason)
			})
		}
	})
	t.Run("user handle", func(t *testing.T) {
		different := bytes.Repeat([]byte{8}, 32)
		for _, tc := range []struct {
			name    string
			require bool
			omit    bool
			stored  []byte
			reason  string
		}{
			{name: "required present equal", require: true, stored: testHandle},
			{name: "required omitted", require: true, omit: true, stored: testHandle, reason: "user_handle"},
			{name: "required different", require: true, stored: different, reason: "user_handle"},
			{name: "optional omitted", omit: true, stored: testHandle},
			{name: "optional equal", stored: testHandle},
			{name: "optional different", stored: different, reason: "user_handle"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				auth, stored := enroll(t, webauthntest.Options{})
				auth.OmitUserHandle = tc.omit
				stored.UserHandle = tc.stored
				e := expect()
				e.RequireUserHandle = tc.require
				a, err := webauthn.VerifyAssertion(parse(t, auth.Get(request(), testOrigin)), e, stored)
				wantReason(t, err, tc.reason)
				if err == nil && tc.omit && a.UserHandle != nil {
					t.Fatal("handle reported although omitted")
				}
			})
		}
	})
	t.Run("sign count", func(t *testing.T) {
		for _, tc := range []struct {
			stored, got uint32
			ok          bool
			reason      string
		}{
			{stored: 0, got: 0, ok: true}, {stored: 0, got: 5, ok: true},
			{stored: 5, got: 5, reason: "sign_count"}, {stored: 5, got: 4, reason: "sign_count"},
			{stored: 5, got: 0, reason: "sign_count"}, {stored: 5, got: 6, ok: true},
		} {
			auth, stored := enroll(t, webauthntest.Options{})
			stored.SignCount = tc.stored
			auth.SignCount = tc.got
			a, err := webauthn.VerifyAssertion(parse(t, auth.Get(request(), testOrigin)), expect(), stored)
			if tc.ok != (err == nil) {
				t.Fatalf("stored %d got %d: ok=%v err=%v", tc.stored, tc.got, tc.ok, err)
			}
			if !tc.ok {
				wantReason(t, err, tc.reason)
				continue
			}
			if a.SignCount != tc.got {
				t.Fatalf("count %d want %d", a.SignCount, tc.got)
			}
		}
	})
	t.Run("backup flags", func(t *testing.T) {
		auth, stored := enroll(t, webauthntest.Options{BE: true})
		if !stored.BE {
			t.Fatal("registration lost BE")
		}
		auth.BS = true
		a, err := webauthn.VerifyAssertion(parse(t, auth.Get(request(), testOrigin)), expect(), stored)
		if err != nil || !a.BE || !a.BS {
			t.Fatalf("BS change not accepted: %v %+v", err, a)
		}
		auth.BE, auth.BS = false, false
		_, err = webauthn.VerifyAssertion(parse(t, auth.Get(request(), testOrigin)), expect(), stored)
		wantReason(t, err, "backup_eligibility")
		auth, stored = enroll(t, webauthntest.Options{})
		auth.BE = true
		_, err = webauthn.VerifyAssertion(parse(t, auth.Get(request(), testOrigin)), expect(), stored)
		wantReason(t, err, "backup_eligibility")
	})
	t.Run("stored key unusable", func(t *testing.T) {
		auth, stored := enroll(t, webauthntest.Options{})
		stored.PublicKeyCOSE = []byte{0xa0}
		_, err := webauthn.VerifyAssertion(parse(t, auth.Get(request(), testOrigin)), expect(), stored)
		wantReason(t, err, "key")
	})
	t.Run("attachment reported", func(t *testing.T) {
		auth, stored := enroll(t, webauthntest.Options{Attachment: "cross-platform"})
		a, err := webauthn.VerifyAssertion(parse(t, auth.Get(request(), testOrigin)), expect(), stored)
		if err != nil || a.Attachment != "cross-platform" {
			t.Fatalf("%v %+v", err, a)
		}
	})
	t.Run("registration response refused", func(t *testing.T) {
		auth, stored := enroll(t, webauthntest.Options{})
		_, err := webauthn.VerifyAssertion(parse(t, auth.Create(creation(), testOrigin)), expect(), stored)
		wantReason(t, err, "parse")
		_, err = webauthn.VerifyRegistration(parse(t, auth.Get(request(), testOrigin)), expect())
		wantReason(t, err, "parse")
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
