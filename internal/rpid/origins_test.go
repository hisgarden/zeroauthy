package rpid_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func fingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}

func TestNativeOrigins(t *testing.T) {
	r := rpid.Result{RPID: "example.com", Origin: "https://login.example.com", Kind: rpid.KindCustom, Valid: true}
	keyA := sha256.Sum256([]byte("signing certificate A"))
	keyB := sha256.Sum256([]byte("signing certificate B"))
	c := &store.Client{
		WebOrigins: []string{
			"https://app.example.com",
			"https://APP2.Example.com:8443/",
			"https://example.com",
			"https://login.example.com", // the request origin, listed once
			"https://evil.test",         // not under the RP ID
			"https://notexample.com",    // a suffix match that is not a subdomain
			"http://plain.example.com",  // not https
			"https://*.example.com",     // wildcards never become exact origins
			"https://app.example.com/path",
			"https://user@app.example.com",
			"https://app.example.com:443",
		},
		Mobile: &store.ClientMobile{
			IOS: &store.ClientMobileIOS{TeamID: "ABCDE12345", AppBundleIdentifier: "com.example.app"},
			Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{
				fingerprint(keyA[:]),
				strings.ToLower(fingerprint(keyB[:])),
				"AB:CD",                      // not 32 bytes
				"zz" + fingerprint(keyA[2:]), // not hex
			}},
		},
	}
	got := rpid.NativeOrigins(r, c)
	want := []string{
		"https://login.example.com",
		"https://app.example.com",
		"https://app2.example.com:8443",
		"https://example.com",
		"android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(keyA[:]),
		"android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(keyB[:]),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("NativeOrigins =\n%q\nwant\n%q", got, want)
	}
	if got := rpid.NativeOrigins(r, nil); !slices.Equal(got, []string{"https://login.example.com"}) {
		t.Fatalf("no client = %q", got)
	}
	if got := rpid.NativeOrigins(r, &store.Client{}); !slices.Equal(got, []string{"https://login.example.com"}) {
		t.Fatalf("empty client = %q", got)
	}
	r.Valid = false
	if got := rpid.NativeOrigins(r, c); len(got) != 0 {
		t.Fatalf("invalid result = %q, want none", got)
	}
	// The RP ID itself is the request host: iOS apps report https://<rp id>.
	host := rpid.Result{RPID: "login.example.com", Origin: "https://login.example.com", Kind: rpid.KindCustom, Valid: true}
	if got := rpid.NativeOrigins(host, &store.Client{WebOrigins: []string{"https://app.example.com"}}); !slices.Equal(got, []string{"https://login.example.com"}) {
		t.Fatalf("origin outside a host RP ID = %q", got)
	}
}
