package rpid

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// apkKeyHashPrefix starts the origin Android reports for a native app.
const apkKeyHashPrefix = "android:apk-key-hash:"

// NativeOrigins lists the exact clientDataJSON origins a native or embedded
// ceremony for client c accepts on r's host (LR33b-26), in this order and
// without duplicates: r.Origin (the request host); each https entry of
// c.WebOrigins whose host is r.RPID or a subdomain of it, as a serialized
// origin; and android:apk-key-hash:<base64url SHA-256> for each of
// c.Mobile.Android.SHA256CertFingerprints (32 bytes, hex pairs joined by
// colons). Wildcards, paths, credentials, other schemes and malformed
// fingerprints are skipped. An invalid r accepts nothing.
func NativeOrigins(r Result, c *store.Client) []string {
	if !r.Valid || r.RPID == "" || r.Origin == "" {
		return nil
	}
	out := []string{r.Origin}
	add := func(o string) {
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	if c == nil {
		return out
	}
	for _, raw := range c.WebOrigins {
		if o, ok := webOrigin(raw, r.RPID); ok {
			add(o)
		}
	}
	if c.Mobile != nil && c.Mobile.Android != nil {
		for _, fp := range c.Mobile.Android.SHA256CertFingerprints {
			if h, ok := apkKeyHash(fp); ok {
				add(apkKeyHashPrefix + h)
			}
		}
	}
	return out
}

// webOrigin serializes a web_origins entry as a browser would send it, when
// it is a plain https origin under rpID.
func webOrigin(raw, rpID string) (string, bool) {
	if strings.Contains(raw, "*") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", false
	}
	host := tenant.NormalizeHost(u.Host)
	name := bareName(host)
	if name == "" || net.ParseIP(name) != nil || name != rpID && !strings.HasSuffix(name, "."+rpID) {
		return "", false
	}
	return "https://" + host, true
}

// apkKeyHash converts an AB:CD:… SHA-256 certificate fingerprint to the
// unpadded base64url form Android puts in the origin.
func apkKeyHash(fp string) (string, bool) {
	parts := strings.Split(fp, ":")
	if len(parts) != 32 {
		return "", false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return "", false
		}
	}
	b, err := hex.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(b), true
}
