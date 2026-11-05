package webauthn

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// clientData is the subset of CollectedClientData this package checks.
// tokenBinding and unknown members are ignored. topOrigin is kept raw so
// its presence alone can be refused.
type clientData struct {
	Type        string          `json:"type"`
	Challenge   string          `json:"challenge"`
	Origin      string          `json:"origin"`
	CrossOrigin *bool           `json:"crossOrigin"`
	TopOrigin   json.RawMessage `json:"topOrigin"`
}

// decodeBase64URL decodes base64url, tolerating trailing padding.
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// checkClientData parses clientDataJSON and applies §4.3 step 1 / §4.4: the
// ceremony type, the challenge (constant time), an exact origin match,
// crossOrigin absent or false and topOrigin absent.
func checkClientData(raw []byte, wantType string, e Expect) error {
	if len(raw) > ClientDataMax {
		return fail(ReasonTooLarge, "client data too large")
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return fail(ReasonParse, "client data is not utf-8 json")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var cd clientData
	if err := dec.Decode(&cd); err != nil {
		return fail(ReasonParse, "client data is not json")
	}
	if dec.More() {
		return fail(ReasonParse, "client data has trailing content")
	}
	if cd.Type != wantType {
		return fail(ReasonType, "client data type")
	}
	challenge, err := decodeBase64URL(cd.Challenge)
	if err != nil || len(challenge) == 0 || len(e.Challenge) == 0 {
		return fail(ReasonChallenge, "client data challenge")
	}
	if subtle.ConstantTimeCompare(challenge, e.Challenge) != 1 {
		return fail(ReasonChallenge, "client data challenge")
	}
	if cd.Origin == "" || !originAllowed(cd.Origin, e.Origins) {
		return fail(ReasonOrigin, "client data origin")
	}
	if cd.CrossOrigin != nil && *cd.CrossOrigin {
		return fail(ReasonCrossOrigin, "cross-origin ceremony")
	}
	if len(cd.TopOrigin) != 0 {
		return fail(ReasonCrossOrigin, "top origin present")
	}
	return nil
}

// originAllowed compares serialized origins as exact strings; no
// normalization, no fallback.
func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a != "" && a == origin {
			return true
		}
	}
	return false
}
