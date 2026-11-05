package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Descriptor is a PublicKeyCredentialDescriptor (type "public-key").
type Descriptor struct {
	ID         []byte
	Transports []string
}

// CreationOptions renders as PublicKeyCredentialCreationOptionsJSON (§4.5).
type CreationOptions struct {
	Challenge        []byte
	RPID, RPName     string // RPName defaults to RPID
	UserID           []byte // 1–64 bytes, the user handle
	UserName         string
	DisplayName      string
	Algs             []int64 // default RegistrationAlgs: -8, -7, -257
	Attachment       string  // "", "platform", "cross-platform"
	ResidentKey      string  // "", "discouraged", "preferred", "required"
	UserVerification string  // "", "discouraged", "preferred", "required"; "" renders "preferred"
	Exclude          []Descriptor
	Timeout          time.Duration
}

// RequestOptions renders as PublicKeyCredentialRequestOptionsJSON.
type RequestOptions struct {
	Challenge        []byte
	RPID             string
	UserVerification string       // as in CreationOptions
	Allow            []Descriptor // empty means a discoverable credential
	Timeout          time.Duration
}

type descriptorJSON struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type creationJSON struct {
	RP struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Challenge string `json:"challenge"`
	Params    []struct {
		Type string `json:"type"`
		Alg  int64  `json:"alg"`
	} `json:"pubKeyCredParams"`
	Timeout   int64            `json:"timeout,omitempty"`
	Exclude   []descriptorJSON `json:"excludeCredentials"`
	Selection struct {
		Attachment         string `json:"authenticatorAttachment,omitempty"`
		ResidentKey        string `json:"residentKey,omitempty"`
		RequireResidentKey bool   `json:"requireResidentKey,omitempty"`
		UserVerification   string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Attestation string `json:"attestation"`
}

type requestJSON struct {
	Challenge        string           `json:"challenge"`
	Timeout          int64            `json:"timeout,omitempty"`
	RPID             string           `json:"rpId"`
	Allow            []descriptorJSON `json:"allowCredentials"`
	UserVerification string           `json:"userVerification"`
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func validUV(s string) bool {
	return s == "" || s == "discouraged" || s == "preferred" || s == "required"
}

func descriptorsJSON(list []Descriptor) ([]descriptorJSON, error) {
	out := make([]descriptorJSON, 0, len(list))
	for _, d := range list {
		if len(d.ID) == 0 || len(d.ID) > CredentialIDMax {
			return nil, errors.New("webauthn: descriptor id length")
		}
		out = append(out, descriptorJSON{Type: "public-key", ID: b64url(d.ID), Transports: d.Transports})
	}
	return out, nil
}

func timeoutMillis(d time.Duration) (int64, error) {
	if d < 0 {
		return 0, errors.New("webauthn: negative timeout")
	}
	return d.Milliseconds(), nil
}

// JSON renders the options with attestation "none", rp.name defaulting to
// rp.id, pubKeyCredParams in the documented order and the timeout in
// milliseconds. It refuses options a browser would reject.
func (o CreationOptions) JSON() ([]byte, error) {
	if len(o.Challenge) == 0 || o.RPID == "" || len(o.UserID) == 0 || len(o.UserID) > userHandleMax || o.UserName == "" {
		return nil, errors.New("webauthn: creation options incomplete")
	}
	if o.Attachment != "" && o.Attachment != "platform" && o.Attachment != "cross-platform" {
		return nil, errors.New("webauthn: authenticator attachment")
	}
	if !validUV(o.ResidentKey) || !validUV(o.UserVerification) {
		return nil, errors.New("webauthn: resident key or user verification value")
	}
	var out creationJSON
	out.RP.ID, out.RP.Name = o.RPID, o.RPName
	if out.RP.Name == "" {
		out.RP.Name = o.RPID
	}
	out.User.ID, out.User.Name, out.User.DisplayName = b64url(o.UserID), o.UserName, o.DisplayName
	if out.User.DisplayName == "" {
		out.User.DisplayName = o.UserName
	}
	out.Challenge = b64url(o.Challenge)
	algs := o.Algs
	if algs == nil {
		algs = RegistrationAlgs
	}
	for _, alg := range algs {
		switch alg {
		case AlgEdDSA, AlgES256, AlgES384, AlgES512, AlgRS256, AlgPS256:
		default:
			return nil, errors.New("webauthn: algorithm not supported")
		}
		out.Params = append(out.Params, struct {
			Type string `json:"type"`
			Alg  int64  `json:"alg"`
		}{"public-key", alg})
	}
	var err error
	if out.Timeout, err = timeoutMillis(o.Timeout); err != nil {
		return nil, err
	}
	if out.Exclude, err = descriptorsJSON(o.Exclude); err != nil {
		return nil, err
	}
	out.Selection.Attachment = o.Attachment
	out.Selection.ResidentKey = o.ResidentKey
	out.Selection.RequireResidentKey = o.ResidentKey == "required"
	out.Selection.UserVerification = o.UserVerification
	if out.Selection.UserVerification == "" {
		out.Selection.UserVerification = "preferred"
	}
	out.Attestation = "none"
	return json.Marshal(out)
}

// JSON renders the request options with the timeout in milliseconds and an
// allowCredentials array that is empty for discoverable logins.
func (o RequestOptions) JSON() ([]byte, error) {
	if len(o.Challenge) == 0 || o.RPID == "" {
		return nil, errors.New("webauthn: request options incomplete")
	}
	if !validUV(o.UserVerification) {
		return nil, errors.New("webauthn: user verification value")
	}
	out := requestJSON{Challenge: b64url(o.Challenge), RPID: o.RPID, UserVerification: o.UserVerification}
	if out.UserVerification == "" {
		out.UserVerification = "preferred"
	}
	var err error
	if out.Timeout, err = timeoutMillis(o.Timeout); err != nil {
		return nil, err
	}
	if out.Allow, err = descriptorsJSON(o.Allow); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}
