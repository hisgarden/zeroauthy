package webauthn

import (
	"bytes"
	"encoding/json"
)

// Bounds on members that have no WebAuthn limit of their own.
const (
	userHandleMax    = 64   // user.id is at most 64 bytes
	signatureMax     = 2048 // an 8192-bit RSA signature is 1024 bytes
	transportsMax    = 16
	transportNameMax = 32
	credentialMax    = 2 * AttestationMax // the whole JSON document
)

// Credential is a parsed PublicKeyCredential JSON document, as the page
// script and the native endpoints send it. ID and RawID are the decoded
// credential ID (equal by construction). AttestationObject is set for a
// registration; AuthenticatorData and Signature for an assertion. Members a
// Level 2 browser omits (Attachment, Transports, UserHandle) are empty.
type Credential struct {
	ID, RawID         []byte
	Type, Attachment  string
	ClientDataJSON    []byte
	AttestationObject []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
	Transports        []string
}

type credentialJSON struct {
	ID         *string         `json:"id"`
	RawID      *string         `json:"rawId"`
	Type       *string         `json:"type"`
	Attachment json.RawMessage `json:"authenticatorAttachment"`
	Response   *struct {
		ClientDataJSON    *string         `json:"clientDataJSON"`
		AttestationObject *string         `json:"attestationObject"`
		AuthenticatorData *string         `json:"authenticatorData"`
		Signature         *string         `json:"signature"`
		UserHandle        json.RawMessage `json:"userHandle"`
		Transports        json.RawMessage `json:"transports"`
	} `json:"response"`
}

// ParseCredentialJSON parses the documented authn_response shape: id,
// rawId, type "public-key", optional authenticatorAttachment,
// response.{clientDataJSON, attestationObject | authenticatorData +
// signature, userHandle, transports} and clientExtensionResults (ignored).
// Binary members are base64url; padding is tolerated. id must equal rawId.
// Reasons: parse, type, too_large.
func ParseCredentialJSON(raw []byte) (*Credential, error) {
	if len(raw) > credentialMax {
		return nil, fail(ReasonTooLarge, "credential json too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var doc credentialJSON
	if err := dec.Decode(&doc); err != nil {
		return nil, fail(ReasonParse, "credential is not json")
	}
	if dec.More() {
		return nil, fail(ReasonParse, "credential json has trailing content")
	}
	if doc.Type == nil || *doc.Type != "public-key" {
		return nil, fail(ReasonType, "credential type")
	}
	if doc.ID == nil || doc.RawID == nil || doc.Response == nil || doc.Response.ClientDataJSON == nil {
		return nil, fail(ReasonParse, "credential member missing")
	}
	c := &Credential{Type: "public-key"}
	var err error
	if c.RawID, err = decodeBase64URL(*doc.RawID); err != nil {
		return nil, fail(ReasonParse, "rawId encoding")
	}
	if len(c.RawID) > CredentialIDMax {
		return nil, fail(ReasonTooLarge, "credential id too long")
	}
	if c.ID, err = decodeBase64URL(*doc.ID); err != nil || len(c.ID) == 0 || !bytes.Equal(c.ID, c.RawID) {
		return nil, fail(ReasonParse, "id does not match rawId")
	}
	if len(doc.Attachment) != 0 {
		var s string
		if json.Unmarshal(doc.Attachment, &s) != nil || (s != "platform" && s != "cross-platform") {
			return nil, fail(ReasonParse, "authenticator attachment")
		}
		c.Attachment = s
	}
	r := doc.Response
	if c.ClientDataJSON, err = decodeBase64URL(*r.ClientDataJSON); err != nil {
		return nil, fail(ReasonParse, "clientDataJSON encoding")
	}
	if len(c.ClientDataJSON) > ClientDataMax {
		return nil, fail(ReasonTooLarge, "client data too large")
	}
	if len(c.ClientDataJSON) == 0 {
		return nil, fail(ReasonParse, "client data empty")
	}
	// A registration carries attestationObject; Level 3 serializers may add
	// authenticatorData (and publicKey) beside it, which is ignored. An
	// assertion carries authenticatorData and signature.
	switch {
	case r.AttestationObject != nil && r.Signature == nil:
		if c.AttestationObject, err = decodeBase64URL(*r.AttestationObject); err != nil || len(c.AttestationObject) == 0 {
			return nil, fail(ReasonParse, "attestationObject encoding")
		}
		if len(c.AttestationObject) > AttestationMax {
			return nil, fail(ReasonTooLarge, "attestation object too large")
		}
	case r.AttestationObject == nil && r.AuthenticatorData != nil && r.Signature != nil:
		if c.AuthenticatorData, err = decodeBase64URL(*r.AuthenticatorData); err != nil || len(c.AuthenticatorData) == 0 {
			return nil, fail(ReasonParse, "authenticatorData encoding")
		}
		if len(c.AuthenticatorData) > AttestationMax {
			return nil, fail(ReasonTooLarge, "authenticator data too large")
		}
		if c.Signature, err = decodeBase64URL(*r.Signature); err != nil || len(c.Signature) == 0 {
			return nil, fail(ReasonParse, "signature encoding")
		}
		if len(c.Signature) > signatureMax {
			return nil, fail(ReasonTooLarge, "signature too large")
		}
	default:
		return nil, fail(ReasonParse, "response is neither an attestation nor an assertion")
	}
	if len(r.UserHandle) != 0 && !bytes.Equal(r.UserHandle, []byte("null")) {
		var s string
		if json.Unmarshal(r.UserHandle, &s) != nil {
			return nil, fail(ReasonParse, "userHandle")
		}
		if c.UserHandle, err = decodeBase64URL(s); err != nil {
			return nil, fail(ReasonParse, "userHandle encoding")
		}
		if len(c.UserHandle) > userHandleMax {
			return nil, fail(ReasonTooLarge, "user handle too long")
		}
		if len(c.UserHandle) == 0 {
			c.UserHandle = nil
		}
	}
	if len(r.Transports) != 0 && !bytes.Equal(r.Transports, []byte("null")) {
		var list []string
		if json.Unmarshal(r.Transports, &list) != nil || len(list) > transportsMax {
			return nil, fail(ReasonParse, "transports")
		}
		for _, name := range list {
			if name == "" || len(name) > transportNameMax {
				return nil, fail(ReasonParse, "transport name")
			}
		}
		if len(list) > 0 {
			c.Transports = list
		}
	}
	return c, nil
}
