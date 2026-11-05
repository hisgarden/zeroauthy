package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
)

// Expect carries what the relying party expects of a ceremony.
type Expect struct {
	Challenge []byte
	RPID      string
	Origins   []string // exact serialized origins
	RequireUV bool
	Algs      []int64 // registration only; nil means RegistrationAlgs
	// RequireUserHandle makes an assertion without a user handle, or with
	// one that differs from the stored handle, fail (discoverable logins).
	// Without it a present handle must still match (MFA with an allow list).
	RequireUserHandle bool
}

// Registration is an accepted registration (§4.3).
type Registration struct {
	CredentialID  []byte
	PublicKeyCOSE []byte
	Alg           int64
	AAGUID        [16]byte
	SignCount     uint32
	UV, BE, BS    bool
	Format        string // always "none" (LR33b-9)
	Transports    []string
	Attachment    string
}

// Assertion is an accepted assertion (§4.4).
type Assertion struct {
	CredentialID []byte
	UserHandle   []byte
	SignCount    uint32
	UV, BE, BS   bool
	Attachment   string
}

// Stored is what the store keeps about a credential for assertions.
type Stored struct {
	PublicKeyCOSE []byte
	SignCount     uint32
	BE            bool
	UserHandle    []byte
}

// Attestation formats accepted without verifying the statement (LR33b-9).
var attestationFormats = map[string]bool{"none": true, "packed": true, "tpm": true, "android-key": true, "android-safetynet": true, "fido-u2f": true, "apple": true}

// VerifyRegistration applies the §4.3 checks to a registration response and
// returns what the store needs. Credential ID uniqueness is the store's job.
func VerifyRegistration(c *Credential, e Expect) (*Registration, error) {
	if c == nil || c.Type != "public-key" {
		return nil, fail(ReasonType, "credential type")
	}
	if len(c.AttestationObject) == 0 {
		return nil, fail(ReasonParse, "not a registration response")
	}
	if err := checkClientData(c.ClientDataJSON, "webauthn.create", e); err != nil {
		return nil, err
	}
	if len(c.AttestationObject) > AttestationMax {
		return nil, fail(ReasonTooLarge, "attestation object too large")
	}
	v, err := DecodeCBOR(c.AttestationObject, CBORDepth, CBORItems)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[any]any)
	if !ok || len(obj) != 3 {
		return nil, fail(ReasonAttestation, "attestation object shape")
	}
	format, okF := obj["fmt"].(string)
	stmt, okS := obj["attStmt"].(map[any]any)
	raw, okA := obj["authData"].([]byte)
	if !okF || !okS || !okA {
		return nil, fail(ReasonAttestation, "attestation object members")
	}
	ad, err := parseAuthData(raw)
	if err != nil {
		return nil, err
	}
	if err := checkAuthData(ad, e); err != nil {
		return nil, err
	}
	if ad.Attested == nil {
		return nil, fail(ReasonParse, "attested credential data missing")
	}
	if !bytes.Equal(ad.Attested.ID, c.RawID) {
		return nil, fail(ReasonParse, "credential id does not match attested data")
	}
	key, err := ParseCOSEKey(ad.Attested.COSE)
	if err != nil {
		return nil, err
	}
	algs := e.Algs
	if algs == nil {
		algs = RegistrationAlgs
	}
	if !containsAlg(algs, key.Alg) {
		return nil, fail(ReasonAlg, "algorithm not offered")
	}
	if !attestationFormats[format] {
		return nil, fail(ReasonAttestation, "attestation format not accepted")
	}
	if format == "none" && len(stmt) != 0 {
		return nil, fail(ReasonAttestation, "attestation statement not empty")
	}
	return &Registration{
		CredentialID:  ad.Attested.ID,
		PublicKeyCOSE: ad.Attested.COSE,
		Alg:           key.Alg,
		AAGUID:        ad.Attested.AAGUID,
		SignCount:     ad.SignCount,
		UV:            ad.uv(),
		BE:            ad.be(),
		BS:            ad.bs(),
		Format:        "none",
		Transports:    c.Transports,
		Attachment:    c.Attachment,
	}, nil
}

// VerifyAssertion applies the §4.4 checks to an assertion response against
// the stored credential and returns the values the store writes back.
func VerifyAssertion(c *Credential, e Expect, s Stored) (*Assertion, error) {
	if c == nil || c.Type != "public-key" {
		return nil, fail(ReasonType, "credential type")
	}
	if len(c.AuthenticatorData) == 0 || len(c.Signature) == 0 {
		return nil, fail(ReasonParse, "not an assertion response")
	}
	if err := checkClientData(c.ClientDataJSON, "webauthn.get", e); err != nil {
		return nil, err
	}
	ad, err := parseAuthData(c.AuthenticatorData)
	if err != nil {
		return nil, err
	}
	if err := checkAuthData(ad, e); err != nil {
		return nil, err
	}
	key, err := ParseCOSEKey(s.PublicKeyCOSE)
	if err != nil {
		return nil, err
	}
	if len(c.Signature) > signatureMax {
		return nil, fail(ReasonTooLarge, "signature too large")
	}
	hash := sha256.Sum256(c.ClientDataJSON)
	signed := make([]byte, 0, len(c.AuthenticatorData)+len(hash))
	signed = append(signed, c.AuthenticatorData...)
	signed = append(signed, hash[:]...)
	if !verifySignature(key, signed, c.Signature) {
		return nil, fail(ReasonSignature, "signature does not verify")
	}
	if c.UserHandle == nil {
		if e.RequireUserHandle {
			return nil, fail(ReasonUserHandle, "user handle missing")
		}
	} else if len(s.UserHandle) == 0 || subtle.ConstantTimeCompare(c.UserHandle, s.UserHandle) != 1 {
		return nil, fail(ReasonUserHandle, "user handle differs")
	}
	if (s.SignCount != 0 || ad.SignCount != 0) && ad.SignCount <= s.SignCount {
		return nil, fail(ReasonSignCount, "sign count did not increase")
	}
	if ad.be() != s.BE {
		return nil, fail(ReasonBackupEligibility, "backup eligibility changed")
	}
	return &Assertion{
		CredentialID: c.RawID,
		UserHandle:   c.UserHandle,
		SignCount:    ad.SignCount,
		UV:           ad.uv(),
		BE:           ad.be(),
		BS:           ad.bs(),
		Attachment:   c.Attachment,
	}, nil
}

// checkAuthData applies the flag and RP ID checks shared by both ceremonies.
func checkAuthData(ad *authData, e Expect) error {
	want := sha256.Sum256([]byte(e.RPID))
	if e.RPID == "" || subtle.ConstantTimeCompare(ad.RPIDHash[:], want[:]) != 1 {
		return fail(ReasonRPID, "rp id hash")
	}
	if !ad.up() {
		return fail(ReasonUserPresent, "user not present")
	}
	if e.RequireUV && !ad.uv() {
		return fail(ReasonUserVerified, "user not verified")
	}
	if ad.bs() && !ad.be() {
		return fail(ReasonBackupState, "backed up without backup eligibility")
	}
	return nil
}

func containsAlg(algs []int64, alg int64) bool {
	for _, a := range algs {
		if a == alg {
			return true
		}
	}
	return false
}

// verifySignature checks sig over msg per the key's COSE algorithm: ECDSA
// as ASN.1 DER with the curve's hash, Ed25519 raw, RSA PKCS#1 v1.5 or PSS
// with SHA-256.
func verifySignature(pk PublicKey, msg, sig []byte) bool {
	switch key := pk.Key.(type) {
	case ed25519.PublicKey:
		return pk.Alg == AlgEdDSA && len(sig) == ed25519.SignatureSize && ed25519.Verify(key, msg, sig)
	case *ecdsa.PublicKey:
		var digest []byte
		switch pk.Alg {
		case AlgES256:
			h := sha256.Sum256(msg)
			digest = h[:]
		case AlgES384:
			h := sha512.Sum384(msg)
			digest = h[:]
		case AlgES512:
			h := sha512.Sum512(msg)
			digest = h[:]
		default:
			return false
		}
		return ecdsa.VerifyASN1(key, digest, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		switch pk.Alg {
		case AlgRS256:
			return rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) == nil
		case AlgPS256:
			return rsa.VerifyPSS(key, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
	}
	return false
}
