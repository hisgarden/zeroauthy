// Package webauthn verifies WebAuthn registrations and assertions with the
// standard library only: a bounded CBOR subset, COSE public keys, client
// data, authenticator data, the Level 2/3 checks, option rendering and
// user-agent device classification. It holds no state and does no I/O;
// callers pass the expected values and receive typed results or an error
// carrying a bounded reason code.
package webauthn

import "errors"

// Parser bounds (§4.2, LR33b-34). Task 1 freezes the same values in
// webauthnrules.Limits; these constants may later alias them.
const (
	AttestationMax  = 64 << 10 // attestation object and authenticator data
	ClientDataMax   = 16 << 10 // clientDataJSON
	CredentialIDMax = 1023     // credential ID (Level 3)
	COSEMax         = 16 << 10 // one COSE_Key
	CBORDepth       = 16       // nesting of arrays and maps
	CBORItems       = 1024     // data items in one CBOR document
)

// Reason codes. They are bounded so logs and tests can name a failure
// without carrying any ceremony data.
const (
	ReasonParse             = "parse"
	ReasonType              = "type"
	ReasonChallenge         = "challenge"
	ReasonOrigin            = "origin"
	ReasonCrossOrigin       = "cross_origin"
	ReasonRPID              = "rp_id"
	ReasonUserPresent       = "user_present"
	ReasonUserVerified      = "user_verified"
	ReasonAlg               = "alg"
	ReasonKey               = "key"
	ReasonAttestation       = "attestation"
	ReasonSignature         = "signature"
	ReasonUserHandle        = "user_handle"
	ReasonSignCount         = "sign_count"
	ReasonBackupEligibility = "backup_eligibility"
	ReasonBackupState       = "backup_state"
	ReasonTooLarge          = "too_large"
)

// Error is a verification failure with a bounded reason code. The detail is
// a short fixed phrase, never input data.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "webauthn: " + e.Code
	}
	return "webauthn: " + e.Code + ": " + e.Detail
}

func fail(code, detail string) error { return &Error{Code: code, Detail: detail} }

// Reason returns the bounded reason code of err: "" for nil, the code of an
// error produced by this package, and "parse" for any other error so the
// set of values a caller can see stays closed.
func Reason(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return e.Code
	}
	return ReasonParse
}
