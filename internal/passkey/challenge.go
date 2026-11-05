package passkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Purpose is what a challenge is for. It is stored as the MFAChallenge
// kind, so the four values are the store's WebAuthn challenge kinds.
type Purpose string

const (
	PurposePasskeyRegister  Purpose = "passkey-register"  // passkey signup or enrollment
	PurposePasskeyLogin     Purpose = "passkey-login"     // passkey first-factor login
	PurposeWebAuthnRegister Purpose = "webauthn-register" // WebAuthn MFA enrollment
	PurposeWebAuthnAssert   Purpose = "webauthn-assert"   // WebAuthn MFA challenge
)

func (p Purpose) valid() bool {
	switch p {
	case PurposePasskeyRegister, PurposePasskeyLogin, PurposeWebAuthnRegister, PurposeWebAuthnAssert:
		return true
	}
	return false
}

// Binding is everything a challenge is bound to (spec section 4.5). A hosted
// challenge names the transaction (TxnID) and the hash of its browser
// cookie (CookieHash); a native one names the client, realm and
// organization instead and is addressed by an auth_session. UserID is set
// for enrollment and MFA and empty for a usernameless login or a signup.
// Take accepts a challenge only for an identical Binding.
type Binding struct {
	Purpose                       Purpose
	RPID                          string
	Origins                       []string // exact serialized origins
	TxnID, CookieHash             string   // hosted
	ClientID, Realm, Organization string   // native
	UserID                        string   // enrollment and MFA
}

// bindingJSON is the stored form of Binding (MFAChallenge.Binding).
type bindingJSON struct {
	Purpose      Purpose  `json:"purpose"`
	RPID         string   `json:"rp_id"`
	Origins      []string `json:"origins"`
	TxnID        string   `json:"txn_id,omitempty"`
	CookieHash   string   `json:"cookie_hash,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	Realm        string   `json:"realm,omitempty"`
	Organization string   `json:"organization,omitempty"`
	UserID       string   `json:"user_id,omitempty"`
}

func (b Binding) stored() bindingJSON {
	return bindingJSON{Purpose: b.Purpose, RPID: b.RPID, Origins: b.Origins, TxnID: b.TxnID, CookieHash: b.CookieHash, ClientID: b.ClientID, Realm: b.Realm, Organization: b.Organization, UserID: b.UserID}
}

func (b bindingJSON) equal(o bindingJSON) bool {
	return b.Purpose == o.Purpose && b.RPID == o.RPID && slices.Equal(b.Origins, o.Origins) && b.TxnID == o.TxnID && b.CookieHash == o.CookieHash &&
		b.ClientID == o.ClientID && b.Realm == o.Realm && b.Organization == o.Organization && b.UserID == o.UserID
}

// native reports whether b is a native (Passkey API) binding: no hosted
// transaction, a client.
func (b Binding) native() bool { return b.TxnID == "" && b.ClientID != "" }

func (b Binding) check() error {
	switch {
	case !b.Purpose.valid(), b.RPID == "", len(b.Origins) == 0:
		return errInvalidBinding
	case b.TxnID == "" && b.ClientID == "":
		return errInvalidBinding // neither hosted nor native
	case b.UserID == "" && !store.ChallengeUserOptional(string(b.Purpose)):
		return errInvalidBinding // WebAuthn MFA always has a user
	}
	return nil
}

var errInvalidBinding = fmt.Errorf("passkey: invalid challenge binding: %w", store.ErrInvalid)

// Issued is a stored challenge. ID addresses it: the challenge_id a hosted
// page posts back, or for a native challenge secrets.HashToken(Session),
// where Session is the auth_session given to the client once and never
// stored. Challenge is the raw value the client signs.
type Issued struct {
	ID, Session string
	Challenge   []byte
	ExpiresAt   time.Time
}

// SessionID is the challenge ID of a native auth_session.
func SessionID(session string) string { return secrets.HashToken(session) }

// randomBytes returns n bytes of crypto/rand output.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Issue stores a fresh challenge bound to b, live for ttl. A ttl of zero or
// less takes the frozen default: webauthnrules.Limits.HostedChallengeTTL
// for a hosted binding, NativeTimeout plus NativeGrace for a native one.
// A malformed binding is store.ErrInvalid.
func (s *Service) Issue(ctx context.Context, tid string, b Binding, ttl time.Duration) (*Issued, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = webauthnrules.Limits.HostedChallengeTTL
		if b.native() {
			ttl = webauthnrules.Limits.NativeTimeout + webauthnrules.Limits.NativeGrace
		}
	}
	challenge, err := randomBytes(webauthnrules.Limits.ChallengeBytes)
	if err != nil {
		return nil, err
	}
	// The challenge ID and the auth_session are as long as a challenge.
	handle, err := randomBytes(webauthnrules.Limits.ChallengeBytes)
	if err != nil {
		return nil, err
	}
	out := &Issued{Challenge: challenge, ExpiresAt: s.now().Add(ttl)}
	if b.native() {
		out.Session = base64.RawURLEncoding.EncodeToString(handle)
		out.ID = SessionID(out.Session)
	} else {
		out.ID = base64.RawURLEncoding.EncodeToString(handle)
	}
	raw, err := json.Marshal(b.stored())
	if err != nil {
		return nil, err
	}
	err = s.st.MFA().CreateChallenge(ctx, &store.MFAChallenge{
		TenantID: tid, ID: out.ID, UserID: b.UserID, Kind: string(b.Purpose),
		Challenge: challenge, Binding: raw, ExpiresAt: out.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Take consumes the challenge id and returns its raw value when it is
// unexpired and bound exactly to want. The challenge is consumed first, by
// the store's conditional single-use delete, so a mismatched binding, a
// concurrent second Take or a later failed verification leaves nothing
// reusable; of concurrent Takes exactly one wins. A missing, expired,
// consumed or mismatched challenge is ErrCeremony (reason challenge);
// other errors are storage failures.
func (s *Service) Take(ctx context.Context, tid, id string, want Binding) ([]byte, error) {
	now := s.now()
	c, err := s.st.MFA().GetChallenge(ctx, tid, id, now)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ceremony(webauthn.ReasonChallenge, "challenge not found")
	}
	if err != nil {
		return nil, err
	}
	err = s.st.MFA().ConsumeChallenge(ctx, tid, id, now)
	if errors.Is(err, store.ErrPrecondition) || errors.Is(err, store.ErrNotFound) {
		return nil, ceremony(webauthn.ReasonChallenge, "challenge already used")
	}
	if err != nil {
		return nil, err
	}
	var got bindingJSON
	if json.Unmarshal(c.Binding, &got) != nil || c.Kind != string(want.Purpose) || c.UserID != want.UserID || !got.equal(want.stored()) {
		return nil, ceremony(webauthn.ReasonChallenge, "challenge binding differs")
	}
	return c.Challenge, nil
}
