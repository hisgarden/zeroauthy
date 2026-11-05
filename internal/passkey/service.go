// Package passkey runs the WebAuthn ceremonies shared by the hosted pages,
// the native Passkey APIs and grant, and WebAuthn MFA (Plan 33b spec
// sections 3, 4.5 and 7): it issues and consumes bound challenges, renders
// creation and request options, and verifies passkey logins, enrollments
// and signups against the store. It never logs; nothing it returns carries
// client data, attestations, signatures, sessions or user handles except
// the values the caller must send to the client.
package passkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// ErrCeremony is every ceremony failure the client may only learn as the
// generic error: a missing, expired, used or mismatched challenge, an
// unknown or unusable credential, and every verification failure. It wraps
// a *webauthn.Error, so webauthn.Reason gives the bounded reason code for
// logs (ReasonCredential or a webauthn.Reason* code).
var ErrCeremony = errors.New("passkey: ceremony failed")

// ErrMaxPasskeys is an enrollment refused because the user already holds
// webauthnrules.Limits.MaxPasskeys passkeys; ErrorKey maps it to
// KeyMaxPasskeys.
var ErrMaxPasskeys = errors.New("passkey: passkey limit reached")

// KeyMaxPasskeys is the documented error key of ErrMaxPasskeys.
const KeyMaxPasskeys = "passkey-enrollment-max-allowed-reached"

// ReasonCredential is the reason of a credential the ceremony cannot use:
// unknown in the tenant, not a passkey, its user missing or not on the
// native realm, or (on registration) already stored in the tenant.
const ReasonCredential = "credential"

// ErrorKey returns the documented error key for err, or "" when err has no
// specific key (the caller then uses its generic failure key).
func ErrorKey(err error) string {
	if errors.Is(err, ErrMaxPasskeys) {
		return KeyMaxPasskeys
	}
	return ""
}

func ceremony(code, detail string) error {
	return fmt.Errorf("%w: %w", ErrCeremony, &webauthn.Error{Code: code, Detail: detail})
}

// failed wraps a verifier error as ErrCeremony, keeping its reason.
func failed(err error) error {
	var we *webauthn.Error
	if errors.As(err, &we) {
		return fmt.Errorf("%w: %w", ErrCeremony, err)
	}
	return ceremony(webauthn.ReasonParse, "credential not usable")
}

// Service runs passkey and WebAuthn ceremonies over a store.
type Service struct {
	st  store.Store
	rp  rpid.Policy
	now func() time.Time
}

// New returns a Service over st with the deployment's RP ID policy. now is
// the clock (nil means time.Now).
func New(st store.Store, rp rpid.Policy, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{st: st, rp: rp, now: now}
}

// LoginResult is an accepted passkey login: the credential's user, the
// passkey (with the sign count, backup state and last use just written)
// and the verified assertion.
type LoginResult struct {
	User      *store.User
	Method    *store.Authenticator
	Assertion *webauthn.Assertion
}

// UserDisplay is the creation options' user.name and user.displayName.
type UserDisplay struct{ Name, DisplayName string }

// Display is u's §4.5 display: Name is the highest-precedence identifier
// the user has among email, phone number and username, in that order,
// counting only identifiers active on conn (all of them when conn is nil;
// when none of the active ones is set, the first set one); DisplayName is
// u.Name when set, else that identifier.
func Display(u *store.User, conn *store.Connection) UserDisplay {
	if u == nil {
		return UserDisplay{}
	}
	ids := []struct{ attr, value string }{{"email", u.Email}, {"phone_number", u.PhoneNumber}, {"username", u.Username}}
	name := ""
	for _, id := range ids {
		if id.value != "" && (conn == nil || store.IdentifierActive(conn, id.attr)) {
			name = id.value
			break
		}
	}
	for _, id := range ids {
		if name == "" && id.value != "" {
			name = id.value
		}
	}
	d := UserDisplay{Name: name, DisplayName: u.Name}
	if d.DisplayName == "" {
		d.DisplayName = name
	}
	return d
}

// EnrollKind selects the §4.5 creation parameters.
type EnrollKind int

const (
	Signup      EnrollKind = iota + 1 // passkey signup: no user yet, nothing excluded
	Progressive                       // progressive enrollment (and other enrollments of an existing user)
	Local                             // local enrollment: a platform authenticator
)

// userAgentMax bounds the user agent stored with a passkey.
const userAgentMax = 512

// handleLabel separates the derived first user handle from other uses of
// a challenge.
const handleLabel = "zeroauthy passkey user handle\x00"

// deriveHandle is a user's first user handle, derived from the fresh
// random challenge of the ceremony that creates it so CreationOptions and
// Enroll/Signup agree without storing anything in between (LR33b-7; it
// carries no PII and is as unpredictable as the challenge, which the
// client sees in the same options document).
func deriveHandle(ch []byte) []byte {
	n := webauthnrules.Limits.UserHandleBytes
	out := make([]byte, 0, n+sha256.Size)
	for i := uint32(0); len(out) < n; i++ {
		h := sha256.New()
		h.Write([]byte(handleLabel))
		_ = binary.Write(h, binary.BigEndian, i)
		h.Write(ch)
		out = h.Sum(out)
	}
	return out[:n]
}

// passkeyData is the allowlisted public data of a passkey row.
type passkeyData struct {
	AAGUID         string   `json:"aaguid,omitempty"`
	Attachment     string   `json:"attachment,omitempty"`
	BackupEligible bool     `json:"backup_eligible"`
	BackedUp       bool     `json:"backed_up"`
	IdentityUserID string   `json:"identity_user_id,omitempty"`
	Transports     []string `json:"transports,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
	UserHandle     string   `json:"user_handle,omitempty"`
}

func dataOf(a *store.Authenticator) passkeyData {
	var d passkeyData
	if len(a.PublicData) > 0 {
		_ = json.Unmarshal(a.PublicData, &d)
	}
	return d
}

func (d passkeyData) handle() []byte {
	h, err := base64.RawURLEncoding.DecodeString(d.UserHandle)
	if err != nil {
		return nil
	}
	return h
}

func webauthnType(t string) bool {
	return t == "passkey" || t == "webauthn-roaming" || t == "webauthn-platform"
}

// existingHandle is the handle of the user's first passkey (by creation
// time, then ID), or nil when the user has none.
func existingHandle(list []store.Authenticator) []byte {
	var first *store.Authenticator
	for i := range list {
		a := &list[i]
		if a.Type != "passkey" || len(dataOf(a).handle()) == 0 {
			continue
		}
		if first == nil || a.CreatedAt.Before(first.CreatedAt) || a.CreatedAt.Equal(first.CreatedAt) && a.ID < first.ID {
			first = a
		}
	}
	if first == nil {
		return nil
	}
	return dataOf(first).handle()
}

// handleFor returns the user handle of a new passkey for uid: the user's
// existing handle, else the one derived from ch.
func (s *Service) handleFor(ctx context.Context, tid, uid string, ch []byte) ([]byte, []store.Authenticator, error) {
	list, err := s.st.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil {
		return nil, nil, err
	}
	if h := existingHandle(list); h != nil {
		return h, list, nil
	}
	return deriveHandle(ch), list, nil
}

func aaguid(b [16]byte) string {
	const hex = "0123456789abcdef"
	var out strings.Builder
	for i, c := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out.WriteByte('-')
		}
		out.WriteByte(hex[c>>4])
		out.WriteByte(hex[c&0x0f])
	}
	return out.String()
}

func boundedUserAgent(ua string) string {
	if len(ua) <= userAgentMax {
		return ua
	}
	ua = ua[:userAgentMax]
	for !utf8.ValidString(ua) {
		ua = ua[:len(ua)-1]
	}
	return ua
}

// newPasskey builds the passkey row of an accepted registration.
func (s *Service) newPasskey(tid, uid, identityUserID string, reg *webauthn.Registration, rpID string, handle []byte, userAgent string) (*store.Authenticator, error) {
	data, err := json.Marshal(passkeyData{
		AAGUID: aaguid(reg.AAGUID), Attachment: reg.Attachment, BackupEligible: reg.BE, BackedUp: reg.BS,
		IdentityUserID: identityUserID, Transports: reg.Transports, UserAgent: boundedUserAgent(userAgent),
		UserHandle: base64.RawURLEncoding.EncodeToString(handle),
	})
	if err != nil {
		return nil, err
	}
	return &store.Authenticator{
		TenantID: tid, UserID: uid, ID: "passkey|dev_" + secrets.RandomString(20), Type: "passkey", Confirmed: true,
		CredentialID: reg.CredentialID, PublicKey: reg.PublicKeyCOSE, RPID: rpID, SignCount: reg.SignCount,
		PublicData: data, CreatedAt: s.now(),
	}, nil
}

// register verifies a registration response against the taken challenge.
func register(raw, ch []byte, b Binding) (*webauthn.Registration, error) {
	cred, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		return nil, failed(err)
	}
	reg, err := webauthn.VerifyRegistration(cred, webauthn.Expect{Challenge: ch, RPID: b.RPID, Origins: b.Origins})
	if err != nil {
		return nil, failed(err)
	}
	return reg, nil
}

// databaseIdentity returns u's own database identity, or nil.
func databaseIdentity(u *store.User) *store.Identity {
	for i := range u.Identities {
		if id := &u.Identities[i]; id.Provider == store.StrategyDatabase && !id.Linked() {
			return id
		}
	}
	return nil
}

// Login verifies a passkey-login assertion (raw, the authn_response JSON)
// against the taken challenge ch and b (LR33b-16). The credential's user is
// the user, whatever identifier was typed: the credential must be a
// passkey of the tenant stored for b.RPID, and with a native b.Realm its
// user must have an identity on that connection. A blocked user whose
// passkey verifies gets identity.ErrUserBlocked; every other refusal is
// ErrCeremony (a sign-count regression with reason sign_count). On
// success the sign count, backup state and last use are written.
// Connection and client checks are the caller's.
func (s *Service) Login(ctx context.Context, tid string, raw []byte, ch []byte, b Binding) (*LoginResult, error) {
	if b.Purpose != PurposePasskeyLogin {
		return nil, ceremony(webauthn.ReasonChallenge, "not a login challenge")
	}
	cred, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		return nil, failed(err)
	}
	a, err := s.st.WebAuthn().GetAuthenticatorByCredentialID(ctx, tid, cred.RawID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ceremony(ReasonCredential, "credential not found")
	}
	if err != nil {
		return nil, err
	}
	if a.Type != "passkey" || !a.Confirmed {
		return nil, ceremony(ReasonCredential, "not a passkey")
	}
	if a.RPID != b.RPID {
		return nil, ceremony(webauthn.ReasonRPID, "credential of another relying party")
	}
	u, err := s.st.Users().Get(ctx, tid, a.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ceremony(ReasonCredential, "credential user not found")
	}
	if err != nil {
		return nil, err
	}
	data := dataOf(a)
	assertion, err := webauthn.VerifyAssertion(cred, webauthn.Expect{Challenge: ch, RPID: b.RPID, Origins: b.Origins, RequireUserHandle: true},
		webauthn.Stored{PublicKeyCOSE: a.PublicKey, SignCount: a.SignCount, BE: data.BackupEligible, UserHandle: data.handle()})
	if err != nil {
		return nil, failed(err)
	}
	if u.Blocked {
		return nil, identity.ErrUserBlocked
	}
	if b.Realm != "" && !slices.ContainsFunc(u.Identities, func(id store.Identity) bool { return id.Connection == b.Realm }) {
		return nil, ceremony(ReasonCredential, "credential user not on this connection")
	}
	at := s.now()
	err = s.st.WebAuthn().AcceptAssertion(ctx, tid, u.UserID, a.ID, assertion.SignCount, assertion.BS, at)
	switch {
	case errors.Is(err, store.ErrPrecondition):
		return nil, ceremony(webauthn.ReasonSignCount, "sign count did not increase")
	case errors.Is(err, store.ErrNotFound):
		return nil, ceremony(ReasonCredential, "credential removed")
	case err != nil:
		return nil, err
	}
	a.SignCount, a.LastAuthAt = assertion.SignCount, at
	data.BackedUp = assertion.BS
	if pd, err := json.Marshal(data); err == nil {
		a.PublicData = pd
	}
	return &LoginResult{User: u, Method: a, Assertion: assertion}, nil
}

// Enroll verifies a registration response for the existing user u against
// the taken challenge ch (bound to u) and stores the passkey for b.RPID
// with the user's handle (LR33b-7). identityUserID is the identity the
// passkey is created for ("" means u's database identity). The user's
// 21st passkey is ErrMaxPasskeys; a credential the tenant already holds
// and every verification failure are ErrCeremony.
func (s *Service) Enroll(ctx context.Context, tid string, u *store.User, identityUserID string, raw, ch []byte, b Binding, userAgent string) (*store.Authenticator, error) {
	if u == nil || u.TenantID != tid || b.Purpose != PurposePasskeyRegister || b.UserID == "" || b.UserID != u.UserID {
		return nil, ceremony(webauthn.ReasonChallenge, "challenge not bound to this user")
	}
	reg, err := register(raw, ch, b)
	if err != nil {
		return nil, err
	}
	if identityUserID == "" {
		if id := databaseIdentity(u); id != nil {
			identityUserID = id.UserID
		}
	}
	handle, _, err := s.handleFor(ctx, tid, u.UserID, ch)
	if err != nil {
		return nil, err
	}
	a, err := s.newPasskey(tid, u.UserID, identityUserID, reg, b.RPID, handle, userAgent)
	if err != nil {
		return nil, err
	}
	err = s.st.WebAuthn().CreatePasskey(ctx, a, webauthnrules.Limits.MaxPasskeys)
	switch {
	case errors.Is(err, store.ErrPrecondition):
		return nil, ErrMaxPasskeys
	case errors.Is(err, store.ErrConflict):
		return nil, ceremony(ReasonCredential, "credential already registered")
	case err != nil:
		return nil, err
	}
	return a, nil
}

// CreationOptions renders the §4.5 creation options for u on rpID with the
// raw challenge ch: pubKeyCredParams -8, -7, -257, attestation none,
// rp.name = rp.id, residentKey required, userVerification preferred, and
// authenticatorAttachment platform for Local. The user handle is the
// user's existing one, else derived from ch (Enroll and Signup store the
// same). Except for Signup (no user yet), excludeCredentials lists every
// WebAuthn credential of u stored for rpID. An empty display is filled
// from Display(u, nil). timeout <= 0 means
// webauthnrules.Limits.HostedChallengeTTL.
func (s *Service) CreationOptions(ctx context.Context, tid string, u *store.User, display UserDisplay, rpID string, kind EnrollKind, ch []byte, timeout time.Duration) (webauthn.CreationOptions, error) {
	if u == nil || rpID == "" || len(ch) == 0 || kind < Signup || kind > Local {
		return webauthn.CreationOptions{}, store.ErrInvalid
	}
	if timeout <= 0 {
		timeout = webauthnrules.Limits.HostedChallengeTTL
	}
	if display.Name == "" {
		d := Display(u, nil)
		display.Name = d.Name
		if display.DisplayName == "" {
			display.DisplayName = d.DisplayName
		}
	}
	if display.DisplayName == "" {
		display.DisplayName = display.Name
	}
	opts := webauthn.CreationOptions{
		Challenge: bytes.Clone(ch), RPID: rpID, RPName: rpID, UserName: display.Name, DisplayName: display.DisplayName,
		Algs: slices.Clone(webauthn.RegistrationAlgs), ResidentKey: "required", UserVerification: "preferred", Timeout: timeout,
	}
	if kind == Local {
		opts.Attachment = "platform"
	}
	if kind == Signup {
		opts.UserID = deriveHandle(ch)
		return opts, nil
	}
	handle, list, err := s.handleFor(ctx, tid, u.UserID, ch)
	if err != nil {
		return webauthn.CreationOptions{}, err
	}
	opts.UserID = handle
	for i := range list {
		if a := &list[i]; webauthnType(a.Type) && a.RPID == rpID && len(a.CredentialID) > 0 {
			opts.Exclude = append(opts.Exclude, webauthn.Descriptor{ID: bytes.Clone(a.CredentialID), Transports: dataOf(a).Transports})
		}
	}
	return opts, nil
}

// RequestOptions renders the passkey-login request options: rpID, the raw
// challenge ch, userVerification preferred and an empty allowCredentials
// (discoverable credentials). timeout <= 0 means
// webauthnrules.Limits.HostedChallengeTTL.
func (s *Service) RequestOptions(rpID string, ch []byte, timeout time.Duration) webauthn.RequestOptions {
	if timeout <= 0 {
		timeout = webauthnrules.Limits.HostedChallengeTTL
	}
	return webauthn.RequestOptions{Challenge: bytes.Clone(ch), RPID: rpID, UserVerification: "preferred", Allow: []webauthn.Descriptor{}, Timeout: timeout}
}

// Effective reports whether passkeys work for conn on the request res of
// tenant tid: the connection's policy against the tenant's prompt
// settings (connrules.Passkeys), the host's RP ID (rpid.Policy.For), and
// whether the store holds passkeys (webauthn.v1). The bool is true only
// when the policy is effective, the RP ID is valid and the store supports
// WebAuthn; the error is only for storage failures.
func (s *Service) Effective(ctx context.Context, tid string, res tenant.Resolved, conn *store.Connection) (connrules.PasskeyPolicy, rpid.Result, bool, error) {
	var prompts map[string]any
	cfg, err := s.st.HostedLogins().Get(ctx, tid)
	switch {
	case err == nil:
		prompts = cfg.Prompts
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrHostedLoginRepositoryUnavailable):
	default:
		return connrules.PasskeyPolicy{}, rpid.Result{}, false, err
	}
	policy, _ := connrules.Passkeys(conn, prompts)
	r, err := s.rp.For(ctx, res)
	if err != nil {
		return policy, rpid.Result{}, false, err
	}
	supported, err := s.webauthnSupported(ctx)
	if err != nil {
		return policy, r, false, err
	}
	ok := policy.Effective && r.Valid && supported && res.Tenant != nil && res.Tenant.ID == tid && conn != nil && conn.TenantID == tid
	return policy, r, ok, nil
}

// webauthnSupported reports whether the store holds passkeys: a negotiating
// driver must answer its capability, and a driver whose WebAuthn() is the
// unimplemented stub never does.
func (s *Service) webauthnSupported(ctx context.Context) (bool, error) {
	if ws, ok := s.st.(store.WebAuthnSupporter); ok {
		err := ws.CheckWebAuthnSupport(ctx)
		if errors.Is(err, store.ErrWebAuthnUnavailable) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	_, stub := s.st.WebAuthn().(store.UnimplementedWebAuthn)
	return !stub, nil
}
