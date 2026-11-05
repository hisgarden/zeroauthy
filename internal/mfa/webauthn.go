package mfa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// The WebAuthn MFA factors (Plan 33b spec section 6). Their Guardian factor
// names, authenticator types and Actions factor names are the same string.
const (
	FactorRoaming  = "webauthn-roaming"  // security keys
	FactorPlatform = "webauthn-platform" // device biometrics
)

// RoamingSettingsKey is the GuardianSettings.Stored key of the security-key
// user-verification setting (LR33b-22).
const RoamingSettingsKey = "webauthn-roaming/settings"

// RoamingUVValues are the setting's values: "discouraged" (never, the
// default), "preferred" (if supported) and "required".
var RoamingUVValues = []string{"discouraged", "preferred", "required"}

// DefaultRoamingName is the name a security key gets until the user names it.
const DefaultRoamingName = "Security key"

var (
	// ErrWebAuthn is a WebAuthn ceremony that did not validate: a missing,
	// expired, used or foreign challenge, an unknown credential or a failed
	// verification. It is an ErrInvalidCode, so callers that do not tell the
	// factors apart answer as for a wrong code.
	ErrWebAuthn = fmt.Errorf("%w: WebAuthn ceremony failed", ErrInvalidCode)
	// ErrNickname is a key nickname outside 1–20 characters (LR33b-31) or
	// with control characters.
	ErrNickname = errors.New("mfa: invalid authenticator nickname")
	// ErrWebAuthnUnavailable is a WebAuthn factor this deployment, store or
	// host cannot run (no ceremony service, no webauthn.v1, an invalid RP ID
	// or no hosted transaction binding).
	ErrWebAuthnUnavailable = fmt.Errorf("%w: WebAuthn unavailable", ErrNoFactor)
)

// WebAuthnInput is the WebAuthn context of one MFA decision. The zero value
// (no capability result, for example a browser without script, or a grant)
// makes the WebAuthn factors unavailable.
type WebAuthnInput struct {
	// Available is true when the browser reported WebAuthn and this host can
	// run WebAuthn ceremonies.
	Available bool
	// Platform is true when the browser also reported a user-verifying
	// platform authenticator.
	Platform bool
	// RPID is the request host's effective RP ID. Authenticators stored for
	// another RP ID are not the user's on this host (LR33b-5).
	RPID string
	// Device classifies the request's user agent (LR33b-19).
	Device webauthn.Device
}

// IsWebAuthnFactor reports whether f is one of the WebAuthn MFA factors.
func IsWebAuthnFactor(f string) bool { return f == FactorRoaming || f == FactorPlatform }

// RoamingUV returns the stored security-key user-verification setting:
// "discouraged" (the default), "preferred" or "required".
func RoamingUV(g *store.GuardianSettings) string {
	if g != nil {
		var v struct {
			UV string `json:"user_verification"`
		}
		if raw := g.Stored[RoamingSettingsKey]; len(raw) > 0 && json.Unmarshal(raw, &v) == nil && slices.Contains(RoamingUVValues, v.UV) {
			return v.UV
		}
	}
	return "discouraged"
}

// factorUV is the userVerification of a factor's ceremonies (spec 4.5):
// platform always requires it; security keys follow the setting.
func factorUV(factor string, g *store.GuardianSettings) string {
	if factor == FactorPlatform {
		return "required"
	}
	return RoamingUV(g)
}

// webauthnData is the allowlisted public data of a WebAuthn MFA row.
type webauthnData struct {
	AAGUID         string   `json:"aaguid,omitempty"`
	Attachment     string   `json:"attachment,omitempty"`
	BackupEligible bool     `json:"backup_eligible"`
	BackedUp       bool     `json:"backed_up"`
	Transports     []string `json:"transports,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
	UserHandle     string   `json:"user_handle,omitempty"`
}

func webauthnDataOf(a store.Authenticator) webauthnData {
	var d webauthnData
	if len(a.PublicData) > 0 {
		_ = json.Unmarshal(a.PublicData, &d)
	}
	return d
}

func (d webauthnData) handle() []byte {
	h, err := base64.RawURLEncoding.DecodeString(d.UserHandle)
	if err != nil {
		return nil
	}
	return h
}

// DeviceKey is the device recognition key of an authenticator's stored user
// agent (LR33b-19).
func DeviceKey(a store.Authenticator) string {
	return webauthn.DeviceOf(webauthnDataOf(a).UserAgent).Key()
}

// enrolledWebAuthn reports whether a is a confirmed WebAuthn MFA
// authenticator of an enabled factor stored for w.RPID. With no RP ID (an
// MFA API grant) every RP ID counts, so a credential the request cannot use
// still counts as enrolled and fails closed.
func enrolledWebAuthn(a store.Authenticator, enabled map[string]bool, w WebAuthnInput) bool {
	return IsWebAuthnFactor(a.Type) && a.Confirmed && enabled[a.Type] && len(a.CredentialID) > 0 && (w.RPID == "" || a.RPID == w.RPID)
}

// UsableWebAuthn reports whether a can satisfy a WebAuthn challenge in the
// context w: enrolled for w.RPID, the browser reported WebAuthn, and for a
// platform authenticator the browser reported one and the stored user agent
// maps to the request's device key.
func UsableWebAuthn(a store.Authenticator, enabled map[string]bool, w WebAuthnInput) bool {
	if !w.Available || w.RPID == "" || !enrolledWebAuthn(a, enabled, w) {
		return false
	}
	return a.Type == FactorRoaming || w.Platform && DeviceKey(a) == w.Device.Key()
}

// EnrolledMethod extends UsableMethod to WebAuthn for the "already has a
// factor" rules (first-only enrollment, tickets): it also counts a confirmed
// WebAuthn authenticator of an enabled factor stored for w.RPID, whether or
// not this browser can use it.
func EnrolledMethod(u *store.User, a store.Authenticator, enabled map[string]bool, w WebAuthnInput) bool {
	return UsableMethod(u, a, enabled) || enrolledWebAuthn(a, enabled, w)
}

// WithHostedBinding returns a request-local view whose WebAuthn challenges
// are bound to the hosted transaction txnID and the hash of its browser
// cookie. WebAuthn ceremonies need it; without it they are unavailable.
func (s *Service) WithHostedBinding(txnID, cookieHash string) *Service {
	local := *s
	local.hostedTxn, local.hostedCookie = txnID, cookieHash
	return &local
}

// RelyingParty resolves the request host's RP ID and hosted origin.
func (s *Service) RelyingParty(ctx context.Context, res tenant.Resolved) (rpid.Result, error) {
	return s.RPIDs.For(ctx, res)
}

// webauthnSupported reports whether WebAuthn ceremonies can run: a
// ceremony service and a store that holds WebAuthn data (webauthn.v1).
func (s *Service) webauthnSupported(ctx context.Context) (bool, error) {
	if s.Passkeys == nil || s.st == nil {
		return false, nil
	}
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

// WebAuthnContext is the WebAuthn input of a hosted decision made before
// the browser reported its capabilities: it assumes a capable browser
// (Available and Platform) whenever this host can run ceremonies, so the
// requirement lists every WebAuthn factor that could be offered. The hosted
// pages then narrow it with the mfa-detect-browser-capabilities result.
func (s *Service) WebAuthnContext(ctx context.Context, res tenant.Resolved, userAgent string) (WebAuthnInput, error) {
	out := WebAuthnInput{Device: webauthn.DeviceOf(userAgent)}
	ok, err := s.webauthnSupported(ctx)
	if err != nil || !ok {
		return out, err
	}
	rp, err := s.RelyingParty(ctx, res)
	if err != nil {
		return out, err
	}
	if !rp.Valid {
		return out, nil
	}
	out.RPID, out.Available, out.Platform = rp.RPID, true, true
	return out, nil
}

// webauthnBinding is the challenge binding of a WebAuthn MFA ceremony.
func (s *Service) webauthnBinding(p passkey.Purpose, uid, rpID, origin string) (passkey.Binding, error) {
	if s.Passkeys == nil || s.hostedTxn == "" || s.hostedCookie == "" || rpID == "" || origin == "" {
		return passkey.Binding{}, ErrWebAuthnUnavailable
	}
	return passkey.Binding{Purpose: p, RPID: rpID, Origins: []string{origin}, TxnID: s.hostedTxn, CookieHash: s.hostedCookie, UserID: uid}, nil
}

// handleLabel separates a derived WebAuthn MFA user handle from other uses
// of a challenge.
const handleLabel = "zeroauthy webauthn mfa user handle\x00"

// userHandle is the user handle for a new WebAuthn MFA credential: the one
// already stored on any of the user's WebAuthn rows (passkeys included, so
// one user has one handle), else one derived from the fresh challenge,
// which carries no PII and is as unpredictable as the challenge.
func userHandle(list []store.Authenticator, ch []byte) []byte {
	var first *store.Authenticator
	for i := range list {
		a := &list[i]
		if (a.Type == "passkey" || IsWebAuthnFactor(a.Type)) && len(webauthnDataOf(*a).handle()) > 0 {
			if first == nil || a.CreatedAt.Before(first.CreatedAt) || a.CreatedAt.Equal(first.CreatedAt) && a.ID < first.ID {
				first = a
			}
		}
	}
	if first != nil {
		return webauthnDataOf(*first).handle()
	}
	sum := sha256.Sum256(append([]byte(handleLabel), ch...))
	return sum[:webauthnrules.Limits.UserHandleBytes]
}

// ValidNickname reports whether name is a storable key nickname: 1–20
// characters (LR33b-31) and no control characters.
func ValidNickname(name string) bool {
	n := utf8.RuneCountInString(name)
	if !utf8.ValidString(name) || n < webauthnrules.Limits.NicknameMin || n > webauthnrules.Limits.NicknameMax || strings.TrimSpace(name) == "" {
		return false
	}
	return !strings.ContainsFunc(name, unicode.IsControl)
}

// DefaultWebAuthnName is a new WebAuthn authenticator's name: the security
// key default, or "<browser> on <OS>" for device biometrics (LR33b-31).
func DefaultWebAuthnName(factor, userAgent string) string {
	if factor != FactorPlatform {
		return DefaultRoamingName
	}
	d := webauthn.DeviceOf(userAgent)
	browsers := map[string]string{"chrome": "Chrome", "edge": "Edge", "safari": "Safari", "firefox": "Firefox"}
	systems := map[string]string{"windows": "Windows", "ios": "iOS", "macos": "macOS", "android": "Android"}
	b, os := browsers[d.Browser], systems[d.OS]
	if b == "" {
		b = "Browser"
	}
	if os == "" {
		os = "this device"
	}
	return b + " on " + os
}

// emitWebAuthn records a WebAuthn MFA outcome with its §8.2 details.
func (s *Service) emitWebAuthn(ctx context.Context, tid, uid, kind string, details map[string]any) {
	recorder := s.Recorder
	if recorder == nil {
		recorder = logs.RecorderFromContext(ctx)
	}
	e := logs.Event{TenantID: tid, UserID: uid, Type: kind, Date: s.now(), Details: details}
	if observeWebAuthnEvent != nil {
		observeWebAuthnEvent(e)
	}
	logs.RecordEvent(ctx, recorder, e)
}

// observeWebAuthnEvent sees every WebAuthn MFA outcome before the log
// catalog gate (gd_webauthn_* stay deferred until Plan 33b Task 19). Only
// this package's tests set it.
var observeWebAuthnEvent func(logs.Event)

func authenticatorDetail(factor string) map[string]any { return map[string]any{"type": factor} }

func failureDetail(err error) map[string]any {
	return map[string]any{"errorCode": webauthn.Reason(err)}
}

// BeginWebAuthnEnroll starts enrolling a WebAuthn factor for uid on rp: it
// issues a webauthn-register challenge bound to the hosted transaction (see
// WithHostedBinding), the user and rp, and returns the enrollment (its
// ChallengeID, RPID and Origin) with the creation options to send to the
// browser (spec 4.5). No authenticator exists until ConfirmWebAuthnEnroll.
func (s *Service) BeginWebAuthnEnroll(ctx context.Context, tid, uid, factor string, rp rpid.Result, display passkey.UserDisplay) (out *Enrollment, opts webauthn.CreationOptions, err error) {
	ctx = s.operationContext(ctx)
	defer func() {
		if err != nil {
			s.emit(ctx, tid, uid, "gd_start_enroll_failed")
		}
	}()
	if !IsWebAuthnFactor(factor) || !rp.Valid {
		return nil, opts, ErrNoFactor
	}
	if err = enabled(ctx, s.st, tid, factor); err != nil {
		return nil, opts, err
	}
	b, err := s.webauthnBinding(passkey.PurposeWebAuthnRegister, uid, rp.RPID, rp.Origin)
	if err != nil {
		return nil, opts, err
	}
	u, err := s.st.Users().Get(ctx, tid, uid)
	if err != nil {
		return nil, opts, err
	}
	g, err := s.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return nil, opts, err
	}
	list, err := s.st.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil {
		return nil, opts, err
	}
	if s.newFactorOnly && slices.ContainsFunc(list, func(a store.Authenticator) bool { return a.Confirmed && a.Type == factor }) {
		return nil, opts, ErrNoFactor
	}
	issued, err := s.Passkeys.Issue(ctx, tid, b, 0)
	if err != nil {
		return nil, opts, err
	}
	ctx = s.operationContext(ctx, issued.ID)
	if display.Name == "" {
		display = passkey.Display(u, nil)
	}
	if display.DisplayName == "" {
		display.DisplayName = display.Name
	}
	opts = webauthn.CreationOptions{
		Challenge: bytes.Clone(issued.Challenge), RPID: rp.RPID, RPName: rp.RPID, UserID: userHandle(list, issued.Challenge),
		UserName: display.Name, DisplayName: display.DisplayName, Algs: slices.Clone(webauthn.RegistrationAlgs),
		Attachment: "cross-platform", ResidentKey: "discouraged", UserVerification: factorUV(factor, g),
		Timeout: webauthnrules.Limits.HostedChallengeTTL,
	}
	if factor == FactorPlatform {
		opts.Attachment = "platform"
	}
	for _, a := range list {
		if a.Type == factor && a.RPID == rp.RPID && len(a.CredentialID) > 0 {
			opts.Exclude = append(opts.Exclude, webauthn.Descriptor{ID: bytes.Clone(a.CredentialID), Transports: webauthnDataOf(a).Transports})
		}
	}
	s.emit(ctx, tid, uid, "gd_start_enroll")
	return &Enrollment{Factor: factor, ChallengeID: issued.ID, RPID: rp.RPID, Origin: rp.Origin}, opts, nil
}

// ConfirmWebAuthnEnroll verifies the registration response raw (the
// credential JSON) for the enrollment e and stores the confirmed
// authenticator named name ("" takes DefaultWebAuthnName). The challenge is
// spent whatever the outcome. Like ConfirmEnroll it counts in the per-user,
// per-factor throttle, creates the first recovery code (returned once) and
// runs the WithProofCommit callback in the same transaction. A failed
// ceremony is ErrWebAuthn.
func (s *Service) ConfirmWebAuthnEnroll(ctx context.Context, tid, uid string, e *Enrollment, raw []byte, name, userAgent string) (*Confirmed, error) {
	return s.confirmWebAuthn(ctx, tid, uid, e, raw, name, userAgent, false)
}

// ConfirmFirstWebAuthnEnroll is ConfirmWebAuthnEnroll that refuses
// (ErrAlreadyEnrolled) when the user now holds another enrolled factor
// (EnrolledMethod for e's RP ID), as ConfirmFirstEnroll does.
func (s *Service) ConfirmFirstWebAuthnEnroll(ctx context.Context, tid, uid string, e *Enrollment, raw []byte, name, userAgent string) (*Confirmed, error) {
	return s.confirmWebAuthn(ctx, tid, uid, e, raw, name, userAgent, true)
}

func (s *Service) confirmWebAuthn(ctx context.Context, tid, uid string, e *Enrollment, raw []byte, name, userAgent string, firstOnly bool) (out *Confirmed, err error) {
	ctx = s.operationContext(ctx)
	factor := ""
	if e != nil {
		factor = e.Factor
		ctx = s.operationContext(ctx, e.ChallengeID)
	}
	defer func() {
		switch {
		case err == nil:
			s.emitWebAuthn(ctx, tid, uid, "gd_enrollment_complete", map[string]any{"authenticator": authenticatorDetail(factor)})
		case !errors.Is(err, ErrThrottled):
			s.emitWebAuthn(ctx, tid, uid, "gd_webauthn_enrollment_failed", map[string]any{"authenticator": authenticatorDetail(factor), "failure_details": failureDetail(err)})
		}
	}()
	if e == nil || !IsWebAuthnFactor(e.Factor) {
		return nil, ErrWebAuthn
	}
	if name == "" {
		name = DefaultWebAuthnName(factor, userAgent)
	}
	if !ValidNickname(name) {
		return nil, ErrNickname
	}
	if err = enabled(ctx, s.st, tid, factor); err != nil {
		return nil, err
	}
	b, err := s.webauthnBinding(passkey.PurposeWebAuthnRegister, uid, e.RPID, e.Origin)
	if err != nil {
		return nil, err
	}
	receipt, err := s.reserveProof(ctx, tid, uid, factor)
	if err != nil {
		return nil, err
	}
	outcome := "refund"
	defer func() {
		if ferr := s.finishProof(ctx, tid, uid, factor, receipt, outcome); ferr != nil && err == nil {
			out, err = nil, ferr
		}
	}()
	ch, err := s.Passkeys.Take(ctx, tid, e.ChallengeID, b)
	if errors.Is(err, passkey.ErrCeremony) {
		outcome = "failure"
		return nil, fmt.Errorf("%w: %w", ErrWebAuthn, err)
	}
	if err != nil {
		return nil, err
	}
	cred, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		outcome = "failure"
		return nil, fmt.Errorf("%w: %w", ErrWebAuthn, err)
	}
	g, err := s.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return nil, err
	}
	reg, err := webauthn.VerifyRegistration(cred, webauthn.Expect{Challenge: ch, RPID: e.RPID, Origins: []string{e.Origin}, RequireUV: factorUV(factor, g) == "required"})
	if err != nil {
		outcome = "failure"
		return nil, fmt.Errorf("%w: %w", ErrWebAuthn, err)
	}
	result := &Confirmed{}
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		u, e2 := tx.Users().GetForUpdate(ctx, tid, uid)
		if e2 != nil {
			return e2
		}
		if e2 = enabled(ctx, tx, tid, factor); e2 != nil {
			return e2
		}
		g, e2 := tx.MFA().GetGuardian(ctx, tid)
		if e2 != nil {
			return e2
		}
		list, e2 := tx.MFA().ListAuthenticators(ctx, tid, uid)
		if e2 != nil {
			return e2
		}
		hasRecovery := false
		for _, other := range list {
			hasRecovery = hasRecovery || other.Type == "recovery-code"
			if firstOnly && EnrolledMethod(u, other, g.Factors, WebAuthnInput{RPID: e.RPID}) {
				return ErrAlreadyEnrolled
			}
			if s.newFactorOnly && other.Confirmed && other.Type == factor {
				return ErrInvalidCode
			}
		}
		data, e2 := json.Marshal(webauthnData{
			AAGUID: aaguidText(reg.AAGUID), Attachment: reg.Attachment, BackupEligible: reg.BE, BackedUp: reg.BS,
			Transports: reg.Transports, UserAgent: boundedUserAgent(userAgent),
			UserHandle: base64.RawURLEncoding.EncodeToString(userHandle(list, ch)),
		})
		if e2 != nil {
			return e2
		}
		a := &store.Authenticator{TenantID: tid, UserID: uid, ID: NewMethodID(factor), Type: factor, Name: name, Confirmed: true,
			CredentialID: reg.CredentialID, PublicKey: reg.PublicKeyCOSE, RPID: e.RPID, SignCount: reg.SignCount, PublicData: data,
			LastStep: -1, CreatedAt: s.now()}
		if e2 = tx.MFA().CreateAuthenticator(ctx, a); errors.Is(e2, store.ErrConflict) {
			return fmt.Errorf("%w: %w", ErrWebAuthn, &webauthn.Error{Code: passkey.ReasonCredential, Detail: "credential already registered"})
		} else if e2 != nil {
			return e2
		}
		result.AuthenticatorID = a.ID
		if !hasRecovery {
			recovery := NewRecoveryCode()
			ctx = s.operationContext(ctx, recovery)
			if e2 = tx.MFA().ReplaceRecoveryCode(ctx, tid, uid, "", secrets.HashToken(recovery), s.now()); e2 != nil {
				return e2
			}
			result.RecoveryCode = recovery
		}
		if s.proofCommit != nil {
			return s.proofCommit(tx)
		}
		return nil
	})
	switch {
	case err == nil:
		outcome = "success"
		return result, nil
	case errors.Is(err, ErrAlreadyEnrolled):
		// Nothing was stored; the page restarts at the existing factor.
	case errors.Is(err, ErrWebAuthn), errors.Is(err, ErrInvalidCode), errors.Is(err, store.ErrPrecondition):
		outcome = "failure"
		if !errors.Is(err, ErrInvalidCode) {
			err = fmt.Errorf("%w: %w", ErrWebAuthn, err)
		}
	}
	return nil, err
}

// BeginWebAuthnChallenge starts a WebAuthn challenge for uid's factor on rp
// (with the request's device, which a platform authenticator must match):
// it issues a webauthn-assert challenge bound to the hosted transaction,
// the user and rp, and returns it with request options whose
// allowCredentials are the user's usable credentials of that factor.
// ErrNoFactor when the user has none.
func (s *Service) BeginWebAuthnChallenge(ctx context.Context, tid, uid, factor string, rp rpid.Result, device webauthn.Device) (*Challenge, webauthn.RequestOptions, error) {
	ctx = s.operationContext(ctx)
	var opts webauthn.RequestOptions
	if !IsWebAuthnFactor(factor) || !rp.Valid {
		return nil, opts, ErrNoFactor
	}
	if err := enabled(ctx, s.st, tid, factor); err != nil {
		return nil, opts, err
	}
	b, err := s.webauthnBinding(passkey.PurposeWebAuthnAssert, uid, rp.RPID, rp.Origin)
	if err != nil {
		return nil, opts, err
	}
	g, err := s.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return nil, opts, err
	}
	list, err := s.st.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil {
		return nil, opts, err
	}
	w := WebAuthnInput{Available: true, Platform: true, RPID: rp.RPID, Device: device}
	allow := []webauthn.Descriptor{}
	for _, a := range list {
		if a.Type == factor && UsableWebAuthn(a, g.Factors, w) {
			allow = append(allow, webauthn.Descriptor{ID: bytes.Clone(a.CredentialID), Transports: webauthnDataOf(a).Transports})
		}
	}
	if len(allow) == 0 {
		return nil, opts, ErrNoFactor
	}
	issued, err := s.Passkeys.Issue(ctx, tid, b, 0)
	if err != nil {
		return nil, opts, err
	}
	ctx = s.operationContext(ctx, issued.ID)
	opts = webauthn.RequestOptions{Challenge: bytes.Clone(issued.Challenge), RPID: rp.RPID, UserVerification: factorUV(factor, g), Allow: allow, Timeout: webauthnrules.Limits.HostedChallengeTTL}
	s.emit(ctx, tid, uid, "gd_start_auth")
	return &Challenge{ID: issued.ID, Factor: factor, RPID: rp.RPID, Origin: rp.Origin, DeviceKey: device.Key()}, opts, nil
}

// VerifyWebAuthn verifies the assertion response raw against the challenge
// c. The credential must be one of the user's usable authenticators of
// c.Factor for c.RPID (and c's device for a platform authenticator); user
// verification is required for platform and for security keys when the
// setting says "required". The challenge is spent whatever the outcome.
// Failures count in the per-user, per-factor throttle, log
// gd_webauthn_challenge_failed (first_factor false) and gd_auth_failed and
// are ErrWebAuthn; success writes the sign count and last use, runs the
// WithProofCommit callback and logs gd_auth_succeed.
func (s *Service) VerifyWebAuthn(ctx context.Context, tid, uid string, c *Challenge, raw []byte) (err error) {
	ctx = s.operationContext(ctx)
	factor := ""
	if c != nil {
		factor = c.Factor
		ctx = s.operationContext(ctx, c.ID)
	}
	defer func() {
		switch {
		case err == nil:
			s.emit(ctx, tid, uid, "gd_auth_succeed")
		case errors.Is(err, ErrThrottled):
		default:
			s.emitWebAuthn(ctx, tid, uid, "gd_webauthn_challenge_failed", map[string]any{"first_factor": false, "authenticator": authenticatorDetail(factor), "failure_details": failureDetail(err)})
			s.emit(ctx, tid, uid, "gd_auth_failed")
		}
	}()
	if c == nil || !IsWebAuthnFactor(c.Factor) {
		return ErrWebAuthn
	}
	if err = enabled(ctx, s.st, tid, factor); err != nil {
		return err
	}
	b, err := s.webauthnBinding(passkey.PurposeWebAuthnAssert, uid, c.RPID, c.Origin)
	if err != nil {
		return err
	}
	receipt, err := s.reserveProof(ctx, tid, uid, factor)
	if err != nil {
		return err
	}
	outcome := "refund"
	defer func() {
		if ferr := s.finishProof(ctx, tid, uid, factor, receipt, outcome); ferr != nil && err == nil {
			err = ferr
		}
	}()
	fail := func(cause error) error {
		outcome = "failure"
		return fmt.Errorf("%w: %w", ErrWebAuthn, cause)
	}
	ch, err := s.Passkeys.Take(ctx, tid, c.ID, b)
	if errors.Is(err, passkey.ErrCeremony) {
		return fail(err)
	}
	if err != nil {
		return err
	}
	cred, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		return fail(err)
	}
	g, err := s.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return err
	}
	list, err := s.st.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil {
		return err
	}
	w := WebAuthnInput{RPID: c.RPID}
	var a *store.Authenticator
	for i := range list {
		if v := list[i]; v.Type == factor && bytes.Equal(v.CredentialID, cred.RawID) && enrolledWebAuthn(v, g.Factors, w) && (factor != FactorPlatform || DeviceKey(v) == c.DeviceKey) {
			a = &list[i]
		}
	}
	if a == nil {
		return fail(&webauthn.Error{Code: passkey.ReasonCredential, Detail: "credential not usable"})
	}
	data := webauthnDataOf(*a)
	assertion, err := webauthn.VerifyAssertion(cred, webauthn.Expect{Challenge: ch, RPID: c.RPID, Origins: []string{c.Origin}, RequireUV: factorUV(factor, g) == "required"},
		webauthn.Stored{PublicKeyCOSE: a.PublicKey, SignCount: a.SignCount, BE: data.BackupEligible, UserHandle: data.handle()})
	if err != nil {
		return fail(err)
	}
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		if s.proofCommit != nil {
			if _, e := tx.Users().GetForUpdate(ctx, tid, uid); e != nil {
				return e
			}
		}
		if e := enabled(ctx, tx, tid, factor); e != nil {
			return e
		}
		if e := tx.MFA().AcceptSignCount(ctx, tid, uid, a.ID, assertion.SignCount, s.now()); e != nil {
			return e
		}
		if s.proofCommit != nil {
			return s.proofCommit(tx)
		}
		return nil
	})
	switch {
	case err == nil:
		outcome = "success"
		return nil
	case errors.Is(err, store.ErrPrecondition):
		return fail(&webauthn.Error{Code: webauthn.ReasonSignCount, Detail: "sign count did not increase"})
	case errors.Is(err, store.ErrNotFound):
		return fail(&webauthn.Error{Code: passkey.ReasonCredential, Detail: "credential removed"})
	case errors.Is(err, ErrInvalidCode):
		outcome = "failure"
	}
	return err
}

// RenameWebAuthn sets the nickname of uid's WebAuthn MFA authenticator id
// (the change-key-nickname screen). ErrNickname for a name outside 1–20
// characters; store.ErrNotFound for another user's or a non-WebAuthn row.
func (s *Service) RenameWebAuthn(ctx context.Context, tid, uid, id, name string) error {
	if !ValidNickname(name) {
		return ErrNickname
	}
	a, err := s.st.MFA().GetAuthenticator(ctx, tid, uid, id)
	if err != nil {
		return err
	}
	if !IsWebAuthnFactor(a.Type) {
		return store.ErrNotFound
	}
	a.Name = name
	return s.st.MFA().UpdateAuthenticator(ctx, a)
}

// userAgentMax bounds the user agent stored with an authenticator.
const userAgentMax = 512

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

func aaguidText(b [16]byte) string {
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

// ReportWebAuthnError logs a WebAuthn ceremony the browser stopped (the
// page posts only the DOMException name, already reduced to the closed
// set): gd_webauthn_enrollment_failed or gd_webauthn_challenge_failed
// (first_factor false) with failure_details.errorCode = name. Nothing was
// verified, so no throttle budget is spent.
func (s *Service) ReportWebAuthnError(ctx context.Context, tid, uid, factor string, enroll bool, name string) {
	ctx = s.operationContext(ctx)
	details := map[string]any{"authenticator": authenticatorDetail(factor), "failure_details": map[string]any{"errorCode": name}}
	if enroll {
		s.emitWebAuthn(ctx, tid, uid, "gd_webauthn_enrollment_failed", details)
		return
	}
	details["first_factor"] = false
	s.emitWebAuthn(ctx, tid, uid, "gd_webauthn_challenge_failed", details)
}
