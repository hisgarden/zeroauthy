package login

import (
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"html/template"
)

// webauthnErrorNames are the DOMException names the page script may post
// (spec section 5.2). Anything else becomes UnknownError, and the posted
// value is never echoed back or logged.
var webauthnErrorNames = []string{
	"NotAllowedError", "InvalidStateError", "NotSupportedError",
	"SecurityError", "AbortError", "ConstraintError", "UnknownError",
}

// passkeyBinding is the binding every challenge of this ceremony is issued
// and consumed with (spec section 5.3): the transaction, its browser cookie
// hash, the host's RP ID and its exact origin.
func (h *Handlers) passkeyBinding(f *flow, rpID, origin string) passkey.Binding {
	return passkey.Binding{
		Purpose: passkey.PurposePasskeyLogin, RPID: rpID, Origins: []string{origin},
		TxnID: f.txn.ID, CookieHash: f.txn.CookieHash,
	}
}

// passkeyMarkup builds the login-id page's WebAuthn data when passkeys are
// effective for this transaction, or nil when they are not. A host whose
// stored RP ID is invalid renders no markup at all (R1), and neither does a
// connection whose policy is not effective.
func (h *Handlers) passkeyMarkup(r *http.Request, f *flow) (*ui.PasskeyData, error) {
	if h.Passkeys == nil {
		return nil, nil
	}
	policy, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil {
		return nil, err
	}
	if !effective || !rp.Valid {
		return nil, nil
	}
	autofill := policy.ChallengeUI == "both" || policy.ChallengeUI == "autofill"
	button := policy.ChallengeUI == "both" || policy.ChallengeUI == "button"
	if !autofill && !button {
		return nil, nil
	}
	issued, err := h.Passkeys.Issue(r.Context(), f.res.Tenant.ID, h.passkeyBinding(f, rp.RPID, f.res.Origin()), 0)
	if err != nil {
		return nil, err
	}
	raw, err := h.Passkeys.RequestOptions(rp.RPID, issued.Challenge, 0).JSON()
	if err != nil {
		return nil, err
	}
	return &ui.PasskeyData{
		ChallengeID: issued.ID,
		Options:     template.JS(raw),
		Button:      button,
		Autofill:    autofill,
		ButtonText:  f.view.L.T(i18n.KeyPasskeyButtonText),
	}, nil
}

// LoginPasskeyPost is POST /u/login/passkey: the page script's assertion.
//
// The single-use challenge, not the hosted revision, is what makes one
// assertion win: a double submit or a second tab loses the consume and is
// answered like any other failed assertion, on a freshly rendered page
// (Review Focus 2). The revision guard therefore cannot abort the request;
// it only decides whether this submit may advance the form state.
func (h *Handlers) LoginPasskeyPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	if step := f.txn.HostedState.Step; step != "" && step != "identifier" {
		h.fail(w, r, errTxn, f)
		return
	}
	h.authenticatePasskey(w, r, f)
}

// authenticatePasskey proves the assertion and then continues exactly as a
// password login does: Actions, MFA policy, consent and organizations all
// run from the same place (spec section 3.3).
func (h *Handlers) authenticatePasskey(w http.ResponseWriter, r *http.Request, f *flow) {
	h.withFlowEvent(r, f)
	if h.Passkeys == nil {
		h.fail(w, r, errTxn, f)
		return
	}
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	// A page rendered before passkeys were switched off, or for a host whose
	// RP ID is no longer valid, gets the same generic failure; nothing here
	// reveals which case applied (Review Focus 3).
	if !effective || !rp.Valid {
		h.passkeyFailure(w, r, f, i18n.KeyPasskeyAuthenticationFailed, string(webauthn.ReasonRPID))
		return
	}

	// A script-reported DOMException is not an assertion: a cancellation
	// re-renders silently, anything else is a bounded server-side answer.
	if posted := r.PostForm.Get("webauthn_error"); posted != "" {
		name := "UnknownError"
		if slices.Contains(webauthnErrorNames, posted) {
			name = posted
		}
		if name == "NotAllowedError" {
			d := h.stageData(f, "")
			d.Error = f.view.L.T(i18n.KeyPasskeyNotAllowed)
			h.renderIdentifier(w, r, http.StatusUnauthorized, f, d)
			return
		}
		h.passkeyFailure(w, r, f, i18n.KeyPasskeyNotAllowed, name)
		return
	}

	raw := r.PostForm.Get("credential")
	if raw == "" {
		h.passkeyFailure(w, r, f, i18n.KeyPasskeyAuthenticationFailed, string(webauthn.ReasonParse))
		return
	}

	binding := h.passkeyBinding(f, rp.RPID, f.res.Origin())
	challenge, err := h.Passkeys.Take(r.Context(), f.res.Tenant.ID, r.PostForm.Get("challenge_id"), binding)
	if err != nil {
		// A missing, expired, reused or differently bound challenge consumes
		// nothing reusable and is the generic failure (Review Focus 2).
		h.passkeyFailure(w, r, f, i18n.KeyPasskeyAuthenticationFailed, string(webauthn.ReasonChallenge))
		return
	}

	svc := h.protectionService()
	decision, err := svc.Begin(r.Context(), protection.Attempt{
		Tenant: f.res.Tenant, Connection: f.conn, Identifier: "", IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "login",
	})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		d := h.stageData(f, "")
		d.Error = f.view.L.T(i18n.KeyTooManyAttempts)
		h.renderIdentifier(w, r, http.StatusTooManyRequests, f, d)
		return
	}

	res, err := h.Passkeys.Login(r.Context(), f.res.Tenant.ID, []byte(raw), challenge, binding)
	if err != nil {
		h.passkeyLoginError(w, r, f, svc, decision, err)
		return
	}
	if err := svc.Finish(r.Context(), decision.Receipt, "success"); err != nil {
		h.fail(w, r, err, f)
		return
	}
	// A successful passkey login clears the identity's failure counter.
	if err := h.recordFailure(r, f.res, "login", secrets.RandomString(32), nil); err != nil {
		h.fail(w, r, err, f)
		return
	}
	// The assertion's authenticator attachment decides the local-enrollment
	// prompt after this login (spec section 3.5, Review Focus 5).
	if res.Assertion != nil {
		f.passkeyAttachment = res.Assertion.Attachment
	}
	h.completeWithMethods(w, r, f, res.User, store.AuthMethod{Name: "passkey", At: h.now()})
}

// passkeyLoginError maps an assertion failure to its answer. A blocked user
// is named because the passkey already proved possession (LR33b-16); every
// other failure is one generic message.
func (h *Handlers) passkeyLoginError(w http.ResponseWriter, r *http.Request, f *flow, svc *protection.Service, decision protection.Decision, err error) {
	if errors.Is(err, identity.ErrUserBlocked) {
		if finishErr := svc.Finish(r.Context(), decision.Receipt, "blocked"); finishErr != nil {
			h.fail(w, r, finishErr, f)
			return
		}
		d := h.stageData(f, "")
		d.Error = f.view.L.T(i18n.KeyUserBlocked)
		h.renderIdentifier(w, r, http.StatusForbidden, f, d)
		return
	}
	if !errors.Is(err, passkey.ErrCeremony) {
		h.fail(w, r, err, f)
		return
	}
	// Spend the IP's suspicious-login budget and the identity's counter
	// exactly as the password path does (R3).
	if finishErr := svc.Finish(r.Context(), decision.Receipt, "failure"); finishErr != nil {
		h.fail(w, r, finishErr, f)
		return
	}
	if recErr := h.recordFailure(r, f.res, "login", secrets.RandomString(32), identity.ErrInvalidCredentials); recErr != nil {
		h.fail(w, r, recErr, f)
		return
	}
	h.passkeyFailure(w, r, f, i18n.KeyPasskeyAuthenticationFailed, webauthn.Reason(err))
}

// passkeyFailure answers every unsuccessful assertion with one generic
// message and logs gd_webauthn_challenge_failed with a bounded reason
// (spec section 8.2, LR33b-17).
func (h *Handlers) passkeyFailure(w http.ResponseWriter, r *http.Request, f *flow, key, reason string) {
	h.eventWithDetails(r, f, "gd_webauthn_challenge_failed", nil, map[string]any{
		"first_factor":    true,
		"failure_details": map[string]any{"errorCode": boundedReason(reason)},
	})
	d := h.stageData(f, "")
	d.Error = f.view.L.T(key)
	h.renderIdentifier(w, r, http.StatusUnauthorized, f, d)
}

// boundedReason keeps a log detail to the verifier's bounded vocabulary, so
// no input data can reach a log (spec section 8.2).
func boundedReason(reason string) string {
	switch reason {
	case webauthn.ReasonParse, webauthn.ReasonType, webauthn.ReasonChallenge, webauthn.ReasonOrigin,
		webauthn.ReasonCrossOrigin, webauthn.ReasonRPID, webauthn.ReasonUserPresent, webauthn.ReasonUserVerified,
		webauthn.ReasonAlg, webauthn.ReasonKey, webauthn.ReasonAttestation, webauthn.ReasonSignature,
		webauthn.ReasonUserHandle, webauthn.ReasonSignCount, webauthn.ReasonBackupEligibility,
		webauthn.ReasonBackupState, webauthn.ReasonTooLarge:
		return reason
	}
	return webauthn.ReasonParse
}
