package login

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Plan 33b WebAuthn MFA hosted paths (LR33b-37: the paths are local, the
// prompt and screen names Auth0's).
const (
	mfaDetectPath           = "/u/mfa-detect-browser-capabilities"
	mfaWebAuthnNicknamePath = "/u/mfa-webauthn-change-key-nickname"
	mfaWebAuthnSuccessPath  = "/u/mfa-webauthn-enrollment-success"
)

// WebAuthn page steps after a successful enrollment.
const (
	webauthnStepNickname = "nickname"
	webauthnStepSuccess  = "success"
)

// MFAWebAuthnPaths are the hosted WebAuthn MFA paths, served by MFAPage and
// MFASubmit.
var MFAWebAuthnPaths = []string{
	mfaDetectPath,
	"/u/mfa-webauthn-roaming-enrollment", "/u/mfa-webauthn-platform-enrollment",
	"/u/mfa-webauthn-roaming-challenge", "/u/mfa-webauthn-platform-challenge",
	mfaWebAuthnNicknamePath, mfaWebAuthnSuccessPath,
}

// webauthnKind is "roaming" or "platform" for a WebAuthn factor.
func webauthnKind(factor string) string { return strings.TrimPrefix(factor, "webauthn-") }

// fresh is an empty page state that keeps what outlives one factor: the
// switched requirement and the browser capability result.
func (p mfaPageState) fresh() mfaPageState {
	return mfaPageState{Switched: p.Switched, Detected: p.Detected, CanWebAuthn: p.CanWebAuthn, CanPlatform: p.CanPlatform}
}

// needsDetection reports whether the factor choice must wait for the
// browser capability page: a WebAuthn factor could be offered and the
// browser has not reported yet (spec 6.1).
func needsDetection(f *mfaFlow) bool {
	return !f.page.Detected && slices.ContainsFunc(f.pending.Requirement.Factors, mfa.IsWebAuthnFactor)
}

// applyDetection narrows the requirement to what the browser reported: no
// result keeps it (the detection page comes first), no WebAuthn drops both
// WebAuthn factors and no platform authenticator drops device biometrics.
func applyDetection(f *mfaFlow) {
	if !f.page.Detected {
		return
	}
	f.pending.Requirement.Factors = slices.DeleteFunc(slices.Clone(f.pending.Requirement.Factors), func(factor string) bool {
		return factor == mfa.FactorRoaming && !f.page.CanWebAuthn || factor == mfa.FactorPlatform && !(f.page.CanWebAuthn && f.page.CanPlatform)
	})
}

// webauthnInput is the WebAuthn context of a hosted decision made before
// the capability page (see mfa.Service.WebAuthnContext).
func (h *Handlers) webauthnInput(r *http.Request, f *flow) (mfa.WebAuthnInput, error) {
	if h.MFA == nil {
		return mfa.WebAuthnInput{}, nil
	}
	return h.MFA.WebAuthnContext(r.Context(), f.res, r.UserAgent())
}

// webauthnService is the MFA service bound to this hosted transaction.
func (h *Handlers) webauthnService(f *mfaFlow) *mfa.Service {
	svc := h.MFA.WithHostedBinding(f.txn.ID, f.txn.CookieHash)
	if f.pending.Requirement.Reason == "action" {
		svc = svc.WithNewFactorEnrollment()
	}
	return svc
}

// webauthnKeys maps the logical text names a WebAuthn screen documents to
// their catalog keys; platform variants replace the plain names.
func webauthnKeys(prompt, screen string, platform bool) map[string]string {
	documented := webauthnrules.TextKeys(screen)
	out := map[string]string{}
	for _, k := range documented {
		out[k] = prompt + "." + screen + "." + k
	}
	if platform {
		for _, k := range []string{"title", "description", "nickname", "nicknamePlaceholder"} {
			if v, ok := out[k+"Platform"]; ok {
				out[k] = v
			}
		}
	}
	return out
}

// webauthnErrorKey is the screen's documented failure key.
func webauthnErrorKey(f *mfaFlow, enroll bool) string {
	switch {
	case enroll && f.page.Factor == mfa.FactorPlatform:
		return "webauthn-platform-associate-error"
	case enroll:
		return "webauthn-associate-error"
	case f.page.Factor == mfa.FactorPlatform:
		return "webauthn-platform-challenge-error"
	}
	return "webauthn-challenge-error"
}

// domExceptionName is the posted webauthn_error reduced to the closed set
// of DOMException names the page may report (spec 5.2); it is logged only
// as this value and never echoed.
func domExceptionName(v string) string {
	if slices.Contains(webauthnrules.Inventory().DOMExceptionNames, v) {
		return v
	}
	return "UnknownError"
}

// renderWebAuthn renders the current WebAuthn MFA page. The ceremony pages
// issue a fresh bound challenge on every render, so a failed, expired or
// raced attempt always leaves a usable page.
func (h *Handlers) renderWebAuthn(w http.ResponseWriter, r *http.Request, status int, f *mfaFlow, message string) {
	ctx, tid := r.Context(), f.res.Tenant.ID
	page := mfaPage(f)
	view := &ui.WebAuthnView{View: "ceremony"}
	switch f.page.WebAuthnStep {
	case webauthnStepNickname:
		view.View, view.NicknameMax = "nickname", webauthnrules.Limits.NicknameMax
		if a, err := h.Store.MFA().GetAuthenticator(ctx, tid, f.pending.UserID, f.page.AuthenticatorID); err == nil {
			view.Nickname = a.Name
		}
	case webauthnStepSuccess:
		view.View = "success"
	default:
		rp, err := h.MFA.RelyingParty(ctx, f.res)
		if err != nil {
			h.fail(w, r, err, f.flow)
			return
		}
		svc := h.webauthnService(f)
		var doc map[string]any
		if f.pending.Requirement.Enroll {
			e, opts, e2 := svc.BeginWebAuthnEnroll(ctx, tid, f.pending.UserID, f.page.Factor, rp, passkey.UserDisplay{})
			err = e2
			if err == nil {
				f.page.ChallengeID = e.ChallengeID
				var raw []byte
				if raw, err = opts.JSON(); err == nil {
					doc = map[string]any{"mode": "create", "publicKey": json.RawMessage(raw)}
				}
			}
		} else {
			c, opts, e2 := svc.BeginWebAuthnChallenge(ctx, tid, f.pending.UserID, f.page.Factor, rp, webauthn.DeviceOf(r.UserAgent()))
			err = e2
			if err == nil {
				f.page.ChallengeID = c.ID
				var raw []byte
				if raw, err = opts.JSON(); err == nil {
					doc = map[string]any{"mode": "get", "publicKey": json.RawMessage(raw)}
				}
			}
		}
		if errors.Is(err, mfa.ErrNoFactor) {
			h.renderWebAuthnNotice(w, r, f, "mfa_webauthn_not_available", http.StatusBadRequest)
			return
		}
		if err != nil {
			h.fail(w, r, err, f.flow)
			return
		}
		*r = *r.WithContext(logscrub.WithCredentials(r.Context(), f.page.ChallengeID))
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		view.Options = doc
	}
	prompt, screen := ui.MFAScreen(page)
	if !h.prepareHostedForm(w, r, f.flow, prompt, screen) {
		return
	}
	view.Keys = webauthnKeys(prompt, screen, f.page.Factor == mfa.FactorPlatform)
	if f.page.Factor == mfa.FactorRoaming && f.pending.Requirement.Enroll && f.page.WebAuthnStep == "" {
		for _, k := range []string{"instructions1", "instructions2", "instructions3"} {
			if v, ok := view.Keys[k]; ok {
				view.Instructions = append(view.Instructions, v)
			}
		}
	}
	d := ui.MFAData{RedirectURI: f.txn.Params["redirect_uri"], State: f.txn.ID, CSRF: f.txn.CSRFToken, Revision: f.txn.HostedState.Revision,
		Action: mfaPath(f), Error: message, Enroll: f.pending.Requirement.Enroll, WebAuthn: view,
		AllowRemember: f.pending.Requirement.AllowRemember && !f.pending.Requirement.Enroll && view.View == "ceremony"}
	if view.View == "ceremony" {
		d.AnotherURL = mfaURL(f, "/u/mfa") + "&action=another"
	}
	ui.RenderMFA(w, status, f.view, page, d)
}

// renderWebAuthnNotice renders a WebAuthn error screen in place:
// mfa_webauthn_error (the browser stopped the ceremony) or
// mfa_webauthn_not_available (the factor cannot run in this browser).
func (h *Handlers) renderWebAuthnNotice(w http.ResponseWriter, r *http.Request, f *mfaFlow, page string, status int) {
	prompt, screen := ui.MFAScreen(page)
	view := &ui.WebAuthnView{View: "error", Keys: webauthnKeys(prompt, screen, f.page.Factor == mfa.FactorPlatform)}
	if page == "mfa_webauthn_error" {
		view.Keys["title"] = view.Keys["errorTitleChallenge"]
		if f.page.Factor == mfa.FactorPlatform {
			view.Keys["title"] = view.Keys["errorTitlePlatformChallenge"]
		}
		view.RetryURL = mfaURL(f, mfaPath(f))
	} else {
		view.View = "not-available"
		view.Keys["title"], view.Keys["description"] = view.Keys["errorTitle"], view.Keys["errorDescription"]
	}
	d := ui.MFAData{RedirectURI: f.txn.Params["redirect_uri"], State: f.txn.ID, CSRF: f.txn.CSRFToken, Revision: f.txn.HostedState.Revision, WebAuthn: view}
	if others := slices.DeleteFunc(slices.Clone(f.pending.Requirement.Factors), func(v string) bool { return v == f.page.Factor }); len(others) > 0 {
		d.AnotherURL = mfaURL(f, "/u/mfa") + "&action=another"
	}
	ui.RenderMFA(w, status, f.view, page, d)
}

// renderDetect renders mfa-detect-browser-capabilities: the page script
// posts what the browser supports; without script the user continues with
// another method.
func (h *Handlers) renderDetect(w http.ResponseWriter, r *http.Request, f *mfaFlow) {
	prompt, screen := ui.MFAScreen("mfa_detect")
	if !h.prepareHostedForm(w, r, f.flow, prompt, screen) {
		return
	}
	view := &ui.WebAuthnView{View: "detect", Options: map[string]any{"mode": "detect"}, DetectURL: mfaURL(f, mfaDetectPath)}
	ui.RenderMFA(w, http.StatusOK, f.view, "mfa_detect", ui.MFAData{RedirectURI: f.txn.Params["redirect_uri"], State: f.txn.ID, CSRF: f.txn.CSRFToken, Revision: f.txn.HostedState.Revision, Action: mfaDetectPath, WebAuthn: view})
}

// submitDetect stores the capability result and returns to /u/mfa. An
// absent value means the capability is unavailable.
func (h *Handlers) submitDetect(w http.ResponseWriter, r *http.Request, f *mfaFlow) {
	prompt, screen := ui.MFAScreen("mfa_detect")
	if !h.guardHostedForm(w, r, f.flow, prompt, screen, func(int, string) { h.renderDetect(w, r, f) }) {
		return
	}
	if f.page.Proven || f.page.RecoveryPending {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	next := f.page.fresh()
	next.Factor = ""
	next.Detected = true
	next.CanWebAuthn = r.PostForm.Get("webauthn") == "yes"
	next.CanPlatform = next.CanWebAuthn && r.PostForm.Get("platform") == "yes"
	f.page = next
	if err := h.saveMFAPage(r, f, "mfa-page"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	http.Redirect(w, r, mfaURL(f, "/u/mfa"), http.StatusSeeOther)
}

// webauthnPageFactor returns the WebAuthn factor a GET of path addresses,
// or "" when path is not a WebAuthn ceremony path for this requirement.
func webauthnPageFactor(f *mfaFlow, path string) string {
	for _, factor := range []string{mfa.FactorRoaming, mfa.FactorPlatform} {
		kind := webauthnKind(factor)
		if f.pending.Requirement.Enroll && path == "/u/mfa-webauthn-"+kind+"-enrollment" || !f.pending.Requirement.Enroll && path == "/u/mfa-webauthn-"+kind+"-challenge" {
			return factor
		}
	}
	return ""
}

// webauthnStepPath reports whether path is the page of the current
// post-enrollment step.
func webauthnStepPath(f *mfaFlow, path string) bool {
	return mfa.IsWebAuthnFactor(f.page.Factor) && f.page.Proven && !f.page.RecoveryPending &&
		(path == mfaWebAuthnNicknamePath && f.page.WebAuthnStep == webauthnStepNickname || path == mfaWebAuthnSuccessPath && f.page.WebAuthnStep == webauthnStepSuccess)
}

// submitWebAuthn handles a POST to the current WebAuthn MFA page.
func (h *Handlers) submitWebAuthn(w http.ResponseWriter, r *http.Request, f *mfaFlow, prompt, screen string) {
	ctx, tid, uid := r.Context(), f.res.Tenant.ID, f.pending.UserID
	switch f.page.WebAuthnStep {
	case webauthnStepNickname:
		name := strings.TrimSpace(r.PostForm.Get("nickname"))
		if !mfa.ValidNickname(name) {
			key := "nickname-too-long"
			if name == "" {
				key = "no-nickname"
			} else if utf8.RuneCountInString(name) < webauthnrules.Limits.NicknameMin {
				key = "nickname-too-short"
			}
			h.renderWebAuthn(w, r, http.StatusBadRequest, f, f.view.L.T(prompt+"."+screen+"."+key))
			return
		}
		if err := h.MFA.RenameWebAuthn(ctx, tid, uid, f.page.AuthenticatorID, name); err != nil {
			key := "error-while-patching"
			if errors.Is(err, store.ErrNotFound) {
				key = "error-while-retrieving-authenticator"
			}
			h.renderWebAuthn(w, r, http.StatusBadRequest, f, f.view.L.T(prompt+"."+screen+"."+key))
			return
		}
		f.page.WebAuthnStep = webauthnStepSuccess
		if err := h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		http.Redirect(w, r, mfaURL(f, mfaPath(f)), http.StatusSeeOther)
		return
	case webauthnStepSuccess:
		if err := h.saveMFAPage(r, f, "mfa-busy"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		h.finishMFA(w, r, f)
		return
	}
	if f.page.Proven {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	rp, err := h.MFA.RelyingParty(ctx, f.res)
	if err != nil {
		h.fail(w, r, err, f.flow)
		return
	}
	if !rp.Valid {
		h.renderWebAuthnNotice(w, r, f, "mfa_webauthn_not_available", http.StatusBadRequest)
		return
	}
	enroll := f.pending.Requirement.Enroll
	if name := r.PostForm.Get("webauthn_error"); name != "" && r.PostForm.Get("credential") == "" {
		h.MFA.ReportWebAuthnError(ctx, tid, uid, f.page.Factor, enroll, domExceptionName(name))
		if enroll {
			h.renderWebAuthn(w, r, http.StatusBadRequest, f, f.view.L.T(prompt+"."+screen+"."+webauthnErrorKey(f, true)))
		} else {
			h.renderWebAuthnNotice(w, r, f, "mfa_webauthn_error", http.StatusBadRequest)
		}
		return
	}
	raw := r.PostForm.Get("credential")
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), raw, f.page.ChallengeID))
	if err = h.saveMFAPage(r, f, "mfa-busy"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if enroll {
		h.confirmWebAuthn(w, r, f, rp, raw, prompt, screen)
		return
	}
	svc := h.webauthnService(f)
	c := &mfa.Challenge{ID: f.page.ChallengeID, Factor: f.page.Factor, RPID: rp.RPID, Origin: rp.Origin, DeviceKey: webauthn.DeviceOf(r.UserAgent()).Key()}
	if err = svc.VerifyWebAuthn(ctx, tid, uid, c, []byte(raw)); err != nil {
		if e := h.saveMFAPage(r, f, "mfa-page"); e != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		key, status := webauthnErrorKey(f, false), http.StatusBadRequest
		if errors.Is(err, mfa.ErrThrottled) {
			key, status = "too-many-webauthn-challenge-attempts-error", http.StatusTooManyRequests
		} else if !errors.Is(err, mfa.ErrInvalidCode) {
			h.fail(w, r, err, f.flow)
			return
		}
		h.renderWebAuthn(w, r, status, f, f.view.L.T(prompt+"."+screen+"."+key))
		return
	}
	f.page.Proven = true
	f.page.Remember = f.pending.Requirement.AllowRemember && r.PostForm.Get("remember") == "yes"
	h.finishMFA(w, r, f)
}

// confirmWebAuthn finishes a WebAuthn enrollment ceremony: it confirms the
// registration (spending a ticket in the same transaction), then shows the
// first recovery code when one was created and continues to the nickname
// screen.
func (h *Handlers) confirmWebAuthn(w http.ResponseWriter, r *http.Request, f *mfaFlow, rp rpid.Result, raw, prompt, screen string) {
	ctx, tid, uid := r.Context(), f.res.Tenant.ID, f.pending.UserID
	svc := h.webauthnService(f)
	if f.pending.Requirement.Reason == "ticket" {
		hash := f.pending.TicketHash
		svc = svc.WithProofCommit(func(tx store.Store) error {
			t, e := tx.MFA().ConsumeTicket(ctx, tid, hash, h.now())
			if errors.Is(e, store.ErrNotFound) || e == nil && t.UserID != uid {
				return mfa.ErrInvalidCode
			}
			return e
		})
	}
	confirm := svc.ConfirmWebAuthnEnroll
	if firstOnlyEnrollment(f.pending) || f.pending.Requirement.Reason == "ticket" && !f.pending.TicketAllowMultiple {
		confirm = svc.ConfirmFirstWebAuthnEnroll
	}
	e := &mfa.Enrollment{Factor: f.page.Factor, ChallengeID: f.page.ChallengeID, RPID: rp.RPID, Origin: rp.Origin}
	result, err := confirm(ctx, tid, uid, e, []byte(raw), "", r.UserAgent())
	if errors.Is(err, mfa.ErrAlreadyEnrolled) && firstOnlyEnrollment(f.pending) {
		f.page = f.page.fresh()
		h.restartSwitchedMFA(w, r, f)
		return
	}
	if err != nil {
		if e := h.saveMFAPage(r, f, "mfa-page"); e != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		if !errors.Is(err, mfa.ErrInvalidCode) && !errors.Is(err, mfa.ErrThrottled) {
			h.fail(w, r, err, f.flow)
			return
		}
		h.renderWebAuthn(w, r, http.StatusBadRequest, f, f.view.L.T(prompt+"."+screen+"."+webauthnErrorKey(f, true)))
		return
	}
	f.page.Proven = true
	f.page.AuthenticatorID = result.AuthenticatorID
	f.page.ChallengeID = ""
	f.page.WebAuthnStep = webauthnStepNickname
	if result.RecoveryCode != "" {
		f.page.RecoveryPending = true
		if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
			h.fail(w, r, errTxn, f.flow)
			return
		}
		*r = *r.WithContext(logscrub.WithCredentials(r.Context(), result.RecoveryCode))
		h.renderMFA(w, r, http.StatusOK, f, result.RecoveryCode, "")
		return
	}
	if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	http.Redirect(w, r, mfaURL(f, mfaPath(f)), http.StatusSeeOther)
}

// webauthnFactorLabel is a WebAuthn factor's label on the factor lists.
func webauthnFactorLabel(l *i18n.Localizer, factor string) string {
	if factor == mfa.FactorPlatform {
		return l.T(i18n.KeyWebAuthnPlatformFactor)
	}
	return l.T(i18n.KeyWebAuthnRoamingFactor)
}
