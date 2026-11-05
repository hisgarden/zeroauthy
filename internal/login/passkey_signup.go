package login

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/signupactions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"html/template"
	"slices"
)

// Split signup (spec section 3.4, LR33b-15): only when passkeys are
// effective. The identifier step collects the account details, then the
// passkey-enrollment step offers a passkey or a password, and the password
// choice falls through to the existing Plan 22/34 signup rules.
const (
	signupStepIdentifier = "signup-identifier"
	signupStepPasskey    = "signup-passkey"
	signupStepPassword   = "signup-password"
)

// splitSignup reports whether this transaction uses the split flow. It is
// false without effective passkeys, and false for an invitation signup,
// which never shows the passkey choice (LR33b-32).
func (h *Handlers) splitSignup(r *http.Request, f *flow) bool {
	if h.Passkeys == nil || f.txn.Params[orglogin.InvitationIDParam] != "" {
		return false
	}
	_, _, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	return err == nil && effective
}

func signupIdentifierLocation(f *flow) string {
	return "/u/signup/identifier?" + url.Values{"state": {f.txn.ID}}.Encode()
}
func signupPasskeyLocation(f *flow) string {
	return "/u/signup/passkey?" + url.Values{"state": {f.txn.ID}}.Encode()
}
func signupPasswordLocation(f *flow) string {
	return "/u/signup/password?" + url.Values{"state": {f.txn.ID}}.Encode()
}

// SignupIdentifierGet is the split flow's first step.
func (h *Handlers) SignupIdentifierGet(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !h.splitSignup(r, f) {
		http.Redirect(w, r, "/u/signup?"+url.Values{"state": {f.txn.ID}}.Encode(), http.StatusSeeOther)
		return
	}
	if step := f.txn.HostedState.Step; step != "" && step != signupStepIdentifier {
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.captchaPage(w, r, f, "signup") {
		return
	}
	h.renderSignupIdentifier(w, r, http.StatusOK, f, h.signupStageData(f, r))
}

// SignupIdentifierPost collects the identifier and moves to the passkey
// choice. Nothing is written yet.
func (h *Handlers) SignupIdentifierPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	if !h.splitSignup(r, f) {
		h.SignupSubmit(w, r)
		return
	}
	data := h.signupStageData(f, r)
	if !h.guardHostedForm(w, r, f, "signup-id", "signup-id", func(status int, message string) {
		data.Error = message
		h.renderSignupIdentifier(w, r, status, f, data)
	}) {
		return
	}
	if err := h.checkSignupIdentifier(f, r, data); err != nil {
		var pe *identity.PolicyError
		if errors.As(err, &pe) {
			data.Error = policyMessage(f.view.L, pe)
		} else {
			h.fail(w, r, err, f)
			return
		}
		h.renderSignupIdentifier(w, r, http.StatusBadRequest, f, data)
		return
	}
	// Record the collected details before advancing, so no later step can
	// change them.
	if err := h.storeSignupIdentifier(r, f, data, signupStepPasskey); err != nil {
		h.fail(w, r, err, f)
		return
	}
	http.Redirect(w, r, signupPasskeyLocation(f), http.StatusSeeOther)
}

// SignupPasswordGet is the "create a password" choice.
func (h *Handlers) SignupPasswordGet(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if f.txn.HostedState.Step != signupStepPasskey && f.txn.HostedState.Step != signupStepPassword {
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.captchaPage(w, r, f, "signup") {
		return
	}
	h.renderSignupPassword(w, r, http.StatusOK, f, h.signupStageData(f, r))
}

// SignupPasswordPost runs the ordinary signup with the identifier the first
// step stored, so the passkey choice cannot be used to change it.
func (h *Handlers) SignupPasswordPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	if f.txn.HostedState.Step != signupStepPasskey && f.txn.HostedState.Step != signupStepPassword {
		h.fail(w, r, errTxn, f)
		return
	}
	if !postedHostedRevision(r, f) {
		h.fail(w, r, errTxn, f)
		return
	}
	// The step is already signup-passkey or signup-password here; SignupSubmit
	// runs the hosted-form guard itself, so the revision must not move first.
	// Restore the identifier the first step stored, so the password step
	// cannot be used to change it, then run the ordinary signup.
	r.PostForm.Set("email", f.txn.Params[signupEmailParam])
	r.PostForm.Set("username", f.txn.Params[signupUsernameParam])
	if phone := f.txn.Params[signupPhoneParam]; phone != "" {
		r.PostForm.Set("phone_number", phone)
	}
	h.SignupSubmit(w, r)
}

// signupStageData rebuilds the collected account details from the
// transaction, so every step works from what the first step stored.
func (h *Handlers) signupStageData(f *flow, r *http.Request) ui.SignupData {
	email, username := f.txn.Params[signupEmailParam], f.txn.Params[signupUsernameParam]
	if email == "" {
		email = r.PostForm.Get("email")
	}
	if username == "" {
		username = r.PostForm.Get("username")
	}
	return ui.SignupData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken, Email: email, Username: username,
		PhoneNumber:      f.txn.Params[signupPhoneParam],
		RequiresUsername: f.conn.RequiresUsername,
		LoginURL:         "/u/login?" + url.Values{"state": {f.txn.ID}}.Encode(),
		RedirectURI:      f.txn.Params["redirect_uri"],
		Revision:         f.txn.HostedState.Revision,
		BackURL:          signupIdentifierLocation(f),
		PasskeyAction:    "/u/signup/passkey",
		PasswordAction:   "/u/signup/password",
	}
}

const (
	signupEmailParam    = "za_signup_email"
	signupUsernameParam = "za_signup_username"
	signupPhoneParam    = "za_signup_phone"
)

// checkSignupIdentifier validates the account details the first step
// collected, without writing anything.
func (h *Handlers) checkSignupIdentifier(f *flow, r *http.Request, data ui.SignupData) error {
	email, username := strings.TrimSpace(r.PostForm.Get("email")), strings.TrimSpace(r.PostForm.Get("username"))
	phone := r.PostForm.Get("phone_number")
	switch {
	case store.PhoneSignupStatus(f.conn) == "not_allowed" && phone != "":
		return &identity.PolicyError{Reason: "Phone number is not allowed at signup"}
	case store.PhoneSignupStatus(f.conn) == "required" && phone == "":
		return &identity.PolicyError{Reason: "Phone number is required"}
	case email == "" && !store.PhoneIdentifierActive(f.conn):
		return identity.CheckEmail("")
	case f.conn.RequiresUsername && username == "":
		return identity.CheckUsername(f.conn, "")
	}
	if email != "" {
		if err := identity.CheckEmail(email); err != nil {
			return err
		}
	}
	if username != "" {
		if err := identity.CheckUsername(f.conn, username); err != nil {
			return err
		}
	}
	return nil
}

// storeSignupIdentifier records the collected details in the transaction,
// so no later step can change them. The write follows orglogin's pattern:
// compare-and-swap the hosted state, then rewrite the row's parameters.
func (h *Handlers) storeSignupIdentifier(r *http.Request, f *flow, data ui.SignupData, step string) error {
	ctx := r.Context()
	tid := f.res.Tenant.ID
	cur, err := h.Store.AuthTransactions().Get(ctx, tid, f.txn.ID)
	if err != nil {
		return err
	}
	if cur.Params == nil {
		cur.Params = map[string]string{}
	}
	cur.Params[signupEmailParam] = strings.TrimSpace(r.PostForm.Get("email"))
	cur.Params[signupUsernameParam] = strings.TrimSpace(r.PostForm.Get("username"))
	cur.Params[signupPhoneParam] = r.PostForm.Get("phone_number")
	cur.HostedState.Step = step
	if err := h.Store.AuthTransactions().CompareAndSwapHosted(ctx, tid, cur.ID, cur.HostedState.Revision, cur.HostedState, h.now()); err != nil {
		return err
	}
	cur.HostedState.Revision++
	if err := h.Store.AuthTransactions().Delete(ctx, tid, cur.ID); err != nil {
		return err
	}
	if err := h.Store.AuthTransactions().Create(ctx, cur); err != nil {
		return err
	}
	f.txn = cur
	return nil
}

// renderSignupIdentifier renders the split flow's first step.
func (h *Handlers) renderSignupIdentifier(w http.ResponseWriter, r *http.Request, status int, f *flow, data ui.SignupData) {
	if !h.prepareHostedForm(w, r, f, "signup-id", "signup-id") {
		return
	}
	data.Revision = f.txn.HostedState.Revision
	data.EmailCodeEnabled = h.codeTemplateEnabled(r.Context(), f.res.Tenant.ID, "verify_email_by_code")
	data.PhoneEnabled = store.PhoneIdentifierActive(f.conn) && store.PhoneSignupStatus(f.conn) != "not_allowed"
	ui.RenderSignupIdentifier(w, status, f.view, data)
}

// renderSignupPassword renders the split flow's password step.
func (h *Handlers) renderSignupPassword(w http.ResponseWriter, r *http.Request, status int, f *flow, data ui.SignupData) {
	if !h.prepareHostedForm(w, r, f, "signup-password", "signup-password") {
		return
	}
	data.Revision = f.txn.HostedState.Revision
	data.EmailCodeEnabled = h.codeTemplateEnabled(r.Context(), f.res.Tenant.ID, "verify_email_by_code")
	data.PhoneEnabled = store.PhoneIdentifierActive(f.conn) && store.PhoneSignupStatus(f.conn) != "not_allowed"
	ui.RenderSignupPassword(w, status, f.view, data)
}

// SignupPasskeyGet is the passkey-enrollment step: it issues a registration
// challenge bound to the transaction and its browser cookie.
func (h *Handlers) SignupPasskeyGet(w http.ResponseWriter, r *http.Request) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if f.txn.HostedState.Step != signupStepPasskey {
		h.fail(w, r, errTxn, f)
		return
	}
	if !h.captchaPage(w, r, f, "signup") {
		return
	}
	h.renderPasskeyEnrollment(w, r, http.StatusOK, f, h.signupStageData(f, r))
}

// renderPasskeyEnrollment issues a challenge and renders the screen. The
// page also offers a plain form whose "create a password" submit works
// without JavaScript (Review Focus 4).
func (h *Handlers) renderPasskeyEnrollment(w http.ResponseWriter, r *http.Request, status int, f *flow, data ui.SignupData) {
	if !h.prepareHostedForm(w, r, f, "passkeys", "passkey-enrollment") {
		return
	}
	data.Revision = f.txn.HostedState.Revision
	markup, err := h.signupPasskeyMarkup(r, f, data)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	data.Passkey = markup
	ui.RenderPasskeyEnrollment(w, status, f.view, data)
}

// signupPasskeyMarkup issues the signup registration challenge. The user
// does not exist yet, so the challenge carries no user (Task 8's
// ChallengeUserOptional) and the draft's handle is derived from it.
func (h *Handlers) signupPasskeyMarkup(r *http.Request, f *flow, data ui.SignupData) (*ui.PasskeyEnrollmentData, error) {
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil || !effective || !rp.Valid {
		return nil, err
	}
	b := passkey.Binding{
		Purpose: passkey.PurposePasskeyRegister, RPID: rp.RPID,
		Origins: []string{f.res.Origin()}, TxnID: f.txn.ID, CookieHash: f.txn.CookieHash,
	}
	issued, err := h.Passkeys.Issue(r.Context(), f.res.Tenant.ID, b, 0)
	if err != nil {
		return nil, err
	}
	// The account does not exist yet: CreationOptions takes the draft the
	// signup will create, whose display name is the collected identifier.
	display := passkey.UserDisplay{Name: data.Email, DisplayName: data.Email}
	if display.Name == "" {
		display.Name, display.DisplayName = data.Username, data.Username
	}
	draft := &store.User{TenantID: f.res.Tenant.ID, Email: display.Name, Username: data.Username, Name: display.DisplayName}
	opts, err := h.Passkeys.CreationOptions(r.Context(), f.res.Tenant.ID, draft, display, rp.RPID, passkey.Signup, issued.Challenge, 0)
	if err != nil {
		return nil, err
	}
	raw, err := opts.JSON()
	if err != nil {
		return nil, err
	}
	return &ui.PasskeyEnrollmentData{
		ChallengeID: issued.ID,
		Options:     template.JS(raw),
		Creation:    true,
		CreateText:  f.view.L.T("passkeys.passkey-enrollment.createButtonText"),
	}, nil
}

// SignupPasskeyPost runs the signup registration ceremony. The user and the
// passkey are written in one transaction after pre-user-registration
// succeeds, and the account is created with no password.
func (h *Handlers) SignupPasskeyPost(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	if f.txn.HostedState.Step != signupStepPasskey {
		h.fail(w, r, errTxn, f)
		return
	}
	if !postedHostedRevision(r, f) {
		h.fail(w, r, errTxn, f)
		return
	}
	data := h.signupStageData(f, r)
	h.signupWithPasskey(w, r, f, data)
}

// signupWithPasskey is the passkey branch: validation, protection, the two
// registration Actions, and one atomic user-plus-passkey write.
func (h *Handlers) signupWithPasskey(w http.ResponseWriter, r *http.Request, f *flow, data ui.SignupData) {
	h.withFlowEvent(r, f)
	code := "fs"
	var eventUser *store.User
	defer func() { h.event(r, f, code, eventUser) }()

	if !organizationSignupAllowed(f) || f.conn.DisableSignup {
		ui.RenderError(w, http.StatusForbidden, f.view, f.view.L.T(i18n.KeyErrSignupDisabled))
		return
	}
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, f.conn)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !effective || !rp.Valid {
		h.passkeyEnrollmentFailure(w, r, f, data, string(webauthn.ReasonRPID))
		return
	}
	svc := h.protectionService()
	decision, err := svc.Begin(r.Context(), protection.Attempt{
		Tenant: f.res.Tenant, Connection: f.conn, Identifier: data.Email, IP: httpx.ClientIP(r, h.TrustProxyHeaders), Flow: "signup",
	})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		data.Error = f.view.L.T(i18n.KeyTooManyAttempts)
		h.renderPasskeyEnrollment(w, r, http.StatusTooManyRequests, f, data)
		return
	}
	// Registration spends its token before email-in-use can be revealed (R3).
	if err := svc.Finish(r.Context(), decision.Receipt, "failure"); err != nil {
		h.fail(w, r, err, f)
		return
	}
	attemptID := secrets.RandomString(32)

	if posted := r.PostForm.Get("webauthn_error"); posted != "" {
		name := "UnknownError"
		if slices.Contains(webauthnErrorNames, posted) {
			name = posted
		}
		h.passkeyEnrollmentFailure(w, r, f, data, name)
		return
	}
	raw := r.PostForm.Get("credential")
	if raw == "" {
		h.passkeyEnrollmentFailure(w, r, f, data, string(webauthn.ReasonParse))
		return
	}
	b := passkey.Binding{
		Purpose: passkey.PurposePasskeyRegister, RPID: rp.RPID,
		Origins: []string{f.res.Origin()}, TxnID: f.txn.ID, CookieHash: f.txn.CookieHash,
	}
	challenge, err := h.Passkeys.Take(r.Context(), f.res.Tenant.ID, r.PostForm.Get("challenge_id"), b)
	if err != nil {
		h.passkeyEnrollmentFailure(w, r, f, data, string(webauthn.ReasonChallenge))
		return
	}

	callbacks, err := h.signupFlowCallbacks(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	// pre-user-registration runs before any write: the draft is built first
	// so the Action sees the account the passkey will belong to.
	draft, err := h.signupDraft(r, f, data, callbacks)
	if err != nil {
		h.signupDraftFailure(w, r, f, data, err, &eventUser, &code)
		return
	}
	user, _, err := h.Passkeys.Signup(r.Context(), f.res.Tenant.ID, draft, []byte(raw), challenge, b, r.UserAgent())
	if err != nil {
		if riskErr := h.recordFailure(r, f.res, "signup", attemptID, err); riskErr != nil {
			h.fail(w, r, riskErr, f)
			return
		}
		if errors.Is(err, passkey.ErrCeremony) {
			h.passkeyEnrollmentFailure(w, r, f, data, webauthn.Reason(err))
			return
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, identity.ErrUserExists) {
			data.Error = f.view.L.T(i18n.KeyEmailInUse)
			h.renderPasskeyEnrollment(w, r, http.StatusBadRequest, f, data)
			return
		}
		h.fail(w, r, err, f)
		return
	}
	code, eventUser = "ss", user
	h.eventWithDetails(r, f, "ss", user, map[string]any{"authentication_methods": []string{"passkey"}})
	h.sendSignupVerification(f, user)
	h.completeWithMethods(w, r, f, user, store.AuthMethod{Name: "passkey", At: h.now()})
}

// signupDraft builds the user the passkey will belong to, running
// pre-user-registration through the callbacks' Run hook exactly as the
// password path does. The account carries no password.
func (h *Handlers) signupDraft(r *http.Request, f *flow, data ui.SignupData, callbacks identity.SignupActions) (*store.User, error) {
	draft := &store.User{
		TenantID: f.res.Tenant.ID,
		Email:    identity.NormalizeLogin(data.Email),
		Username: strings.TrimSpace(data.Username),
		Name:     data.Username,
		Identities: []store.Identity{{
			Connection: f.conn.Name, Provider: store.StrategyDatabase,
		}},
	}
	if draft.Name == "" {
		draft.Name = draft.Email
	}
	if callbacks.Run != nil {
		if _, err := callbacks.Run(r.Context(), draft); err != nil {
			return nil, err
		}
	}
	return draft, nil
}

// signupDraftFailure maps a pre-registration refusal onto the screen.
func (h *Handlers) signupDraftFailure(w http.ResponseWriter, r *http.Request, f *flow, data ui.SignupData, err error, eventUser **store.User, code *string) {
	var denied *identity.ErrSignupDenied
	var failed *identity.ErrSignupActionFailed
	var pe *identity.PolicyError
	switch {
	case errors.As(err, &denied):
		data.Error = denied.Description
		h.renderPasskeyEnrollment(w, r, http.StatusBadRequest, f, data)
	case errors.As(err, &failed):
		ui.RenderErrorReference(w, http.StatusBadRequest, f.view, f.view.L.T(i18n.KeyErrServer), failed.ExecutionID)
	case errors.As(err, &pe):
		data.Error = policyMessage(f.view.L, pe)
		h.renderPasskeyEnrollment(w, r, http.StatusBadRequest, f, data)
	default:
		h.fail(w, r, err, f)
	}
}

// signupFlowCallbacks builds the signup Action callbacks shared with the
// password path.
func (h *Handlers) signupFlowCallbacks(r *http.Request, f *flow) (identity.SignupActions, error) {
	if h.Actions == nil {
		return signupactions.Callbacks(h.Store, nil, actions.RegistrationInput{Tenant: f.res, Connection: f.conn, Transaction: &actions.TransactionInfo{ID: f.txn.ID}}), nil
	}
	client, err := h.Store.Clients().Get(r.Context(), f.res.Tenant.ID, f.txn.ClientID)
	if err != nil {
		return identity.SignupActions{}, err
	}
	body := map[string]any{}
	for k, v := range r.PostForm {
		if len(v) == 1 {
			body[k] = v[0]
		} else {
			body[k] = v
		}
	}
	input := signupactions.Input(r, f.res, client, f.conn, body, h.TrustProxyHeaders)
	input = signupactions.WithOrganization(input, f.org.Org)
	p := f.txn.Params
	input.Transaction = &actions.TransactionInfo{ID: f.txn.ID, Locale: f.view.L.Lang(), Protocol: actions.ProtocolOIDCBasicProfile, RedirectURI: p["redirect_uri"], RequestedScopes: strings.Fields(p["scope"]), ResponseMode: p["response_mode"], ResponseType: p["response_type"], State: p["state"], UILocales: p["ui_locales"], Prompt: p["prompt"], LoginHint: p["login_hint"], ACRValues: p["acr_values"]}
	return signupactions.Callbacks(h.Store, h.Actions, input), nil
}

// passkeyEnrollmentFailure logs the enrollment failure and re-renders with a
// fresh challenge. The reason is bounded and neither the challenge nor the
// credential reaches the page or a log.
func (h *Handlers) passkeyEnrollmentFailure(w http.ResponseWriter, r *http.Request, f *flow, data ui.SignupData, reason string) {
	h.eventWithDetails(r, f, "gd_webauthn_enrollment_failed", nil, map[string]any{
		"authentication_methods": []string{"passkey"},
		"failure_details":        map[string]any{"errorCode": boundedReason(reason)},
	})
	data.Error = f.view.L.T("passkeys.passkey-enrollment.passkey-enrollment-failure")
	h.renderPasskeyEnrollment(w, r, http.StatusBadRequest, f, data)
}
