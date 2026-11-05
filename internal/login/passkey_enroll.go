package login

import (
	"errors"
	"html/template"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

// Post-login passkey enrollment (spec section 3.5): the progressive offer
// after a password login and the device-local offer after a cross-device
// passkey login. Both are bound to the login transaction, its browser cookie
// and a single-use challenge; both can be skipped for this login only, or
// snoozed for 30 days.

// storedTxn re-reads the transaction and checks it is this browser's and is
// waiting on the passkey prompt.
func (h *Handlers) enrollTxn(r *http.Request, f *flow) (*store.AuthTransaction, error) {
	stored, err := h.Store.AuthTransactions().Get(r.Context(), f.res.Tenant.ID, f.txn.ID)
	if err != nil {
		return nil, errTxn
	}
	if stored.Params[authz.ParamStage] != authz.StagePasskeyPrompt || !h.now().Before(stored.ExpiresAt) || f.res.CheckOrigin(stored.Origin) != nil {
		return nil, errTxn
	}
	cookie, err := r.Cookie(authz.TxnCookiePrefix + stored.ID)
	if err != nil || secrets.HashToken(cookie.Value) != stored.CookieHash {
		return nil, errTxn
	}
	return stored, nil
}

// enrollSession is the session the prompt belongs to, from the transaction.
func (h *Handlers) enrollSession(r *http.Request, f *flow, stored *store.AuthTransaction) (*store.LoginSession, error) {
	id := stored.Params["za_session"]
	if id == "" {
		return nil, errTxn
	}
	sess, err := h.Store.Sessions().Get(r.Context(), f.res.Tenant.ID, id)
	if err != nil || !h.now().Before(sess.ExpiresAt) || !h.now().Before(sess.IdleExpiresAt) {
		return nil, errTxn
	}
	return sess, nil
}

// PasskeyEnrollmentGet serves both enrollment screens.
func (h *Handlers) PasskeyEnrollmentGet(w http.ResponseWriter, r *http.Request) {
	h.passkeyEnrollmentPage(w, r, false)
}
func (h *Handlers) PasskeyEnrollmentLocalGet(w http.ResponseWriter, r *http.Request) {
	h.passkeyEnrollmentPage(w, r, true)
}

func (h *Handlers) passkeyEnrollmentPage(w http.ResponseWriter, r *http.Request, local bool) {
	f, err := h.load(r, r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	stored, err := h.enrollTxn(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	kind := stored.Params[authz.ParamPasskeyPrompt]
	want := passkey.PromptProgressive
	if local {
		want = passkey.PromptLocal
	}
	// A direct GET for the other variant, or without a pending prompt, is the
	// session-expired page.
	if kind != want {
		h.fail(w, r, errTxn, f)
		return
	}
	sess, err := h.enrollSession(r, f, stored)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, sess.UserID)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.renderPasskeyEnroll(w, r, http.StatusOK, f, stored, u, local)
}

// userConnection is the user's own connection in this tenant, or nil.
func (h *Handlers) userConnection(r *http.Request, f *flow, u *store.User) (*store.Connection, error) {
	if u == nil {
		return nil, nil
	}
	for _, id := range u.Identities {
		c, err := h.Store.Connections().GetByName(r.Context(), f.res.Tenant.ID, id.Connection)
		if err == nil {
			return c, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	return nil, nil
}

// enrollScreen is the prompt/screen pair of an enrollment variant.
func enrollScreen(local bool) (string, string) {
	if local {
		return "passkeys", "passkey-enrollment-local"
	}
	return "passkeys", "passkey-enrollment"
}

// renderPasskeyEnroll issues a fresh challenge and renders the screen.
func (h *Handlers) renderPasskeyEnroll(w http.ResponseWriter, r *http.Request, status int, f *flow, stored *store.AuthTransaction, u *store.User, local bool) {
	prompt, screen := enrollScreen(local)
	if !h.prepareHostedForm(w, r, f, prompt, screen) {
		return
	}
	data := h.enrollData(f, stored, local)
	markup, err := h.enrollMarkup(r, f, stored, u, local)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	data.Passkey = markup
	ui.RenderPasskeyEnrollment(w, status, f.view, data)
}

// enrollData is the screen's non-WebAuthn state.
func (h *Handlers) enrollData(f *flow, stored *store.AuthTransaction, local bool) ui.SignupData {
	return ui.SignupData{
		State: f.txn.ID, CSRF: f.txn.CSRFToken,
		Revision:       revisionOf(f),
		RedirectURI:    stored.Params["redirect_uri"],
		PasskeyAction:  enrollAction(local),
		PasswordAction: enrollAction(local) + "?decision=skip",
		SecondaryText:  f.view.L.T("passkeys." + screenName(local) + ".continueButtonText"),
	}
}

func enrollAction(local bool) string {
	if local {
		return "/u/passkey-enrollment-local"
	}
	return "/u/passkey-enrollment"
}

// revisionOf is the hosted form revision of the current transaction.
func revisionOf(f *flow) int64 {
	if f.txn == nil {
		return 0
	}
	return f.txn.HostedState.Revision
}

// enrollMarkup issues the creation challenge for the prompt. Progressive
// enrollment excludes the user's credentials for this RP ID (CreationOptions
// does that for a non-signup kind); local enrollment asks for a platform
// authenticator.
func (h *Handlers) enrollMarkup(r *http.Request, f *flow, stored *store.AuthTransaction, u *store.User, local bool) (*ui.PasskeyEnrollmentData, error) {
	conn, err := h.userConnection(r, f, u)
	if err != nil {
		return nil, err
	}
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, conn)
	if err != nil {
		return nil, err
	}
	if !effective || !rp.Valid {
		return nil, errTxn
	}
	kind := passkey.Progressive
	if local {
		kind = passkey.Local
	}
	b := passkey.Binding{
		Purpose: passkey.PurposePasskeyRegister, RPID: rp.RPID, Origins: []string{f.res.Origin()},
		TxnID: f.txn.ID, CookieHash: stored.CookieHash, UserID: u.UserID,
	}
	issued, err := h.Passkeys.Issue(r.Context(), f.res.Tenant.ID, b, 0)
	if err != nil {
		return nil, err
	}
	opts, err := h.Passkeys.CreationOptions(r.Context(), f.res.Tenant.ID, u, passkey.Display(u, conn), rp.RPID, kind, issued.Challenge, 0)
	if err != nil {
		return nil, err
	}
	raw, err := opts.JSON()
	if err != nil {
		return nil, err
	}
	text := f.view.L.T("passkeys." + screenName(local) + ".createButtonText")
	return &ui.PasskeyEnrollmentData{ChallengeID: issued.ID, Options: template.JS(raw), Creation: true, Local: local, CreateText: text}, nil
}

func screenName(local bool) string {
	if local {
		return "passkey-enrollment-local"
	}
	return "passkey-enrollment"
}

// PasskeyEnrollmentPost handles both the enrollment ceremony and the two
// skip choices.
func (h *Handlers) PasskeyEnrollmentPost(w http.ResponseWriter, r *http.Request) {
	h.passkeyEnrollmentSubmit(w, r, false)
}
func (h *Handlers) PasskeyEnrollmentLocalPost(w http.ResponseWriter, r *http.Request) {
	h.passkeyEnrollmentSubmit(w, r, true)
}

func (h *Handlers) passkeyEnrollmentSubmit(w http.ResponseWriter, r *http.Request, local bool) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	stored, err := h.enrollTxn(r, f)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	kind := stored.Params[authz.ParamPasskeyPrompt]
	want := passkey.PromptProgressive
	if local {
		want = passkey.PromptLocal
	}
	if kind != want {
		h.fail(w, r, errTxn, f)
		return
	}
	sess, err := h.enrollSession(r, f, stored)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if r.URL.Query().Get("decision") == "skip" {
		h.finishEnrollment(w, r, f, stored, false)
		return
	}
	h.submitPasskeyEnrollment(w, r, f, stored, sess, local)
}

// submitPasskeyEnrollment runs the registration ceremony and completes the
// transaction. A failure re-renders with a fresh challenge.
func (h *Handlers) submitPasskeyEnrollment(w http.ResponseWriter, r *http.Request, f *flow, stored *store.AuthTransaction, sess *store.LoginSession, local bool) {
	prompt, screen := enrollScreen(local)
	if !h.guardHostedForm(w, r, f, prompt, screen, func(status int, message string) {
		data := h.enrollData(f, stored, local)
		data.Error = message
		u, uerr := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, sess.UserID)
		if uerr != nil {
			h.fail(w, r, uerr, f)
			return
		}
		h.renderPasskeyEnroll(w, r, status, f, stored, u, local)
	}) {
		return
	}
	u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, sess.UserID)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	conn, err := h.userConnection(r, f, u)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, conn)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !effective || !rp.Valid {
		h.enrollFailure(w, r, f, stored, u, local, string(webauthn.ReasonRPID))
		return
	}
	raw := r.PostForm.Get("credential")
	if posted := r.PostForm.Get("webauthn_error"); posted != "" {
		name := "UnknownError"
		if slices.Contains(webauthnErrorNames, posted) {
			name = posted
		}
		h.enrollFailure(w, r, f, stored, u, local, name)
		return
	}
	if raw == "" {
		h.enrollFailure(w, r, f, stored, u, local, string(webauthn.ReasonParse))
		return
	}
	b := passkey.Binding{
		Purpose: passkey.PurposePasskeyRegister, RPID: rp.RPID, Origins: []string{f.res.Origin()},
		TxnID: f.txn.ID, CookieHash: stored.CookieHash, UserID: u.UserID,
	}
	challenge, err := h.Passkeys.Take(r.Context(), f.res.Tenant.ID, r.PostForm.Get("challenge_id"), b)
	if err != nil {
		h.enrollFailure(w, r, f, stored, u, local, string(webauthn.ReasonChallenge))
		return
	}
	if _, err := h.Passkeys.Enroll(r.Context(), f.res.Tenant.ID, u, enrollmentIdentity(u, conn), []byte(raw), challenge, b, r.UserAgent()); err != nil {
		if errors.Is(err, passkey.ErrMaxPasskeys) {
			data := h.enrollData(f, stored, local)
			data.Error = f.view.L.T("passkeys." + screenName(local) + ".passkey-enrollment-max-allowed-reached")
			h.renderPasskeyEnroll(w, r, http.StatusBadRequest, f, stored, u, local)
			return
		}
		if errors.Is(err, passkey.ErrCeremony) {
			h.enrollFailure(w, r, f, stored, u, local, webauthn.Reason(err))
			return
		}
		h.fail(w, r, err, f)
		return
	}
	h.eventWithDetails(r, f, "gd_enrollment_complete", u, map[string]any{
		"authenticator": map[string]any{"type": "passkey"},
	})
	h.finishEnrollment(w, r, f, stored, false)
}

// enrollmentIdentity is the database identity the passkey is attached to.
func enrollmentIdentity(u *store.User, conn *store.Connection) string {
	for _, id := range u.Identities {
		if conn == nil || id.Connection == conn.Name {
			return id.UserID
		}
	}
	return ""
}

// enrollFailure logs the bounded reason and re-renders with a fresh
// challenge.
func (h *Handlers) enrollFailure(w http.ResponseWriter, r *http.Request, f *flow, stored *store.AuthTransaction, u *store.User, local bool, reason string) {
	h.eventWithDetails(r, f, "gd_webauthn_enrollment_failed", u, map[string]any{
		"authentication_methods": []string{"passkey"},
		"failure_details":        map[string]any{"errorCode": boundedReason(reason)},
	})
	data := h.enrollData(f, stored, local)
	data.Error = f.view.L.T("passkeys." + screenName(local) + ".passkey-enrollment-failure")
	h.renderPasskeyEnroll(w, r, http.StatusBadRequest, f, stored, u, local)
}

// finishEnrollment answers the prompt and resumes the login. A skip records
// nothing; the checkbox path stores the 30-day snooze before resuming.
func (h *Handlers) finishEnrollment(w http.ResponseWriter, r *http.Request, f *flow, stored *store.AuthTransaction, _ bool) {
	sess, err := h.enrollSession(r, f, stored)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if r.PostForm.Get("checkbox") != "" {
		if err := h.snoozeEnrollment(r, f, stored, sess); err != nil {
			h.fail(w, r, err, f)
			return
		}
	}
	// Mark the prompt answered and drop the prompt stage, so the resumed
	// transaction neither re-asks nor looks like a pending prompt, then hand
	// back to the flow the way the login pages do.
	params := stored.Params
	params[authz.ParamPasskeyAnswered] = "1"
	delete(params, authz.ParamStage)
	delete(params, authz.ParamPasskeyPrompt)
	if err := h.Store.AuthTransactions().Delete(r.Context(), f.res.Tenant.ID, stored.ID); err != nil {
		h.fail(w, r, err, f)
		return
	}
	stored.HostedState.Revision++
	if err := h.Store.AuthTransactions().Create(r.Context(), stored); err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.Authz.Resume(w, r, f.res, stored, sess)
}

// snoozeEnrollment stores the prompt's 30-day snooze, scoped to the RP ID
// for progressive and to the hashed device cookie for local.
func (h *Handlers) snoozeEnrollment(r *http.Request, f *flow, stored *store.AuthTransaction, sess *store.LoginSession) error {
	u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, sess.UserID)
	if err != nil {
		return err
	}
	conn, err := h.userConnection(r, f, u)
	if err != nil {
		return err
	}
	_, rp, effective, err := h.Passkeys.Effective(r.Context(), f.res.Tenant.ID, f.res, conn)
	if err != nil || !effective || !rp.Valid {
		return err
	}
	kind := stored.Params[authz.ParamPasskeyPrompt]
	snoozeKind := store.SnoozePasskeyProgressive
	scope := rp.RPID
	if kind == passkey.PromptLocal {
		snoozeKind = store.SnoozePasskeyLocal
		scope = authz.PasskeyScope(stored.CookieHash, rp.RPID, kind)
	}
	if scope == "" {
		return nil
	}
	return h.Passkeys.Snooze(r.Context(), f.res.Tenant.ID, u.UserID, snoozeKind, scope, h.now())
}

// deviceCookie is this browser's device cookie, when it has one.
func deviceCookie(r *http.Request) string {
	if c, err := r.Cookie("za_mfa_dev"); err == nil {
		return c.Value
	}
	return ""
}
