package authz

import (
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Post-login passkey enrollment (spec section 3.5). The prompt is a stage of
// the login transaction: the redirect cannot proceed until the user answers
// it, and an independent GET of the enrollment page is refused.
const (
	// StagePasskeyPrompt marks a transaction that is waiting on the
	// post-login enrollment prompt.
	StagePasskeyPrompt = "passkey-prompt"
	// ParamPasskeyPrompt carries the offered kind ("progressive"/"local").
	ParamPasskeyPrompt = "za_pk_prompt"
	// ParamPasskeyScope carries the RP ID (progressive) or the hashed device
	// cookie (local) the prompt and its snooze are scoped to.
	ParamPasskeyScope = "za_pk_scope"
	// ParamPasskeyDevice reports whether the page saw a user-verifying
	// platform authenticator.
	ParamPasskeyDevice = "za_pk_device"
	// ParamPasskeyBrowser carries the login transaction's cookie hash, the
	// stable per-browser key a local prompt binds its snooze to.
	ParamPasskeyBrowser = "za_pk_browser"
	// ParamPasskeyAnswered records that this login already showed the prompt,
	// so a resumed transaction never asks twice.
	ParamPasskeyAnswered = "za_pk_answered"
	// ParamPasskeyAttachment carries the passkey login's
	// authenticatorAttachment, so local enrollment can require
	// "cross-platform" (Review Focus 5).
	ParamPasskeyAttachment = "za_pk_attachment"
	// ParamPasskeyFactor carries the login's first factor.
	ParamPasskeyFactor = "za_pk_factor"
)

// passkeyPromptKind decides and, when it offers one, starts the enrollment
// prompt. It returns true when the request was answered by the prompt.
func (h *Handlers) passkeyPrompt(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, screenShown bool) bool {
	return h.passkeyPromptFor(w, r, res, client, fr, sess, screenShown, fr.stageParams[ParamPasskeyBrowser])
}

// passkeyPromptFor is passkeyPrompt with the browser scope the local prompt
// binds its snooze to: the login transaction's cookie hash.
func (h *Handlers) passkeyPromptFor(w http.ResponseWriter, r *http.Request, res tenant.Resolved, client *store.Client, fr flowReq, sess *store.LoginSession, screenShown bool, browserScope string) bool {
	if h.Passkeys == nil || fr.device() {
		return false
	}
	// The prompt follows a login, not a registration (LR33b-13): a signup
	// that just created the account is never asked to enroll again.
	if fr.ScreenHint == "signup" {
		return false
	}
	// The prompt is offered once per login: the transaction that carried the
	// login records the answer, and a resumed transaction does not re-ask.
	carried := fr.stageParams
	if carried[ParamPasskeyPrompt] != "" || carried[ParamPasskeyAnswered] != "" {
		return false
	}
	u, err := h.Store.Users().Get(r.Context(), res.Tenant.ID, sess.UserID)
	if err != nil {
		// A missing user is not a prompt problem; let the flow decide.
		return false
	}
	conn := h.passkeyConnection(r, res, u)
	in := passkey.LoginContext{FirstFactor: h.loginFirstFactor(sess), Attachment: carried[ParamPasskeyAttachment], DeviceScope: browserScope}
	if in.FirstFactor == "passkey" {
		in.PlatformAvailable = carried[ParamPasskeyDevice] == "1"
	}
	kind, err := h.Passkeys.EnrollmentPrompt(r.Context(), res.Tenant.ID, u, conn, res, in)
	if err != nil || kind == "" {
		return false
	}
	params := fr.params()
	params[ParamStage] = StagePasskeyPrompt
	params[sessionKey] = sess.ID
	params[ParamPasskeyPrompt] = kind
	page := "/u/passkey-enrollment"
	if kind == passkey.PromptLocal {
		page = "/u/passkey-enrollment-local"
	}
	h.startTxnWith(w, r, res, client, fr, params, page, func(string, map[string]string) error { return nil })
	return true
}

// loginFirstFactor is the session's first authentication method, defaulting
// to a password login for a session with no record (a legacy session).
func (h *Handlers) loginFirstFactor(sess *store.LoginSession) string {
	for _, m := range sess.AuthMethods {
		switch m.Name {
		case "passkey", "pwd", "federated", "email", "sms":
			return m.Name
		}
	}
	return "pwd"
}

// passkeyConnection is the connection the prompt evaluates: the login
// session's own connection.
func (h *Handlers) passkeyConnection(r *http.Request, res tenant.Resolved, u *store.User) *store.Connection {
	if u == nil || len(u.Identities) == 0 {
		return nil
	}
	conn, err := h.Store.Connections().GetByName(r.Context(), res.Tenant.ID, u.Identities[0].Connection)
	if err != nil {
		return nil
	}
	return conn
}

// PasskeyScope is the snooze scope a prompt of this kind binds to: the RP ID
// for progressive, and for local a stable per-browser key. The caller passes
// the login transaction's cookie hash, which is exactly this browser.
func PasskeyScope(cookieHash, rpID, kind string) string {
	if kind == passkey.PromptLocal {
		return cookieHash
	}
	return rpID
}

var _ = strings.TrimSpace
