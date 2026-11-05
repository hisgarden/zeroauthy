package login

// Plan 33b hosted passkey login (spec sections 3.3, 5.1-5.4, 14a R3).

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// keyPasskeyFailed is the generic answer to every refused passkey login
// (LR33b-16): it never reveals which check failed.
const keyPasskeyFailed = i18n.KeyPasskeyLoginFailed

// Session method names (SessionAuthenticationSignal, spec section 5.4).
const (
	methodPassword = "pwd"
	methodPasskey  = "passkey"
)

// reasonConnection is the logged reason of a passkey the transaction's
// connection cannot use: passkeys not effective on it, or the credential's
// user not on it.
const reasonConnection = "connection"

var errPasskeyConnection = errors.New("login: passkey not usable on this connection")

// webauthnErrorNames are the DOMException names a page may report.
var webauthnErrorNames = webauthnrules.Inventory().DOMExceptionNames

// webauthnErrorName maps a posted webauthn_error to an allowed DOMException
// name; anything else is UnknownError. The value is never echoed.
func webauthnErrorName(name string) string {
	if slices.Contains(webauthnErrorNames, name) {
		return name
	}
	return "UnknownError"
}

// loginBinding binds a hosted passkey-login challenge to the transaction,
// its browser cookie, the RP ID and the exact hosted origin.
func loginBinding(f *flow, rp rpid.Result) passkey.Binding {
	return passkey.Binding{Purpose: passkey.PurposePasskeyLogin, RPID: rp.RPID, Origins: []string{rp.Origin}, TxnID: f.txn.ID, CookieHash: f.txn.CookieHash}
}

// passkeyLogin returns the login-id page's passkey offer with a fresh
// challenge, or nil when passkeys are not effective for the transaction's
// database connection on this host (section 3.3; a host whose RP ID is
// unusable offers none, R1).
func (h *Handlers) passkeyLogin(r *http.Request, f *flow) (*ui.PasskeyLogin, error) {
	if h.Passkeys == nil || f.conn == nil || f.txn.HostedState.Step != "identifier" {
		return nil, nil
	}
	ctx := r.Context()
	policy, rp, ok, err := h.Passkeys.Effective(ctx, f.res.Tenant.ID, f.res, f.conn)
	if err != nil || !ok {
		return nil, err
	}
	iss, err := h.Passkeys.Issue(ctx, f.res.Tenant.ID, loginBinding(f, rp), 0)
	if err != nil {
		return nil, err
	}
	opts, err := h.Passkeys.RequestOptions(rp.RPID, iss.Challenge, 0).JSON()
	if err != nil {
		return nil, err
	}
	autofill, button := policy.ChallengeUI != "button", policy.ChallengeUI != "autofill"
	doc := ui.WebAuthnDoc{Mode: "login", ChallengeID: iss.ID, Button: button, PublicKey: opts}
	if autofill {
		doc.Mediation = "conditional"
	}
	return &ui.PasskeyLogin{Doc: doc, Autofill: autofill, Button: button, Script: ui.WebAuthnScript()}, nil
}

// onConnection reports whether u has an identity on conn (its own or a
// linked one).
func onConnection(u *store.User, conn *store.Connection) *store.Identity {
	var found *store.Identity
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Connection != conn.Name || id.Provider != store.StrategyDatabase {
			continue
		}
		if !id.Linked() {
			return id
		}
		if found == nil {
			found = id
		}
	}
	return found
}

// LoginPasskey is POST /u/login/passkey: the login-id page's passkey
// assertion (button or autofill). The credential's user is the user
// (LR33b-16); MFA, Actions, consent and organizations follow as after a
// password.
func (h *Handlers) LoginPasskey(w http.ResponseWriter, r *http.Request) {
	f, ok := h.postedFlow(w, r)
	if !ok {
		return
	}
	credential := r.PostForm.Get("credential")
	*r = *r.WithContext(logscrub.WithValues(r.Context(), credential))
	if h.Passkeys == nil || f.txn.HostedState.Step != "identifier" {
		h.fail(w, r, errTxn, f)
		return
	}
	h.withFlowEvent(r, f)
	ctx := r.Context()
	tid := f.res.Tenant.ID
	_, rp, effective, err := h.Passkeys.Effective(ctx, tid, f.res, f.conn)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !rp.Valid {
		// R1: an unusable RP ID fails closed on the hosted error page.
		ui.RenderError(w, http.StatusBadRequest, f.view, f.view.L.T(keyPasskeyFailed))
		return
	}
	b := loginBinding(f, rp)
	id := r.PostForm.Get("challenge_id")
	// spend consumes the posted challenge when the attempt ends before it
	// is verified, so nothing it names stays usable.
	spend := func() {
		if id != "" {
			_, _ = h.Passkeys.Take(ctx, tid, id, b)
		}
	}
	redisplay := func(status int, message string) {
		d := h.stageData(f, "")
		d.Error = message
		h.renderIdentifier(w, r, status, f, d)
	}
	if f.config != nil && !postedHostedRevision(r, f) {
		spend()
		redisplay(http.StatusConflict, f.view.L.T(i18n.KeyHostedFormChanged))
		return
	}
	if name := r.PostForm.Get("webauthn_error"); name != "" || credential == "" {
		// The browser ceremony did not produce a credential: show the page
		// again with a fresh challenge. Nothing was verified; no log.
		spend()
		message := ""
		if n := webauthnErrorName(name); n != "NotAllowedError" && n != "AbortError" {
			message = f.view.L.T(keyPasskeyFailed)
		}
		redisplay(http.StatusOK, message)
		return
	}

	svc := h.protectionService()
	ip := httpx.ClientIP(r, h.TrustProxyHeaders)
	gate, err := svc.Begin(ctx, protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, IP: ip, Flow: protection.FlowPasskeyLogin})
	if err != nil {
		spend()
		h.fail(w, r, err, f)
		return
	}
	if !gate.Allowed {
		spend()
		redisplay(http.StatusTooManyRequests, f.view.L.T(i18n.KeyTooManyAttempts))
		return
	}
	var result *passkey.LoginResult
	ch, err := h.Passkeys.Take(ctx, tid, id, b)
	if err == nil {
		if effective {
			result, err = h.Passkeys.Login(ctx, tid, []byte(credential), ch, b)
		} else {
			err = errPasskeyConnection
		}
	}
	var ident *store.Identity
	if err == nil {
		if ident = onConnection(result.User, f.conn); ident == nil {
			err = errPasskeyConnection
		}
	}
	outcome := "success"
	switch {
	case err == nil, errors.Is(err, identity.ErrUserBlocked):
	case errors.Is(err, passkey.ErrCeremony), errors.Is(err, errPasskeyConnection):
		outcome = "failure"
	default:
		outcome = "refund"
	}
	if finishErr := svc.Finish(ctx, gate.Receipt, outcome); finishErr != nil {
		h.fail(w, r, finishErr, f)
		return
	}
	switch {
	case errors.Is(err, identity.ErrUserBlocked):
		redisplay(http.StatusForbidden, f.view.L.T(i18n.KeyUserBlocked))
		return
	case outcome == "failure":
		reason := reasonConnection
		if !errors.Is(err, errPasskeyConnection) {
			reason = webauthn.Reason(err)
		}
		if riskErr := svc.RecordFailure(ctx, h.captchaAttempt(r, f.res, "login"), secrets.RandomString(32)); riskErr != nil {
			h.fail(w, r, riskErr, f)
			return
		}
		h.passkeyChallengeFailed(r, f, reason)
		redisplay(http.StatusUnauthorized, f.view.L.T(keyPasskeyFailed))
		return
	case err != nil:
		h.fail(w, r, err, f)
		return
	}

	// R3: the identified user's brute-force block refuses the passkey as it
	// refuses a password, and a success resets the identity's counter.
	user := result.User
	decision, err := svc.Begin(ctx, protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, Identifier: protection.IdentityIdentifier(user, ident), IP: ip, Flow: "login"})
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	if !decision.Allowed {
		redisplay(http.StatusTooManyRequests, f.view.L.T(i18n.KeyTooManyAttempts))
		return
	}
	err = h.passkeyMembership(ctx, f, user)
	outcome = "success"
	if err != nil {
		outcome = "refund"
	}
	if finishErr := svc.Finish(ctx, decision.Receipt, outcome); finishErr != nil {
		h.fail(w, r, finishErr, f)
		return
	}
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	h.complete(w, r, f, user, methodPasskey)
}

// passkeyMembership applies the organization rules of a password login:
// the organization must allow the client and membership is assigned per
// the connection's rule; a policy refusal is left to authorization.
func (h *Handlers) passkeyMembership(ctx context.Context, f *flow, u *store.User) error {
	if f.org.Org == nil || f.txn.Params[orglogin.InvitationIDParam] != "" {
		return nil
	}
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		oc, err := orglogin.Load(ctx, tx, f.res.Tenant.ID, f.txn.Params)
		if err != nil {
			return err
		}
		if oc.Org != nil {
			err = orglogin.CheckMemberClient(ctx, tx, f.res.Tenant.ID, oc.Org.ID, f.txn.ClientID)
		}
		if err == nil {
			err = EnsureMembership(ctx, tx, oc, u.UserID, f.conn.ID)
		}
		if errors.Is(err, ErrNotMember) {
			return nil
		}
		return err
	})
}

// passkeyChallengeFailed logs a refused hosted passkey login (LR33b-17):
// first_factor true and a bounded reason code, never the credential or
// the user it named.
func (h *Handlers) passkeyChallengeFailed(r *http.Request, f *flow, reason string) {
	h.eventDetails(r, f, "gd_webauthn_challenge_failed", nil, map[string]any{"first_factor": true, "failure_details": map[string]any{"errorCode": reason}})
}
