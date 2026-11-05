package authz

import (
	"context"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// freshLoginParam carries a FreshLogin across the steps of one
// authorization that run in later requests (MFA, consent and an Actions
// redirect): "<session ID> <method>".
const freshLoginParam = "za_pk_login"

type freshLoginKey struct{}

// FreshLogin is the first factor a hosted login page just used to start
// session SessionID in this authorization (Plan 33b). Method is its
// SessionAuthenticationSignal name (pwd, passkey, ...). The success log
// reports the passkey prompt from it, and it ends with the authorization:
// a session reused by a later authorization carries none.
type FreshLogin struct {
	SessionID, Method string
}

// WithFreshLogin records fl on ctx; the login pages call it before Resume.
func WithFreshLogin(ctx context.Context, fl FreshLogin) context.Context {
	return context.WithValue(ctx, freshLoginKey{}, fl)
}

// freshLogin returns the request's fresh login when it is sess's.
func freshLogin(ctx context.Context, sess *store.LoginSession) (FreshLogin, bool) {
	fl, ok := ctx.Value(freshLoginKey{}).(FreshLogin)
	if !ok || sess == nil || sess.ID == "" || fl.SessionID != sess.ID {
		return FreshLogin{}, false
	}
	return fl, true
}

// carryFreshLogin copies the request's fresh login of sess into the params
// of a transaction or continuation that resumes this authorization.
func carryFreshLogin(ctx context.Context, params map[string]string, sess *store.LoginSession) {
	if fl, ok := freshLogin(ctx, sess); ok {
		params[freshLoginParam] = fl.SessionID + " " + fl.Method
	}
}

// resumeFreshLogin restores the fresh login carried by params when it is
// sess's.
func resumeFreshLogin(ctx context.Context, params map[string]string, sess *store.LoginSession) context.Context {
	id, method, ok := strings.Cut(params[freshLoginParam], " ")
	if !ok || sess == nil || id != sess.ID || method == "" {
		return ctx
	}
	return WithFreshLogin(ctx, FreshLogin{SessionID: id, Method: method})
}

// passkeyPrompts are the s log details of a login whose first factor was a
// passkey (spec section 8.2).
func passkeyPrompts(ctx context.Context, sess *store.LoginSession) map[string]any {
	if fl, ok := freshLogin(ctx, sess); !ok || fl.Method != "passkey" {
		return nil
	}
	return map[string]any{"prompts": []any{map[string]any{"name": "login-id", "performed_amr": []any{"phr"}}}}
}
