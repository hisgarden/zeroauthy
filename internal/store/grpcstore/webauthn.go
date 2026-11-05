package grpcstore

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// webauthn.v1 carries store.WebAuthn over the plugin protocol. It is
// negotiated by WebAuthnCapabilities, separately from every earlier
// capability, so a plugin that predates it keeps working and yields
// store.ErrWebAuthnUnavailable. It builds on MFA v1 (passkeys are MFA
// authenticator rows): a plugin without MFA has no WebAuthn either. The
// capability also covers the Plan 33b
// fields of other records (LoginSession.AuthMethods, Client.Mobile,
// Tenant.DomainRPIDs, MFAChallenge.Binding): without it the client neither
// sends nor returns them.

type clientWebAuthn struct{ c *Client }

func (c *Client) WebAuthn() store.WebAuthn { return clientWebAuthn{c} }

// A definitive unsupported answer is latched for the connection lifetime;
// transient transport errors are not.
func (c *Client) CheckWebAuthnSupport(ctx context.Context) error {
	if c.webauthnCap.v.Load() == 2 {
		return store.ErrWebAuthnUnavailable
	}
	v, err := c.rpc.WebAuthnCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("WebAuthn capability", capabilityError(err, store.ErrWebAuthnUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 1 {
			err = store.ErrWebAuthnUnavailable
		}
	}
	// Passkeys are MFA authenticator rows, so webauthn.v1 needs MFA v1.
	if err == nil {
		if err = c.CheckMFASupport(ctx); errors.Is(err, store.ErrMFAUnavailable) {
			err = store.ErrWebAuthnUnavailable
		}
	}
	if errors.Is(err, store.ErrWebAuthnUnavailable) {
		c.webauthnCap.v.Store(2)
	} else if err == nil {
		c.webauthnCap.v.CompareAndSwap(0, 1)
	}
	if c.webauthnCap.v.Load() == 2 {
		return store.ErrWebAuthnUnavailable
	}
	return err
}

func (c *Client) WebAuthnSupported() bool {
	switch c.webauthnCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckWebAuthnSupport(ctx) == nil
}

func (s *Server) WebAuthnCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if c, ok := s.st.(store.WebAuthnSupporter); ok {
		if err := c.CheckWebAuthnSupport(ctx); err != nil {
			return &storev1.EventsCapabilitiesResult{Error: errToPB(err)}, nil
		}
		if !c.WebAuthnSupported() {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
	}
	switch s.st.WebAuthn().(type) {
	case store.UnimplementedWebAuthn, *store.UnimplementedWebAuthn:
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// webauthnCall probes the capability, runs one RPC and folds its outcome
// into the latch. call returns the RPC's error envelope.
func webauthnCall(ctx context.Context, c *Client, op string, call func() (*storev1.Error, error)) error {
	if err := c.CheckWebAuthnSupport(ctx); err != nil {
		return err
	}
	e, err := call()
	if err != nil {
		err = capabilityError(err, store.ErrWebAuthnUnavailable)
		if errors.Is(err, store.ErrWebAuthnUnavailable) {
			c.webauthnCap.v.Store(2)
		}
		return rpcErr(op, err)
	}
	err = errFromPB(e)
	if errors.Is(err, store.ErrWebAuthnUnavailable) {
		c.webauthnCap.v.Store(2)
	}
	return err
}

// ---- fields of other records covered by webauthn.v1 ----

// webauthnFieldsAllowed reports whether the webauthn.v1 record fields may
// cross the wire. It probes only while the answer is unknown, and callers
// ask only when such a field is set, so records without them cost nothing.
// A transient probe failure is returned rather than guessed: dropping the
// fields would lose data on write and could clear them on a later update.
func (c *Client) webauthnFieldsAllowed(ctx context.Context) (bool, error) {
	switch c.webauthnCap.v.Load() {
	case 1:
		return true, nil
	case 2:
		return false, nil
	}
	err := c.CheckWebAuthnSupport(ctx)
	if errors.Is(err, store.ErrWebAuthnUnavailable) {
		return false, nil
	}
	return err == nil, err
}

// webauthnGate names one record type's webauthn.v1 fields.
type webauthnGate[T any] struct {
	has   func(*T) bool
	strip func(*T)
}

var (
	sessionGate   = webauthnGate[store.LoginSession]{func(v *store.LoginSession) bool { return v.AuthMethods != nil }, func(v *store.LoginSession) { v.AuthMethods = nil }}
	clientGate    = webauthnGate[store.Client]{func(v *store.Client) bool { return v.Mobile != nil }, func(v *store.Client) { v.Mobile = nil }}
	tenantGate    = webauthnGate[store.Tenant]{func(v *store.Tenant) bool { return v.DomainRPIDs != nil }, func(v *store.Tenant) { v.DomainRPIDs = nil }}
	challengeGate = webauthnGate[store.MFAChallenge]{func(v *store.MFAChallenge) bool { return v.Binding != nil }, func(v *store.MFAChallenge) { v.Binding = nil }}
)

// write returns v, or a shallow copy without the fields when the plugin has
// not negotiated webauthn.v1. The caller's value is never modified.
func (g webauthnGate[T]) write(ctx context.Context, c *Client, v *T) (*T, error) {
	if v == nil || !g.has(v) {
		return v, nil
	}
	ok, err := c.webauthnFieldsAllowed(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		return v, nil
	}
	cp := *v
	g.strip(&cp)
	return &cp, nil
}

// read clears the fields of decoded values when the plugin has not
// negotiated webauthn.v1.
func (g webauthnGate[T]) read(ctx context.Context, c *Client, vs ...*T) error {
	need := false
	for _, v := range vs {
		if v != nil && g.has(v) {
			need = true
			break
		}
	}
	if !need {
		return nil
	}
	ok, err := c.webauthnFieldsAllowed(ctx)
	if err != nil {
		return err
	}
	if !ok {
		for _, v := range vs {
			if v != nil {
				g.strip(v)
			}
		}
	}
	return nil
}

// one gates a single decoded result, keeping an earlier error as is.
func (g webauthnGate[T]) one(ctx context.Context, c *Client, v *T, err error) (*T, error) {
	if err != nil {
		return v, err
	}
	if err := g.read(ctx, c, v); err != nil {
		return nil, err
	}
	return v, nil
}

// list gates decoded results, keeping an earlier error as is.
func (g webauthnGate[T]) list(ctx context.Context, c *Client, vs []*T, err error) ([]*T, error) {
	if err != nil {
		return vs, err
	}
	if err := g.read(ctx, c, vs...); err != nil {
		return nil, err
	}
	return vs, nil
}

// ---- codecs ----

func authMethodsToPB(v []store.AuthMethod) *storev1.AuthMethodList {
	if v == nil {
		return nil
	}
	out := &storev1.AuthMethodList{Values: make([]*storev1.AuthMethod, 0, len(v))}
	for _, m := range v {
		out.Values = append(out.Values, &storev1.AuthMethod{Name: m.Name, Type: m.Type, At: tsToPB(m.At)})
	}
	return out
}

func authMethodsFromPB(l *storev1.AuthMethodList) ([]store.AuthMethod, error) {
	if l == nil {
		return nil, nil
	}
	out := make([]store.AuthMethod, 0, len(l.Values))
	for _, m := range l.Values {
		if err := checkTS(m.GetAt()); err != nil {
			return nil, err
		}
		out = append(out, store.AuthMethod{Name: m.GetName(), Type: m.GetType(), At: tsFromPB(m.GetAt())})
	}
	return out, nil
}

func clientMobileToPB(m *store.ClientMobile) *storev1.ClientMobile {
	if m == nil {
		return nil
	}
	out := &storev1.ClientMobile{}
	if m.IOS != nil {
		out.Ios = &storev1.ClientMobileIOS{TeamId: m.IOS.TeamID, AppBundleIdentifier: m.IOS.AppBundleIdentifier}
	}
	if m.Android != nil {
		out.Android = &storev1.ClientMobileAndroid{AppPackageName: m.Android.AppPackageName, Sha256CertFingerprints: stringsToPB(m.Android.SHA256CertFingerprints)}
	}
	return out
}

func clientMobileFromPB(m *storev1.ClientMobile) *store.ClientMobile {
	if m == nil {
		return nil
	}
	out := &store.ClientMobile{}
	if ios := m.GetIos(); ios != nil {
		out.IOS = &store.ClientMobileIOS{TeamID: ios.GetTeamId(), AppBundleIdentifier: ios.GetAppBundleIdentifier()}
	}
	if a := m.GetAndroid(); a != nil {
		out.Android = &store.ClientMobileAndroid{AppPackageName: a.GetAppPackageName(), SHA256CertFingerprints: stringsFromPB(a.GetSha256CertFingerprints())}
	}
	return out
}

func snoozeToPB(s *store.WebAuthnSnooze) *storev1.WebAuthnSnooze {
	if s == nil {
		return nil
	}
	return &storev1.WebAuthnSnooze{TenantId: s.TenantID, UserId: s.UserID, Kind: s.Kind, ScopeKey: s.ScopeKey, Until: tsToPB(s.Until)}
}

func snoozeFromPB(s *storev1.WebAuthnSnooze) (*store.WebAuthnSnooze, error) {
	if s == nil {
		return nil, store.ErrInvalid
	}
	if err := checkTS(s.Until); err != nil {
		return nil, err
	}
	return &store.WebAuthnSnooze{TenantID: s.TenantId, UserID: s.UserId, Kind: s.Kind, ScopeKey: s.ScopeKey, Until: tsFromPB(s.Until)}, nil
}

func authenticatorToPB(a *store.Authenticator) (*storev1.MFAAuthenticator, error) {
	var out *storev1.MFAAuthenticator
	if err := copyMFA(&out, a); err != nil {
		return nil, err
	}
	return out, nil
}

func authenticatorFromPB(a *storev1.MFAAuthenticator) (*store.Authenticator, error) {
	if a == nil {
		return nil, store.ErrInvalid
	}
	var out *store.Authenticator
	if err := copyMFA(&out, a); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- client ----

func (o clientWebAuthn) GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*store.Authenticator, error) {
	var r *storev1.WebAuthnAuthenticatorResponse
	if err := webauthnCall(ctx, o.c, "WebAuthnGetAuthenticatorByCredentialID", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.WebAuthnGetAuthenticatorByCredentialID(ctx, &storev1.WebAuthnCredentialRequest{TxId: o.c.txID, Tid: tid, CredentialId: credID})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	return authenticatorFromPB(r.Value)
}

func (o clientWebAuthn) CreatePasskey(ctx context.Context, a *store.Authenticator, limit int) error {
	if a == nil {
		return store.ErrInvalid
	}
	pb, err := authenticatorToPB(a)
	if err != nil {
		return err
	}
	return webauthnCall(ctx, o.c, "WebAuthnCreatePasskey", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnCreatePasskey(ctx, &storev1.WebAuthnCreatePasskeyRequest{TxId: o.c.txID, V: pb, Limit: int64(limit)})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) CreateUserWithPasskey(ctx context.Context, u *store.User, a *store.Authenticator) error {
	if u == nil || a == nil {
		return store.ErrInvalid
	}
	if microsoftUser(u) {
		if err := o.c.MicrosoftFederationSupported(ctx); err != nil {
			return err
		}
	}
	upb, err := userToPB(u)
	if err != nil {
		return err
	}
	apb, err := authenticatorToPB(a)
	if err != nil {
		return err
	}
	return webauthnCall(ctx, o.c, "WebAuthnCreateUserWithPasskey", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnCreateUserWithPasskey(ctx, &storev1.WebAuthnCreateUserRequest{TxId: o.c.txID, User: upb, Authenticator: apb})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error {
	return webauthnCall(ctx, o.c, "WebAuthnAcceptAssertion", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnAcceptAssertion(ctx, &storev1.WebAuthnAcceptAssertionRequest{TxId: o.c.txID, Tid: tid, Uid: uid, Id: id, Count: count, BackedUp: backedUp, At: tsToPB(at)})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error {
	return webauthnCall(ctx, o.c, "WebAuthnMovePasskeys", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnMovePasskeys(ctx, &storev1.WebAuthnMovePasskeysRequest{TxId: o.c.txID, Tid: tid, FromUid: fromUID, ToUid: toUID, IdentityUserId: identityUserID})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) PutSnooze(ctx context.Context, s *store.WebAuthnSnooze) error {
	if s == nil {
		return store.ErrInvalid
	}
	return webauthnCall(ctx, o.c, "WebAuthnPutSnooze", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnPutSnooze(ctx, &storev1.WebAuthnSnoozeRequest{TxId: o.c.txID, V: snoozeToPB(s)})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*store.WebAuthnSnooze, error) {
	var r *storev1.WebAuthnSnoozeResponse
	if err := webauthnCall(ctx, o.c, "WebAuthnGetSnooze", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.WebAuthnGetSnooze(ctx, &storev1.WebAuthnGetSnoozeRequest{TxId: o.c.txID, Tid: tid, Uid: uid, Kind: kind, Scope: scope, Now: tsToPB(now)})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	return snoozeFromPB(r.Value)
}

func (o clientWebAuthn) HostTenantsUnder(ctx context.Context, suffix string, limit int) ([]string, error) {
	var r *storev1.WebAuthnTenantIDsResponse
	if err := webauthnCall(ctx, o.c, "WebAuthnHostTenantsUnder", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.WebAuthnHostTenantsUnder(ctx, &storev1.WebAuthnHostTenantsRequest{TxId: o.c.txID, Suffix: suffix, Limit: int64(limit)})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	return append([]string{}, r.TenantIds...), nil
}

func (o clientWebAuthn) PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error) {
	var r *storev1.WebAuthnCountResponse
	if err := webauthnCall(ctx, o.c, "WebAuthnPurge", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.WebAuthnPurge(ctx, &storev1.WebAuthnPurgeRequest{TxId: o.c.txID, Before: tsToPB(before), Limit: int64(limit)})
		return r.GetError(), err
	}); err != nil {
		return 0, err
	}
	return int(r.Count), nil
}

// ---- server ----

func (s *Server) WebAuthnGetAuthenticatorByCredentialID(ctx context.Context, q *storev1.WebAuthnCredentialRequest) (*storev1.WebAuthnAuthenticatorResponse, error) {
	out := &storev1.WebAuthnAuthenticatorResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.WebAuthn().GetAuthenticatorByCredentialID(ctx, q.GetTid(), q.GetCredentialId())
		if err != nil {
			return err
		}
		out.Value, err = authenticatorToPB(v)
		return err
	}))
	return out, nil
}

func (s *Server) WebAuthnCreatePasskey(ctx context.Context, q *storev1.WebAuthnCreatePasskeyRequest) (*storev1.WebAuthnErrorResponse, error) {
	if q.GetV() == nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	a, err := authenticatorFromPB(q.V)
	if err != nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().CreatePasskey(ctx, a, int(q.GetLimit()))
	}))}, nil
}

func (s *Server) WebAuthnCreateUserWithPasskey(ctx context.Context, q *storev1.WebAuthnCreateUserRequest) (*storev1.WebAuthnErrorResponse, error) {
	if q.GetUser() == nil || q.GetAuthenticator() == nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	u, err := userFromPB(q.User)
	if err != nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	a, err := authenticatorFromPB(q.Authenticator)
	if err != nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().CreateUserWithPasskey(ctx, u, a)
	}))}, nil
}

func (s *Server) WebAuthnAcceptAssertion(ctx context.Context, q *storev1.WebAuthnAcceptAssertionRequest) (*storev1.WebAuthnErrorResponse, error) {
	if err := checkTS(q.GetAt()); err != nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().AcceptAssertion(ctx, q.GetTid(), q.GetUid(), q.GetId(), q.GetCount(), q.GetBackedUp(), tsFromPB(q.GetAt()))
	}))}, nil
}

func (s *Server) WebAuthnMovePasskeys(ctx context.Context, q *storev1.WebAuthnMovePasskeysRequest) (*storev1.WebAuthnErrorResponse, error) {
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().MovePasskeys(ctx, q.GetTid(), q.GetFromUid(), q.GetToUid(), q.GetIdentityUserId())
	}))}, nil
}

func (s *Server) WebAuthnPutSnooze(ctx context.Context, q *storev1.WebAuthnSnoozeRequest) (*storev1.WebAuthnErrorResponse, error) {
	v, err := snoozeFromPB(q.GetV())
	if err != nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().PutSnooze(ctx, v)
	}))}, nil
}

func (s *Server) WebAuthnGetSnooze(ctx context.Context, q *storev1.WebAuthnGetSnoozeRequest) (*storev1.WebAuthnSnoozeResponse, error) {
	out := &storev1.WebAuthnSnoozeResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		if err := checkTS(q.GetNow()); err != nil {
			return store.ErrInvalid
		}
		v, err := st.WebAuthn().GetSnooze(ctx, q.GetTid(), q.GetUid(), q.GetKind(), q.GetScope(), tsFromPB(q.GetNow()))
		out.Value = snoozeToPB(v)
		return err
	}))
	return out, nil
}

func (s *Server) WebAuthnHostTenantsUnder(ctx context.Context, q *storev1.WebAuthnHostTenantsRequest) (*storev1.WebAuthnTenantIDsResponse, error) {
	out := &storev1.WebAuthnTenantIDsResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.WebAuthn().HostTenantsUnder(ctx, q.GetSuffix(), int(q.GetLimit()))
		out.TenantIds = v
		return err
	}))
	return out, nil
}

func (s *Server) WebAuthnPurge(ctx context.Context, q *storev1.WebAuthnPurgeRequest) (*storev1.WebAuthnCountResponse, error) {
	out := &storev1.WebAuthnCountResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		if err := checkTS(q.GetBefore()); err != nil {
			return store.ErrInvalid
		}
		n, err := st.WebAuthn().PurgeWebAuthn(ctx, tsFromPB(q.GetBefore()), int(q.GetLimit()))
		out.Count = int64(n)
		return err
	}))
	return out, nil
}
