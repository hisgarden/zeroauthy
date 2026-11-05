package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type webauthn struct{ s *Store }

func (s *Store) WebAuthn() store.WebAuthn { return webauthn{s} }

// snoozeKey addresses a snooze so tenant purge works unchanged.
func snoozeKey(tid, uid, kind, scope string) key {
	return key{tid, uid + "\x00" + kind + "\x00" + scope}
}

// publicDataString returns one string field of an authenticator's public
// data, or "" when absent or not a string.
func publicDataString(a *store.Authenticator, field string) string {
	if len(a.PublicData) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(a.PublicData, &m) != nil {
		return ""
	}
	v, _ := m[field].(string)
	return v
}

// credentialTaken reports whether another authenticator of the tenant holds
// cred. The caller holds the lock.
func (s *Store) credentialTaken(tid string, cred []byte, exceptID string) bool {
	if len(cred) == 0 {
		return false
	}
	for k, x := range s.authenticators {
		if k.tenant == tid && k.id != exceptID && bytes.Equal(cred, x.CredentialID) {
			return true
		}
	}
	return false
}

// checkPasskey validates a passkey insert against the tenant's rows without
// writing: ErrInvalid for a malformed row, ErrConflict for a duplicate ID or
// credential, ErrPrecondition when the user already holds limit passkeys.
// The caller holds the lock.
func (s *Store) checkPasskey(a *store.Authenticator, limit int) error {
	if a.Type != "passkey" || len(a.CredentialID) == 0 || a.ID == "" {
		return store.ErrInvalid
	}
	if s.authenticators[key{a.TenantID, a.ID}] != nil || s.credentialTaken(a.TenantID, a.CredentialID, "") {
		return store.ErrConflict
	}
	if limit > 0 {
		n := 0
		for k, x := range s.authenticators {
			if k.tenant == a.TenantID && x.UserID == a.UserID && x.Type == "passkey" {
				n++
			}
		}
		if n >= limit {
			return store.ErrPrecondition
		}
	}
	return nil
}

func (r webauthn) GetAuthenticatorByCredentialID(_ context.Context, tid string, credID []byte) (*store.Authenticator, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if len(credID) == 0 {
		return nil, store.ErrNotFound
	}
	for k, a := range r.s.authenticators {
		if k.tenant == tid && bytes.Equal(a.CredentialID, credID) {
			return cloneAuthenticator(a), nil
		}
	}
	return nil, store.ErrNotFound
}

// CreatePasskey checks the limit and inserts under one lock, so concurrent
// creates for one user admit exactly as many as the limit allows.
func (r webauthn) CreatePasskey(_ context.Context, a *store.Authenticator, limit int) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{a.TenantID, a.UserID}] == nil {
		return store.ErrNotFound
	}
	if err := r.s.checkPasskey(a, limit); err != nil {
		return err
	}
	r.s.authenticators[key{a.TenantID, a.ID}] = cloneAuthenticator(a)
	return nil
}

// CreateUserWithPasskey validates the passkey before the user is stored and
// writes both under one lock, so a failure of either leaves nothing behind.
func (r webauthn) CreateUserWithPasskey(_ context.Context, u *store.User, a *store.Authenticator) error {
	r.s.lock()
	defer r.s.unlock()
	if a.TenantID != u.TenantID || a.UserID != u.UserID {
		return store.ErrInvalid
	}
	if err := r.s.checkPasskey(a, 0); err != nil {
		return err
	}
	if err := (users{r.s}).create(u); err != nil {
		return err
	}
	r.s.authenticators[key{a.TenantID, a.ID}] = cloneAuthenticator(a)
	return nil
}

func (r webauthn) AcceptAssertion(_ context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	a := r.s.authenticators[key{tid, id}]
	if a == nil || a.UserID != uid {
		return store.ErrNotFound
	}
	if !(count > a.SignCount || count == 0 && a.SignCount == 0) {
		return store.ErrPrecondition
	}
	public := map[string]any{}
	if len(a.PublicData) > 0 {
		_ = json.Unmarshal(a.PublicData, &public)
	}
	public["backed_up"] = backedUp
	data, err := json.Marshal(public)
	if err != nil {
		return err
	}
	a.SignCount, a.LastAuthAt, a.PublicData = count, at, data
	return nil
}

func (r webauthn) MovePasskeys(_ context.Context, tid, fromUID, toUID, identityUserID string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{tid, fromUID}] == nil || r.s.users[key{tid, toUID}] == nil {
		return store.ErrNotFound
	}
	for k, a := range r.s.authenticators {
		if k.tenant != tid || a.UserID != fromUID || a.Type != "passkey" {
			continue
		}
		if identityUserID != "" && publicDataString(a, "identity_user_id") != identityUserID {
			continue
		}
		a.UserID = toUID
	}
	return nil
}

func (r webauthn) PutSnooze(_ context.Context, v *store.WebAuthnSnooze) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{v.TenantID, v.UserID}] == nil {
		return store.ErrNotFound
	}
	r.s.snoozes[snoozeKey(v.TenantID, v.UserID, v.Kind, v.ScopeKey)] = cloneValue(v)
	return nil
}

func (r webauthn) GetSnooze(_ context.Context, tid, uid, kind, scope string, now time.Time) (*store.WebAuthnSnooze, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.snoozes[snoozeKey(tid, uid, kind, scope)]
	if v == nil || !now.Before(v.Until) {
		return nil, store.ErrNotFound
	}
	return cloneValue(v), nil
}

func (r webauthn) HostTenantsUnder(_ context.Context, suffix string, limit int) ([]string, error) {
	suffix = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(suffix)), ".")
	out := []string{}
	if suffix == "" {
		return out, nil
	}
	r.s.readLock()
	defer r.s.readUnlock()
	for host, h := range r.s.hostBindings {
		if (host == suffix || strings.HasSuffix(host, "."+suffix)) && !slices.Contains(out, h.TenantID) {
			out = append(out, h.TenantID)
		}
	}
	slices.Sort(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r webauthn) PurgeWebAuthn(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, v := range r.s.snoozes {
		if limit > 0 && n >= limit {
			break
		}
		if v.Until.Before(before) {
			delete(r.s.snoozes, k)
			n++
		}
	}
	return n, nil
}
