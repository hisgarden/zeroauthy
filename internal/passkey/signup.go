package passkey

import (
	"context"
	"errors"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

// Signup verifies a registration response for a new user against the
// taken challenge ch (a passkey-register challenge without a user) and
// creates draft and its passkey in one CreateUserWithPasskey transaction
// (spec section 3.4): either both exist afterwards or neither. The draft
// must have its own database identity and no password: the user is
// created passwordless (LR33b-36). An empty draft.UserID gets a new
// database user ID. The passkey's handle is the one CreationOptions
// rendered for Signup with the same ch.
//
// Errors: store.ErrInvalid for a malformed draft; ErrCeremony for a wrong
// challenge binding, a failed verification or a credential the tenant
// already holds; the store's ErrConflict when another user has the
// draft's email or username on the connection. Pre-user-registration,
// email verification and events are the caller's.
func (s *Service) Signup(ctx context.Context, tid string, draft *store.User, raw, ch []byte, b Binding, userAgent string) (*store.User, *store.Authenticator, error) {
	if draft == nil || draft.TenantID != "" && draft.TenantID != tid {
		return nil, nil, store.ErrInvalid
	}
	u := *draft
	u.TenantID = tid
	u.Identities = append([]store.Identity(nil), draft.Identities...)
	ident := databaseIdentity(&u)
	if ident == nil || ident.PasswordHash != "" || ident.ImportedHash != "" {
		return nil, nil, store.ErrInvalid
	}
	if b.Purpose != PurposePasskeyRegister || b.UserID != "" {
		return nil, nil, ceremony(webauthn.ReasonChallenge, "not a signup challenge")
	}
	reg, err := register(raw, ch, b)
	if err != nil {
		return nil, nil, err
	}
	prefix := store.StrategyDatabase + "|"
	switch {
	case u.UserID == "" && ident.UserID == "":
		ident.UserID = secrets.RandomHex(12)
		u.UserID = prefix + ident.UserID
	case u.UserID == "":
		u.UserID = prefix + ident.UserID
	case ident.UserID == "":
		ident.UserID = strings.TrimPrefix(u.UserID, prefix)
	}
	now := s.now()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}
	// The store refuses a duplicate credential too; asking first keeps it
	// from reading as a user conflict (email in use).
	if _, err := s.st.WebAuthn().GetAuthenticatorByCredentialID(ctx, tid, reg.CredentialID); err == nil {
		return nil, nil, ceremony(ReasonCredential, "credential already registered")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	a, err := s.newPasskey(tid, u.UserID, ident.UserID, reg, b.RPID, deriveHandle(ch), userAgent)
	if err != nil {
		return nil, nil, err
	}
	if err := s.st.WebAuthn().CreateUserWithPasskey(ctx, &u, a); err != nil {
		return nil, nil, err
	}
	return &u, a, nil
}
