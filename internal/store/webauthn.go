package store

import (
	"context"
	"errors"
	"time"
)

// ErrWebAuthnUnavailable is returned by drivers that have not negotiated the
// webauthn.v1 capability (and by UnimplementedWebAuthn).
var ErrWebAuthnUnavailable = errors.New("store: WebAuthn unavailable")

// Snooze kinds of WebAuthnSnooze.Kind and what ScopeKey holds for each.
const (
	SnoozePasskeyProgressive = "passkey-progressive" // scope: RP ID
	SnoozePasskeyLocal       = "passkey-local"       // scope: hashed device cookie
	SnoozePlatformRemind     = "platform-remind"     // scope: device key
	SnoozePlatformRefuse     = "platform-refuse"     // scope: device key
)

// AuthenticatorPublicDataKeys is the allowlist of Authenticator.PublicData
// keys. It holds the Plan 33 WebAuthn MFA metadata plus the passkey fields
// added by Plan 33b (backup_eligible, backed_up, attachment); nothing else is
// stored or returned. Sorted.
var AuthenticatorPublicDataKeys = []string{
	"aaguid", "attachment", "backed_up", "backup_eligible", "credential_backed_up", "credential_device_type",
	"identity_user_id", "transports", "user_agent", "user_handle",
}

// WebAuthnSupporter is implemented by drivers that negotiate the webauthn.v1
// capability (the gRPC plugin client); others support WebAuthn unconditionally.
type WebAuthnSupporter interface {
	CheckWebAuthnSupport(context.Context) error
	WebAuthnSupported() bool
}

// WebAuthnSnooze records that a user declined or postponed a passkey or
// platform-authenticator prompt. The row is keyed by (TenantID, UserID, Kind,
// ScopeKey) and is live until Until.
type WebAuthnSnooze struct {
	TenantID, UserID, Kind, ScopeKey string // Kind: Snooze* constants
	Until                            time.Time
}

// WebAuthn adds passkey creation, assertion acceptance, passkey moves and
// snoozes on top of MFA's authenticator rows. Passkeys are Authenticator rows
// with Type "passkey"; they share the tenant-wide credential ID uniqueness
// rule of every WebAuthn authenticator.
type WebAuthn interface {
	// GetAuthenticatorByCredentialID finds the tenant's authenticator of any
	// type whose CredentialID equals credID. ErrNotFound if none.
	GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*Authenticator, error)
	// CreatePasskey stores a (Type "passkey") and, in the same atomic step,
	// refuses a credential ID already stored in the tenant (ErrConflict,
	// also for a duplicate ID) and a user who already holds limit passkeys
	// (ErrPrecondition; limit <= 0 means no limit). ErrNotFound if the user
	// is missing; ErrInvalid if a.Type is not "passkey" or CredentialID is empty.
	CreatePasskey(ctx context.Context, a *Authenticator, limit int) error
	// CreateUserWithPasskey creates u and a in one transaction: either both
	// exist afterwards or neither. ErrConflict for a user conflict
	// (Users.Create rules) or a duplicate credential; ErrInvalid if a does
	// not name u.
	CreateUserWithPasskey(ctx context.Context, u *User, a *Authenticator) error
	// AcceptAssertion applies the sign-counter rule in one conditional
	// write: ErrPrecondition unless count > stored or both are zero. On
	// success it stores count, writes backedUp as "backed_up" in PublicData
	// and sets LastAuthAt = at. ErrNotFound if the authenticator is absent
	// or belongs to another user.
	AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error
	// MovePasskeys reassigns fromUID's passkeys to toUID unchanged (their
	// identity_user_id is kept). An identityUserID of "" moves all of them;
	// otherwise only those whose PublicData identity_user_id equals it.
	// Other authenticator types stay. ErrNotFound if either user is missing.
	MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error
	// PutSnooze upserts s by (TenantID, UserID, Kind, ScopeKey). ErrNotFound
	// if the user is missing.
	PutSnooze(ctx context.Context, s *WebAuthnSnooze) error
	// GetSnooze returns the live snooze: ErrNotFound if none or Until is not
	// after now.
	GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*WebAuthnSnooze, error)
	// HostTenantsUnder returns the distinct IDs, in byte order, of the
	// tenants owning a host binding (any kind, active or not) whose host
	// equals suffix or ends with "."+suffix: whole labels only, so
	// "ample.com" is not under "example.com". The suffix is compared
	// lowercase without a trailing dot; limit <= 0 means every match.
	HostTenantsUnder(ctx context.Context, suffix string, limit int) ([]string, error)
	// PurgeWebAuthn deletes up to limit (<= 0: all) snoozes whose Until is
	// before before and returns how many. Expired challenges are PurgeMFA's.
	PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error)
}

// UnimplementedWebAuthn answers ErrWebAuthnUnavailable to every call; drivers
// without the webauthn.v1 capability return it from Store.WebAuthn.
type UnimplementedWebAuthn struct{}

func (UnimplementedWebAuthn) GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*Authenticator, error) {
	return nil, ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) CreatePasskey(ctx context.Context, a *Authenticator, limit int) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) CreateUserWithPasskey(ctx context.Context, u *User, a *Authenticator) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) PutSnooze(ctx context.Context, s *WebAuthnSnooze) error {
	return ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*WebAuthnSnooze, error) {
	return nil, ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) HostTenantsUnder(ctx context.Context, suffix string, limit int) ([]string, error) {
	return nil, ErrWebAuthnUnavailable
}
func (UnimplementedWebAuthn) PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error) {
	return 0, ErrWebAuthnUnavailable
}
