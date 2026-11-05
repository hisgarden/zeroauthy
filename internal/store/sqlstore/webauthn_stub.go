package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// WebAuthn is a stub until migration 0035 and the SQL repository land
// (Plan 33b Task 5); every call answers store.ErrWebAuthnUnavailable.
func (s *Store) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }
