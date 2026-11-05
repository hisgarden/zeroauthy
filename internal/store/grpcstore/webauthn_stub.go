package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// WebAuthn is a stub until the webauthn.v1 plugin capability lands (Plan 33b
// Task 6); every call answers store.ErrWebAuthnUnavailable.
func (c *Client) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }
