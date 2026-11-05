package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestWebAuthnConformance(t *testing.T) {
	storetest.WebAuthn(t, func(*testing.T) store.Store { return memory.New() })
}

// noWebAuthn is a driver without the webauthn.v1 capability, as sqlstore and
// grpcstore are until Plan 33b Tasks 5 and 6 land.
type noWebAuthn struct{ store.Store }

func (noWebAuthn) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }

// The conformance suite skips, rather than fails, a driver whose WebAuthn
// repository answers ErrWebAuthnUnavailable.
func TestWebAuthnSuiteSkipsWithoutCapability(t *testing.T) {
	ok := t.Run("suite", func(t *testing.T) {
		storetest.WebAuthn(t, func(*testing.T) store.Store { return noWebAuthn{memory.New()} })
		t.Fatal("suite ran against a driver without WebAuthn")
	})
	if !ok {
		t.Fatal("suite did not skip")
	}
	// The stub answers the sentinel on every call.
	if _, err := (noWebAuthn{memory.New()}).WebAuthn().HostTenantsUnder(context.Background(), "example.test", 0); !errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("stub = %v", err)
	}
}

// A rolled-back transaction leaves no passkey, snooze or moved row behind.
func TestWebAuthnTransactionRollback(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
	must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
	must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "v"}))
	must(s.WebAuthn().CreatePasskey(ctx, &store.Authenticator{TenantID: "t", UserID: "u", ID: "passkey|dev_1", Type: "passkey", CredentialID: []byte("c1")}, 20))
	sentinel := errors.New("rollback")
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.WebAuthn().CreatePasskey(ctx, &store.Authenticator{TenantID: "t", UserID: "u", ID: "passkey|dev_2", Type: "passkey", CredentialID: []byte("c2")}, 20); err != nil {
			return err
		}
		if err := tx.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "t", UserID: "u", Kind: store.SnoozePasskeyLocal, ScopeKey: "d", Until: now.Add(time.Hour)}); err != nil {
			return err
		}
		if err := tx.WebAuthn().MovePasskeys(ctx, "t", "u", "v", ""); err != nil {
			return err
		}
		if err := tx.WebAuthn().AcceptAssertion(ctx, "t", "v", "passkey|dev_1", 9, true, now); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "t", []byte("c2")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back passkey visible: %v", err)
	}
	if _, err := s.WebAuthn().GetSnooze(ctx, "t", "u", store.SnoozePasskeyLocal, "d", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back snooze visible: %v", err)
	}
	got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "t", []byte("c1"))
	must(err)
	if got.UserID != "u" || got.SignCount != 0 {
		t.Fatalf("rolled-back move or assertion visible: %+v", got)
	}
}
