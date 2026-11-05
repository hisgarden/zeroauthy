package session

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestStartRecordsMethods covers Plan 33b section 5.4: a login records how it
// was authenticated, first factor first, and a caller that passes none leaves
// the record absent so readers fall back to the password answer.
func TestStartRecordsMethods(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()

	plain, err := m.Start(ctx, httptest.NewRecorder(), requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	if plain.AuthMethods != nil {
		t.Fatalf("no methods became %v", plain.AuthMethods)
	}
	stored, err := m.Store.Sessions().Get(ctx, tn.ID, plain.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AuthMethods != nil {
		t.Fatalf("stored methods = %v", stored.AuthMethods)
	}

	at := c.t
	s, err := m.Start(ctx, httptest.NewRecorder(), requestWith(nil), tn, "auth0|2", "Database", at,
		store.AuthMethod{Name: "passkey", At: at})
	if err != nil {
		t.Fatal(err)
	}
	stored, err = m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []store.AuthMethod{{Name: "passkey", At: at}}; !slices.Equal(stored.AuthMethods, want) {
		t.Fatalf("stored methods = %+v, want %+v", stored.AuthMethods, want)
	}
}

// TestAddMethodAppends covers the MFA step: AddMethod appends to the record
// and persists it, so a later reader (the Actions event) sees the factor.
func TestAddMethodAppends(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	at := c.t
	s, err := m.Start(ctx, httptest.NewRecorder(), requestWith(nil), tn, "auth0|1", "Database", at,
		store.AuthMethod{Name: "pwd", At: at})
	if err != nil {
		t.Fatal(err)
	}
	second := at.Add(time.Minute)
	if err := m.AddMethod(ctx, s, store.AuthMethod{Name: "mfa", Type: "otp", At: second}); err != nil {
		t.Fatal(err)
	}
	want := []store.AuthMethod{{Name: "pwd", At: at}, {Name: "mfa", Type: "otp", At: second}}
	if !slices.Equal(s.AuthMethods, want) {
		t.Fatalf("in-memory methods = %+v", s.AuthMethods)
	}
	stored, err := m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored.AuthMethods, want) {
		t.Fatalf("stored methods = %+v, want %+v", stored.AuthMethods, want)
	}

	// A legacy session with no record gains only the MFA step.
	legacy, err := m.Start(ctx, httptest.NewRecorder(), requestWith(nil), tn, "auth0|2", "Database", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddMethod(ctx, legacy, store.AuthMethod{Name: "mfa", Type: "otp", At: second}); err != nil {
		t.Fatal(err)
	}
	stored, err = m.Store.Sessions().Get(ctx, tn.ID, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []store.AuthMethod{{Name: "mfa", Type: "otp", At: second}}; !slices.Equal(stored.AuthMethods, want) {
		t.Fatalf("legacy methods = %+v, want %+v", stored.AuthMethods, want)
	}

	if err := m.AddMethod(ctx, nil, store.AuthMethod{Name: "mfa"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("nil session = %v", err)
	}
	absent := &store.LoginSession{TenantID: tn.ID, ID: "gone"}
	if err := m.AddMethod(ctx, absent, store.AuthMethod{Name: "mfa"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("absent session = %v", err)
	}
}
