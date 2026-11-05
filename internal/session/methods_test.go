package session

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestSessionMethods pins the Plan 33b session record (spec section 5.4):
// Start records the first factor at the authentication time, AddMethod
// appends MFA with its factor and keeps every other field of the row.
func TestSessionMethods(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	authAt := c.t.Add(-time.Second)
	s, err := m.Start(ctx, httptest.NewRecorder(), requestWith(nil), tn, "auth0|1", "Database", authAt, store.AuthMethod{Name: "passkey"})
	if err != nil {
		t.Fatal(err)
	}
	want := []store.AuthMethod{{Name: "passkey", At: authAt}}
	if !equalMethods(s.AuthMethods, want) {
		t.Fatalf("started methods = %+v", s.AuthMethods)
	}
	got, err := m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if err != nil || !equalMethods(got.AuthMethods, want) {
		t.Fatalf("stored methods = %+v, %v", got, err)
	}
	if err := m.AddClient(ctx, s, "app"); err != nil {
		t.Fatal(err)
	}

	c.t = c.t.Add(time.Minute)
	if err := m.MarkMFA(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := m.AddMethod(ctx, s, store.AuthMethod{Name: "mfa", Type: "otp"}); err != nil {
		t.Fatal(err)
	}
	want = append(want, store.AuthMethod{Name: "mfa", Type: "otp", At: c.t})
	if !equalMethods(s.AuthMethods, want) {
		t.Fatalf("caller methods = %+v", s.AuthMethods)
	}
	got, err = m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !equalMethods(got.AuthMethods, want) || got.TokenHash != s.TokenHash || !got.MFAAt.Equal(c.t) || len(got.ClientIDs) != 1 || got.ClientIDs[0] != "app" ||
		!got.AuthenticatedAt.Equal(authAt) || !got.ExpiresAt.Equal(s.ExpiresAt) || got.Connection != "Database" || got.UserID != "auth0|1" {
		t.Fatalf("session after AddMethod = %+v", got)
	}
	// The row is still found by its cookie.
	if byHash, err := m.Store.Sessions().GetByTokenHash(ctx, tn.ID, s.TokenHash); err != nil || byHash.ID != s.ID {
		t.Fatalf("by token hash = %+v, %v", byHash, err)
	}

	// Without a first factor the record stays absent (legacy shape).
	legacy, err := m.Start(ctx, httptest.NewRecorder(), requestWith(nil), tn, "auth0|2", "Database", c.t)
	if err != nil || legacy.AuthMethods != nil {
		t.Fatalf("legacy = %+v, %v", legacy, err)
	}
	if err := m.AddMethod(ctx, &store.LoginSession{TenantID: tn.ID, ID: "missing"}, store.AuthMethod{Name: "mfa"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing session = %v", err)
	}
	if err := m.AddMethod(ctx, nil, store.AuthMethod{Name: "mfa"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("nil session = %v", err)
	}
}

func equalMethods(a, b []store.AuthMethod) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Type != b[i].Type || !a[i].At.Equal(b[i].At) {
			return false
		}
	}
	return true
}
