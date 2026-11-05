package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// concurrencyDeadline bounds how long a concurrency case waits for every
// goroutine to return; outcomes are asserted, never timings.
const concurrencyDeadline = 10 * time.Second

// WebAuthn runs the Plan 33b storage contract (passkeys, assertion
// acceptance, passkey moves, snoozes, host lookups and the new session,
// client, tenant and challenge fields) against a fresh driver for each case.
// A driver that has not negotiated the webauthn.v1 capability is skipped.
func WebAuthn(t *testing.T, factory Factory) {
	ctx := context.Background()
	now := ts(0)
	probe := open(t, factory)
	if ws, ok := probe.(store.WebAuthnSupporter); ok && !ws.WebAuthnSupported() {
		t.Skip("WebAuthn not supported by this driver")
	}
	if _, err := probe.WebAuthn().GetSnooze(ctx, "probe", "u", store.SnoozePasskeyProgressive, "rp", now); errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Skip("WebAuthn not implemented by this driver")
	}

	setup := func(t *testing.T) store.Store {
		s := open(t, factory)
		for _, tid := range []string{"a", "b"} {
			tenant := newTenant(tid)
			tenant.ID = tid
			mustNoErr(t, s.Tenants().Create(ctx, tenant))
			for _, uid := range []string{"u", "v"} {
				mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: tid, UserID: uid, Identities: []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: uid}}}))
			}
		}
		return s
	}
	passkey := func(tid, uid, id string, cred string) *store.Authenticator {
		return &store.Authenticator{TenantID: tid, UserID: uid, ID: "passkey|dev_" + id, Type: "passkey", Name: "key " + id, Confirmed: true,
			CredentialID: []byte(cred), PublicKey: []byte("cose-" + cred), RPID: "a.example.test", CreatedAt: now,
			PublicData: []byte(`{"backup_eligible":true,"backed_up":false,"identity_user_id":"auth0|` + uid + `","user_handle":"aGFuZGxl"}`)}
	}
	publicData := func(t *testing.T, a *store.Authenticator) map[string]any {
		t.Helper()
		var m map[string]any
		if len(a.PublicData) > 0 {
			if err := json.Unmarshal(a.PublicData, &m); err != nil {
				t.Fatalf("public data %q: %v", a.PublicData, err)
			}
		}
		return m
	}
	ids := func(list []store.Authenticator) []string {
		out := []string{}
		for _, a := range list {
			out = append(out, a.ID)
		}
		return out
	}
	// waitAll runs f concurrently n times and fails the test when any call is
	// still running after concurrencyDeadline.
	waitAll := func(t *testing.T, n int, f func(i int) error) []error {
		t.Helper()
		var errs []error
		done := make(chan struct{})
		go func() {
			errs = parallel(n, f)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(concurrencyDeadline):
			t.Fatalf("%d concurrent calls did not all return within %s", n, concurrencyDeadline)
		}
		return errs
	}

	t.Run("CreatePasskeyLimit", func(t *testing.T) {
		s := setup(t)
		// Other authenticator types do not count towards the passkey limit.
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "webauthn-roaming|dev_r", Type: "webauthn-roaming", CredentialID: []byte("roaming"), RPID: "a.example.test"}))
		for i := range 20 {
			mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", fmt.Sprintf("%02d", i), fmt.Sprintf("cred-%02d", i)), 20))
		}
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "21", "cred-21"), 20), store.ErrPrecondition)
		list, err := s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, err)
		if len(list) != 21 {
			t.Fatalf("refused passkey stored: %d authenticators", len(list))
		}
		// Another user, another tenant and a higher limit are unaffected.
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "v", "v1", "cred-v1"), 20))
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("b", "u", "b1", "cred-b1"), 20))
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "21", "cred-21"), 21))
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "22", "cred-22"), 0))
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "missing", "m", "cred-m"), 20), store.ErrNotFound)
		got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("cred-07"))
		mustNoErr(t, err)
		if got.ID != "passkey|dev_07" || got.UserID != "u" || got.Type != "passkey" || string(got.PublicKey) != "cose-cred-07" || got.RPID != "a.example.test" || !got.Confirmed || got.Name != "key 07" {
			t.Fatalf("stored passkey = %+v", got)
		}
		if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("cred-23")); !isErr(err, store.ErrNotFound) {
			t.Fatalf("missing credential: %v", err)
		}
		if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", nil); !isErr(err, store.ErrNotFound) {
			t.Fatalf("empty credential: %v", err)
		}
		got, err = s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("roaming"))
		mustNoErr(t, err)
		if got.Type != "webauthn-roaming" {
			t.Fatalf("roaming lookup = %+v", got)
		}
	})
	t.Run("CreatePasskeyLimitConcurrent", func(t *testing.T) {
		s := setup(t)
		for i := range 19 {
			mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", fmt.Sprintf("%02d", i), fmt.Sprintf("cred-%02d", i)), 20))
		}
		errs := waitAll(t, 10, func(i int) error {
			return s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", fmt.Sprintf("race-%d", i), fmt.Sprintf("cred-race-%d", i)), 20)
		})
		oneSuccess(t, errs)
		list, err := s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, err)
		if len(list) != 20 {
			t.Fatalf("%d passkeys after the race, want 20", len(list))
		}
	})
	t.Run("CredentialUniquePerTenant", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "1", "shared"), 20))
		// The same credential in another tenant is allowed.
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("b", "u", "1", "shared"), 20))
		// Same tenant: refused across users, IDs and authenticator types.
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "v", "2", "shared"), 20), store.ErrConflict)
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "1", "other"), 20), store.ErrConflict)
		mustErrIs(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "v", ID: "webauthn-roaming|dev_1", Type: "webauthn-roaming", CredentialID: []byte("shared")}), store.ErrConflict)
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "v", ID: "webauthn-roaming|dev_2", Type: "webauthn-roaming", CredentialID: []byte("roaming")}))
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "3", "roaming"), 20), store.ErrConflict)
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "totp|dev_x", Type: "totp"}, 20), store.ErrInvalid)
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "passkey|dev_x", Type: "passkey"}, 20), store.ErrInvalid)
		list, err := s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, err)
		mustEqual(t, ids(list), []string{"passkey|dev_1"})
		// Stored bytes do not alias the caller's.
		a := passkey("a", "v", "4", "fresh")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		a.CredentialID[0], a.PublicData[0] = 'X', 'X'
		got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("fresh"))
		mustNoErr(t, err)
		if got.PublicData[0] != '{' {
			t.Fatal("stored public data aliases the caller's bytes")
		}
	})
	t.Run("CreateUserWithPasskeyAtomic", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "1", "taken"), 20))
		newUser := func(uid, email string) *store.User {
			return &store.User{TenantID: "a", UserID: uid, Email: email, Identities: []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: uid}}}
		}
		// A credential conflict leaves no user behind.
		mustErrIs(t, s.WebAuthn().CreateUserWithPasskey(ctx, newUser("n1", "n1@example.test"), passkey("a", "n1", "n1", "taken")), store.ErrConflict)
		if _, err := s.Users().Get(ctx, "a", "n1"); !isErr(err, store.ErrNotFound) {
			t.Fatalf("user survived the failed passkey: %v", err)
		}
		if _, err := s.Users().FindByLogin(ctx, "a", "Database", "n1@example.test"); !isErr(err, store.ErrNotFound) {
			t.Fatalf("login survived the failed passkey: %v", err)
		}
		// A user conflict leaves no passkey behind.
		mustErrIs(t, s.WebAuthn().CreateUserWithPasskey(ctx, newUser("u", "u@example.test"), passkey("a", "u", "2", "fresh")), store.ErrConflict)
		if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("fresh")); !isErr(err, store.ErrNotFound) {
			t.Fatalf("passkey survived the failed user: %v", err)
		}
		mustNoErr(t, s.Users().Create(ctx, newUser("n0", "dup@example.test")))
		mustErrIs(t, s.WebAuthn().CreateUserWithPasskey(ctx, newUser("n2", "dup@example.test"), passkey("a", "n2", "3", "fresh")), store.ErrConflict)
		if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("fresh")); !isErr(err, store.ErrNotFound) {
			t.Fatalf("passkey survived the duplicate login: %v", err)
		}
		// The passkey must name the user.
		mustErrIs(t, s.WebAuthn().CreateUserWithPasskey(ctx, newUser("n3", "n3@example.test"), passkey("a", "u", "4", "fresh")), store.ErrInvalid)
		if _, err := s.Users().Get(ctx, "a", "n3"); !isErr(err, store.ErrNotFound) {
			t.Fatalf("user created with a foreign passkey: %v", err)
		}
		// Both land together, inside and outside a transaction.
		mustNoErr(t, s.WebAuthn().CreateUserWithPasskey(ctx, newUser("n4", "n4@example.test"), passkey("a", "n4", "5", "fresh")))
		u, err := s.Users().Get(ctx, "a", "n4")
		mustNoErr(t, err)
		if u.Email != "n4@example.test" || u.Version != 0 {
			t.Fatalf("user = %+v", u)
		}
		got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("fresh"))
		mustNoErr(t, err)
		if got.UserID != "n4" || got.ID != "passkey|dev_5" {
			t.Fatalf("passkey = %+v", got)
		}
		sentinel := errors.New("rollback")
		err = s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.WebAuthn().CreateUserWithPasskey(ctx, newUser("n5", "n5@example.test"), passkey("a", "n5", "6", "rolled")); err != nil {
				return err
			}
			return sentinel
		})
		mustErrIs(t, err, sentinel)
		if _, err := s.Users().Get(ctx, "a", "n5"); !isErr(err, store.ErrNotFound) {
			t.Fatalf("rolled-back user visible: %v", err)
		}
		if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("rolled")); !isErr(err, store.ErrNotFound) {
			t.Fatalf("rolled-back passkey visible: %v", err)
		}
	})
	t.Run("AcceptAssertionCounter", func(t *testing.T) {
		s := setup(t)
		for i, tc := range []struct {
			stored, got uint32
			ok          bool
		}{
			{0, 0, true}, {0, 5, true},
			{5, 5, false}, {5, 4, false},
			{5, 0, false}, {5, 6, true},
		} {
			a := passkey("a", "u", fmt.Sprint(i), fmt.Sprintf("cred-%d", i))
			a.SignCount = tc.stored
			mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
			err := s.WebAuthn().AcceptAssertion(ctx, "a", "u", a.ID, tc.got, false, now)
			got, e := s.MFA().GetAuthenticator(ctx, "a", "u", a.ID)
			mustNoErr(t, e)
			if tc.ok {
				mustNoErr(t, err)
				if got.SignCount != tc.got {
					t.Fatalf("stored %d got %d: count = %d", tc.stored, tc.got, got.SignCount)
				}
			} else {
				mustErrIs(t, err, store.ErrPrecondition)
				if got.SignCount != tc.stored || !got.LastAuthAt.IsZero() {
					t.Fatalf("stored %d got %d: refused assertion changed the row: %+v", tc.stored, tc.got, got)
				}
			}
		}
		mustErrIs(t, s.WebAuthn().AcceptAssertion(ctx, "a", "u", "passkey|dev_missing", 1, false, now), store.ErrNotFound)
		mustErrIs(t, s.WebAuthn().AcceptAssertion(ctx, "a", "v", "passkey|dev_0", 1, false, now), store.ErrNotFound)
		// Two concurrent assertions with the same counter: exactly one wins.
		a := passkey("a", "u", "race", "cred-race")
		a.SignCount = 6
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		errs := waitAll(t, 2, func(int) error { return s.WebAuthn().AcceptAssertion(ctx, "a", "u", a.ID, 7, false, now) })
		oneSuccess(t, errs)
		got, err := s.MFA().GetAuthenticator(ctx, "a", "u", a.ID)
		mustNoErr(t, err)
		if got.SignCount != 7 {
			t.Fatalf("count after race = %d", got.SignCount)
		}
	})
	t.Run("AcceptAssertionWritesBackupStateAndLastAuth", func(t *testing.T) {
		s := setup(t)
		a := passkey("a", "u", "1", "cred-1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		mustNoErr(t, s.WebAuthn().AcceptAssertion(ctx, "a", "u", a.ID, 1, true, now.Add(time.Minute)))
		got, err := s.MFA().GetAuthenticator(ctx, "a", "u", a.ID)
		mustNoErr(t, err)
		if !got.LastAuthAt.Equal(now.Add(time.Minute)) || got.SignCount != 1 {
			t.Fatalf("after assertion: %+v", got)
		}
		pd := publicData(t, got)
		if pd["backed_up"] != true || pd["backup_eligible"] != true || pd["identity_user_id"] != "auth0|u" || pd["user_handle"] != "aGFuZGxl" {
			t.Fatalf("public data = %v", pd)
		}
		mustNoErr(t, s.WebAuthn().AcceptAssertion(ctx, "a", "u", a.ID, 2, false, now.Add(2*time.Minute)))
		got, err = s.MFA().GetAuthenticator(ctx, "a", "u", a.ID)
		mustNoErr(t, err)
		if pd = publicData(t, got); pd["backed_up"] != false || pd["backup_eligible"] != true || !got.LastAuthAt.Equal(now.Add(2*time.Minute)) {
			t.Fatalf("second assertion: %+v %v", got, pd)
		}
		// A refused assertion writes nothing.
		mustErrIs(t, s.WebAuthn().AcceptAssertion(ctx, "a", "u", a.ID, 2, true, now.Add(3*time.Minute)), store.ErrPrecondition)
		got, err = s.MFA().GetAuthenticator(ctx, "a", "u", a.ID)
		mustNoErr(t, err)
		if pd = publicData(t, got); pd["backed_up"] != false || !got.LastAuthAt.Equal(now.Add(2*time.Minute)) {
			t.Fatalf("refused assertion wrote: %+v %v", got, pd)
		}
		// A row without public data gains only the backup state.
		b := passkey("a", "u", "2", "cred-2")
		b.PublicData = nil
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, b, 20))
		mustNoErr(t, s.WebAuthn().AcceptAssertion(ctx, "a", "u", b.ID, 0, true, now))
		got, err = s.MFA().GetAuthenticator(ctx, "a", "u", b.ID)
		mustNoErr(t, err)
		mustEqual(t, publicData(t, got), map[string]any{"backed_up": true})
	})
	t.Run("MovePasskeysAllAndByIdentity", func(t *testing.T) {
		s := setup(t)
		withIdentity := func(id, cred, identity string) *store.Authenticator {
			a := passkey("a", "u", id, cred)
			a.PublicData = []byte(`{"identity_user_id":"` + identity + `","backup_eligible":false}`)
			return a
		}
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, withIdentity("1", "c1", "auth0|u"), 20))
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, withIdentity("2", "c2", "auth0|x"), 20))
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, withIdentity("3", "c3", "auth0|u"), 20))
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "webauthn-roaming|dev_r", Type: "webauthn-roaming", CredentialID: []byte("r"), PublicData: []byte(`{"identity_user_id":"auth0|x"}`)}))
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "totp|dev_t", Type: "totp"}))
		mustErrIs(t, s.WebAuthn().MovePasskeys(ctx, "a", "u", "missing", ""), store.ErrNotFound)
		mustErrIs(t, s.WebAuthn().MovePasskeys(ctx, "a", "missing", "v", ""), store.ErrNotFound)
		// By identity: only the unlinked identity's passkeys move, unchanged.
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "a", "u", "v", "auth0|x"))
		moved, err := s.MFA().ListAuthenticators(ctx, "a", "v")
		mustNoErr(t, err)
		mustEqual(t, ids(moved), []string{"passkey|dev_2"})
		if pd := publicData(t, &moved[0]); pd["identity_user_id"] != "auth0|x" || moved[0].TenantID != "a" || moved[0].UserID != "v" || string(moved[0].CredentialID) != "c2" {
			t.Fatalf("moved passkey = %+v %v", moved[0], pd)
		}
		left, err := s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, err)
		mustEqual(t, ids(left), []string{"passkey|dev_1", "passkey|dev_3", "totp|dev_t", "webauthn-roaming|dev_r"})
		got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("c2"))
		mustNoErr(t, err)
		if got.UserID != "v" {
			t.Fatalf("credential lookup after move = %+v", got)
		}
		// All: every remaining passkey moves; MFA authenticators stay.
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "a", "u", "v", ""))
		moved, err = s.MFA().ListAuthenticators(ctx, "a", "v")
		mustNoErr(t, err)
		mustEqual(t, ids(moved), []string{"passkey|dev_1", "passkey|dev_2", "passkey|dev_3"})
		left, err = s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, err)
		mustEqual(t, ids(left), []string{"totp|dev_t", "webauthn-roaming|dev_r"})
		// Nothing to move is not an error; the other tenant is untouched.
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "a", "u", "v", ""))
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "b", "u", "v", ""))
		if got, _ := s.MFA().ListAuthenticators(ctx, "b", "v"); len(got) != 0 {
			t.Fatalf("other tenant gained %v", got)
		}
	})
	t.Run("DeleteUserAuthenticatorsNilKeepsPasskeys", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "1", "c1"), 20))
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "totp|dev_t", Type: "totp"}))
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "webauthn-roaming|dev_r", Type: "webauthn-roaming", CredentialID: []byte("r")}))
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "recovery-code|dev_c", Type: "recovery-code", CodeHash: "h"}))
		mustNoErr(t, s.MFA().DeleteUserAuthenticators(ctx, "a", "u", nil))
		list, err := s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, err)
		mustEqual(t, ids(list), []string{"passkey|dev_1"})
		// An explicit type list still removes passkeys.
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "totp|dev_t", Type: "totp"}))
		mustNoErr(t, s.MFA().DeleteUserAuthenticators(ctx, "a", "u", []string{"passkey"}))
		list, err = s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, err)
		mustEqual(t, ids(list), []string{"totp|dev_t"})
	})
	t.Run("DeleteUserMFARemovesPasskeys", func(t *testing.T) {
		s := setup(t)
		snooze := func(tid, uid string) *store.WebAuthnSnooze {
			return &store.WebAuthnSnooze{TenantID: tid, UserID: uid, Kind: store.SnoozePasskeyProgressive, ScopeKey: "a.example.test", Until: now.Add(time.Hour)}
		}
		seed := func(tid, uid, cred string) {
			mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey(tid, uid, cred, cred), 20))
			mustNoErr(t, s.WebAuthn().PutSnooze(ctx, snooze(tid, uid)))
		}
		gone := func(tid, uid, cred string) {
			t.Helper()
			if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, tid, []byte(cred)); !isErr(err, store.ErrNotFound) {
				t.Fatalf("%s/%s passkey kept: %v", tid, uid, err)
			}
			if _, err := s.WebAuthn().GetSnooze(ctx, tid, uid, store.SnoozePasskeyProgressive, "a.example.test", now); !isErr(err, store.ErrNotFound) {
				t.Fatalf("%s/%s snooze kept: %v", tid, uid, err)
			}
		}
		kept := func(tid, uid, cred string) {
			t.Helper()
			if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, tid, []byte(cred)); err != nil {
				t.Fatalf("%s/%s passkey lost: %v", tid, uid, err)
			}
			if _, err := s.WebAuthn().GetSnooze(ctx, tid, uid, store.SnoozePasskeyProgressive, "a.example.test", now); err != nil {
				t.Fatalf("%s/%s snooze lost: %v", tid, uid, err)
			}
		}
		seed("a", "u", "au")
		seed("a", "v", "av")
		seed("b", "u", "bu")
		mustNoErr(t, s.MFA().DeleteUserMFA(ctx, "a", "u"))
		gone("a", "u", "au")
		kept("a", "v", "av")
		kept("b", "u", "bu")
		// User deletion removes passkeys and snoozes too.
		mustNoErr(t, s.Users().Delete(ctx, "a", "v"))
		gone("a", "v", "av")
		kept("b", "u", "bu")
		// Tenant deletion removes everything of the tenant.
		mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: "a", UserID: "w"}))
		seed("a", "w", "aw")
		mustNoErr(t, s.Tenants().Delete(ctx, "a"))
		gone("a", "w", "aw")
		kept("b", "u", "bu")
	})
	t.Run("SnoozeUpsertAndExpiry", func(t *testing.T) {
		s := setup(t)
		until := now.Add(30 * 24 * time.Hour)
		in := &store.WebAuthnSnooze{TenantID: "a", UserID: "u", Kind: store.SnoozePasskeyProgressive, ScopeKey: "a.example.test", Until: until}
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, in))
		got, err := s.WebAuthn().GetSnooze(ctx, "a", "u", store.SnoozePasskeyProgressive, "a.example.test", now)
		mustNoErr(t, err)
		mustEqual(t, got, in)
		got, err = s.WebAuthn().GetSnooze(ctx, "a", "u", store.SnoozePasskeyProgressive, "a.example.test", until.Add(-time.Second))
		mustNoErr(t, err)
		if !got.Until.Equal(until) {
			t.Fatalf("until = %v", got.Until)
		}
		// Expired exactly at Until.
		if _, err := s.WebAuthn().GetSnooze(ctx, "a", "u", store.SnoozePasskeyProgressive, "a.example.test", until); !isErr(err, store.ErrNotFound) {
			t.Fatalf("at Until: %v", err)
		}
		// Another scope, kind, user or tenant is a different row.
		for _, probe := range [][4]string{{"a", "u", store.SnoozePasskeyProgressive, "other.example.test"}, {"a", "u", store.SnoozePasskeyLocal, "a.example.test"}, {"a", "v", store.SnoozePasskeyProgressive, "a.example.test"}, {"b", "u", store.SnoozePasskeyProgressive, "a.example.test"}} {
			if _, err := s.WebAuthn().GetSnooze(ctx, probe[0], probe[1], probe[2], probe[3], now); !isErr(err, store.ErrNotFound) {
				t.Fatalf("%v: %v", probe, err)
			}
		}
		// Upsert replaces Until; the key stays unique.
		later := until.Add(24 * time.Hour)
		in.Until = later
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, in))
		got, err = s.WebAuthn().GetSnooze(ctx, "a", "u", store.SnoozePasskeyProgressive, "a.example.test", until)
		mustNoErr(t, err)
		if !got.Until.Equal(later) {
			t.Fatalf("upsert kept the old Until: %v", got.Until)
		}
		// Rewinding is an upsert too: an earlier Until makes it expire earlier.
		in.Until = now.Add(time.Minute)
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, in))
		if _, err := s.WebAuthn().GetSnooze(ctx, "a", "u", store.SnoozePasskeyProgressive, "a.example.test", now.Add(time.Minute)); !isErr(err, store.ErrNotFound) {
			t.Fatalf("rewound snooze still live: %v", err)
		}
		n, err := s.WebAuthn().PurgeWebAuthn(ctx, now.Add(2*time.Minute), 0)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatalf("upsert left %d rows, want 1", n)
		}
		// Every kind round-trips; the user must exist.
		for _, kind := range []string{store.SnoozePasskeyLocal, store.SnoozePlatformRemind, store.SnoozePlatformRefuse} {
			mustNoErr(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "a", UserID: "u", Kind: kind, ScopeKey: "scope", Until: until}))
			got, err := s.WebAuthn().GetSnooze(ctx, "a", "u", kind, "scope", now)
			mustNoErr(t, err)
			if got.Kind != kind || got.ScopeKey != "scope" {
				t.Fatalf("%s = %+v", kind, got)
			}
		}
		mustErrIs(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "a", UserID: "missing", Kind: store.SnoozePasskeyLocal, ScopeKey: "x", Until: until}), store.ErrNotFound)
		mustErrIs(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "missing", UserID: "u", Kind: store.SnoozePasskeyLocal, ScopeKey: "x", Until: until}), store.ErrNotFound)
	})
	t.Run("HostTenantsUnder", func(t *testing.T) {
		s := setup(t)
		mk := func(id string, domains ...string) {
			tenant := newTenant(id)
			tenant.ID = id
			tenant.Domains = domains
			mustNoErr(t, s.Tenants().Create(ctx, tenant))
		}
		mk("c", "login.example.com", "id.example.com")
		mk("d", "ample.com")
		mk("e", "example.com")
		mustNoErr(t, s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "auth.corp.example", TenantID: "a", DomainID: "cd_1", Kind: store.HostPublic, Active: false}))
		under := func(suffix string, limit int) []string {
			t.Helper()
			got, err := s.WebAuthn().HostTenantsUnder(ctx, suffix, limit)
			mustNoErr(t, err)
			if got == nil {
				got = []string{}
			}
			return got
		}
		mustEqual(t, under("example.com", 0), []string{"c", "e"}) // d (ample.com) is not under example.com
		mustEqual(t, under("login.example.com", 0), []string{"c"})
		mustEqual(t, under("id.example.com", 0), []string{"c"})
		mustEqual(t, under("ample.com", 0), []string{"d"})
		mustEqual(t, under("example.test", 0), []string{"a", "b"}) // setup gives a and b <name>.example.test
		mustEqual(t, under("example.test", 1), []string{"a"})
		mustEqual(t, under("EXAMPLE.com.", 0), []string{"c", "e"})
		mustEqual(t, under("corp.example", 0), []string{"a"}) // an inactive public claim still counts
		mustEqual(t, under("xample.com", 0), []string{})
		mustEqual(t, under("com", 0), []string{"c", "d", "e"})
		mustEqual(t, under("", 0), []string{})
		mustNoErr(t, s.Tenants().Delete(ctx, "e"))
		mustEqual(t, under("example.com", 0), []string{"c"})
	})
	t.Run("SessionAuthMethodsRoundTrip", func(t *testing.T) {
		s := setup(t)
		plain := newSession("a", "s1", "h1")
		mustNoErr(t, s.Sessions().Create(ctx, plain))
		got, err := s.Sessions().Get(ctx, "a", "s1")
		mustNoErr(t, err)
		if got.AuthMethods != nil {
			t.Fatalf("nil methods became %v", got.AuthMethods)
		}
		want := newSession("a", "s2", "h2")
		want.AuthMethods = []store.AuthMethod{{Name: "pwd", At: now}, {Name: "mfa", Type: "otp", At: now.Add(time.Minute)}}
		mustNoErr(t, s.Sessions().Create(ctx, want))
		want.AuthMethods[0].Name = "changed" // the store keeps its own copy
		got, err = s.Sessions().Get(ctx, "a", "s2")
		mustNoErr(t, err)
		mustEqual(t, got.AuthMethods, []store.AuthMethod{{Name: "pwd", At: now}, {Name: "mfa", Type: "otp", At: now.Add(time.Minute)}})
		got.AuthMethods[1].Type = "changed"
		for _, read := range []func() (*store.LoginSession, error){
			func() (*store.LoginSession, error) { return s.Sessions().Get(ctx, "a", "s2") },
			func() (*store.LoginSession, error) { return s.Sessions().GetByTokenHash(ctx, "a", "h2") },
			func() (*store.LoginSession, error) {
				l, err := s.Sessions().ListByUser(ctx, "a", "auth0|u1")
				if err != nil {
					return nil, err
				}
				i := slices.IndexFunc(l, func(x *store.LoginSession) bool { return x.ID == "s2" })
				return l[i], nil
			},
		} {
			got, err := read()
			mustNoErr(t, err)
			mustEqual(t, got.AuthMethods, []store.AuthMethod{{Name: "pwd", At: now}, {Name: "mfa", Type: "otp", At: now.Add(time.Minute)}})
		}
		// Touch, AddClient and MarkMFA leave the record alone.
		mustNoErr(t, s.Sessions().Touch(ctx, "a", "s2", now.Add(time.Hour), now.Add(2*time.Hour), "198.51.100.9", "ua"))
		mustNoErr(t, s.Sessions().AddClient(ctx, "a", "s2", "web"))
		mustNoErr(t, s.Sessions().MarkMFA(ctx, "a", "s2", now.Add(time.Minute)))
		got, err = s.Sessions().Get(ctx, "a", "s2")
		mustNoErr(t, err)
		if len(got.AuthMethods) != 2 {
			t.Fatalf("methods after updates = %v", got.AuthMethods)
		}
		empty := newSession("a", "s3", "h3")
		empty.AuthMethods = []store.AuthMethod{}
		mustNoErr(t, s.Sessions().Create(ctx, empty))
		got, err = s.Sessions().Get(ctx, "a", "s3")
		mustNoErr(t, err)
		if len(got.AuthMethods) != 0 {
			t.Fatalf("empty methods = %v", got.AuthMethods)
		}
	})
	t.Run("ClientMobileRoundTrip", func(t *testing.T) {
		s := setup(t)
		plain := newClient("a", "c0")
		mustNoErr(t, s.Clients().Create(ctx, plain))
		got, err := s.Clients().Get(ctx, "a", "c0")
		mustNoErr(t, err)
		if got.Mobile != nil {
			t.Fatalf("nil mobile became %+v", got.Mobile)
		}
		want := newClient("a", "c1")
		want.Mobile = &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "ABCDE12345", AppBundleIdentifier: "com.example.app"},
			Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{"AB:CD", "EF:01"}}}
		mustNoErr(t, s.Clients().Create(ctx, want))
		want.Mobile.Android.SHA256CertFingerprints[0] = "changed"
		want.Mobile.IOS.TeamID = "changed"
		got, err = s.Clients().Get(ctx, "a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got.Mobile, &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "ABCDE12345", AppBundleIdentifier: "com.example.app"},
			Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{"AB:CD", "EF:01"}}})
		got.Mobile.Android.SHA256CertFingerprints[1] = "changed"
		again, err := s.Clients().Get(ctx, "a", "c1")
		mustNoErr(t, err)
		if again.Mobile.Android.SHA256CertFingerprints[1] != "EF:01" {
			t.Fatal("stored mobile aliases the returned value")
		}
		list, _, err := s.Clients().List(ctx, "a", store.ClientFilter{}, store.Page{})
		mustNoErr(t, err)
		i := slices.IndexFunc(list, func(c *store.Client) bool { return c.ClientID == "c1" })
		mustEqual(t, list[i].Mobile, again.Mobile)
		// Update replaces it, including to one platform only and to none.
		again.Mobile = &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "ZZZZZ99999", AppBundleIdentifier: "com.example.other"}}
		mustNoErr(t, s.Clients().Update(ctx, again))
		got, err = s.Clients().Get(ctx, "a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got.Mobile, &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "ZZZZZ99999", AppBundleIdentifier: "com.example.other"}})
		got.Mobile = nil
		mustNoErr(t, s.Clients().Update(ctx, got))
		got, err = s.Clients().Get(ctx, "a", "c1")
		mustNoErr(t, err)
		if got.Mobile != nil {
			t.Fatalf("cleared mobile = %+v", got.Mobile)
		}
	})
	t.Run("TenantDomainRPIDsRoundTrip", func(t *testing.T) {
		s := setup(t)
		got, err := s.Tenants().Get(ctx, "a")
		mustNoErr(t, err)
		if got.DomainRPIDs != nil {
			t.Fatalf("nil map became %v", got.DomainRPIDs)
		}
		want := newTenant("c")
		want.Domains = []string{"login.example.com", "c.example.test"}
		want.DomainRPIDs = map[string]string{"login.example.com": "example.com"}
		mustNoErr(t, s.Tenants().Create(ctx, want))
		want.DomainRPIDs["login.example.com"] = "changed"
		for _, read := range []func() (*store.Tenant, error){
			func() (*store.Tenant, error) { return s.Tenants().Get(ctx, "ten_c") },
			func() (*store.Tenant, error) { return s.Tenants().GetByName(ctx, "c") },
			func() (*store.Tenant, error) { return s.Tenants().GetByDomain(ctx, "login.example.com") },
			func() (*store.Tenant, error) {
				l, err := s.Tenants().List(ctx)
				if err != nil {
					return nil, err
				}
				return l[slices.IndexFunc(l, func(x *store.Tenant) bool { return x.ID == "ten_c" })], nil
			},
		} {
			got, err := read()
			mustNoErr(t, err)
			mustEqual(t, got.DomainRPIDs, map[string]string{"login.example.com": "example.com"})
		}
		got, err = s.Tenants().Get(ctx, "ten_c")
		mustNoErr(t, err)
		got.DomainRPIDs["login.example.com"] = "changed"
		again, err := s.Tenants().Get(ctx, "ten_c")
		mustNoErr(t, err)
		if again.DomainRPIDs["login.example.com"] != "example.com" {
			t.Fatal("stored map aliases the returned value")
		}
		again.DomainRPIDs = map[string]string{"c.example.test": "example.test"}
		mustNoErr(t, s.Tenants().Update(ctx, again))
		got, err = s.Tenants().Get(ctx, "ten_c")
		mustNoErr(t, err)
		mustEqual(t, got.DomainRPIDs, map[string]string{"c.example.test": "example.test"})
		got.DomainRPIDs = nil
		mustNoErr(t, s.Tenants().Update(ctx, got))
		got, err = s.Tenants().Get(ctx, "ten_c")
		mustNoErr(t, err)
		if got.DomainRPIDs != nil {
			t.Fatalf("cleared map = %v", got.DomainRPIDs)
		}
	})
	t.Run("ChallengeBindingRoundTrip", func(t *testing.T) {
		s := setup(t)
		plain := &store.MFAChallenge{TenantID: "a", ID: "c0", UserID: "u", Kind: "webauthn", Challenge: []byte("chal"), ExpiresAt: now.Add(5 * time.Minute)}
		mustNoErr(t, s.MFA().CreateChallenge(ctx, plain))
		got, err := s.MFA().GetChallenge(ctx, "a", "c0", now)
		mustNoErr(t, err)
		if len(got.Binding) != 0 {
			t.Fatalf("empty binding became %q", got.Binding)
		}
		binding := []byte(`{"purpose":"passkey-login","rp_id":"a.example.test","origins":["https://a.example.test"],"txn_id":"t1"}`)
		want := &store.MFAChallenge{TenantID: "a", ID: "c1", UserID: "u", Kind: "passkey-login", Challenge: []byte("32-random-bytes-go-here-exactly!"), Binding: slices.Clone(binding), ExpiresAt: now.Add(5 * time.Minute)}
		mustNoErr(t, s.MFA().CreateChallenge(ctx, want))
		want.Binding[0] = 'X'
		got, err = s.MFA().GetChallenge(ctx, "a", "c1", now)
		mustNoErr(t, err)
		if string(got.Binding) != string(binding) || got.Kind != "passkey-login" || string(got.Challenge) != "32-random-bytes-go-here-exactly!" {
			t.Fatalf("challenge = %+v", got)
		}
		got.Binding[0] = 'X'
		again, err := s.MFA().GetChallenge(ctx, "a", "c1", now)
		mustNoErr(t, err)
		if string(again.Binding) != string(binding) {
			t.Fatal("stored binding aliases the returned value")
		}
		// Failures keep it; consumption removes the row.
		if _, err := s.MFA().FailChallenge(ctx, "a", "c1"); err != nil {
			t.Fatal(err)
		}
		again, err = s.MFA().GetChallenge(ctx, "a", "c1", now)
		mustNoErr(t, err)
		if string(again.Binding) != string(binding) || again.Attempts != 1 {
			t.Fatalf("after failure: %+v", again)
		}
		mustNoErr(t, s.MFA().ConsumeChallenge(ctx, "a", "c1", now))
		if _, err := s.MFA().GetChallenge(ctx, "a", "c1", now); !isErr(err, store.ErrNotFound) {
			t.Fatalf("consumed challenge: %v", err)
		}
		// A challenge without a user (native, pre-signup) is not supported by
		// CreateChallenge; the kinds carry no store semantics beyond email/oob.
		mustNoErr(t, s.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "a", ID: "c2", UserID: "u", Kind: "passkey-register", Attempts: 5, Binding: binding, ExpiresAt: now.Add(time.Minute)}))
		mustNoErr(t, s.MFA().ConsumeChallenge(ctx, "a", "c2", now))
	})
	t.Run("PurgeWebAuthnExpired", func(t *testing.T) {
		s := setup(t)
		put := func(uid, scope string, until time.Time) {
			mustNoErr(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "a", UserID: uid, Kind: store.SnoozePasskeyProgressive, ScopeKey: scope, Until: until}))
		}
		put("u", "rp1", now.Add(-3*time.Second))
		put("u", "rp2", now.Add(-2*time.Second))
		put("v", "rp1", now.Add(-time.Second))
		put("v", "live", now.Add(time.Hour))
		put("v", "edge", now) // not before now: kept
		n, err := s.WebAuthn().PurgeWebAuthn(ctx, now, 2)
		mustNoErr(t, err)
		if n != 2 {
			t.Fatalf("first purge = %d, want 2", n)
		}
		n, err = s.WebAuthn().PurgeWebAuthn(ctx, now, 2)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatalf("second purge = %d, want 1", n)
		}
		n, err = s.WebAuthn().PurgeWebAuthn(ctx, now, 0)
		mustNoErr(t, err)
		if n != 0 {
			t.Fatalf("third purge = %d, want 0", n)
		}
		if _, err := s.WebAuthn().GetSnooze(ctx, "a", "v", store.SnoozePasskeyProgressive, "live", now); err != nil {
			t.Fatalf("live snooze purged: %v", err)
		}
		if _, err := s.WebAuthn().GetSnooze(ctx, "a", "v", store.SnoozePasskeyProgressive, "edge", now.Add(-time.Second)); err != nil {
			t.Fatalf("edge snooze purged: %v", err)
		}
		n, err = s.WebAuthn().PurgeWebAuthn(ctx, now.Add(time.Second), 0)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatalf("edge purge = %d, want 1", n)
		}
		// Expired challenges stay PurgeMFA's job; passkeys are never purged.
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("a", "u", "1", "c1"), 20))
		mustNoErr(t, s.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "a", ID: "old", UserID: "u", Kind: "passkey-login", Binding: []byte(`{}`), ExpiresAt: now.Add(-time.Second)}))
		n, err = s.WebAuthn().PurgeWebAuthn(ctx, now.Add(time.Hour), 0)
		mustNoErr(t, err)
		if n != 0 {
			t.Fatalf("purge touched other rows: %d", n)
		}
		n, err = s.MFA().PurgeMFA(ctx, now, 0)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatalf("PurgeMFA = %d, want the expired challenge", n)
		}
		if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("c1")); err != nil {
			t.Fatalf("passkey purged: %v", err)
		}
	})
	t.Run("TenantIsolation", func(t *testing.T) {
		s := setup(t)
		a := passkey("a", "u", "1", "c1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "a", UserID: "u", Kind: store.SnoozePasskeyProgressive, ScopeKey: "rp", Until: now.Add(time.Hour)}))
		mustNoErr(t, s.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "a", ID: "ch", UserID: "u", Kind: "passkey-login", Binding: []byte(`{}`), ExpiresAt: now.Add(time.Hour)}))

		if _, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "b", []byte("c1")); !isErr(err, store.ErrNotFound) {
			t.Fatalf("GetAuthenticatorByCredentialID = %v", err)
		}
		mustErrIs(t, s.WebAuthn().AcceptAssertion(ctx, "b", "u", a.ID, 1, true, now), store.ErrNotFound)
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, passkey("missing", "u", "2", "c2"), 20), store.ErrNotFound)
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "b", "u", "v", ""))
		if l, _ := s.MFA().ListAuthenticators(ctx, "b", "v"); len(l) != 0 {
			t.Fatalf("foreign move produced %v", l)
		}
		if _, err := s.WebAuthn().GetSnooze(ctx, "b", "u", store.SnoozePasskeyProgressive, "rp", now); !isErr(err, store.ErrNotFound) {
			t.Fatalf("GetSnooze = %v", err)
		}
		if _, err := s.MFA().GetChallenge(ctx, "b", "ch", now); !isErr(err, store.ErrNotFound) {
			t.Fatalf("GetChallenge = %v", err)
		}
		mustNoErr(t, s.MFA().DeleteUserAuthenticators(ctx, "b", "u", []string{"passkey"}))
		mustNoErr(t, s.MFA().DeleteUserMFA(ctx, "b", "u"))
		mustNoErr(t, s.MFA().DeleteTenantMFA(ctx, "b"))
		n, err := s.WebAuthn().PurgeWebAuthn(ctx, now, 0)
		mustNoErr(t, err)
		if n != 0 {
			t.Fatalf("purge removed a live row: %d", n)
		}
		// The same credential may exist in the other tenant and resolves there.
		mustNoErr(t, s.WebAuthn().CreateUserWithPasskey(ctx, &store.User{TenantID: "b", UserID: "n", Identities: []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: "n"}}}, passkey("b", "n", "1", "c1")))
		got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "b", []byte("c1"))
		mustNoErr(t, err)
		if got.UserID != "n" {
			t.Fatalf("other tenant's credential = %+v", got)
		}
		// The owner's rows survived every foreign-tenant call.
		got, err = s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "a", []byte("c1"))
		mustNoErr(t, err)
		if got.UserID != "u" || got.SignCount != 0 {
			t.Fatalf("owner's passkey changed: %+v", got)
		}
		if _, err := s.WebAuthn().GetSnooze(ctx, "a", "u", store.SnoozePasskeyProgressive, "rp", now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.MFA().GetChallenge(ctx, "a", "ch", now); err != nil {
			t.Fatal(err)
		}
	})
}
