package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type webauthn struct{ s *Store }

// WebAuthn stores passkeys in mfa_authenticators (type "passkey"), snoozes
// in webauthn_snoozes and challenge bindings in mfa_challenges.data.
func (s *Store) WebAuthn() store.WebAuthn { return webauthn{s} }

// SQL stores support WebAuthn unconditionally (migration 0035).
func (s *Store) CheckWebAuthnSupport(context.Context) error { return nil }
func (s *Store) WebAuthnSupported() bool                    { return true }

func (r webauthn) GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*store.Authenticator, error) {
	if len(credID) == 0 {
		return nil, store.ErrNotFound
	}
	return scanAuth(r.s.queryRow(ctx, `SELECT `+authCols+` FROM mfa_authenticators WHERE tenant_id=? AND credential_id=?`, tid, credID))
}

// validPasskey reports whether a is a storable passkey row.
func validPasskey(a *store.Authenticator) bool {
	return a.Type == "passkey" && len(a.CredentialID) > 0 && a.ID != ""
}

// insertPasskey stores a inside s's transaction, whose caller holds the
// user row: ErrConflict when the tenant already has a's ID or credential ID,
// ErrPrecondition when the user already holds limit passkeys (limit <= 0: no
// limit). The checks run in that order, as in the memory store; the unique
// indexes remain the final word on conflicts.
func insertPasskey(ctx context.Context, s *Store, a *store.Authenticator, limit int) error {
	var n int
	if err := s.queryRow(ctx, `SELECT COUNT(*) FROM mfa_authenticators WHERE tenant_id=? AND (id=? OR credential_id=?)`, a.TenantID, a.ID, a.CredentialID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return store.ErrConflict
	}
	if limit > 0 {
		if err := s.queryRow(ctx, `SELECT COUNT(*) FROM mfa_authenticators WHERE tenant_id=? AND user_id=? AND type='passkey'`, a.TenantID, a.UserID).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return store.ErrPrecondition
		}
	}
	_, err := s.exec(ctx, `INSERT INTO mfa_authenticators (`+authCols+`,recovery_user) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.TenantID, a.UserID, a.ID, a.Type, a.Name, a.Confirmed, a.Preferred, a.SealedSecret, a.LastStep, a.CodeHash, a.Email, a.Phone,
		a.CredentialID, a.PublicKey, a.RPID, a.SignCount, micros(a.CreatedAt), micros(a.LastAuthAt), a.PhoneMethod, a.PublicData, nil)
	return s.conflict(err)
}

// CreatePasskey counts and inserts in one transaction with the user row
// locked (FOR UPDATE on PostgreSQL and MySQL; SQLite transactions are BEGIN
// IMMEDIATE on one connection), so concurrent creates for one user admit
// exactly as many passkeys as the limit allows. Deadlocks are retried.
func (r webauthn) CreatePasskey(ctx context.Context, a *store.Authenticator, limit int) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := (mfa{s}).user(ctx, a.TenantID, a.UserID); err != nil {
			return err
		}
		if !validPasskey(a) {
			return store.ErrInvalid
		}
		return insertPasskey(ctx, s, a, limit)
	})
}

// CreateUserWithPasskey creates the user (Users.Create rules) and its
// passkey in one transaction; a failure of either rolls back both.
func (r webauthn) CreateUserWithPasskey(ctx context.Context, u *store.User, a *store.Authenticator) error {
	if a.TenantID != u.TenantID || a.UserID != u.UserID || !validPasskey(a) {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := (users{s}).Create(ctx, u); err != nil {
			return err
		}
		return insertPasskey(ctx, s, a, 0)
	})
}

// AcceptAssertion decides in one conditional UPDATE: the sign-counter
// predicate admits exactly one of two concurrent assertions with the same
// counter. The backup state is merged into the public data read just before;
// a racing writer either fails the predicate or carried an older counter.
func (r webauthn) AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error {
	a, err := (mfa{r.s}).GetAuthenticator(ctx, tid, uid, id)
	if err != nil {
		return err
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
	return (mfa{r.s}).conditional(ctx, tid, uid, id, `UPDATE mfa_authenticators SET sign_count=?,last_auth_at=?,public_data=? WHERE tenant_id=? AND user_id=? AND id=? AND (sign_count<? OR (sign_count=0 AND ?=0))`,
		count, micros(at), data, tid, uid, id, count, count)
}

// MovePasskeys locks both users (in byte order), then reassigns the chosen
// passkeys one primary key at a time; their rows are otherwise unchanged.
func (r webauthn) MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		first, second := fromUID, toUID
		if second < first {
			first, second = second, first
		}
		for _, uid := range []string{first, second} {
			if err := (mfa{s}).user(ctx, tid, uid); err != nil {
				return err
			}
		}
		rows, err := s.query(ctx, `SELECT id,public_data FROM mfa_authenticators WHERE tenant_id=? AND user_id=? AND type='passkey' ORDER BY id`+s.d.byteOrder, tid, fromUID)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			var public []byte
			if err := rows.Scan(&id, &public); err != nil {
				rows.Close()
				return err
			}
			if identityUserID == "" || publicDataString(public, "identity_user_id") == identityUserID {
				ids = append(ids, id)
			}
		}
		err = rows.Err()
		rows.Close() // release the single SQLite connection before writing
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := s.exec(ctx, `UPDATE mfa_authenticators SET user_id=? WHERE tenant_id=? AND id=? AND user_id=?`, toUID, tid, id, fromUID); err != nil {
				return err
			}
		}
		return nil
	})
}

// publicDataString returns one string field of authenticator public data,
// or "" when absent or not a string.
func publicDataString(public []byte, field string) string {
	if len(bytes.TrimSpace(public)) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(public, &m) != nil {
		return ""
	}
	v, _ := m[field].(string)
	return v
}

func (r webauthn) PutSnooze(ctx context.Context, v *store.WebAuthnSnooze) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := (mfa{s}).user(ctx, v.TenantID, v.UserID); err != nil {
			return err
		}
		q := `INSERT INTO webauthn_snoozes (tenant_id,user_id,kind,scope_key,until) VALUES (?,?,?,?,?)`
		if s.d.name == "mysql" {
			q += ` ON DUPLICATE KEY UPDATE until=VALUES(until)`
		} else {
			q += ` ON CONFLICT (tenant_id,user_id,kind,scope_key) DO UPDATE SET until=excluded.until`
		}
		_, err := s.exec(ctx, q, v.TenantID, v.UserID, v.Kind, v.ScopeKey, micros(v.Until))
		return err
	})
}

func (r webauthn) GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*store.WebAuthnSnooze, error) {
	var until int64
	err := r.s.queryRow(ctx, `SELECT until FROM webauthn_snoozes WHERE tenant_id=? AND user_id=? AND kind=? AND scope_key=? AND until>?`, tid, uid, kind, scope, micros(now)).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &store.WebAuthnSnooze{TenantID: tid, UserID: uid, Kind: kind, ScopeKey: scope, Until: fromMicros(until)}, nil
}

// HostTenantsUnder matches whole labels: host = suffix, or host LIKE
// '%.' + suffix with the suffix's LIKE wildcards escaped ('!' is the escape
// character, as in user search), so "ample.com" is not under "example.com".
func (r webauthn) HostTenantsUnder(ctx context.Context, suffix string, limit int) ([]string, error) {
	suffix = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(suffix)), ".")
	out := []string{}
	if suffix == "" {
		return out, nil
	}
	pattern := "%." + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(suffix)
	q := `SELECT tenant_id FROM host_bindings WHERE host=? OR host LIKE ? ESCAPE '!' GROUP BY tenant_id ORDER BY tenant_id` + r.s.d.byteOrder
	args := []any{suffix, pattern}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// PurgeWebAuthn deletes expired snoozes like PurgeMFA: select up to limit
// keys, then delete each by primary key with the expiry predicate repeated.
func (r webauthn) PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error) {
	n := 0
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(s *Store) error {
		n = 0 // a retry starts after the previous transaction was rolled back
		q := `SELECT tenant_id,user_id,kind,scope_key FROM webauthn_snoozes WHERE until<?`
		args := []any{micros(before)}
		if limit > 0 {
			q += ` LIMIT ?`
			args = append(args, limit)
		}
		rows, err := s.query(ctx, q, args...)
		if err != nil {
			return err
		}
		var keys [][4]string
		for rows.Next() {
			var k [4]string
			if err := rows.Scan(&k[0], &k[1], &k[2], &k[3]); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, k := range keys {
			res, err := s.exec(ctx, `DELETE FROM webauthn_snoozes WHERE tenant_id=? AND user_id=? AND kind=? AND scope_key=? AND until<?`, k[0], k[1], k[2], k[3], micros(before))
			if err != nil {
				return err
			}
			a, err := res.RowsAffected()
			if err != nil {
				return err
			}
			n += int(a)
		}
		return nil
	})
	return n, err
}
