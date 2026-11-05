# Plan 33b — Task 5 record: migration 0035 and SQL store

Worktree `/home/user/zeroauthy-wt/task-5`, branch `claude/plan-33b-task-5`,
based on `3bcb1b2` (`feat: add WebAuthn storage contract and memory store`).
Every command ran from the worktree root with `GOTOOLCHAIN=go1.26.10
GOTMPDIR=/home/user/gotmp`.

## Dialects

| Dialect | Status |
| --- | --- |
| SQLite | executed (always on; no container) |
| PostgreSQL 16.15 | executed: no Docker daemon here, so `scripts/test-sql.sh` could not run; a local cluster from the installed `postgresql-16` package was started instead (`initdb` + `pg_ctl` as the `postgres` user, port 55432, `fsync=off`), and the tests ran with `ZA_TEST_POSTGRES_DSN=postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable`. The script asks for PostgreSQL 14+; it uses 17 in its container. |
| MySQL | **written, NOT executed**: no `mysqld`/`mariadbd` binary and no container runtime. `ZA_TEST_MYSQL_DSN` was unset, so every MySQL subtest (including `TestWebAuthnMySQLMigrationResume35`, which only selects MySQL) ran nothing. |

MySQL points to verify on the first real run: `until` as a column name (a
non-reserved keyword in MySQL 8 as far as known; also non-reserved in
PostgreSQL, where it ran), the `webauthn_snoozes` primary-key length
(`tenant_id VARCHAR(64)`, `user_id VARCHAR(255)`, `kind VARCHAR(32)`,
`scope_key VARCHAR(255)` = 2424 bytes in utf8mb4, under InnoDB's 3072),
`ON DUPLICATE KEY UPDATE until=VALUES(until)`, the resumable-DDL path for
version 35, and the `CreatePasskey` lock/count/insert under REPEATABLE READ
(the count is the first consistent read, taken after the user row lock).

## Files

| Change | Files |
| --- | --- |
| Migration | new `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0035_webauthn.sql`; `migrate.go` (35 joins the MySQL resumable list, like 30–34) |
| Repository | new `internal/store/sqlstore/webauthn.go` (replaces the deleted `webauthn_stub.go`) |
| Read/write paths | `sessions.go` (`auth_methods`), `clients.go` (`mobile`), `tenants.go` (`domain_rp_ids`), `mfa.go` (`DeleteUserAuthenticators(nil)` keeps passkeys; `DeleteUserMFA`/`DeleteTenantMFA` drop snoozes), `users.go`/`tenants.go` (`webauthn_snoozes` in `userDependents`/`tenantTables`) |
| Tests | new `webauthn_test.go`; version pins moved from 34 to 35 in `migrate_test.go` (`TestLatestVersion`), `mfa_test.go` (`TestMFAMySQLMigrationResume33`) and `events_test.go` (`TestEventsMigrationFrom30`, the MySQL resume test at line 674) |

## Schema

- `sessions.auth_methods`, `clients.mobile`, `tenants.domain_rp_ids`: `TEXT
  NULL` on SQLite and PostgreSQL, `LONGTEXT NULL` on MySQL (the MySQL
  convention for JSON columns, e.g. `organization_discovery_methods`). NULL
  means none; no UPDATE of existing rows.
- `webauthn_snoozes (tenant_id, user_id, kind, scope_key, until BIGINT
  micros, PRIMARY KEY (tenant_id,user_id,kind,scope_key))` and
  `webauthn_snoozes_until`.
- Challenge bindings ride in `mfa_challenges.data`: the row is the JSON of
  `store.MFAChallenge`, so `Binding` needed no code change (base64 in JSON;
  covered by `ChallengeBindingRoundTrip` and the migration test).
- Stored JSON: `auth_methods` is `[{"name","type"?,"at":micros}]`; `mobile`
  is `{"ios":{"team_id","app_bundle_identifier"},"android":{"app_package_name","sha256_cert_fingerprints"}}`
  (Management API names); `domain_rp_ids` is the host → RP ID object.

## Implementation notes

- `WebAuthnSupported()` true and `CheckWebAuthnSupport` nil, like Logs and
  Events. Transaction views are `*Store` too, so they serve `WebAuthn()`.
- `CreatePasskey`: one `atomicRetry` transaction; locks the user row
  (`SELECT … FOR UPDATE` on PostgreSQL/MySQL; SQLite DSNs use
  `_txlock=immediate` on a single connection), then checks conflicts (ID or
  credential in the tenant, `ErrConflict`), then counts passkeys
  (`ErrPrecondition`), then inserts; the unique indexes stay the final word.
  Error order matches memory: `ErrNotFound` (user) → `ErrInvalid` →
  `ErrConflict` → `ErrPrecondition`. Deadlocks use the existing retry.
- `CreateUserWithPasskey`: one transaction around `Users.Create` (all its
  rules and locks) and the passkey insert.
- `AcceptAssertion`: reads the row, merges `backed_up` into public data, and
  decides with one conditional `UPDATE … AND (sign_count<? OR (sign_count=0
  AND ?=0))` (via the existing `mfa.conditional`, which maps 0 rows to
  `ErrNotFound`/`ErrPrecondition`).
- `MovePasskeys`: locks both users in byte order, selects the passkeys, then
  updates each by primary key.
- `PutSnooze`: user lock + upsert (`ON CONFLICT … DO UPDATE` /
  `ON DUPLICATE KEY UPDATE`). `PurgeWebAuthn` follows `PurgeMFA` (sweep
  isolation, bounded key select, per-key delete).
- `HostTenantsUnder`: `host = suffix OR host LIKE '%.' || escaped(suffix)
  ESCAPE '!'` with the pattern built in Go (`!`, `%`, `_` escaped, as in
  user search), `GROUP BY tenant_id ORDER BY tenant_id` + byte order, over
  every `host_bindings` row (any kind, active or not).
- Old-schema fixtures: many sqlstore tests create tenants through the
  repository at schema 22–33, so `Tenants.Create` names `domain_rp_ids` only
  when the map is non-nil (NULL is the default); `clientCols`/`clientArgs`
  stay the pre-0035 list (fixtures seed with them) and `mobile` is added in
  `clientRowCols`.

## Contract deviations

None from the Task 4 contract. Dialect mapping only: MySQL uses `LONGTEXT
NULL` where the plan says `TEXT NULL`, and `tenant_id VARCHAR(64)` in
`webauthn_snoozes` (InnoDB key length; `tenants.id` is `VARCHAR(64)` there).

## RED

`go test ./internal/store/sqlstore/... -run 'WebAuthn|TestLatestVersion' -count=1`
(SQLite + PostgreSQL), stub still in place: exit 1 —
`TestLatestVersion` (34, want 35), `TestWebAuthnConformance` ("sqlstore does
not report WebAuthn support"), `TestWebAuthnHostTenantsUnderWildcards` and
`TestWebAuthnCreatePasskeyLimitAcrossConnections` (`store: WebAuthn
unavailable`), `TestWebAuthnMigrationLeavesRows` (version 34).

## GREEN

New tests in `webauthn_test.go`: `TestWebAuthnConformance` (asserts
`WebAuthnSupported()` and no `ErrWebAuthnUnavailable`, then runs
`storetest.WebAuthn`, so the suite cannot silently skip),
`TestWebAuthnMigrationLeavesRows` (seeds tenants, tenant_domains, users,
sessions, clients, mfa_authenticators and mfa_challenges at 0034 with raw
SQL; after migrating, every old column of every row is identical and the only
new columns are NULL; repositories read the rows with the new fields absent),
`TestWebAuthnHostTenantsUnderWildcards` (`%`, `_`, `!` in the suffix stay
literal), `TestWebAuthnCreatePasskeyLimitAcrossConnections` (10 writers on
two pools for the last slot: exactly one wins), `TestWebAuthnMySQLMigrationResume35`
(MySQL only: not executed).

| Command | Dialects | Exit |
| --- | --- | --- |
| `go test ./internal/store/sqlstore/... -run 'WebAuthn' -count=1 -v` | SQLite + PostgreSQL | 0; `TestWebAuthnConformance` 17/17 cases PASS on each, 0 SKIP |
| `go test ./internal/store/sqlstore/... -run 'WebAuthn\|Conformance' -count=1` | SQLite | 0 (183.8s) |
| same, with `ZA_TEST_POSTGRES_DSN` | SQLite + PostgreSQL | 0 (599.1s, just under go test's default 10m timeout) |
| `go test ./internal/store/memory ./internal/store/sqlstore/... -count=1` (first run) | SQLite | 1: `TestEventsMigrationFrom30` pinned `LatestVersion() == 34`; pin moved to 35 (and its MySQL sibling), focused rerun PASS on SQLite + PostgreSQL |
| `go test ./internal/store/memory ./internal/store/sqlstore/... -count=1` (rerun) | SQLite | 0 (`memory` 15.0s, `sqlstore` 199.9s) |
| `go test ./internal/store/sqlstore/... -skip 'Conformance' -timeout=60m -count=1` | SQLite + PostgreSQL | 0 (311.4s) |
| `go build ./...` | | 0 |
| `go vet ./internal/store/...` | | 0 |
| `gofmt -l internal/store` | | 0, no output |

During GREEN, `TestWebAuthnMigrationLeavesRows` failed once on PostgreSQL
with `cached plan must not change result type`: a test artifact (pgx caches
`SELECT *` by text across the ALTER); the snapshot query now carries a
per-phase comment.

Not run: MySQL (no server), `./scripts/test-sql.sh` (no container runtime),
the full repository suite and E2E (out of scope).
