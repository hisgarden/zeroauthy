# Plan 33b — Task 4 record: WebAuthn storage contract and memory store

Worktree `/home/user/zeroauthy-wt/task-4`, branch `claude/plan-33b-task-4`,
based on `42c1258` (`docs: plan Plan 33b passkeys and WebAuthn MFA`). Every
command ran from the worktree root with `GOTOOLCHAIN=go1.26.10
GOTMPDIR=/home/user/gotmp` (`go version go1.26.10 linux/amd64`). Memory-store
and mock tests only; no SQL, gRPC or E2E suite was run (Tasks 5 and 6).

## Files

| Change | Files |
| --- | --- |
| Contract | new `internal/store/webauthn.go`; `internal/store/{store,types,mfa}.go`; `pkg/store/store.go` (aliases) |
| Memory | new `internal/store/memory/webauthn.go`, `webauthn_test.go`; `memory/{memory,tx,clone,mfa,users}.go` |
| Compile stubs until Tasks 5/6 | new `internal/store/sqlstore/webauthn_stub.go`, `internal/store/grpcstore/webauthn_stub.go` (`UnimplementedWebAuthn`) |
| Conformance | new `pkg/storetest/webauthn.go`; `pkg/storetest/storetest.go` (`"WebAuthn"` after `"Phone"` in `Suites` and `suiteOrder`) |
| Sweeper | `internal/app/sweeper.go` (`purgeWebAuthn`), `internal/app/sweeper_test.go` (`TestSweepPurgesWebAuthn`) |

`memory/sessions.go`, `clients.go` and `tenants.go` needed no change: the new
fields ride through `cloneSession`, `cloneClient` and `Tenant.Clone`, and
`deleteTenantMFA` (called by tenant deletion) now also drops snoozes.

## Contract as implemented

- `Store.WebAuthn() WebAuthn` on every store and transaction view;
  `ErrWebAuthnUnavailable`; `WebAuthnSupporter`; `UnimplementedWebAuthn`.
- `WebAuthnSnooze{TenantID, UserID, Kind, ScopeKey; Until}` with the kind
  constants `SnoozePasskeyProgressive`, `SnoozePasskeyLocal`,
  `SnoozePlatformRemind`, `SnoozePlatformRefuse`.
- `WebAuthn` interface exactly as the plan's Go block, with these documented
  edges: `CreatePasskey` answers `ErrInvalid` for a row whose `Type` is not
  `passkey` or whose `CredentialID` is empty and `ErrNotFound` for a missing
  user; `limit <= 0` means no limit. `CreateUserWithPasskey` answers
  `ErrInvalid` when `a` does not name `u`. `MovePasskeys` answers `ErrNotFound`
  when either user is missing. `PutSnooze` answers `ErrNotFound` for a missing
  user. `GetSnooze` is `ErrNotFound` at and after `Until`. `HostTenantsUnder`
  compares the lowercased suffix without a trailing dot against every host
  binding of any kind, active or not, and returns sorted distinct tenant IDs.
  `PurgeWebAuthn` removes snoozes with `Until` before `before`; expired
  challenges stay `PurgeMFA`'s.
- `AuthMethod{Name, Type; At}`, `LoginSession.AuthMethods`, `Client.Mobile
  *ClientMobile`, `Tenant.DomainRPIDs map[string]string`,
  `MFAChallenge.Binding []byte`, `AuthenticatorTypes` gains `passkey` (sorted),
  `AuthenticatorPublicDataKeys` (the allowlist, now with `backup_eligible`,
  `backed_up`, `attachment`).
- `DeleteUserAuthenticators(ctx, tid, uid, nil)` removes every type except
  `passkey`; `DeleteUserMFA`, user deletion and tenant deletion remove all,
  snoozes included.

**Deviation (named for later tasks):** `ClientMobile` uses named member types
`ClientMobileIOS{TeamID, AppBundleIdentifier}` and
`ClientMobileAndroid{AppPackageName; SHA256CertFingerprints []string}`
instead of the plan's anonymous `*struct{…}` members, and gains `Clone()`.
Field names and shapes are the plan's; only the type names are new (an
anonymous pointer-to-struct member cannot be written or cloned from another
package without repeating the literal type).

The mgmt allowlist literals in `internal/mgmt/user_auth_methods.go` are not
touched here (Management API is Task 14); the store exports the list for it.

## RED

```
go test ./internal/store/... ./pkg/storetest ./internal/app -run 'WebAuthn|Sweep' -count=1
```

exit 1: `internal/store/memory` fails to build (`*Store does not implement
store.Store (missing method WebAuthn)`), so `memory`, `sqlstore`, `grpcstore`
and `internal/app` report `[build failed]`.

## GREEN

| Command | Exit |
| --- | --- |
| `go build ./...` | 0 |
| `go vet ./internal/store/... ./pkg/storetest ./internal/app` | 0 |
| `go test ./internal/store/... ./pkg/storetest ./internal/app -run 'WebAuthn\|Sweep' -count=1` | 0 (`memory` 0.338s, `app` 1.672s; `sqlstore` and `grpcstore` select no test by that name) |
| `go test ./internal/store/memory ./pkg/storetest ./internal/app -count=1` | 0 (`memory` 20.8s incl. full `TestConformance`, `app` 20.2s) |
| `go test ./internal/store/memory ./pkg/storetest ./internal/app ./pkg/store ./internal/store -count=1` | 0 |
| `gofmt -l internal/store pkg/storetest pkg/store internal/app` | 0, no output |

`TestWebAuthnConformance` runs the 17 named cases: `CreatePasskeyLimit`,
`CreatePasskeyLimitConcurrent`, `CredentialUniquePerTenant`,
`CreateUserWithPasskeyAtomic`, `AcceptAssertionCounter`,
`AcceptAssertionWritesBackupStateAndLastAuth`, `MovePasskeysAllAndByIdentity`,
`DeleteUserAuthenticatorsNilKeepsPasskeys`, `DeleteUserMFARemovesPasskeys`,
`SnoozeUpsertAndExpiry`, `HostTenantsUnder`, `SessionAuthMethodsRoundTrip`,
`ClientMobileRoundTrip`, `TenantDomainRPIDsRoundTrip`,
`ChallengeBindingRoundTrip`, `PurgeWebAuthnExpired`, `TenantIsolation`; all
PASS. Concurrency cases wait up to 10 s for every goroutine and assert exactly
one winner. `TestWebAuthnSuiteSkipsWithoutCapability` shows the suite skips
(`--- SKIP`) on a driver whose `WebAuthn()` is `UnimplementedWebAuthn`, which
is what `sqlstore` and `grpcstore` conformance runs see until Tasks 5 and 6;
`TestWebAuthnTransactionRollback` covers the memory transaction snapshot.
`internal/app`: `TestSweepPurgesWebAuthn` PASS (bounded batches, live rows
kept, `ErrWebAuthnUnavailable` tolerated).

One test fix during GREEN: the first `HostTenantsUnder` expectation assumed
`newTenant` domains for tenants whose `Domains` the case overrides; corrected
to the two tenants that carry `<name>.example.test`.
