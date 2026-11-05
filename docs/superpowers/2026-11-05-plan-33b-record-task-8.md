# Plan 33b — Task 8 record: passkey ceremony service and secret scrubbing

Worktree `/home/user/zeroauthy-wt/task-8`, branch `claude/plan-33b-task-8`,
based on `a7ba62c` (`feat: resolve relying party IDs per host and passkey
prerequisites`, Tasks 1–7 landed). Every command ran from the worktree root
with `GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp` under `nice -n 5`.
Memory store, SQLite and gRPC suites only; no
PostgreSQL, MySQL, E2E or full repository suite.

## Files

| Change | Files |
| --- | --- |
| Service | new `internal/passkey/{service,challenge,signup}.go` |
| Tests | new `internal/passkey/{helpers,challenge,service,signup}_test.go`, `internal/logscrub/webauthn_test.go` |
| Scrubber | `internal/logscrub/scrub.go` (reads `webauthnrules.ScrubKeys()`) |
| Challenge user (deviation 1) | `internal/store/mfa.go` (`ChallengeUserOptional`, `CreateChallenge` doc), `internal/store/memory/mfa.go`, `internal/store/sqlstore/mfa.go`, `pkg/store/store.go` (re-export), `pkg/storetest/webauthn.go` (`ChallengeWithoutUser`, stale comment in `ChallengeBindingRoundTrip` fixed) |
| Wiring | `internal/app/app.go` (`passkey.New(st, rpPolicy, nil)`), `internal/server/server.go` (`Deps.Passkeys`, unused by routes until Task 9) |

`internal/store/grpcstore` needed no change: the server forwards
`MFACreateChallenge` to the backing store and the codec carries an empty
`user_id`; the new storetest case runs over gRPC (memory-backed) and passes.

## Exported API (`internal/passkey`)

```go
type Purpose string
const (
	PurposePasskeyRegister  Purpose = "passkey-register"
	PurposePasskeyLogin     Purpose = "passkey-login"
	PurposeWebAuthnRegister Purpose = "webauthn-register"
	PurposeWebAuthnAssert   Purpose = "webauthn-assert"
)
type Binding struct {
	Purpose                       Purpose
	RPID                          string
	Origins                       []string // exact serialized origins
	TxnID, CookieHash             string   // hosted
	ClientID, Realm, Organization string   // native
	UserID                        string   // enrollment and MFA
}
type Issued struct {
	ID, Session string
	Challenge   []byte
	ExpiresAt   time.Time
}
type UserDisplay struct{ Name, DisplayName string }
type EnrollKind int
const (
	Signup      EnrollKind = iota + 1
	Progressive
	Local
)
type LoginResult struct {
	User      *store.User
	Method    *store.Authenticator
	Assertion *webauthn.Assertion
}
var ErrCeremony = errors.New("passkey: ceremony failed")
var ErrMaxPasskeys = errors.New("passkey: passkey limit reached")
const KeyMaxPasskeys = "passkey-enrollment-max-allowed-reached"
const ReasonCredential = "credential"

func ErrorKey(err error) string
func Display(u *store.User, conn *store.Connection) UserDisplay
func SessionID(session string) string
func New(st store.Store, rp rpid.Policy, now func() time.Time) *Service
func (s *Service) Issue(ctx context.Context, tid string, b Binding, ttl time.Duration) (*Issued, error)
func (s *Service) Take(ctx context.Context, tid, id string, want Binding) ([]byte, error)
func (s *Service) Login(ctx context.Context, tid string, raw []byte, ch []byte, b Binding) (*LoginResult, error)
func (s *Service) Enroll(ctx context.Context, tid string, u *store.User, identityUserID string, raw, ch []byte, b Binding, userAgent string) (*store.Authenticator, error)
func (s *Service) Signup(ctx context.Context, tid string, draft *store.User, raw, ch []byte, b Binding, userAgent string) (*store.User, *store.Authenticator, error)
func (s *Service) CreationOptions(ctx context.Context, tid string, u *store.User, display UserDisplay, rpID string, kind EnrollKind, ch []byte, timeout time.Duration) (webauthn.CreationOptions, error)
func (s *Service) RequestOptions(rpID string, ch []byte, timeout time.Duration) webauthn.RequestOptions
func (s *Service) Effective(ctx context.Context, tid string, res tenant.Resolved, conn *store.Connection) (connrules.PasskeyPolicy, rpid.Result, bool, error)
```

Behaviour as implemented:

- **Issue** validates the binding (`store.ErrInvalid` for an unknown
  purpose, empty RP ID or origins, neither `TxnID` nor `ClientID`, or a
  WebAuthn MFA purpose without a user). Hosted = `TxnID` set; native =
  no `TxnID` and a `ClientID`. `ttl <= 0` takes
  `Limits.HostedChallengeTTL` (hosted) or `Limits.NativeTimeout +
  Limits.NativeGrace` (native); `ExpiresAt = now + ttl`. The challenge is
  `Limits.ChallengeBytes` random bytes. Hosted `ID` is a random base64url
  token of the same length (the `challenge_id` the page posts);
  native `Session` is such a token and `ID = secrets.HashToken(Session)`
  (`SessionID`), the only form stored. The row is an `MFAChallenge` with
  `Kind = Purpose`, `UserID = b.UserID`, the raw challenge, and
  `Binding` = JSON `{purpose, rp_id, origins, txn_id, cookie_hash,
  client_id, realm, organization, user_id}` (empty strings omitted).
- **Take** reads the row (`GetChallenge` at `now`), then consumes it with
  the store's conditional single-use `ConsumeChallenge` (the same delete
  Plan 33's MFA proofs use: `DELETE … WHERE … AND expires_at > now`, 0 rows =
  `ErrPrecondition`), and only then compares kind, user and every binding
  field (origins as an ordered list). Missing, expired (at `ExpiresAt`),
  consumed or mismatched → `ErrCeremony` (reason `challenge`); a mismatched
  `Take` has already spent the challenge. The native caller passes
  `SessionID(auth_session)`.
- **Login** (LR33b-16): parse; look the credential up by ID in the tenant;
  it must be a confirmed `passkey` whose `RPID` equals `b.RPID` (else
  `ErrCeremony`, reason `credential` or `rp_id`); load its user; verify
  with `RequireUserHandle` against the stored key, sign count, BE and
  `user_handle`; then a blocked user → `identity.ErrUserBlocked` (not
  wrapped in `ErrCeremony`); with a native `b.Realm` the user must have an
  identity on that connection; `AcceptAssertion` writes count, BS and
  `last_auth_at` (`ErrPrecondition` → `ErrCeremony` reason `sign_count`).
  The returned `Method` carries the new count, `LastAuthAt` and
  `backed_up`. Connection-enabled-for-client and passkeys-effective checks
  are the caller's (Task 9/15).
- **Enroll**: the binding must be `passkey-register` for `u`; verify;
  handle = the user's existing passkey handle (first by `CreatedAt`, then
  ID), else derived from `ch` (deviation 2); `CreatePasskey(a,
  Limits.MaxPasskeys)`: `ErrPrecondition` → `ErrMaxPasskeys` (`ErrorKey` =
  `passkey-enrollment-max-allowed-reached`), `ErrConflict` → `ErrCeremony`
  (reason `credential`). `identityUserID == ""` defaults to the user's own
  database identity's `Identity.UserID` (provider-local ID). Row:
  `ID passkey|dev_<20>`, `Confirmed`, credential ID, COSE key, `RPID`, sign
  count, `CreatedAt = now`, public data `aaguid` (UUID text),
  `attachment`, `backup_eligible`, `backed_up`, `identity_user_id`,
  `transports`, `user_agent` (bounded to 512 bytes), `user_handle`
  (base64url) — all in `store.AuthenticatorPublicDataKeys`. `Name` is left
  empty (LR33b-31 default names are a page/console concern).
- **Signup**: draft validated first (`store.ErrInvalid` without an own
  database identity, with a password or imported hash, or of another
  tenant); binding must be `passkey-register` without a user; verify; an
  empty `UserID` gets `auth0|<RandomHex(12)>` as `identity.database` does;
  a credential already in the tenant is `ErrCeremony` before the write;
  then one `CreateUserWithPasskey` (the store's `ErrConflict` for a taken
  email/username is returned unchanged). Handle derived from `ch`.
- **CreationOptions**: `-8, -7, -257`, `attestation: none`, `rp.name =
  rp.id`, `residentKey: required`, `userVerification: preferred`,
  `authenticatorAttachment: platform` for `Local`; `timeout <= 0` =
  `HostedChallengeTTL`. Except for `Signup`, `excludeCredentials` lists
  every WebAuthn credential of the user (`passkey`, `webauthn-roaming`,
  `webauthn-platform`) whose `RPID` equals `rpID`, with stored transports.
  An empty display is filled from `Display(u, nil)`. Kind 0 or out of
  range is `store.ErrInvalid`.
- **Display**: `user.name` = first of email, phone number, username that
  the user has and that is active on `conn` (`store.IdentifierActive`;
  `conn == nil` counts all; when none qualifies, the first value the user
  has); `displayName` = `u.Name`, else that identifier.
- **RequestOptions**: discoverable (`allowCredentials: []`),
  `userVerification: preferred`, `timeout <= 0` = `HostedChallengeTTL`.
- **Effective**: prompts from `HostedLogins().Get` (`ErrNotFound` and
  `ErrHostedLoginRepositoryUnavailable` = defaults), `connrules.Passkeys`,
  `rpid.Policy.For`, and WebAuthn support (`WebAuthnSupporter.CheckWebAuthnSupport`
  when the store negotiates, and never with `UnimplementedWebAuthn`). The
  bool is policy effective ∧ RP ID valid ∧ supported ∧ request tenant and
  connection tenant equal `tid`. Errors only for storage failures.
- **Scrubber**: `SensitiveKey` also hides the nine §8.2 names, normalized
  like every key (case, `_`, `-`, `.` ignored) and matched exactly, read
  from `webauthnrules.ScrubKeys()`.

## Deviations

1. **User-less passkey challenges (store contract change).** Task 6 found
   that `MFA().CreateChallenge` answers `ErrNotFound` unless `UserID` names
   a user, so a usernameless `passkey-login` (hosted or native) and a
   signup `passkey-register` challenge could not be stored. Fix: the new
   `store.ChallengeUserOptional(kind)` is true for `passkey-login` and
   `passkey-register`; for those kinds `CreateChallenge` accepts `UserID ==
   ""`, requiring only an existing tenant (`ErrNotFound` otherwise) and no
   `AuthenticatorID` (`ErrNotFound` when set). Every other kind keeps the
   user check. Memory checks `tenants[tid]`; SQL checks the `tenants` row
   and inserts `user_id = ''` (`mfa_challenges.user_id` is `NOT NULL`
   without a foreign key; no migration). gRPC forwards unchanged. Pinned by
   `pkg/storetest` `WebAuthn/ChallengeWithoutUser` (create/get/consume once,
   tenant isolation, conflict, other kinds refused, authenticator refused,
   missing tenant refused, user deletion leaves the row, `PurgeMFA` and
   `DeleteTenantMFA` remove it), run on memory, SQLite and gRPC. The
   alternative (binding pre-login challenges to a placeholder user) would
   have needed a fake user row per tenant; this change is smaller and keeps
   user deletion semantics intact.
2. **First user handle derived from the challenge.** LR33b-7 says 32 random
   bytes at the user's first passkey, reused after. The contract gives
   `CreationOptions` and `Enroll`/`Signup` only the raw challenge in common
   (a registration response does not carry `user.id`), so a handle drawn at
   `CreationOptions` time could not be stored by `Enroll` without extra
   state. A user's first handle is therefore `SHA-256("zeroauthy passkey
   user handle\0" ‖ counter ‖ ch)` truncated to `Limits.UserHandleBytes`:
   unpredictable as the fresh 32-byte challenge, no PII, and visible only
   where `user.id` already is (the same options document). Later passkeys
   reuse the stored handle. Known edge: two concurrent *first* enrollments
   of one user in two transactions (both rendered before either stored)
   give the second passkey a stored handle that differs from the one its
   authenticator holds, and that passkey then fails `user_handle` at login;
   signup and local enrollment (which needs an existing passkey) cannot
   hit it.
3. `Effective` returns `connrules.PasskeyPolicy` (Task 7's type name); the
   plan's contract block says `connrules.Policy`.
4. Additions beyond the contract block, needed to use it: `Purpose*`
   constants, `New`, `Display`, `SessionID`, `ErrMaxPasskeys`,
   `KeyMaxPasskeys`, `ErrorKey`, `ReasonCredential`, `EnrollKind` constants
   starting at 1 (zero is invalid), `pkg/store.ChallengeUserOptional`,
   `server.Deps.Passkeys`.
5. Extra test `TestEffective` (not named by the plan).

## RED

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./internal/passkey ./internal/logscrub -count=1` | 1 | `internal/passkey`: `no non-test Go files` (`[build failed]`); `internal/logscrub`: `TestScrubWebAuthnKeys` FAIL (every §8.2 name visible except `challenge_id`, which the existing `challenge` fragment already hid) |
| `go test ./internal/store/memory -run WebAuthn -count=1` | 1 | `TestWebAuthnConformance/ChallengeWithoutUser`: `unexpected error: store: not found` |

## GREEN

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./internal/passkey ./internal/logscrub -count=1` | 0 | `passkey` 0.063s (the nine named tests plus `TestEffective`, all PASS in a `-v` run), `logscrub` 0.018s |
| `go build ./...` | 0 | |
| `go vet ./internal/passkey ./internal/logscrub ./internal/store ./internal/store/memory ./internal/store/sqlstore ./pkg/store ./pkg/storetest ./internal/app ./internal/server` | 0 | |
| `go test ./internal/store/memory ./internal/store/grpcstore -run 'MFA\|WebAuthn\|Conformance' -count=1 -timeout=30m` | 0 | `memory` 16.1s, `grpcstore` 190.2s |
| `go test ./internal/store/sqlstore/... -run 'MFA\|WebAuthn' -count=1` (SQLite) | 0 | 15.7s |
| `go test ./internal/app ./internal/mfa -count=1` | 0 | `app` 14.8s, `mfa` 0.3s |
| `gofmt -l internal pkg cmd` | 0 | no output |

A focused `-v` run showed `WebAuthn/ChallengeWithoutUser` PASS on memory,
`TestWebAuthnConformance/sqlite/ChallengeWithoutUser` and
`TestWebAuthnCapabilityNegotiated/WebAuthn/ChallengeWithoutUser` (gRPC over
memory).

Mutation check (not committed): with `Take`'s binding comparison and
consume removed, `TestIssueTakeSingleUse` and `TestTakeBinding` fail;
restored before the runs above.

Not run: PostgreSQL, MySQL, E2E, the full repository suite.
