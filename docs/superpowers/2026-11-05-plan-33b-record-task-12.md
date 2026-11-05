# Plan 33b — Task 12 record: WebAuthn MFA with security keys

Branch `claude/plan-33b-passkeys-webauthn`, based on `0dda567c` (Tasks 1–11
landed). Every command ran from the worktree root with
`GOTOOLCHAIN=go1.26.10`. **This record is written in parts; the runtime and
the hosted pages are still in progress.**

## Part 1 — the security-key user-verification setting (landed)

| Change | Files |
| --- | --- |
| Handler | new `internal/mgmt/guardian_webauthn.go` |
| Adapter | `internal/server/mgmtapi.go` (`Get`/`PutWebAuthnRoamingSettings`) |
| Tests | new `internal/server/mgmt_webauthn_settings_test.go` |
| Plan | `docs/superpowers/plans/…-plan-33b-…md` (corrected, see below) |

`GET`/`PUT /api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings`
(spec section 6.1, LR33b-22, D-0062) now run rather than answering 501. The
value is `discouraged` (default), `preferred` or `required`, stored at
`GuardianSettings.Stored["webauthn-roaming/settings"]`, and only those three
are accepted; anything else is `400 invalid_body` and leaves the value alone.
An unset or malformed stored value reads back as `discouraged`.

**Two contract corrections found by reconnaissance and verified in the tree:**

1. **The `mfarules` inventory flip was already done in Task 1.** Both
   `webauthn-roaming` and `webauthn-platform` already read
   `"status": "enforced"` (commit `d0fb560a`), asserted by
   `internal/mfarules/rules_test.go`. The plan's Task 12 file list still asked
   for it; that line is corrected rather than re-applied, because re-editing a
   frozen, test-asserted contract risks churn. `"enforced"` is
   contract metadata only — no Go code branches on it, so it never was the
   runtime gap.
2. **The route was frozen but unwired.** `api/management.yaml` declared both
   operations and the generator emitted the interface methods, but no adapter
   existed in `internal/server/mgmtapi.go`, so the route fell through to
   `mgmtapi.Unimplemented` and answered 501.

### Deviation: the write does not go through `guardianWrite`

`guardianWrite` resolves the tenant from the request context and refuses a
reserved (system) tenant. This is an operator route that lives on the system
host, so the request's resolved tenant **is** the system tenant while the
setting belongs to the tenant named in the path. The write therefore runs in
its own `WithTx`: it reads the named tenant's Guardian settings, sets the
stored key, and calls `PutGuardian(ctx, g, g.Version)` — the version is passed
so the optimistic-concurrency check is real rather than a guaranteed conflict.

### RED

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./internal/server -run 'RoamingUV' -count=1` | 1 | `PUT` = 400; the route answered through the generated `Unimplemented` path and the write was refused |

### GREEN

| Command | Exit |
| --- | --- |
| `go test ./internal/server -run 'RoamingUV' -count=1` | 0 |
| `go build ./...` | 0 |
| `go vet ./internal/mgmt ./internal/server` | 0 |
| `gofmt -l internal pkg` | 0, no output |

`go test ./internal/server -count=1` fails the same four pre-existing
Actions-runtime tests before and after this change
(`TestActionsManagementResponseSchemas`, `TestActionsRedirectContinueHosts`,
`TestHostedLoginOutcomeEvents`, `TestMountedSilentActionCredentialMasks`).

## Part 2 — the runtime (in progress)

Reconnaissance established exactly where a WebAuthn factor must join the
existing MFA machinery. `webauthn-roaming` is **storable today** — the
Management API already accepts `key_id`/`public_key` and
`store.Authenticator` already has `CredentialID`, `PublicKey`, `RPID` and
`SignCount` — but it can never be challenged, because two trailing rejections
gate every path:

- `internal/mfa/service.go` `factorType` returns `""` for it, so `check`,
  `BeginChallenge` and the first-only enrollment loop refuse it;
- `internal/mfa/decide.go` `UsableMethod` ends in `return false`, so `Decide`,
  `Recover` and the hosted factor list never see it.

That is the precise "stored, not enforced" condition the plan describes.
`internal/passkey/service.go` already implements every WebAuthn mechanic
Task 12 needs against the same rows (`newPasskey`, `Login` with
`VerifyAssertion` + `AcceptAssertion`, `CreationOptions`/`RequestOptions`), and
its `webauthnType` already returns true for both MFA types — the verifier work
is done; the wiring is not.

Highest-risk items recorded for the implementation:

1. `mfa.Proof{Code string}` cannot carry raw assertion bytes, so
   `proveMFA` needs a WebAuthn arm that preserves the ticket `WithProofCommit`.
2. A bad signature must surface as `proofErr` (`outcome = "failure"`), not as
   a returned store error, or `check` refunds the attempt and the 10-per-15-
   minute throttle never counts it.
3. `UsableMethod` takes no RP ID, so the RP-ID filter belongs in `Decide`;
   without it `existingFactorChallenge` and `MFATicket` keep treating a
   foreign-RP credential as usable (LR33b-5).
4. Two hardcoded allowlists in `internal/login/mfa.go` (`startMFAMethod` and
   `MFATicket`) are not `switch` statements and are easy to miss.
5. `internal/mfa/decide_test.go` currently asserts WebAuthn *fails closed* in
   two cases; those expectations must flip with the implementation.
