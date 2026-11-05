# Plan 33b — Task 11 record: progressive and local passkey enrollment

Branch `claude/plan-33b-passkeys-webauthn`, based on `b545731a` (Tasks 1–10
landed). Every command ran from the worktree root with
`GOTOOLCHAIN=go1.26.10`.

## Files

| Change | Files |
| --- | --- |
| Decision | new `internal/passkey/enroll.go` (`EnrollmentPrompt`, `Snooze`, `LoginContext`); `internal/session/mfa.go` (`DeviceScope`) |
| Stage | new `internal/authz/passkey.go` (stage, params, `passkeyPrompt`); `internal/authz/{flow,handlers}.go` (`flowReq.stageParams`, the prompt between MFA and code issuance) |
| Pages | new `internal/login/passkey_enroll.go`; `internal/login/{login,passkey}.go` (prompt context on the transaction, assertion attachment); `internal/ui/ui.go` (`SignupData.SecondaryText`), `internal/ui/templates/{passkey_enrollment,login_id,webauthn_script}.html` |
| Server | `internal/server/server.go` (four routes, `az.Passkeys`) |
| Tests | new `internal/login/passkey_enroll_test.go`; `internal/login/passkey_test.go` (fixture wires `Authz.Passkeys`) |

## Decision (spec §3.5, LR33b-13/14)

`passkey.Service.EnrollmentPrompt` returns `""`, `progressive` or `local`:

- **progressive** after a `pwd` first factor, when the connection enables
  `progressive_enrollment_enabled`, the user has no confirmed passkey for the
  effective RP ID, holds fewer than 20 passkeys, and has no live
  `passkey-progressive` snooze for that RP ID;
- **local** after a `passkey` first factor whose assertion carried
  `authenticatorAttachment: "cross-platform"` and whose page reported a
  user-verifying platform authenticator, when `local_enrollment_enabled` is
  on and no live `passkey-local` snooze exists for this browser;
- `""` for every other first factor, for a blocked user, and whenever the
  policy or RP ID is not effective.

Snooze windows come from the frozen limits: 30 days for both passkey kinds
(LR33b-13/14), 14 and 365 days for the platform kinds Task 13 adds.

## Stage and binding

The prompt is a login-transaction stage (`za_stage: passkey-prompt`,
`za_pk_prompt`), inserted in `approve` **after** `requireMFA` and before the
code is issued, so MFA still runs first and consent still runs after. The
page reads the kind from the transaction, checks the transaction cookie and
origin, and refuses a direct GET, the other variant, or another browser with
the session-expired page. Answering the prompt clears the stage but sets
`za_pk_answered`, so the resumed transaction never re-asks.

## Deviations

1. **`flowReq.stageParams`.** The prompt stage markers are transaction
   params, but `Request.Params()` carries only OAuth fields and `ext-*`, so
   `passkeyPrompt` would never see them. `flowReq` gained an unexported
   `stageParams` map that `Resume` fills from the transaction; nothing else
   reads it.
2. **Local scope is the transaction's cookie hash.** LR33b-14 says the local
   snooze is per browser. The MFA device cookie is only set after an MFA
   proof, so a passkey-only login has none; the login transaction's cookie
   hash is always present and is exactly "this browser".
3. **A signup is not a login.** `SignupSubmit` reaches `approve` through the
   same `Resume`, so without a guard the password signup path would be asked
   to enroll immediately after registering. The prompt is skipped for
   `screen_hint=signup`; Task 10's tests caught this.
4. **One template, two labels.** The enrollment screen serves both the
   signup flow (second choice: "create a password") and the prompt (second
   choice: continue/skip), so the label travels as
   `SignupData.SecondaryText` rather than one hard-coded key.
5. `login_id.html` gained a hidden `platform_authenticator` field that the
   inline script fills from
   `isUserVerifyingPlatformAuthenticatorAvailable()`, which is how the local
   decision learns the browser's capability without any `fetch`.
6. `authz.Handlers.Passkeys` is an interface (`EnrollmentPrompt` only), so
   `authz` does not import `internal/passkey`'s concrete service.
7. `session.DeviceScope` was added for callers that hold a raw device cookie;
   Task 11 itself uses the transaction cookie hash instead.

## RED

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./internal/login -run 'Enrollment' -count=1` | 1 | No enrollment prompt was offered at all: the login completed straight to the code, and the enrollment routes did not exist |

## GREEN

| Command | Exit |
| --- | --- |
| `go test ./internal/login -run 'Enrollment' -count=1` | 0 |
| `go test -race ./internal/login -run 'Passkey\|WebAuthnError\|Enrollment' -count=1` | 0 (31.7 s, no data race) |
| `go test ./internal/ui ./internal/passkey ./internal/session -count=1` | 0 |
| `go build ./...` | 0 |
| `go vet ./internal/login ./internal/authz ./internal/ui ./internal/passkey ./internal/server` | 0 |
| `gofmt -l internal pkg` | 0, no output |

`go test ./internal/login -count=1` fails exactly the same 15 pre-existing
tests as before Task 11 (verified by diffing the sets, and by stashing every
Task 11 change). `go test ./internal/authz -count=1` fails 12 tests
(`TestActionsConsentMarker`, `TestActionsContinue*`, `TestActionsDenyAndErrorSurfaces`,
`TestActionsQueryOmitsInternalKeys`, `TestActionsRedirectRoundTrip`,
`TestGateRedirectContinuationChallenges`, `TestInvitationActionsDenialAfterAcceptance`,
`TestSilentAuthorizationOutcomeEvents`) **with every Task 11 change stashed**,
so they are pre-existing too.

Not run: PostgreSQL, MySQL, E2E, the full repository suite.
