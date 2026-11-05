# Plan 33b — Task 9 record: hosted passkey login and session methods

Branch `claude/plan-33b-passkeys-webauthn`, based on `4643dac` (Tasks 1–8
landed). Every command ran from the worktree root with
`GOTOOLCHAIN=go1.26.10`. Go 1.27.1 toolchain, Node v26.4.0, macOS/arm64.

## Files

| Change | Files |
| --- | --- |
| Session record (§5.4) | `internal/session/session.go` (`Start` gains variadic `methods ...store.AuthMethod`), `internal/session/mfa.go` (`AddMethod`) |
| Store contract | `internal/store/store.go` (`Sessions.SetAuthMethods`), `internal/store/memory/sessions.go`, `internal/store/sqlstore/sessions.go`, `internal/store/grpcstore/{client_repos,server_repos}.go`, `proto/store/v1/store.proto` (+ regenerated `store.pb.go`, `store_grpc.pb.go`), `pkg/storetest/webauthn.go` |
| Hosted login | new `internal/login/passkey.go`; `internal/login/{login,events,prompt_fields}.go`, `internal/server/server.go` (`POST /u/login/passkey`, `lg.Passkeys`) |
| UI | `internal/ui/ui.go` (`LoginData.Passkey`, `PasskeyData`), `internal/ui/templates/login_id.html`, new `internal/ui/templates/webauthn_script.html` |
| i18n | `internal/i18n/keys.go`, `internal/i18n/locales/en.json` (seven `login-id` passkey keys) |
| Tests | new `internal/session/methods_test.go`, `internal/login/passkey_test.go`; `internal/login/login_test.go` (route registration) |

## Session record (§5.4)

`Manager.Start` gained a variadic `methods ...store.AuthMethod`, so the four
existing call sites outside `internal/login` compile unchanged; `complete`
now delegates to `completeWithMethods` and records `{Name: "pwd"}`. The
passkey path records `{Name: "passkey"}`. `Manager.AddMethod` appends one
step and persists it; it is wired for `{Name: "mfa", Type: factor}` but the
MFA paths that call it land in Tasks 12–13.

`Sessions.SetAuthMethods` is new on the store contract because the existing
`Sessions` methods are narrow atomic updates and the record is written once
at session creation plus once per later factor. It replaces the whole slice,
stores a copy, and returns `ErrNotFound` for an absent or foreign-tenant
session. The gRPC driver adds `SessionsSetAuthMethods`, which a plugin
predating `webauthn.v1` answers `Unimplemented`; the client maps that to
`store.ErrWebAuthnUnavailable`. The codec already carried
`LoginSession.AuthMethods` (Task 4), so no codec change was needed.

## Hosted passkey login (§3.3)

`GET /u/login` on the `login-id` step renders, when
`passkey.Service.Effective` is true **and** the host's RP ID is valid:

- `autocomplete="username webauthn"` and a
  `<script type="application/json" id="za-webauthn">` options block with the
  hidden `challenge_id`, for `challenge_ui` `both`/`autofill`;
- a `#za-passkey-button` labelled from `passkeyButtonText`, for
  `both`/`button`;
- the in-tree script inlined with the response's existing CSP nonce.

The script is `internal/ui/templates/webauthn_script.html`, included by
`login_id.html` with `$.Nonce`. It is inlined, never a `src`, so the Plan 22
CSP is unchanged: no `connect-src`, no `script-src` relaxation. It uses
`parseRequestOptionsFromJSON` where present and falls back to manual
base64url decoding, aborts a pending conditional `get` before any other
submit, and posts the §4.1 JSON in a hidden `credential` field.

`POST /u/login/passkey` consumes the challenge (the single-use gate), runs
`protection.Begin`/`Finish` and `recordFailure` exactly as the password path,
then hands to the same `completeWithMethods` → `Authz.Resume` used by a
password login, so MFA policy, consent and organizations run unchanged.

**Double submit (Review Focus 2).** The challenge consume, not the hosted
revision, decides the winner. `LoginPasskeyPost` deliberately does **not**
call `guardHostedForm`: that would run `transitionHosted`'s
compare-and-swap first, so the loser would be answered `errTxn` ("session
expired") instead of the generic failure. Consuming first and rendering
second gives exactly one 302 and one `passkey-authentication-failed` page
with a fresh challenge, as `TestHostedPasskeyDoubleSubmit` asserts.

**Stale credential (Review Focus 3).** Deleted credential, passkeys switched
off, connection disabled and an invalid stored RP ID all reach one generic
answer with one bounded log reason; `TestHostedPasskeyStaleCredential`
asserts the answer is identical and that no challenge or credential bytes
appear in the details.

**Errors.** Only `NotAllowedError` re-renders without a challenge-failure
record; the other six names, and any unknown value, map to a bounded name.
The posted value is never echoed into the page and never reaches a detail.

## Deviations

1. `Handlers.Passkeys` and `Deps.Passkeys` already existed (Task 8 added the
   latter "unused by routes until Task 9"); Task 9 wires both.
2. The login-id passkey keys are referenced from Go constants rather than the
   template, because `i18n.TestCatalogMatchesUsage` requires every `en.json`
   key to be named in a template or a `Key*` constant and the button label is
   built in Go.
3. `webauthn_script.html` takes the nonce as its template data (`{{.}}`),
   not the page, so it can be included with `$.Nonce` from any template.
4. The `gd_webauthn_challenge_failed` emission assertions are deferred to
   Task 19 (the code is `emitted: false` until then, and `logs.RecordEvent`
   drops a non-emitting code). Task 9 asserts the observable divergence
   instead and pins the owner to `Plan 33b`.

## RED

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./internal/login -run 'Passkey\|WebAuthnError' -count=1` | 1 | All eight tests failed: no `za-webauthn`/`button` markup, no route (`404`), no `passkey` session method |

## GREEN

| Command | Exit |
| --- | --- |
| `go test ./internal/login -run 'Passkey\|WebAuthnError' -count=1` | 0 |
| `go test -race ./internal/login -run 'Passkey\|WebAuthnError' -count=1` | 0 (no data race; the double-submit test posts through a race-free helper) |
| `go test ./internal/session ./internal/ui ./internal/i18n ./internal/store/memory ./internal/passkey ./internal/logscrub -count=1` | 0 |
| `go test ./internal/store/grpcstore -run 'WebAuthn\|Conformance' -count=1 -timeout=30m` | 0 (70.7 s, new RPC exercised over gRPC) |
| `go build ./...` | 0 |
| `go vet ./internal/login ./internal/ui ./internal/session ./internal/store/... ./internal/server` | 0 |
| `gofmt -l internal pkg` | 0, no output |

Mutation check (not committed): with the challenge consume removed from
`LoginPasskeyPost`, `TestHostedPasskeyDoubleSubmit` accepts two assertions;
restored before the runs above.

## Pre-existing failures observed (not caused by Task 9)

`go test ./internal/login -count=1` fails 15 tests on this branch **before**
any Task 9 change, and the same 15 after (only timing suffixes differ):
`TestActionDenyLogged`, `TestActionExecutionLinksOnSignupEvents`,
`TestCustomDBPrintedPasswordMasked`, `TestLoginLogCarriesExecutionIDs`,
`TestOrganizationPasswordChangeContextActions`, `TestPostChangePassword`,
`TestResetMFACookiePaths`, `TestResetMFAPassFinalBindings`,
`TestResetMFAPassLegacyBoundary`, `TestResetMFAPassRecheckedAtCommit`,
`TestResetPostChallenge`, `TestResetPostChallengeChallengeWith`,
`TestResetPostChallengeChallengeWithBoundaries`,
`TestResetPostChallengeChallengeWithRedirect`, `TestSignupPreRegistration`.
All need the Actions Node runtime to execute a script (`api.access.deny`,
`throw`), which is unavailable here, so the recorded event keeps its generic
description. Verified by stashing every Task 9 change and rerunning.
Task 19 must report these as environment-blocked, never as passing.

Not run: PostgreSQL, MySQL, E2E, the full repository suite.
