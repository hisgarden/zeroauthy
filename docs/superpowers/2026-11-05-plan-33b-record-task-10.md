# Plan 33b — Task 10 record: hosted passkey signup

Branch `claude/plan-33b-passkeys-webauthn`, based on `1ee016a7` (Tasks 1–9
landed). Every command ran from the worktree root with
`GOTOOLCHAIN=go1.26.10`.

## Files

| Change | Files |
| --- | --- |
| Flow | new `internal/login/passkey_signup.go`; `internal/login/login.go` (`SignupPage` split routing, `SignupSubmit` step-aware guard) |
| UI | `internal/ui/ui.go` (`SignupData.Passkey`/`Revision`/`BackURL`/actions, `PasskeyEnrollmentData`, three renderers, four page registrations), new templates `signup_id.html`, `signup_password.html`, `passkey_enrollment.html`, `webauthn_create_script.html` |
| i18n | `internal/i18n/locales/en.json` (`signup-id`, `signup-password`, `passkeys` prompts), `internal/i18n/catalog_test.go` (enumerates the new screens) |
| Rules | `internal/webauthnrules/rules.go` (`AllTextKeys`) |
| Server | `internal/server/server.go` (six new `/u/signup/*` routes) |
| Tests | new `internal/login/passkey_signup_test.go`; `internal/login/login_test.go` (routes, one-redirect `begin`) |

## The split flow (LR33b-15, §3.4)

`/u/signup` redirects to `/u/signup/identifier` **only** when passkeys are
effective and the signup is not an invitation (LR33b-32); every other case
keeps the single Plan 22 page. The steps are hosted-transaction steps
(`signup-identifier` → `signup-passkey`), so back/refresh cannot skip one.

- `/u/signup/identifier` collects the identifier and validates it without
  writing anything. On success the details are stored in the transaction's
  params (`za_signup_email`, `za_signup_username`, `za_signup_phone`) by
  compare-and-swap plus a rewrite, the same way `orglogin` persists an
  invitation transaction.
- `/u/signup/passkey` issues a registration challenge bound to the
  transaction and its browser cookie and renders the enrollment screen, which
  offers "create a passkey" and a plain "create a password" form.
- `/u/signup/password` restores the stored identifier and runs the ordinary
  `SignupSubmit`, so Plan 22/34's rules (captcha, breach check, Actions,
  verification, organizations) apply unchanged. The posted identifier is
  overwritten, so the password step cannot create a different account.

## Passkey registration

`SignupPasskeyPost` spends the registration protection token **before** any
existence answer (R3), consumes the single-use challenge, builds the draft
through the shared signup callbacks (so pre-user-registration runs before any
write), then calls `passkey.Service.Signup`, which creates the user and the
passkey in one transaction. The account's password hash is empty. On success
the code emits `ss` with `details.authentication_methods: ["passkey"]`, sends
verification and starts the session recording the `passkey` first factor; the
password path records `pwd`.

Failures log `gd_webauthn_enrollment_failed` with a bounded reason and
re-render with a fresh challenge; neither the challenge nor the credential
reaches the page or a detail. The `email-in-use` answer is revealed only
after the token is spent.

## Deviations

1. `SignupSubmit`'s hosted-form guard is now step-aware: with the split flow
   it guards prompt/screen `signup-password`, otherwise `signup`. Without
   this the password step is refused `409 hosted-form-changed`, because the
   enrollment screen and the password step are different screens of the same
   transaction.
2. `SignupPasswordPost` deliberately does **not** transition the hosted state
   before calling `SignupSubmit`; that would move the revision the posted
   `hosted_revision` must match and the guard would refuse every submit.
3. `passkey.CreationOptions` rejects a nil user, so the signup screen passes
   the draft the account will be created from (the `Signup` kind takes its
   handle from the challenge and never reads the user's credentials).
4. The catalog test enumerates the two `passkey-enrollment*` screens from
   `webauthnrules.TextKeys` and the two signup prompts explicitly; the
   WebAuthn MFA screens are added by the task that renders them.
5. New export `webauthnrules.AllTextKeys`, for callers that enumerate every
   screen (the catalog test checks one screen at a time otherwise).

## RED

| Command | Exit | Result |
| --- | --- | --- |
| `go test ./internal/login -run 'PasskeySignup' -count=1` | 1 | All four tests failed: `/u/signup` did not route to the split flow, the enrollment page had no challenge block and no password form, and the stored identifier was not carried to the password step |

## GREEN

| Command | Exit |
| --- | --- |
| `go test ./internal/login -run 'PasskeySignup' -count=1` | 0 |
| `go test -race ./internal/login -run 'Passkey\|WebAuthnError' -count=1` | 0 (17.2 s, no data race) |
| `go test ./internal/ui ./internal/i18n ./internal/webauthnrules ./internal/session -count=1` | 0 |
| `go build ./...` | 0 |
| `go vet ./internal/login ./internal/ui ./internal/i18n ./internal/server ./internal/webauthnrules` | 0 |
| `gofmt -l internal pkg` | 0, no output |

`go test ./internal/login -count=1` still fails exactly the same 15
Actions-runtime-dependent tests recorded in the Task 9 record; the set is
identical before and after Task 10, verified by comparison.

Not run: PostgreSQL, MySQL, E2E, the full repository suite.
