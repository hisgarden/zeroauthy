# Plan 33b implementation record

Base: `42c12589e47db53a984398f1e4eab51ee4cb2221` (`docs: plan Plan 33b
passkeys and WebAuthn MFA`, branch `claude/plan-33b-passkeys-webauthn`).
Task 1 was built in the worktree `/home/user/zeroauthy-wt/task-1` on branch
`claude/plan-33b-task-1` (cut from that base). Toolchain: Go 1.26.10
(`GOTOOLCHAIN=go1.26.10`, `GOTMPDIR=/home/user/gotmp`) and Node v22.23.4
(the plan names Node 26 locally; this container has v22.23.4 and the
repository's Node pin is unchanged). Playwright 1.64.0 from
`tests/e2e/package.json` (`npm ci`, 326 packages, exit 0) with Chromium
build 1243 at `/opt/pw-browsers`.
[Spec](specs/2026-11-05-zeroauthy-passkeys-webauthn-design.md),
[plan](plans/2026-11-05-zeroauthy-plan-33b-passkeys-webauthn.md), D-0062.
Work proceeds task by task; the contract freeze does not imply runtime.

## Task 1 — contracts, decisions and the virtual-authenticator spike

**Sources.** Every §2 page was re-fetched on 2026-11-05 at 06:32 UTC as the
published Markdown (`<url>.md`) into a scratch directory outside the
repository; all 17 pages and the three JSON documents (Management API
OpenAPI 7,111,648 bytes, Authentication API OpenAPI 183,476 bytes, logs
schema 1,430,868 bytes) answered 200. The text keys per screen come from
the customize-text page's accordions; the log `details` fields from the
logs schema (`components.schemas.<code>.details`) cross-checked with the
monitor-passkey-events page; the OpenAPI schemas (`ClientMobile*`,
`CreateUserAuthenticationMethodRequestContent`,
`CreatedUserAuthenticationMethodTypeEnum`, `ScreenGroupNameEnum`,
`GuardianEnrollmentFactorEnum`, `SessionAuthenticationSignal`,
`CustomDomain.relying_party_identifier`) from the Management OpenAPI. The
Authentication API OpenAPI documents no `/passkey/*` route and no passkey
grant; those contracts come from the two reference pages and the Passkey
APIs page. No tenant was observed; every undocumented point keeps its
LR33b ruling and W entry.

**Delivered.**

- `internal/webauthnrules` (`inventory.json`, `rules.go`, `rules_test.go`):
  `Rules()` (94 rules, each with a §2 URL), `Screens()`, `Prompt()`,
  `TextKeys()`, `LogDetails()`, `LogCodes()`, `Ceremonies()`, `ScrubKeys()`
  and `Limits` with the plan's exact values (`MaxPasskeys` 20,
  `HostedChallengeTTL` 5 min, `NativeTimeout` 60 s, `NativeGrace` 10 s,
  `ProgressiveSnooze`/`LocalSnooze` 30 d, `PlatformRemind` 14 d,
  `PlatformRefuse` 365 d, `NicknameMin` 1, `NicknameMax` 20,
  `ChallengeBytes`/`UserHandleBytes` 32, `AttestationMax` 64 KiB,
  `ClientDataMax` 16 KiB, `CredentialIDMax` 1023, `COSEMax` 16 KiB,
  `CBORDepth` 16, `CBORItems` 1024, `RPIDMax` 255). `Screens()["mfa-webauthn"]`
  lists the nine §5.1 screens (the eight `mfa-webauthn` screens plus
  `mfa-detect-browser-capabilities`, whose Auth0 prompt is `mfa`, as
  `Prompt()` records) and the two reset-password WebAuthn challenge screens;
  `Screens()` therefore groups by page family and `Prompt()` by Auth0
  prompt. `LogDetails("passkey_challenge_failed")` is `purpose, error`
  (the §8.2 table names `error.message`); the six MFA grant success codes
  carry no details.
- `TestWebAuthnInventory`, `TestPlan33bLogCodes` (emitted-status assertion
  behind `t.Skip("flipped in Task 19")`) and
  `TestWebAuthnFactorsSupported` in `internal/actionsrules/webauthn_test.go`.
  The Actions factor availability lives in
  `internal/mfarules/inventory.json` (`action_members[].available_factors`,
  read by `internal/actions/mfa.go`), so that test asserts the mfarules
  lists; `internal/actionsrules/inventory.json` only had its member notes
  updated.
- Inventories: `logrules` (the ten codes get owner `Plan 33b`, status still
  `deferred`; `gd_auth_rejected` becomes `not_planned` with plan 0, as the
  push codes are; new `details:<code>` allowlists; a gap note),
  `mfarules` (both WebAuthn factors `enforced`; the WebAuthn factors move
  from `unavailable_factors` to `available_factors` on
  `api.multifactor.enable`, `challengeWith`, `challengeWithAny`,
  `enrollWith`, `enrollWithAny`), `brandingrules` (the two
  `reset-password-mfa-webauthn-*-challenge` screens), `actionsrules`
  (member notes). `TestPlan33DeferredLogOwners` needed no change (§8.2 moves
  no owner it checks); `mfarules.TestMFAInventory`'s factor expectation and
  `internal/actions.TestPhoneFactorUnavailable` (now push only) were updated
  for the flipped inventory.
- API documents: `api/management.yaml` (`type: passkey` on
  `MFACreateAuthenticationMethod` with the LR33b-23/29 description,
  `ClientMobile`, `ClientMobileIOS`, `ClientMobileAndroid` replacing the
  ignored `mobile`, `mobile` on the `Client` response, the passkey grant in
  the `grant_types` description, `WebAuthnRoamingSettings`, and the two
  marked extension system routes from §9.2), `api/authentication.yaml`
  (`POST /passkey/register`, `POST /passkey/challenge`, `x-passkey-grants`
  and the grant row on `/oauth/token`, `auth_session` and `authn_response`
  on `TokenRequest`, four `Passkey*` schemas). Every new operation carries
  `x-source`. `make generate` regenerated `internal/gen/authapi` and
  `internal/gen/mgmtapi`; the new Authentication API interface methods are
  bridged by `internal/server/passkey_bridge.go` with `501
  passkey_unavailable` until Task 15 (the Plan 34 pattern); the system
  routes fall to the generated `Unimplemented` 501.
- Docs: D-0062 (evidence and fetch date, the frozen values and limits,
  LR33b-1…37 with cost if wrong, K1–K14 with the §14a calls, R1–R3,
  W1–W12, the D-0039/D-0042/D-0059/D-0061 addenda, the wire additions and
  the spike result), the changelog review row (coverage 2026-10-30) with
  four backlog rows and a Plan 33b section, the matrix Plan 33b section and
  the hosted-login row note, the Plan 33b follow-ups (W1–W12 and Task 1
  carry-overs), the roadmap (Plan 40 loses actions-extensibility F5, K11),
  and the Deploy CLI manifest reasons for `clients`, `connections`,
  `customDomains` and `guardianFactors`.
- E2E: `tests/e2e/playwright.config.mjs` `testMatch` is now
  `/m\d+[a-z]?-.*\.spec\.mjs/`; `tests/e2e/m33b-spike.spec.mjs`.

**RED** (before the sibling inventories were updated; the webauthnrules
inventory itself was already written):
`GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp go test ./internal/webauthnrules ./internal/actionsrules ./internal/logrules ./internal/mfarules ./internal/brandingrules -count=1`
exited 1: `TestWebAuthnInventory` failed (branding inventory lacked the two
reset-password WebAuthn screens; both WebAuthn factors still `stored`),
`TestPlan33bLogCodes` failed (no `Plan 33b` owner on `passkey_challenge_*`,
`sepk*`, `se*`; `gd_auth_rejected` still deferred; no `details:` allowlists)
and `TestWebAuthnFactorsSupported` failed (WebAuthn factors unavailable on
all five members); logrules, mfarules and brandingrules passed.

**GREEN** (2026-11-05):
- `GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp make generate` exited 0
  (a first run exited 2 on a YAML plain scalar containing `type: passkey`
  in a description, fixed by quoting; a second `go test ./api` failure on a
  flow-mapping description containing a comma was fixed the same way and
  `make generate` rerun, exit 0).
- `GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp go build ./...` exited 0;
  `go vet ./internal/webauthnrules ./internal/actionsrules ./internal/logrules ./internal/mfarules ./internal/brandingrules ./internal/server ./internal/actions ./api`
  exited 0.
- `GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp go test ./internal/webauthnrules ./internal/actionsrules ./internal/logrules ./internal/mfarules ./internal/brandingrules -count=1`
  exited 0; `TestPlan33bLogCodes` reports `--- SKIP` with "flipped in
  Task 19" after its owner and allowlist assertions ran.
- `GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp go test ./api -count=1`
  exited 0.
- `GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp go test ./internal/actions -run TestPhoneFactorUnavailable -count=1`
  and `… -run TestChallengeWith -count=1` exited 0 (the two tests touched by
  the factor flip; the rest of the Actions package was not run).
- `make check-sources` exited 2: `api/authentication.yaml` has one
  UNREACHABLE (403) URL, the Plan 34 `x-source`
  `https://github.com/auth0/auth0.js/blob/master/src/authentication/passwordless-authentication.js`;
  `github.com` answers 403 for every URL through this container's HTTPS
  proxy (checked against another GitHub URL), so this is environmental and
  predates Task 1; the other 48 authentication URLs resolved. The script
  stops at the first file, so `./scripts/check-sources.sh api/management.yaml`
  was run separately: exit 0, all 221 URLs ok. The Plan 33b `x-source` entries use
  no GitHub URL.
- Not run: the full Go suite, any SQL or E2E suite, `make console`
  (console types are regenerated by the console task).

**Spike** (`cd tests/e2e && PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers E2E_CHROMIUM=/opt/pw-browsers/chromium-1243/chrome-linux64/chrome ./node_modules/.bin/playwright test m33b-spike.spec.mjs --config playwright.config.mjs`,
exit 0, 1 passed in 6.5 s). The spec starts an in-process Node HTTPS server
for `spike.e2e.test` with a throwaway `openssl req -x509` certificate
(`subjectAltName=DNS:spike.e2e.test`), launches Chromium with
`--host-resolver-rules=MAP spike.e2e.test 127.0.0.1` and `--no-proxy-server`
(the container routes HTTPS through a proxy that would otherwise capture the
host), attaches a CDP virtual authenticator (`WebAuthn.enable`,
`WebAuthn.addVirtualAuthenticator` with `ctap2`, `internal`, resident key,
user verification, automatic presence simulation, backup eligible and
backed up) and runs `navigator.credentials.create`, a button `get` with an
empty allow list and a conditional-mediation `get` on an
`autocomplete="username webauthn"` input. Recorded result
(`M33B_SPIKE_RESULT`): **TLS mode `ignoreHTTPSErrors` worked** (create ok,
button get ok); `PublicKeyCredential.isConditionalMediationAvailable()`
returned true and the **conditional `get` resolved** with the stored
credential after focusing and typing in the input; the created credential
reported `authenticatorAttachment: "platform"`, transports `["internal"]`,
`clientDataJSON.origin` equal to `https://spike.e2e.test:<port>` and the
sent challenge, `crossOrigin` absent. The SPKI-pinning fallback
(`--ignore-certificate-errors-spki-list`) is implemented in the spec but was
not needed and so was not exercised. Autofill can therefore be driven by the
browser in Task 19; Task 9 still covers it by markup and server tests.

## Task 9 — hosted passkey login and session methods

Landed on this branch (Tasks 1–8 already in): the `login-id` page gains the
§3.3 WebAuthn markup and an in-tree inline script, `POST /u/login/passkey`
consumes a bound single-use challenge and continues through the password
path's MFA/consent/organization chain, and the session records its first
factor (`pwd`/`passkey`) per §5.4. Full detail, commands and results:
[task 9 record](2026-11-05-plan-33b-record-task-9.md).

Two findings for later tasks:

- **`internal/login` has 15 pre-existing failing tests on this branch**,
  reproduced with every Task 9 change stashed. They all need the Actions
  Node runtime to execute a script, which is unavailable here. Task 19 must
  report them as environment-blocked, never as passing.
- `logs.RecordEvent` silently drops a code whose inventory `emitted` is
  false, so the ten Plan 33b codes cannot be asserted in a test until Task 19
  flips them. Tasks 10–15 should assert the emission rule and the bounded
  details, and leave the emitted-status assertion to Task 19.

## Task 10 — hosted passkey signup

The split `signup-id` → `passkey-enrollment` → `signup-password` flow lands
for connections where passkeys are effective (LR33b-15), with the passkey
branch creating the user and the passkey in one transaction and no password.
Detail: [task 10 record](2026-11-05-plan-33b-record-task-10.md).

## Task 11 — progressive and local passkey enrollment

The post-login enrollment prompt lands as a login-transaction stage between
MFA and consent: progressive after a password login with no passkey for the
effective RP ID, local after a cross-platform passkey login on a browser with
a user-verifying platform authenticator. Both honour the connection's
options, the 20-passkey limit and 30-day snoozes.
Detail: [task 11 record](2026-11-05-plan-33b-record-task-11.md).

Third pre-existing failure set found: `internal/authz` fails 12
Actions-runtime-dependent tests on this branch, reproduced with every Task 11
change stashed, the same way `internal/login`'s 15 do. Task 19 must report
both sets as environment-blocked, never as passing.

## Task 12 — WebAuthn MFA with security keys (in progress)

Part 1 landed: the operator-only security-key user-verification setting
runs at `GET`/`PUT …/guardian/factors/webauthn-roaming/settings` instead of
answering 501, with the value stored at
`GuardianSettings.Stored["webauthn-roaming/settings"]`. The runtime (the
factor itself in `internal/mfa`, the hosted WebAuthn MFA pages and the
detect page) is still in progress.
Detail: [task 12 record](2026-11-05-plan-33b-record-task-12.md).

Two contract findings, both verified: Task 1 already moved both WebAuthn
factors to `enforced` in `internal/mfarules/inventory.json` (so the plan's
Task 12 line asking for it was stale and is corrected, not re-applied), and
the UV route was frozen in the API document but had no server adapter at all.
