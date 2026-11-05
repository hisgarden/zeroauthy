# Plan 33b — Task 7 record: RP ID resolver, origin policy, shared-RP-ID setting and passkey prerequisites

Worktree `/home/user/zeroauthy-wt/task-7`, branch `claude/plan-33b-task-7`,
based on `d0fb560` (`docs: freeze Plan 33b passkey and WebAuthn contracts`,
Tasks 1–4 landed). Every command ran from the worktree root with
`GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp` under `nice -n 5`.
Memory store and mocks only; `internal/store/sqlstore`, `internal/store/grpcstore`
and `proto/` are untouched (Tasks 5 and 6).

## Files

| Change | Files |
| --- | --- |
| Config | `internal/config/config.go` (`Security.WebAuthn`, `WebAuthn.RestrictSharedRPIDs`, `koanf:"restrict_shared_rp_ids"`, default false), `internal/config/config_test.go` (`TestConfigWebAuthnRestrict`), regenerated `docs/configuration.md` |
| Resolver | new `internal/rpid/{rpid,origins}.go`, `rpid_test.go`, `origins_test.go` |
| Policy | new `internal/connrules/passkey.go`, `passkey_test.go` |
| Custom domains | `internal/customdomain/rules.go` (the Plan 23 check becomes the exported `ValidateRPID`, now also bounded by `webauthnrules.Limits.RPIDMax`); `internal/mgmt/custom_domains.go` (`sharedRPIDAllowed` on `POST`/`PATCH`), `internal/mgmt/clients.go` (`Handlers.RestrictSharedRPIDs`) |
| Prerequisites route | new `internal/mgmt/passkey_prerequisites.go`; `internal/server/mgmtapi.go` (generated-interface override, system API, behind the router's `operatorOnly`) |
| Seed | `internal/seed/seed.go` (`SeedDomain`, `DomainEntries`, `DomainRPIDs`), `validate.go` (registrable-suffix check), `apply.go` (`Options.RPIDs`, store, canonical refusal, strict check after all tenants) |
| Wiring | `internal/app/app.go` (`RPIDPolicy(cfg, st)`, passed to the seed and `server.Deps.RPIDs`), `internal/server/server.go` (`Deps.RPIDs`), `cmd/zeroauthy/seed.go` |
| Tests | `internal/mgmt/passkey_prerequisites_test.go` (`TestPasskeyPrerequisitesRoute`, `TestCustomDomainSharedRPID`), `internal/seed/domains_rpid_test.go` (`TestSeedDomainRPID`), `internal/server/mgmt_passkey_prerequisites_test.go` (router wiring) |

## Interfaces as implemented

- `config.WebAuthn{RestrictSharedRPIDs bool}` at `Security.WebAuthn`
  (`security.webauthn.restrict_shared_rp_ids`,
  `ZEROAUTHY_SECURITY__WEBAUTHN__RESTRICT_SHARED_RP_IDS`).
- `rpid.Kind` (`KindCanonical`, `KindCustom`, `KindOperator`),
  `rpid.Result{RPID, Origin string; Kind Kind; Valid bool; Problem string}`,
  `rpid.Policy{BaseDomain, SystemHost, OriginSuffix string; RestrictShared bool; Store store.Store}`,
  `Policy.For(ctx, tenant.Resolved) (Result, error)`,
  `Policy.Validate(ctx, tenantID, host, rpID) error`,
  `rpid.NativeOrigins(Result, *store.Client) []string` — exactly the plan's
  signatures. Additions: `rpid.ErrInvalid` (fixed message, wraps
  `store.ErrInvalid`; `Validate` returns it for every refusal so no detail
  reveals another tenant's hosts) and the `Problem*` constants
  (`no_tenant`, `unknown_host`, `ip_host`, `not_registrable_suffix`,
  `shared_rp_id_restricted`).
- `For`: the host is normalized with `tenant.NormalizeHost` (lowercase, no
  trailing dot, `:443` dropped), `RPID` is the bare hostname and `Origin` is
  `https://<host>[:port]`. Kind: the tenant's `CanonicalHost`, else the
  store host claim (`CustomDomains().GetHost`) — `canonical`, `operator`
  (override `Tenant.DomainRPIDs[host]`), `public` (override the row's
  `relying_party_identifier`, empty = the domain); a claim of another
  tenant, an inactive claim, an origin alias or no claim is `unknown_host`
  (`Valid: false`). A tenant whose hosts have no claim (no store, or a
  driver without custom domains) falls back to `Tenant.Domains`. The
  canonical host is never checked against the sharing rule; custom domains
  and aliases run the full R1 check on every resolution. An invalid result
  logs one WARN (`tenant`, `host`, `rp_id`, `problem`; no challenge) through
  `slog.Default()` (no logger field was added to keep `Policy` as specified).
  The error return is only for storage failures; under the strict rule a
  driver without `HostTenantsUnder` (`ErrWebAuthnUnavailable`) is an error,
  so ceremonies fail closed.
- `Validate` (R1): IP-literal hosts refused; `customdomain.ValidateRPID`
  (the host itself, or a normalized DNS ancestor that is not a public
  suffix by the pinned `golang.org/x/net/publicsuffix`, at most
  `webauthnrules.Limits.RPIDMax`); with `RestrictShared`, refused when the
  RP ID equals or is an ancestor of `BaseDomain`, `SystemHost` or
  `OriginSuffix`, or when `HostTenantsUnder(rp, 2)` names another tenant.
- `NativeOrigins` (LR33b-26): `r.Origin`; each `web_origins` entry that is
  a plain `https` origin (no wildcard, path other than `/`, query, fragment
  or credentials) whose host is the RP ID or under it, serialized as the
  browser sends it (`:443` dropped); `android:apk-key-hash:<base64url>` per
  32-byte colon-separated hex fingerprint. Deduplicated, in that order;
  `nil` for an invalid result.
- `connrules.PasskeyPolicy{Enabled, Effective bool; ChallengeUI string; Progressive, Local bool}`,
  `connrules.Unmet`, `connrules.Passkeys(conn, prompts) (PasskeyPolicy, []Unmet)`.
  Prompts nil or missing keys take the hosted defaults
  (`universal_login_experience` `new`, `identifier_first` false);
  `passkey_options` absent or unrecognized values take D-0042's `both`,
  true, true. Connection prerequisites are skipped on a non-database
  connection.
- `GET /api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites`:
  `{"effective": bool, "unmet": [...]}`, adding `passkey_disabled` when
  `authentication_methods.passkey.enabled` is not true; unknown tenant
  `404 inexistent_tenant`; missing connection or another tenant's
  connection `404 inexistent_connection`; malformed ID `400 invalid_uri`
  (as the script-try route); non-operators are refused by the router
  (`operatorOnly`, mgmt test uses `RequireOperator`).
- Custom domains: after `ValidateCreate`/`ValidatePatch` accepted an
  explicit `relying_party_identifier`, `rpid.Policy.Validate` runs with the
  handler's base domain, system host, the service's origin suffix and
  `RestrictSharedRPIDs`; a refusal is `400 invalid_body` "Payload validation
  error: the relying party identifier is not allowed for this domain".
  Default RP IDs (absent or `null`) are not re-checked at write; `For`
  checks them at use.
- Seed `domains`: each entry is a host string or
  `{host, relying_party_identifier}` (unknown keys, an empty RP ID, a
  missing host or a non-scalar refused at parse). `Tenant.Domains` keeps its
  `[]string` type (now `yaml:"-"`, filled from `DomainEntries`) so
  programmatic callers are unchanged; `Tenant.DomainRPIDs` is keyed by the
  normalized host. Parse validates the registrable-suffix rule; Apply stores
  only overrides that differ from the host, refuses one on the canonical
  host, keeps stored RP IDs when `domains` is omitted, and after every
  tenant is written runs `Options.RPIDs.Validate` (store = the
  transaction, empty `BaseDomain` = the file's) on each RP ID it wrote.

## Deviations (for Task 8 and later)

1. **`Unmet` values follow the frozen API enum, not the plan's names.**
   Task 1 froze `api/management.yaml`'s enum as `identifier_first`,
   `universal_login`, `requires_username`, `import_mode`, `password`,
   `passkey_disabled`, `strategy` (generated `mgmtapi` types). The plan's
   `username_or_flexible`, `custom_db_import`, `password_enabled` would not
   match the wire, so the constants are `UnmetUniversalLogin`,
   `UnmetIdentifierFirst`, `UnmetRequiresUsername` (`requires_username`),
   `UnmetImportMode` (`import_mode`), `UnmetPassword` (`password`),
   `UnmetStrategy`, plus `UnmetPasskeyDisabled`, which `Passkeys` never
   returns (the route adds it). Order: the constants' order.
2. `Policy.For`'s `tenant.Resolved` carries no host kind; `For` derives it
   from the tenant and the store claim (above), so callers pass the
   request's `Resolved` unchanged.
3. Wiring beyond the listed files: `internal/app/app.go` (`RPIDPolicy`),
   `internal/server/server.go` (`Deps.RPIDs`, for Task 8),
   `cmd/zeroauthy/seed.go`, `internal/mgmt/clients.go`.

## Observed for other tasks

- Task 4's memory `HostTenantsUnder` compares host-claim keys verbatim, so a
  claim with a port (`app.example.com:8443`) is not "under" `example.com`.
  Only the strict rule uses it, and shared hosting has no ports; Tasks 5/6
  should decide whether ports are stripped before comparing.
- `mgmt.domainError` formats `store.ErrInvalid` as
  `badBody("Payload validation error: %s", …)`, and `badBody` adds the same
  prefix again (pre-existing; the RP ID refusal above does not go through it).

## RED

`go test ./internal/rpid ./internal/connrules ./internal/config ./internal/customdomain ./internal/mgmt ./internal/seed -run 'RPID|NativeOrigins|PasskeyPolicy|PasskeyPrereq|WebAuthnRestrict|Reference|Domain' -count=1`
exit 1: `internal/rpid` had no non-test files; `config` (`cfg.Security.WebAuthn
undefined`), `connrules` (`undefined: PasskeyPolicy`), `mgmt`
(`GetPasskeyPrerequisites`, `RestrictSharedRPIDs` undefined) and `seed`
failed to build; `customdomain` passed (its existing tests only).

## GREEN

| Command | Exit |
| --- | --- |
| `go generate ./internal/config` | 0 (adds the `security.webauthn` section to `docs/configuration.md`) |
| `go test ./internal/rpid ./internal/connrules ./internal/config ./internal/customdomain ./internal/mgmt ./internal/seed -run 'RPID\|NativeOrigins\|PasskeyPolicy\|PasskeyPrereq\|WebAuthnRestrict\|Reference\|Domain' -count=1` | 0 (all six `ok`; `TestReferenceUpToDate` included) |
| `go test ./internal/server -run PasskeyPrereq -count=1` | 0 |
| `go build ./...` | 0 |
| `go vet ./internal/rpid ./internal/connrules ./internal/config ./internal/customdomain ./internal/mgmt ./internal/seed ./internal/server ./internal/app ./cmd/zeroauthy` | 0 |
| `gofmt -l internal cmd` | 0, no output |
| `go test ./internal/rpid ./internal/connrules ./internal/config ./internal/customdomain ./internal/mgmt ./internal/seed -count=1` | 0 (`rpid` 0.08s, `connrules` 0.11s, `config` 0.10s, `customdomain` 0.97s, `mgmt` 190.1s, `seed` 7.8s) |
| `go test ./internal/app ./internal/deploymigration -count=1` (wiring and seed parsers) | 0 |
| `go test ./internal/server -run 'Seed\|Domain\|System\|Management\|PasskeyPrereq' -count=1` | 0 |

Not run: the full repository suite, any SQL, gRPC or E2E suite.
