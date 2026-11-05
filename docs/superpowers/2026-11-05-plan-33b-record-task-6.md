# Plan 33b — Task 6 record: `webauthn.v1` storage plugin capability

Worktree `/home/user/zeroauthy-wt/task-6`, branch `claude/plan-33b-task-6`,
based on `3bcb1b2` (`feat: add WebAuthn storage contract and memory store`).
Every command ran from the worktree root with `GOTOOLCHAIN=go1.26.10
GOTMPDIR=/home/user/gotmp`. gRPC, memory-backed and plugin-process tests only;
no SQL dialect suite, no E2E, no full repository suite. `internal/store/sqlstore`
is untouched (Task 5 runs in parallel).

## Files

| Change | Files |
| --- | --- |
| Protocol | `proto/store/v1/store.proto`; regenerated `store.pb.go`, `store_grpc.pb.go` (`make generate`, local `buf` plugins) |
| Client, server, codec | new `internal/store/grpcstore/webauthn.go` (replaces the deleted `webauthn_stub.go`); `client.go`, `client_repos.go`, `codec.go`, `mfa.go` |
| SDK wrapper | `pkg/storeplugin/storeplugin.go` (`opened` forwards `CheckWebAuthnSupport`/`WebAuthnSupported`) |
| Tests | new `internal/store/grpcstore/webauthn_test.go`; `events_test.go` (old-plugin fixture gains `webauthnMissing`, `webauthnProbe`); `codec_test.go`, `mfa_codec_test.go` (full fixtures carry the new fields); `pkg/storeplugin/storeplugin_test.go` (`TestWebAuthnThroughPluginProcess`) |

`cmd/zeroauthy-store-memory` needed no change: it serves `memory.New()`,
whose `WebAuthn()` is the Task 4 implementation, so the server advertises the
capability.

## Protocol

- `rpc WebAuthnCapabilities(PingRequest) returns (EventsCapabilitiesResult)`,
  version `>= 1` means `webauthn.v1`; negotiated separately from every other
  capability. The server answers version 0 when the backing store's
  `WebAuthn()` is `UnimplementedWebAuthn` (today: `sqlstore` until Task 5) and
  forwards a backing `WebAuthnSupporter`'s answer.
- RPCs `WebAuthnGetAuthenticatorByCredentialID`, `WebAuthnCreatePasskey`,
  `WebAuthnCreateUserWithPasskey`, `WebAuthnAcceptAssertion`,
  `WebAuthnMovePasskeys`, `WebAuthnPutSnooze`, `WebAuthnGetSnooze`,
  `WebAuthnHostTenantsUnder`, `WebAuthnPurge`. Passkeys travel as the existing
  `MFAAuthenticator` message (MFA v1 timestamp strings, `copyMFA`); snoozes as
  `WebAuthnSnooze` with a `Timestamp until`.
- Record fields: `Tenant.domain_rp_ids = 34` (`StringMap`), `Client.mobile = 25`
  (`ClientMobile{ios, android}`, fingerprints a `StringList`),
  `LoginSession.auth_methods = 20` (`AuthMethodList{repeated AuthMethod}`),
  `MFAChallengeMsg.binding = 10` (bytes). Wrappers keep nil and empty
  distinct, as the rest of the codec does.

## Client behaviour

- `Client.webauthnCap *orgCapState`, shared with transaction views.
  `CheckWebAuthnSupport`/`WebAuthnSupported` mirror `phone.v1`: a definitive
  unsupported answer (version 0, `Unimplemented`, or a domain
  `ErrWebAuthnUnavailable`) latches; transient errors do not. Every
  `WebAuthn()` method probes first and answers `store.ErrWebAuthnUnavailable`
  without the capability.
- Field gate (`webauthnGate` in `webauthn.go`) on tenant, client and session
  create/update/get/list paths and on `MFA().CreateChallenge`/`GetChallenge`:
  without the capability the new fields are dropped from a shallow copy on
  write (the caller's value is untouched) and cleared on read. The gate only
  consults the capability when such a field is set, and once latched it costs
  no RPC. A transient probe failure is returned instead of silently dropping
  the fields (dropping them could later clear stored values on update).
- `webauthn.v1` requires MFA v1 (see GREEN): without MFA the client reports
  WebAuthn unavailable.
- `CreateUserWithPasskey` applies the same Microsoft-federation admission as
  `Users().Create`.

## RED

```
go test ./internal/store/grpcstore -run WebAuthn -count=1
```

Run with the new tests in place and the implementation set aside (stub
restored, client/codec/repo edits stashed): exit 1, `[build failed]`:
`*Client does not implement store.WebAuthnSupporter (missing method
CheckWebAuthnSupport)`, `c.CheckWebAuthnSupport undefined`,
`c.WebAuthnSupported undefined`.

Baseline at `3bcb1b2` before any change (`go test ./internal/store/grpcstore
-run 'MFA|Conformance' -count=1`, exit 1): every MFA challenge case over gRPC
failed with `MFA: extra field Binding: store: invalid argument`, and
`TestMFARecordWireRoundTripsAllFields/challenge` failed, because Task 4 added
`MFAChallenge.Binding` without a protocol field. This task fixes it.

## GREEN

| Command | Exit |
| --- | --- |
| `make generate` (`go generate ./...`; `proto/store/v1` runs `go tool buf generate` with local `protoc-gen-go`/`protoc-gen-go-grpc`, no network) | 0; only `store.pb.go`/`store_grpc.pb.go` changed |
| `go test ./internal/store/grpcstore -run WebAuthn -count=1` | 0 (`TestWebAuthnCapabilityNegotiated` with all 17 storetest `WebAuthn` cases over gRPC, `TestOldPluginWebAuthnUnavailable`, `TestWebAuthnRequiresMFA`, `TestWebAuthnFieldsTransientProbe`, `TestWebAuthnCodecNotLogged`) |
| `go test ./pkg/storeplugin -run WebAuthn -count=1` | 0 (`TestWebAuthnThroughPluginProcess`) |
| `go build ./...` | 0 |
| `go vet ./internal/store/... ./pkg/...` | 0 |
| `gofmt -l internal/store pkg` | 0, no output |
| `go test ./internal/store/grpcstore ./pkg/storeplugin ./cmd/... -count=1` (first run, logged) | **1**: `TestMFAPrePluginPriorFeatures/WebAuthn/*` failed with `store: MFA unavailable` |
| same, after the fix below (logged) | 0 (`grpcstore` 292.9s, `storeplugin` 80.6s incl. `TestConformanceThroughPluginProcess` running the `WebAuthn` suite through the sample plugin process, `cmd/zeroauthy` 1.9s; `cmd/zeroauthy-store-memory` has no tests) |

The first full run showed that a plugin advertising `webauthn.v1` but lacking
MFA v1 cannot serve the suite: passkeys are MFA authenticator rows. Fix:
`CheckWebAuthnSupport` also requires MFA v1 (a definitive
`ErrMFAUnavailable` latches WebAuthn as unavailable; a transient MFA probe
error is returned, not latched), documented in `store.proto`, pinned by
`TestWebAuthnRequiresMFA`. `TestMFAPrePluginPriorFeatures` now skips the
`WebAuthn` suite for that plugin, as it does for the other MFA-dependent
behaviour. The focused tests and the full run above were then rerun; `make
generate`, build and vet were rerun after the proto comment change (all exit 0).

`TestConformanceSQLite` over gRPC skips the `WebAuthn` suite: `sqlstore`'s
`WebAuthn()` is still the Task 4 stub, so the server advertises version 0.
It will run once Task 5 lands; nothing in this task needs to change for it.

## Notes for later tasks

- `MFA().CreateChallenge` (memory, the reference) answers `ErrNotFound` unless
  `UserID` names an existing user, so a usernameless `passkey-login`
  challenge cannot be stored as an `MFAChallenge` as the contract stands.
  Task 8 must either bind such challenges to a user or the contract must
  change; this task does not change it (the codec test uses a user-bound
  `webauthn-assert` challenge).
- `opened` in `pkg/storeplugin` still does not forward `MFASupporter` or
  `PhoneSupporter`; out of scope here, unchanged.
