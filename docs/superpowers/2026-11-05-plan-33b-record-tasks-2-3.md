# Plan 33b implementation record — Tasks 2 and 3

Partial record for the verifier package, written in a separate file so it
merges without conflict; fold into
`2026-11-05-plan-33b-implementation-record.md` with the rest of the plan.

Worktree: `/home/user/zeroauthy-wt/tasks-2-3`, branch
`claude/plan-33b-tasks-2-3` (from `claude/plan-33b-passkeys-webauthn` at
`42c1258`). Every command ran from the worktree root with
`GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp`. No new Go module.

Task 1 (`internal/webauthnrules.Limits`) was not in this worktree, so the
parser bounds are package constants in `internal/webauthn/errors.go`
(`AttestationMax`, `ClientDataMax`, `CredentialIDMax`, `COSEMax`,
`CBORDepth`, `CBORItems`) with the plan's values; integration may alias
them to `webauthnrules.Limits`.

## Task 2

Files: `internal/webauthn/{errors,cbor,cose}.go`,
`internal/webauthn/{cbor,cose,encode}_test.go`,
`internal/webauthn/testdata/fuzz/{FuzzDecodeCBOR,FuzzParseCOSEKey}/`;
`internal/mgmt/user_auth_methods.go` (`validStoredCOSE` replaced by
`webauthn.ParseCOSEKey`), `internal/mgmt/mfa_cose.go` deleted,
`internal/mgmt/{guardian,guardian_validation}_test.go` (the stored-key
tests used an all-zero P-256 point, which the shared parser refuses as
off-curve; they now use a generated key, and `TestStoredCOSESharesParser`
pins that the API and the parser agree on off-curve, private, truncated
and trailing-byte keys).

| Step | Command | Result |
| --- | --- | --- |
| RED | `go test ./internal/webauthn ./internal/mgmt -run 'CBOR\|COSE' -count=1` | exit 1 (`no non-test Go files`, both packages `build failed`) |
| GREEN | same | exit 0 (first rerun failed `TestCBORSubset/bounds` because the depth bound counted the scalar inside 16 arrays; fixed to count container nesting) |
| Fuzz | `go test ./internal/webauthn -run '^$' -fuzz '^FuzzDecodeCBOR$' -fuzztime 60s` | PASS, 60 s, 3,503,304 execs, 130 new interesting inputs, no crashers |
| Fuzz | `go test ./internal/webauthn -run '^$' -fuzz '^FuzzParseCOSEKey$' -fuzztime 60s` | PASS, 60 s, 3,191,289 execs, 142 new interesting inputs, no crashers |
| Corpus | copied from `GOCACHE/fuzz` into `internal/webauthn/testdata/fuzz/` | FuzzDecodeCBOR 130 entries, FuzzParseCOSEKey 142 entries, all under 4 KiB |
| Seeded rerun | `go test ./internal/webauthn -run 'Fuzz\|CBOR\|COSE' -count=1 -v` | exit 0 |
| Full | `go test ./internal/webauthn/... ./internal/mgmt -count=1` | exit 0 (mgmt 229.6 s) |
| Build | `go build ./...` | exit 0 |
| Vet | `go vet ./internal/webauthn/... ./internal/mgmt` | exit 0 |

Commit: `31f0d3c` `feat: add bounded CBOR and COSE parsing for WebAuthn`.

Notes: CBOR simple values are keyed on the additional-information byte, so
a float whose bit pattern is 20–22 is refused rather than read as a
boolean or null. `Reason` returns `""` for nil and `parse` for any error
this package did not produce, keeping the set closed. EC2 points go through
`ecdsa.ParseUncompressedPublicKey`, which refuses off-curve points and the
point at infinity; RSA exponents are bounded to 2^31-1 (the limit
`crypto/rsa` enforces at verification).

## Task 3

Files: `internal/webauthn/{authdata,clientdata,credential,verify,options,device}.go`,
`internal/webauthn/webauthntest/authenticator.go`,
`internal/webauthn/{verify,credential,options,device}_test.go`,
`internal/webauthn/authdata_fuzz_test.go` (internal package, fuzzes the
unexported `parseAuthData`),
`internal/webauthn/testdata/fuzz/{FuzzParseCredentialJSON,FuzzParseAuthData}/`.

| Step | Command | Result |
| --- | --- | --- |
| RED | `go test ./internal/webauthn/... -count=1` | exit 1 (`setup failed`: `webauthntest` package missing) |
| GREEN | same | exit 0 after two fixes: two test compile errors (multi-value call splat, untyped nil seed) and one parser change — a Level 3 serializer may send `response.authenticatorData` beside `attestationObject` on registration, so the registration shape keys on `attestationObject` present and `signature` absent |
| Fuzz | `go test ./internal/webauthn -run '^$' -fuzz '^FuzzParseCredentialJSON$' -fuzztime 60s` | PASS, 60 s, 1,888,328 execs, 92 new interesting inputs, no crashers |
| Fuzz | `go test ./internal/webauthn -run '^$' -fuzz '^FuzzParseAuthData$' -fuzztime 60s` | PASS, 60 s, 1,933,820 execs, 102 new interesting inputs, no crashers |
| Corpus | copied from `GOCACHE/fuzz` into `internal/webauthn/testdata/fuzz/` | FuzzParseCredentialJSON 92 entries, FuzzParseAuthData 102 entries |
| Full | `go test ./internal/webauthn/... ./internal/mgmt -count=1` | exit 0 (webauthn 2.5 s, mgmt 214.0 s) |
| Build | `go build ./...` | exit 0 |
| Vet | `go vet ./internal/webauthn/... ./internal/mgmt` | exit 0 |
| gofmt | `gofmt -l internal/webauthn internal/mgmt` | clean after formatting `options.go` and `verify_test.go` |

Commit: see the Task 3 commit on the branch (`feat: verify WebAuthn
registrations and assertions`).

Notes and rulings applied:

- Origins compare as exact strings; `crossOrigin: true` and any `topOrigin`
  member (even `null`) fail with `cross_origin`; `tokenBinding` and unknown
  client-data members are ignored. Challenges compare with
  `subtle.ConstantTimeCompare`; ECDSA verifies with `ecdsa.VerifyASN1`
  (SHA-256/384/512 per curve), Ed25519 raw, RSA PKCS#1 v1.5 or PSS
  (salt length = hash length) with SHA-256.
- Registration accepts `Expect.Algs` (default `-8, -7, -257`); `-35`, `-36`
  and `-37` keys verify assertions (LR33b-11). Formats `none` (empty
  `attStmt` required), `packed`, `tpm`, `android-key`,
  `android-safetynet`, `fido-u2f` and `apple` are accepted unverified and
  recorded as `none`; unknown formats fail with `attestation` (LR33b-9).
  The attested credential ID must equal `rawId`.
- Sign counter per LR33b-10 (`sign_count` unless both zero or received >
  stored); BE must equal stored BE (`backup_eligibility`); BS without BE is
  `backup_state`; RFU flag bits are ignored; unparsed authenticator-data
  tail is `parse`.
- User handle: `Expect.RequireUserHandle` refuses a missing or different
  handle; without it a present handle must still match the stored one.
- `ParseCredentialJSON` bounds: document 128 KiB, credential ID 1023,
  clientDataJSON 16 KiB, attestation/authenticator data 64 KiB, signature
  2 KiB, user handle 64 bytes, 16 transports. Padded base64url is accepted;
  `authenticatorAttachment` must be `platform` or `cross-platform` when
  present; Level 2 shapes (no attachment, transports,
  clientExtensionResults; `userHandle: null`) parse (Review Focus 5).
- Options JSON: `pubKeyCredParams` `-8, -7, -257`; `attestation: "none"`;
  `rp.name` defaults to `rp.id`; `userVerification` defaults to
  `preferred`; `requireResidentKey` mirrors `residentKey: "required"`;
  `excludeCredentials`/`allowCredentials` always arrays (empty for
  discoverable logins); timeouts in milliseconds.
- `DeviceOf` (LR33b-19): OS windows/ios/macos/android/other; browser
  chrome/edge/safari/firefox/other; class phone/tablet/desktop. Only Chrome
  is recognized on Android (other Android browsers classify as OS `other`);
  `Key()` is `os/class`, with the browser inserted on macOS. iPadOS Safari
  in desktop mode presents a Macintosh user agent and classifies as macOS,
  the cost LR33b-19 accepts.
- `webauthntest.Options` carries the plan's knobs (`Alg`, `UV`, `BE`, `BS`,
  `Attachment`, `Format`, `SignCount`, `OmitUserHandle`, `CrossOrigin`,
  `TopOrigin`, `TamperRPIDHash`) plus parser-test knobs (`NoUP`, `RFUFlags`,
  `CredentialID`, `AAGUID`, `Transports`, `AuthDataTail`, `Extensions`,
  `AttStmt`, `ClientDataType`, `ClientDataPadding`). Knobs can be changed
  between calls through the embedded `Options`; the key type is fixed at
  `New`. RSA authenticators generate 2048-bit keys.
