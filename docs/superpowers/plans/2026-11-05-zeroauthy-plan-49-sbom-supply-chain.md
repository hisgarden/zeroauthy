# Plan 49 — SBOMs, Supply-Chain Attestations and Hardened Base Images Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** every release artefact ships a CycloneDX 1.6 and an SPDX 2.3
SBOM covering the Go module graph, the console's production JavaScript
dependencies and (for the image) its OS packages, attested with
`actions/attest-sbom` and published as release assets; a grype gate over
those SBOMs and the existing `govulncheck` stop a release with unaccepted
critical/high findings; operators get a verification guide; the image is
built on digest-pinned Chainguard bases; `make sbom` reproduces the SBOMs
locally and a Go test guards the contract.

**Architecture:** one generator script (`scripts/sbom.sh`, syft over a
staging directory holding the extracted binary and the console lockfile;
`cyclonedx-gomod` installed into a temporary `GOBIN` as the Go-only fallback), one scanner
script (`scripts/scan-sbom.sh`, grype with `.grype.yaml` and an optional
`openvex.json`), one contract checker (`internal/sbomcheck`, vendored
CycloneDX 1.6 schema, called by `scripts/check-sbom.sh`). CI and the
release workflow gain a `sbom` job each; the `publish` job attests and
uploads. The Dockerfile moves to `cgr.dev/chainguard/go` and
`cgr.dev/chainguard/node` by digest with the `go.mod` toolchain forced.

**Tech Stack:** Go 1.26.10 (unchanged), `github.com/santhosh-tekuri/jsonschema/v6`
(already required), bash, syft (CI: `anchore/sbom-action/download-syft@v0`),
grype (CI: `anchore/scan-action/download-grype@v7`), `actions/attest-sbom@v2`,
`cyclonedx-gomod` v1.12.0 via `go install` into a temporary `GOBIN`. **No new Go module.**

**Spec:** [SBOM and supply-chain design](../specs/2026-11-05-zeroauthy-sbom-supply-chain-design.md).
Read it before executing any task. Section numbers (§) refer to it.

## Global Constraints

- `go.mod`/`go.sum` do not change: no new `require`, no new `tool`
  directive. `go install <module>@<version>` into a temporary `GOBIN` is the
  only way a Go tool is run (it never edits `go.mod`).
- Workflow edits are additive: new jobs, new steps, new `outputs`, and the
  three existing lines named in Task 4. Never edit a step that mentions
  Node or npm (another branch is switching the console to Bun).
- Every base-image digest is fetched from `cgr.dev` on the day it is
  written and recorded with tag and creation date (spec §7). No invented
  digests, versions or tool behaviour.
- Policy: `fail-on-severity: high`; accepted findings live in `.grype.yaml`
  (`ignore`) or `openvex.json`, with reason and date. **Do not add an
  ignore or VEX statement for a finding this plan discovers**; record it in
  the implementation record for the maintainer (the dependency bump is a
  separate change).
- The console lockfile is read generically (`package-lock.json`, `bun.lock`,
  `yarn.lock`, `pnpm-lock.yaml`); the script refuses syft < 1.46.0 when
  `bun.lock` is the only lockfile.
- Go commands run with `GOTOOLCHAIN=go1.26.10 GOTMPDIR=/home/user/gotmp`;
  heavy commands (`go build`, `go install`, syft, grype) under `nice -n 15`.
  Do not run the full Go test suite; run only `./internal/sbomcheck`.
- Do not touch `internal/webauthn*`, `internal/store`, `api/`, `tests/e2e`
  or `docs/superpowers/*33b*`.
- Work in the `claude/plan-sbom` worktree. Commit per task. Record commits,
  commands and actual exit codes in
  `docs/superpowers/2026-11-05-plan-49-implementation-record.md`; what could
  not run here (no Docker daemon, no Actions) is listed as not run.

## Review Focus

1. **A lockfile that syft cannot read** (old syft with `bun.lock`, or no
   lockfile at all) must not yield an SBOM that silently lacks the console.
   `scripts/sbom.sh` refuses or warns; the strict check fails. Pinned in
   Tasks 1 and 2.
2. **The gate must bite before anything is pushed.** The release `sbom` job
   (archives plus a local amd64 image build) runs before `approve`; the
   published image SBOM comes from the pushed digest. Pinned in Task 4.
3. **The image binary must be built with the same toolchain as the
   archives** whatever Go the Chainguard base ships (`GOTOOLCHAIN` forced
   from `go.mod`). Pinned in Task 3.
4. **The runtime image must still run Actions.** Node ≥ 25, npm beside
   `node`, a shell for the compose health check, CA bundle present, numeric
   uid for `USER`/`--chown`. Pinned in Task 3 (facts from the registry; the
   container run is left to the first dry run).
5. **An accepted finding must be visible in review.** `.grype.yaml` and
   `openvex.json` are the only mechanisms; `scan-sbom.sh` never lowers the
   cutoff. Pinned in Tasks 2 and 5.

## File boundaries and shared interfaces

| Responsibility | Files |
| --- | --- |
| Contract check | new `internal/sbomcheck/{sbomcheck.go,sbomcheck_test.go,schema/bom-1.6.schema.json,schema/spdx.schema.json,schema/jsf-0.82.schema.json,schema/LICENSE}`, new `scripts/check-sbom.sh`; `NOTICE` |
| Generation and scan | new `scripts/sbom.sh`, `scripts/scan-sbom.sh`, `.grype.yaml`; `Makefile` (`sbom`, `sbom-check`, `sbom-scan`) |
| Base images | `Dockerfile`, `.github/workflows/ci.yml` (`sql` services), `scripts/test-sql.sh`, `examples/testing/compose.yaml`, `docs/deployment.md` |
| Workflows | `.github/workflows/ci.yml` (new `sbom` job), `.github/workflows/release.yml` (new `sbom` job, `image` outputs, `publish` steps) |
| Docs | new `docs/supply-chain.md`; `SECURITY.md`, `RELEASING.md`, `.github/release-docker.md`, `README.md`, `CHANGELOG.md`, roadmap spec §0/§2/§3a |
| Record | new `docs/superpowers/2026-11-05-plan-49-implementation-record.md` |

Shared contract, defined in Task 1 and used by name later:

```go
// internal/sbomcheck
type Summary struct {
	Format, SpecVersion string // "CycloneDX" + "1.6", or "SPDX" + "SPDX-2.3"
	Name, Version       string // metadata.component / SPDX document name
	Components          int
	Purls               []string
}
type Requirement struct{ Go, Console, OS bool }
func CheckCycloneDX(data []byte) (*Summary, error) // schema + contract
func CheckSPDX(data []byte) (*Summary, error)      // structural contract
func (s *Summary) Require(r Requirement) error     // pkg:golang/, pkg:npm/vue@ (and no dev-only tool), pkg:apk/
func CheckDir(dir string, strict bool) ([]Result, error)
```

File names (`scripts/sbom.sh` writes, `check-sbom.sh` and the workflows
read): `zeroauthy_<v>_<os>_<arch>.cdx.json`, `.spdx.json`, `.syft.json`
(gate input with Go symbols, not published), `zeroauthy_<v>_image.cdx.json`,
`.spdx.json`, `SBOM_SHA256SUMS` (over `*.cdx.json` and `*.spdx.json`).

### Task 1: Contract check package and script

- [ ] Vendor `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`
      from `CycloneDX/specification` (`schema/`, Apache-2.0) into
      `internal/sbomcheck/schema/` with the LICENSE; add a `NOTICE` entry.
- [ ] `sbomcheck.go`: embed the schemas; compile once with
      `jsonschema.NewCompiler` + `AddResource("http://cyclonedx.org/schema/<file>", doc)`;
      `CheckCycloneDX` (schema, `bomFormat`, `specVersion == "1.6"`,
      `serialNumber`, `metadata.component`, non-empty `components`),
      `CheckSPDX` (`spdxVersion == "SPDX-2.3"`, `dataLicense == "CC0-1.0"`,
      `SPDXID == "SPDXRef-DOCUMENT"`, `name`, `documentNamespace`,
      `creationInfo.created`, non-empty `packages`), `Require`, `CheckDir`
      (strict: both formats per artefact; archives need Go + console; the
      image needs Go + OS).
- [ ] `sbomcheck_test.go`: inline fixtures (valid 1.6; `specVersion: 1.5`;
      missing `bomFormat`; `pkg:npm/vitest@` present; SPDX valid and
      wrong version), and `TestGeneratedSBOMs` driven by `ZA_SBOM_DIR` /
      `ZA_SBOM_STRICT` (skips when unset).
- [ ] `scripts/check-sbom.sh [--strict] [DIR]` → `go test -count=1 -run '^TestGeneratedSBOMs$' ./internal/sbomcheck` with the env set.
- [ ] Run `gofmt -l internal/sbomcheck`, `go vet ./internal/sbomcheck`,
      `go test ./internal/sbomcheck`. Commit: `sbom: contract check for CycloneDX 1.6 and SPDX 2.3 documents`.

### Task 2: Generator, scanner, policy and Makefile

- [ ] `scripts/sbom.sh VERSION [DISTDIR]` and `scripts/sbom.sh image REF VERSION [DISTDIR]`
      (§3, §8): syft from `$SYFT`/`PATH`; per archive a staging dir with the
      binary and `console/{package.json,<lockfiles>}`; `syft scan dir:<stage>
      --source-name --source-version -o cyclonedx-json@1.6=… -o spdx-json@2.3=…`
      plus `-o syft-json=…` with `SYFT_GOLANG_CAPTURE_SYMBOLS=all`; the
      bun.lock version guard; the `cyclonedx-gomod@v1.12.0` fallback per
      `GOOS`/`GOARCH` with a clear message; `SBOM_SHA256SUMS`.
- [ ] `scripts/scan-sbom.sh [DIR...]`: grype from `$GRYPE`/`PATH`; for each
      artefact prefer `<name>.syft.json`, else `<name>.cdx.json`;
      `-c .grype.yaml`, `--vex openvex.json` when present; never passes
      `--fail-on` lower than the config.
- [ ] `.grype.yaml`: `fail-on-severity: high`, `only-fixed: false`, empty
      `ignore` with a commented example (vulnerability, package, reason,
      date), a comment on `openvex.json`.
- [ ] `Makefile`: `VERSION ?= 0.0.0-dev.<sha12>`; `sbom` (builds archives
      with `scripts/dist.sh` when `dist/zeroauthy_$(VERSION)_*.tar.gz` are
      missing, then `scripts/sbom.sh`), `sbom-check` (strict), `sbom-scan`;
      add to `.PHONY`.
- [ ] Run for real: `make sbom` with the downloaded syft (`SYFT=…`),
      `make sbom-check`, `make sbom-scan` (record the actual grype result),
      then the fallback (`SYFT=/nonexistent`) and the expected strict
      failure. Commit: `sbom: generate, check and scan release SBOMs locally`.

### Task 3: Chainguard base images

- [ ] `Dockerfile` (§7): build stage `cgr.dev/chainguard/go@sha256:5755…`
      with the tag/date comment; `GOTOOLCHAIN="go$(sed -n 's/^go //p' go.mod)"`
      on `go mod download` and `go build`; flags unchanged. Runtime stage
      `cgr.dev/chainguard/node@sha256:4ad7…` with the comment (Node 26.13.0,
      user 65532, busybox, CA bundle); drop the CA copy; `--chown=65532:65532`;
      `USER 65532`; header comment updated.
- [ ] `.github/workflows/ci.yml` `sql` job: `postgres:17` →
      `cgr.dev/chainguard/postgres@sha256:c976…` (comment: `latest`
      2026-11-02, PostgreSQL 18.6); env and health check unchanged; MySQL
      unchanged with a comment giving the reason.
- [ ] `scripts/test-sql.sh`: same PostgreSQL image; MySQL unchanged.
- [ ] `examples/testing/compose.yaml` smoke service: the node image by
      digest, `command: ["/tests/smoke.mjs"]`.
- [ ] `docs/deployment.md`: the container ships Node 26 on a Chainguard
      (Wolfi) base.
- [ ] `hadolint Dockerfile`; `python3 -c 'import yaml…'` on the compose
      file. Commit: `build: Chainguard base images pinned by digest`.

### Task 4: Workflows

- [ ] `ci.yml`: new job `sbom` (checkout, setup-go, `scripts/dist.sh
      0.0.0-dev.<sha> dist`, `anchore/sbom-action/download-syft@v0`,
      `scripts/sbom.sh`, `scripts/check-sbom.sh --strict dist/sbom`,
      `anchore/scan-action/download-grype@v7`, `scripts/scan-sbom.sh dist/sbom`,
      upload `sbom-ci` artifact).
- [ ] `release.yml`: new job `sbom` (`needs: [version, binaries]`): download
      `dist`, syft, `scripts/sbom.sh`, strict check, buildx + local amd64
      image build (`push: false`, `load: true`, tag `zeroauthy:sbom-gate`),
      `scripts/sbom.sh image docker:zeroauthy:sbom-gate … dist/sbom-gate`,
      grype over `dist/sbom` and `dist/sbom-gate`, upload `sbom` artifact.
      `approve` gains `sbom` in `needs`.
- [ ] `release.yml` `image` job: add `outputs: { digest: ${{ steps.build.outputs.digest }} }`.
- [ ] `release.yml` `publish` job: add `packages: write`; download `sbom`;
      `docker/login-action`; syft; `scripts/sbom.sh image registry:ghcr.io/<repo>@<digest> <v> dist`;
      strict check; `attest-build-provenance` `subject-path` extended with
      `dist/sbom/*.json` and `dist/sbom/SBOM_SHA256SUMS`; `actions/attest-sbom@v2`
      ×3 archives (`subject-path`, `sbom-path`) and ×1 image (`subject-name`,
      `subject-digest`, `push-to-registry: true`); `gh release create` gains
      `dist/sbom/*.cdx.json dist/sbom/*.spdx.json dist/sbom/SBOM_SHA256SUMS`.
- [ ] `actionlint` on both files (downloaded binary). Commit:
      `ci: SBOM generation, vulnerability gate and SBOM attestations`.

### Task 5: Documentation and roadmap

- [ ] `docs/supply-chain.md` (§6): what is published, verify archives/SBOM
      files/image, BuildKit attestations, cosign note (unexercised), feeding
      grype/osv-scanner/Dependency-Track, policy and acceptance mechanism,
      "what is pinned and how to bump it" with every digest, base-image
      SBOMs (`cosign download sbom`), local `make sbom`.
- [ ] `SECURITY.md` "Supply chain" section; `RELEASING.md` (what a release
      publishes, Step 4 gates, Step 5 checks, base-image bump, `make sbom`);
      `.github/release-docker.md` and `README.md` one line each;
      `CHANGELOG.md` Unreleased entries.
- [ ] Roadmap spec: §0 "Next", §2 order table row `49`, §3a entry
      "Plan 49 — SBOMs, supply-chain attestations and hardened base images"
      linking spec and plan. Commit: `docs: supply-chain verification guide and Plan 49 roadmap entry`.

### Task 6: Acceptance and record

- [ ] Re-run in order: `go test ./internal/sbomcheck`, `make sbom`,
      `make sbom-check`, `make sbom-scan`, the fallback, `actionlint`,
      `hadolint`, `gofmt`/`go vet` on the package, `git status` showing
      `go.mod`/`go.sum` untouched, digest equality between files and the
      record.
- [ ] Write `docs/superpowers/2026-11-05-plan-49-implementation-record.md`:
      commits, each command with its exit code and output summary, the real
      grype findings and their disposition, registry facts, and the list of
      things not run here. Commit: `docs: Plan 49 implementation record`.

## Dependency order and completion audit

Execution order: **1 → 2 → 3 → 4 → 5 → 6**. Task 3 is independent of
1–2 and may run in parallel. Task 4 depends on 1–3 (it calls the scripts
and builds the new Dockerfile). Task 5 depends on 3–4 for the facts it
documents. Task 6 depends on all.

| Spec requirement | Owning tasks |
| --- | --- |
| Formats, names, rules (§2) | 1, 2 |
| Archive SBOMs, image SBOM, attestations (§3) | 2, 4 |
| Console coverage, lockfile guard (§4) | 1, 2 |
| govulncheck unchanged, grype gate, policy files (§5) | 2, 4 |
| Operator verification docs (§6) | 5 |
| Chainguard images, toolchain, pinning, bump procedure (§7) | 3, 5 |
| `make sbom`, fallback, contract test (§8) | 1, 2 |
| Follow-ups and open rulings (§9) | 5 (recorded), 6 |
| Acceptance (§10) | 6 |

Planning self-review: every spec section maps to a task; the file names and
the `sbomcheck` API are defined once here; each Review Focus risk names its
task. No implementation command was run while writing this plan beyond the
registry reads, tool downloads and local trials recorded in the spec.
