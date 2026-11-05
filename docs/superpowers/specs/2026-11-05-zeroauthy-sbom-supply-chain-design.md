# Plan 49 — SBOMs, supply-chain attestations and hardened base images

**Date:** 2026-11-05. **Status:** design; implemented in the same branch
(see the [implementation plan](../plans/2026-11-05-zeroauthy-plan-49-sbom-supply-chain.md)
and the [implementation record](../2026-11-05-plan-49-implementation-record.md)).

**Predecessor:** Plan 46 core (`release.yml`, `scripts/dist.sh`,
`RELEASING.md`). Roadmap entry: [management roadmap, Plan 49](2026-10-19-zeroauthy-management-roadmap-design.md#plan-49--sboms-supply-chain-attestations-and-hardened-base-images).
Read [RELEASING.md](../../../RELEASING.md), [SECURITY.md](../../../SECURITY.md),
the [clean-room policy](../../../CLEAN_ROOM.md) and `.github/workflows/{ci,release}.yml`
before this document.

## 1. Outcome and scope

An operator who downloads a zeroauthy release can answer, with tooling they
already have, three questions: *what is in this artefact*, *who built it
from which commit*, and *does it carry a known vulnerability*. Every release
artefact (three binary archives and the multi-arch container image) ships
with a CycloneDX 1.6 and an SPDX 2.3 software bill of materials that covers
the Go module graph, the admin console's production JavaScript dependencies
(embedded in the binary by `go:embed`) and, for the image, its operating
system packages. The SBOMs are release assets and GitHub artifact
attestations; a vulnerability gate stops a release that carries a critical
or high finding unless a recorded VEX statement says it does not apply. The
image is built on Chainguard (`cgr.dev`) base images pinned by digest.

**Maintainer rulings carried in:**

- **Manual CI (2026-11-04).** `ci.yml` never runs on pushes or pull
  requests. This plan adds jobs to the existing workflows and does not add
  a push or pull-request trigger. `govulncheck` therefore runs on every
  manual CI run and on every release, not "on every push"; a scheduled
  vulnerability re-scan of the last release is proposed in §9 and waits for
  a ruling.
- **Release branches only (2026-11-02).** Nothing here publishes outside
  the `release`/`release/**` workflow and its `production` approval.
- **Chainguard images (2026-11-05).** Use `cgr.dev` images "wherever
  possible", pinned by digest, in the Dockerfile, CI services and examples;
  third-party-only images stay as they are.

**Rule:** workflow changes are additive (new jobs and steps, new outputs),
because another branch is changing the console toolchain in the same files;
no existing step that mentions Node or npm is edited. The Go module graph
does not change: no new `require` in `go.mod`, no new `tool` directive; the
only Go tool this plan runs is `go install <module>@<version>` into a
temporary `GOBIN`.

### In scope

1. **SBOMs for every release artefact** (§3): per archive, from the linked
   binary plus the console lockfile; for the image, BuildKit's attached SBOM
   stays and a standalone SBOM of the pushed image is published too. Both
   formats are release assets; the CycloneDX document of each artefact is an
   `actions/attest-sbom` attestation, and every SBOM file is itself a subject
   of the existing build-provenance attestation.
2. **Console dependency coverage** (§4): the production dependency tree of
   `console/` appears in every archive SBOM, whichever lockfile the console
   uses (`package-lock.json` today, `bun.lock` after the Bun switch).
3. **Vulnerability gate** (§5): `govulncheck` (already in `ci.yml`) stays the
   Go gate; `grype` over the generated SBOMs becomes a CI job and a release
   gate that fails on critical/high, with `.grype.yaml` ignore rules and an
   OpenVEX file as the documented acceptance mechanism.
4. **Verification documentation** (§6): `docs/supply-chain.md` for operators;
   `SECURITY.md`, `RELEASING.md`, `.github/release-docker.md` and one README
   line updated.
5. **Hardened base images** (§7): the Dockerfile's build and runtime stages,
   the CI PostgreSQL service, `scripts/test-sql.sh` and the testing compose
   example move to `cgr.dev` images pinned by digest, with the digest, tag
   and date recorded where they are used and in `docs/supply-chain.md`.
6. **Local reproducibility** (§8): `make sbom`, `make sbom-check` and
   `make sbom-scan` run the same scripts CI runs, into `dist/sbom/`
   (already gitignored under `/dist/`).
7. **A contract test** (§8): `internal/sbomcheck` validates CycloneDX
   documents against the vendored 1.6 JSON schema and checks the contract
   (format, versions, Go and npm coverage, no dev-only tools), used by
   `scripts/check-sbom.sh` in CI and locally.

### Not in scope

- Signing the image with cosign (keyless, GitHub OIDC). GitHub's artifact
  attestations already produce Sigstore bundles for the image and the
  archives; a second signature with a second trust root is a follow-up
  (§9), not a 1.x requirement.
- SLSA level claims, a VEX feed for consumers, Dependency-Track hosting,
  SBOMs for the E2E test kit (`examples/testing`, `tests/e2e`) or the
  conformance tooling. These are not release artefacts.
- Moving `mysql:8.4` to a Chainguard image: `cgr.dev/chainguard/mysql` is
  not pullable anonymously (verified 2026-11-05, §7), and MariaDB is not a
  substitute for the MySQL 8.0.17+ collations the SQL driver needs.
- Changing what `scripts/dist.sh` builds or how; the archive contents and
  `SHA256SUMS` are unchanged.

### Anti-goals

- A digest, version or tool behaviour written from memory. Every digest in
  the repository was fetched from the registry on the recorded date; every
  tool version named was resolved from its repository's tags.
- An SBOM that lists development-only tooling (ESLint, Vitest, Vite, Go test
  dependencies) as part of the product. Consumers feed these documents to
  scanners; false positives cost them time.
- A vulnerability gate that can be silenced without a trace. Every accepted
  finding is a line in `.grype.yaml` or a statement in `openvex.json`, in the
  repository, with a reason.
- Reporting an unrun verification as passing. The implementation record
  lists each command, its exit code and what could not run here (no Docker
  daemon, no GitHub Actions).

## 2. Evidence and rules

| Contract | Primary source |
| --- | --- |
| CycloneDX 1.6 JSON | [CycloneDX specification](https://github.com/CycloneDX/specification) `schema/bom-1.6.schema.json` (Apache-2.0; vendored with `spdx.schema.json` and `jsf-0.82.schema.json`, see `NOTICE`) |
| SPDX 2.3 JSON | [SPDX specification 2.3](https://spdx.github.io/spdx-spec/v2.3/) (`spdxVersion`, `dataLicense`, `SPDXID`, `documentNamespace`, `creationInfo`, `packages`) |
| Package URLs | [purl specification](https://github.com/package-url/purl-spec): `pkg:golang/`, `pkg:npm/`, `pkg:apk/wolfi/` |
| Artifact attestations | [GitHub: using artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations), `actions/attest-build-provenance`, `actions/attest-sbom`, `gh attestation verify` |
| BuildKit SBOM and provenance | [Docker: build attestations](https://docs.docker.com/build/metadata/attestations/) (`sbom: true`, `provenance: mode=max`, `docker buildx imagetools inspect --format`) |
| syft, grype | [anchore/syft](https://github.com/anchore/syft) (`--source-name`, `--source-version`, catalogers; `bun.lock` support since v1.46.0, verified 2026-11-05 on v1.42.0 vs v1.56.0), [anchore/grype](https://github.com/anchore/grype) (`.grype.yaml`, `--fail-on`, `--vex`, `ignore` rules) |
| OpenVEX | [OpenVEX specification](https://github.com/openvex/spec) v0.2.0 and `vexctl` |
| Go vulnerability checking | [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), `golang/govulncheck-action` |
| Chainguard images | [Chainguard image directory](https://images.chainguard.dev/directory): `go`, `node`, `postgres`, `wolfi-base`; registry manifests, configs and SPDX attestations fetched from `cgr.dev` on 2026-11-05 (§7) |
| Go toolchain selection | [Go toolchains](https://go.dev/doc/toolchain): `GOTOOLCHAIN=goX.Y.Z` forces an exact, checksum-verified toolchain |

Rules:

- **Formats.** CycloneDX 1.6 (`bomFormat: CycloneDX`, `specVersion: "1.6"`,
  a `serialNumber`, `metadata.component` naming the artefact and version)
  and SPDX 2.3 (`spdxVersion: SPDX-2.3`, `dataLicense: CC0-1.0`). The
  CycloneDX document is validated against the schema; SPDX is checked
  structurally (the SPDX JSON schema is CC-BY licensed and is not vendored).
- **Names.** `zeroauthy_<version>_<os>_<arch>.cdx.json` and `.spdx.json`
  beside each archive; `zeroauthy_<version>_image.cdx.json` and
  `.spdx.json` for the image; `SBOM_SHA256SUMS` over the SBOM files
  (`SHA256SUMS` keeps covering only the archives, so existing verification
  instructions stay true).
- **One generator, one script.** CI and `make sbom` run `scripts/sbom.sh`
  with syft. Without syft the script falls back to a pinned
  `cyclonedx-gomod` installed into a temporary `GOBIN` (Go modules only,
  CycloneDX only) and says so; the strict check used in CI then fails,
  which is the point.
- **Policy.** A release stops on any unaccepted grype finding of severity
  high or critical in any release SBOM, and on any `govulncheck` finding
  reachable from `./...`. Medium and below are reported, not blocking.
- **Acceptance of a finding** is a change to the repository: an `ignore`
  entry in `.grype.yaml` for a false positive or a vulnerability in code
  zeroauthy does not reach, or an OpenVEX `not_affected`/`fixed` statement
  in `openvex.json` with a justification and impact statement. Both name the
  vulnerability, the package and the reason; both are reviewed like code.
- **No digest without a fetch.** A base-image digest is written only after
  reading it from the registry; the comment beside it records the tag and
  the image's creation date. Bumping is a deliberate commit (§7).
- **No new Go module** and no new `tool` directive. Validation uses the
  already-vendored `github.com/santhosh-tekuri/jsonschema/v6`.

## 3. Release SBOMs and attestations

### What is published

| Asset | Subject | Produced by | Attested as |
| --- | --- | --- | --- |
| `zeroauthy_<v>_<os>_<arch>.tar.gz` (×3) | archive | `scripts/dist.sh` | build provenance (existing) |
| `zeroauthy_<v>_<os>_<arch>.cdx.json` (×3) | archive | `scripts/sbom.sh` (syft over the extracted binary plus the console lockfile) | `attest-sbom` predicate for the archive; also a build-provenance subject |
| `zeroauthy_<v>_<os>_<arch>.spdx.json` (×3) | archive | same run | build-provenance subject |
| `zeroauthy_<v>_image.cdx.json`, `.spdx.json` | image digest | `scripts/sbom.sh image` over the pushed image | `attest-sbom` predicate for the image (pushed to the registry); build-provenance subjects |
| `SBOM_SHA256SUMS` | the SBOM files | `scripts/sbom.sh` | build-provenance subject |
| image `sha256-<digest>` referrers | image | BuildKit (`sbom: true`, `provenance: mode=max`, existing) and `attest-build-provenance` (existing) | — |

### How an archive SBOM is produced

`scripts/sbom.sh VERSION [DISTDIR]` takes the archives `dist.sh` built. For
each one it extracts the binary into a staging directory, copies
`console/package.json` and every console lockfile that exists
(`package-lock.json`, `bun.lock`, `yarn.lock`, `pnpm-lock.yaml`) into
`console/` beside it, and runs one syft scan over the directory with
`--source-name zeroauthy_<v>_<os>_<arch> --source-version <v>`, emitting
both formats from the same catalog. The Go part comes from the binary's
embedded build information (the modules actually linked for that
`GOOS`/`GOARCH`, with their versions and `h1:` sums), so the three archive
SBOMs can differ where platform-specific modules differ. The console part
comes from the lockfile (§4). Each SBOM therefore describes one archive, not
the source tree.

### How the image SBOM is produced

`docker/build-push-action` keeps `sbom: true` and `provenance: mode=max`:
the index pushed to GHCR carries BuildKit's SPDX SBOM and SLSA provenance,
readable with `docker buildx imagetools inspect <ref> --format '{{json .SBOM}}'`.
In addition, after the push, the `publish` job runs
`scripts/sbom.sh image registry:ghcr.io/<repo>@<digest> <v>`; syft catalogs
the Wolfi `apk` packages of the Chainguard base (§7) and the Go modules of
the binary. The resulting CycloneDX document is attested with `attest-sbom`
for the image digest (`push-to-registry: true`) and both files become
release assets. The image's npm coverage is by reference: the console is
compiled into the binary, and the archive SBOMs for the same version list
its dependencies; `docs/supply-chain.md` says so.

Before approval, the `sbom` job in `release.yml` builds a linux/amd64 image
locally (`push: false`, `load: true`) and scans it, so the vulnerability gate
covers the base image's packages before anything is pushed. That gate SBOM
is not published; the published image SBOM is the one taken from the pushed
digest, so its source metadata names the real image.

### Attestations

`actions/attest-sbom@v2` runs in the `publish` job, once per archive with
`subject-path` and `sbom-path`, and once for the image with `subject-name`,
`subject-digest` and `push-to-registry: true`. It uses the same `v2` major
as the existing `actions/attest-build-provenance@v2`, so one Sigstore client
version signs everything in a release. The existing provenance step's
`subject-path` grows to include `dist/sbom/*.json` and `SBOM_SHA256SUMS`, so
`gh attestation verify <sbom file> --repo <repo>` proves an SBOM file came
from the release run.

## 4. Console dependency coverage

The console (`console/`, Vue and Vite) is built into `console/dist`, which
is committed and embedded in the binary. Its production dependencies are
part of the product and must be in every archive SBOM.

- The generator copies `console/package.json` and whichever lockfile is
  present. syft's JavaScript lock cataloger parses `package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` (since syft v1.46.0) and
  `deno.lock`, and skips packages the lockfile marks as development-only.
  Verified 2026-11-05: `console/package-lock.json` and a `bun.lock`
  generated from the same `package.json` both give 64 production components
  with syft 1.56.0, with `vue`, `pinia`, `reka-ui` present and `vitest`,
  `eslint`, `vite` absent; syft 1.42.0 returns no components for `bun.lock`.
- `scripts/sbom.sh` refuses to run with a syft older than 1.46.0 when
  `bun.lock` is the only console lockfile, with a message naming the
  version, rather than silently producing an SBOM without the console.
- The contract check (§8) requires `pkg:npm/vue@` in every archive SBOM and
  rejects `pkg:npm/vitest@`, `pkg:npm/eslint@`, `pkg:npm/vite@` and
  `pkg:npm/vue-tsc@`.
- `tests/e2e/package-lock.json` and other lockfiles outside `console/` are
  never scanned: the staging directory holds only the binary and the
  console manifest.

## 5. Vulnerability gate

- **Go:** the existing `vulncheck` job in `ci.yml` (`golang/govulncheck-action@v1`,
  `./...`) stays as it is. It runs on every manual CI run and, through
  `release.yml`'s `test` job, on every release. No push or pull-request
  trigger is added (maintainer rule).
- **SBOM scan:** `scripts/scan-sbom.sh [DIR...]` runs grype over every
  `*.cdx.json` in the given directories with `-c .grype.yaml`, adds
  `--vex openvex.json` when that file exists, and fails on severity high or
  critical (`fail-on-severity: high` in `.grype.yaml`). It runs in a new
  `sbom` job in `ci.yml` (which builds the archives with `scripts/dist.sh`
  and scans their SBOMs) and in the new `sbom` job of `release.yml` (which
  scans the archive SBOMs and the pre-approval image build). Both jobs run
  `scripts/check-sbom.sh --strict` first, so a malformed or incomplete SBOM
  fails before it is scanned.
- **Accepting a finding.** `.grype.yaml` holds `ignore` rules
  (`vulnerability`, `package`, `fix-state`, with a comment giving the reason
  and date). `openvex.json`, when present, is an OpenVEX document whose
  statements carry `status`, `justification` and `impact_statement`; grype
  applies `not_affected` and `fixed` statements by default. The file does
  not exist until the first statement is needed, because an OpenVEX document
  must contain at least one statement; `docs/supply-chain.md` shows the
  `vexctl create` command and the review rule.
- **Severity source.** grype's own severity (NVD, GitHub, Wolfi and Go
  vulnerability data). A finding with no fix is still blocking; the decision
  to ship with it is a VEX statement, not a lower cutoff.
- **Proposed, pending a ruling (§9):** a `supply-chain.yml` workflow with
  `workflow_dispatch` and a commented weekly `schedule` that re-scans the
  SBOMs attached to the latest release, so a vulnerability disclosed after
  a release is noticed without a new release run.

## 6. Verification for operators

`docs/supply-chain.md` documents, with copy-paste commands:

1. **What is published** (the table in §3) and the naming scheme.
2. **Verify an archive or an SBOM file:** `sha256sum -c SHA256SUMS`,
   `sha256sum -c SBOM_SHA256SUMS`, `gh attestation verify <file> --repo <owner>/<repo>`.
3. **Verify the image:** `gh attestation verify oci://ghcr.io/<repo>:<tag> --repo <owner>/<repo>`
   for provenance, the same command with `--predicate-type https://cyclonedx.org/bom`
   for the SBOM attestation, and `docker buildx imagetools inspect ... --format '{{json .SBOM}}'`
   and `'{{json .Provenance}}'` for BuildKit's attestations.
4. **cosign:** GitHub's attestations are Sigstore bundles; the page gives
   the `cosign verify-attestation --new-bundle-format` form with the
   certificate identity and OIDC issuer to use, marked as not exercised by
   this plan's acceptance run, and points to the cosign-signing follow-up.
5. **Feed the SBOM to a scanner:** `grype sbom:<file>`, `osv-scanner --sbom <file>`,
   and a Dependency-Track upload (`POST /api/v1/bom` with the CycloneDX
   file).
6. **Policy:** which severities block a release, where accepted findings are
   recorded, and how to report a vulnerability (link to `SECURITY.md`).
7. **What is pinned and how to bump it:** every base-image digest with its
   tag and creation date, the tool versions, and the bump procedure (§7).
8. **Base-image SBOMs:** Chainguard publishes an SPDX SBOM for every image
   (`cosign download sbom cgr.dev/chainguard/node@sha256:...`, or the
   `sha256-<digest>.att` referrer); the page records that the published
   image SBOM lists the base's packages by catalog and links to the base's
   own SBOM for its build provenance.

`SECURITY.md` gains a "Supply chain" section (what every release carries,
the gate policy, where to report a dependency vulnerability).
`RELEASING.md` gains the new gates and assets in "What a release publishes"
and "Step 4", the `make sbom` local check, and the base-image bump
procedure. `.github/release-docker.md` and `README.md` each gain one line
pointing at `docs/supply-chain.md`.

## 7. Hardened base images (Chainguard)

Everything below was read from `cgr.dev` on 2026-11-05 through the
anonymous pull token (`https://cgr.dev/token?scope=repository:chainguard/<image>:pull`),
the OCI index, the platform manifest and config, and the SPDX and apko
attestations attached as `sha256-<digest>.att`. No Docker daemon was
available, so no image was run; the implementation record says what that
leaves unverified.

| Use | Before | After | Facts read from the registry |
| --- | --- | --- | --- |
| Dockerfile build stage | `golang:1.26.10-bookworm` | `cgr.dev/chainguard/go@sha256:575572885e29c3c3bac6622d8db116e983436c546cb2987b001747ce6c278891` (`latest`, created 2026-11-02) | Go 1.27.3 (`go-1.27`), bash, git, glibc; `GOTOOLCHAIN=local+auto`; user root |
| Dockerfile runtime stage | `node:26-bookworm-slim` | `cgr.dev/chainguard/node@sha256:4ad7301975908b87d321af8b9ed41630dc69015976269965ee459c27541df252` (`latest`, created 2026-11-02) | Node.js 26.13.0 (`nodejs-26`), npm 12.2.1 at `/usr/lib/node_modules/npm/bin/npm-cli.js`, busybox (`/usr/bin/sh`), dumb-init, `ca-certificates-bundle` at `/etc/ssl/certs/ca-certificates.crt`; user `node` uid/gid 65532, home `/home/node`; entrypoint `/usr/bin/node`, workdir `/app` |
| CI service and `scripts/test-sql.sh` | `postgres:17` | `cgr.dev/chainguard/postgres@sha256:c976eb2e1f7702a9ec38acb3f44c3976b449db7f10181f20b74c53b212a0e202` (`latest`, created 2026-11-02) | PostgreSQL 18.6 with client and contrib, bash and busybox; entrypoint `docker-entrypoint.sh postgres`; `PGDATA=/var/lib/postgresql/data`; the image README documents `POSTGRES_PASSWORD`, `POSTGRES_USER`, `POSTGRES_DB` and `-c` arguments as in the Docker Hub image |
| CI service and `scripts/test-sql.sh` | `mysql:8.4` | unchanged | the token endpoint answers `FORBIDDEN` for `chainguard/mysql` (three attempts); `chainguard/mariadb` is pullable but is a different engine (no `utf8mb4_0900_bin`) |
| `examples/testing/compose.yaml` smoke runner | `node:22-bookworm-slim` | the `node` image above | its entrypoint is `node`, so the service's `command` drops the leading `node` |

Decisions:

- **Build stage toolchain.** The image's Go (1.27.3) is newer than
  `go.mod`'s `go 1.26.10`, so `GOTOOLCHAIN=local+auto` would build with
  1.27.3 while `scripts/dist.sh` and `actions/setup-go` build the archives
  with 1.26.10. The Dockerfile forces the `go.mod` version
  (`GOTOOLCHAIN="go$(sed -n 's/^go //p' go.mod)"`) for `go mod download`
  and `go build`, so the image binary is built with the same toolchain as
  the archives whatever the base image ships. The toolchain download is
  verified by the Go checksum database like any module. `-trimpath
  -buildvcs=false` and the ldflags are unchanged.
- **Runtime stage.** `node:latest` ships Node 26, so the `wolfi-base` plus
  `apk add nodejs` route is not needed (the Wolfi index was fetched and
  lists `nodejs-26`, had it been). `COPY --chown` and `USER` use the numeric
  `65532` so they do not depend on name lookup in the base; the
  `ca-certificates` copy from the build stage is dropped because the base
  ships the bundle at the same path and sets `SSL_CERT_FILE`. Actions'
  npm builds find npm beside `node` (`internal/actions/build`), which
  matches the base's layout. The base includes a busybox shell, so the
  `CMD-SHELL` health check in the compose example keeps working.
- **PostgreSQL 18 in CI.** The driver needs PostgreSQL 14+; the tests run
  against 18.6 instead of 17. The health command (`pg_isready`) and
  `POSTGRES_PASSWORD` are honoured per the image README; the service was not
  started in this environment, so the record marks it "unverified here".
- **Pinning and bumping.** Chainguard's free tier publishes only `latest`,
  so every reference is `@sha256:<index digest>` with a comment giving the
  tag and creation date. To bump: read the new index digest
  (`crane digest cgr.dev/chainguard/node:latest`, or the `cgr.sh` recipe in
  `docs/supply-chain.md`), update the digest and comment, rebuild, run
  `make sbom sbom-check sbom-scan`, and commit with the old and new
  Node/Go/PostgreSQL versions in the message. Renovate/Dependabot digest
  updates are welcome but out of scope.
- **Base-image SBOMs.** Each Chainguard image carries an SPDX SBOM and SLSA
  provenance as cosign attestations. The zeroauthy image SBOM lists the
  base's packages by cataloging the image; the base's own SBOM is the
  authority for how those packages were built, and `docs/supply-chain.md`
  gives the `cosign download sbom` command for the pinned digests.

## 8. Local reproducibility and the contract test

- `make sbom` builds the archives if `dist/` has none for the version
  (`VERSION` defaults to `0.0.0-dev.<12-char sha>`, the same scheme as a
  release dry run) and runs `scripts/sbom.sh` into `dist/sbom/`.
  `make sbom-check` runs `scripts/check-sbom.sh dist/sbom`; `make sbom-scan`
  runs `scripts/scan-sbom.sh dist/sbom`. `/dist/` is already in
  `.gitignore`.
- `scripts/sbom.sh` uses `syft` from `$SYFT` or `PATH`. Without it, it
  installs `github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0`
  into a temporary `GOBIN` (built for the host; `go install pkg@version`
  never edits `go.mod`, verified by a clean `git status` after the run) and
  runs `cyclonedx-gomod app` once per platform with `GOOS`/`GOARCH` set,
  which emits CycloneDX only and covers Go modules only, and prints what is
  missing. The tool reads the module version through git and does not work
  in a `git worktree`; the script says so. (Implementation note: running it
  through `go run` with `GOOS`/`GOARCH` set would cross-compile the tool
  itself, hence the install step.)
- `internal/sbomcheck` (Go, uses the vendored `jsonschema/v6`): `CheckCycloneDX`
  validates against the embedded 1.6 schema and returns a summary;
  `CheckSPDX` checks the SPDX 2.3 fields; `Require` checks purl coverage;
  `CheckDir` applies the contract to a directory. Unit tests use small
  inline documents (valid, wrong `specVersion`, missing `bomFormat`,
  dev-only tool present). `TestGeneratedSBOMs` runs when `ZA_SBOM_DIR` is
  set and is what `scripts/check-sbom.sh` calls; `--strict` additionally
  requires both formats per artefact, console coverage in archive SBOMs and
  `apk` plus Go coverage in the image SBOM.

## 9. Follow-ups and open rulings

- **Scheduled re-scan** (`supply-chain.yml`, weekly): wanted; blocked on the
  maintainer's manual-CI rule. The workflow ships with `workflow_dispatch`
  only and the schedule commented out.
- **cosign keyless signing** of the image and archives (`sigstore/cosign-installer`,
  `cosign sign --yes`): adds a second verification path for operators who
  standardise on cosign. Left out to keep one trust root; revisit if asked.
- **`chainguard/mysql`:** re-check the free catalog periodically; move when
  it becomes pullable.
- **Digest update automation** (Renovate or Dependabot `docker` ecosystem).
- **SPDX schema validation** if the licence question is settled.

## 10. Acceptance and completion

Locally, on this branch, with actual results recorded in the implementation
record:

1. `go test ./internal/sbomcheck` passes (unit fixtures).
2. `make sbom` with syft produces six archive SBOMs and `SBOM_SHA256SUMS`;
   `make sbom-check` (strict) passes: every CycloneDX file validates,
   `pkg:golang/` and `pkg:npm/vue@` are present, no dev-only npm tool is.
3. `make sbom-scan` runs grype over the files and reports its real result
   (pass, or the findings and their disposition).
4. The fallback path (`SYFT=/nonexistent make sbom`) produces CycloneDX
   files from `cyclonedx-gomod` and the strict check fails with the expected
   message.
5. `actionlint` on `ci.yml` and `release.yml`, `hadolint` on the Dockerfile,
   `go vet ./internal/sbomcheck`, `gofmt -l`.
6. The Chainguard digests in the Dockerfile, `ci.yml`, `scripts/test-sql.sh`
   and `examples/testing/compose.yaml` equal the ones fetched and recorded
   in `docs/supply-chain.md`.

Not possible here and therefore not claimed: a `docker build` of the new
Dockerfile, starting the PostgreSQL service image, a GitHub Actions run of
either workflow, `gh attestation verify` against a real release. The first
release dry run (`git push origin main:release` without a tag) exercises
the `sbom` jobs and the image gate; the first tagged release exercises the
attestations and assets. `RELEASING.md` tells the maintainer what to check.
