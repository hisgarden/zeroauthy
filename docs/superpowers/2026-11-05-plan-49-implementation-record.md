# Plan 49 implementation record — SBOMs, supply-chain attestations and Chainguard base images

**Date:** 2026-11-05. **Branch:** `claude/plan-sbom` (worktree
`/home/user/zeroauthy-wt/sbom`). **Spec:** [design](specs/2026-11-05-zeroauthy-sbom-supply-chain-design.md).
**Plan:** [Plan 49](plans/2026-11-05-zeroauthy-plan-49-sbom-supply-chain.md).

Everything below was run in this environment: no Docker daemon, no GitHub
Actions, outbound HTTPS through a proxy, 4 shared cores (heavy commands
under `nice -n 15`). Results are reported as they happened.

## Commits

| Task | Commit | Files |
| --- | --- | --- |
| spec + plan | `c846641` | `docs/superpowers/specs/2026-11-05-zeroauthy-sbom-supply-chain-design.md`, `docs/superpowers/plans/2026-11-05-zeroauthy-plan-49-sbom-supply-chain.md` |
| 1 contract check | `d1d0067` | `internal/sbomcheck/{sbomcheck.go,sbomcheck_test.go,schema/*}`, `scripts/check-sbom.sh`, `NOTICE` |
| 2 generator, scanner, policy | `350238c` | `scripts/sbom.sh`, `scripts/scan-sbom.sh`, `.grype.yaml`, `Makefile` |
| 3 Chainguard bases | `419d7eb` | `Dockerfile`, `scripts/test-sql.sh`, `examples/testing/compose.yaml`, `docs/deployment.md` |
| 5 docs | `7099dfc` | `docs/supply-chain.md`, `SECURITY.md`, `RELEASING.md`, `.github/release-docker.md`, `README.md`, `CHANGELOG.md`, roadmap spec |
| 6 record | this commit | this file, spec §1/§8 wording |
| 4 workflows | last commit on the branch, workflow files only | `.github/workflows/ci.yml` (`sql` service image, new `sbom` job), `.github/workflows/release.yml` (new `sbom` job, `image` outputs, `publish` steps) |

The workflow changes are a separate, final commit because pushes that touch
`.github/workflows/` need a token with the `workflow` scope, which this
session's token lacks; everything else can be pushed without it.
`go.mod`/`go.sum` are unchanged (`git diff --quiet 42c1258 -- go.mod go.sum`,
exit 0).

## Final acceptance run (Task 6), in order

| Command | Exit | Result |
| --- | --- | --- |
| `gofmt -l internal/sbomcheck` | 0 | nothing listed |
| `go vet ./internal/sbomcheck` | 0 | |
| `go test -count=1 ./internal/sbomcheck` | 0 | unit fixtures: valid 1.6, wrong `specVersion`, missing `bomFormat`, schema violation, no serial, no components, dev-only `vitest`, SPDX field cases, strict/lenient `CheckDir` |
| `SYFT=<syft 1.56.0> make sbom VERSION=0.0.0-dev.local` | 0 | 3 × `.cdx.json`, `.spdx.json`, `.syft.json` and `SBOM_SHA256SUMS` in `dist/sbom/` (archives from `scripts/dist.sh 0.0.0-dev.local`, exit 0 earlier) |
| `make sbom-check` (strict) | 0 | CycloneDX 1.6 validates against the vendored schema: 118 components (linux), 119 (darwin); SPDX-2.3 117/118 packages; `pkg:golang/` and `pkg:npm/vue@3.5.43` present, no dev-only npm tool |
| `GRYPE=<grype 0.121.1, db v6.1.10 built 2026-11-04> make sbom-scan` | **2** | one finding per archive: `github.com/go-jose/go-jose/v4 v4.1.5`, **GHSA-mgcc-cww5-fp2q (CVE-2026-116587), High, fixed in 4.1.6** (DoS parsing JWKs with crafted RSA keys). With Go symbols (`.syft.json`) grype confirms the vulnerable function is linked; without symbols it also reported `GO-2026-5932` (x/crypto/openpgp, severity unknown), which the symbol-aware scan drops because openpgp is not linked. **Not accepted**: no ignore rule or VEX statement was added. The fix is a dependency bump (`go-jose/v4` → 4.1.6), which this plan must not make; until it lands, the release gate fails by design. |
| `actionlint ci.yml release.yml` (actionlint 1.7.7) | 0 | |
| `hadolint Dockerfile` (hadolint 2.12.0) | 0 | |
| `bash -n scripts/{sbom,scan-sbom,check-sbom}.sh` | 0 | |
| digest equality | | `go@sha256:5755…` ×1 (Dockerfile), `node@sha256:4ad7…` ×4 (Dockerfile, compose example, docs ×2), `postgres@sha256:c976…` ×2 (ci.yml, test-sql.sh); all five occurrences in `docs/supply-chain.md` match |

### Fallback path

- `SYFT=/nonexistent scripts/sbom.sh 0.0.0-dev.local <dir>` in the **git
  worktree**: `go install` of `cyclonedx-gomod@v1.12.0` into a temporary
  `GOBIN` succeeds; the tool fails with "failed to determine version of
  main module: git: reference not found" (it reads the version through
  go-git, which does not resolve a `git worktree`); the script prints the
  "needs a normal clone, install syft instead" message, exit 1.
- The same in a **normal clone** of the branch: exit 0; three CycloneDX 1.6
  files (51 Go components each, `metadata.component` = the module at its
  pseudo-version) and `SBOM_SHA256SUMS`; `go.mod`/`go.sum` untouched.
- `scripts/check-sbom.sh --strict` on that output: exit 1 with the expected
  messages (no `pkg:npm/vue@`, no SPDX counterpart ×3). Lenient check: exit 0.
- An earlier draft ran the tool with `GOOS`/`GOARCH` set on `go run`, which
  built the tool itself for darwin/arm64 ("exec format error"); hence the
  `go install` into a temporary `GOBIN` and per-platform execution. The
  spec's §8 wording was adjusted in this commit.

### Lockfile coverage (spec §4), measured

| Input | syft 1.42.0 | syft 1.56.0 |
| --- | --- | --- |
| `console/package-lock.json` | 64 components, `vue` ✓, `vitest`/`eslint`/`vite` absent | 64, same |
| `bun.lock` generated from the same `package.json` (`bun install --lockfile-only`, 317 packages) | **0 components** | 64 components, `vue` ✓, dev tools absent |

`bun.lock` parsing exists in syft since v1.46.0 (`parse_bun_lock.go` is
absent at v1.45.0 and present at v1.46.0 on GitHub); `scripts/sbom.sh`
refuses older syft when `bun.lock` is the only lockfile.

## Registry facts (Chainguard), read 2026-11-05

Through `https://cgr.dev/token?scope=repository:chainguard/<image>:pull`
and the OCI API; configs and the SPDX/apko attestations
(`sha256-<platform digest>.att`) decoded locally.

| Image | Index digest | Created | Facts |
| --- | --- | --- | --- |
| `chainguard/go` | `575572885e29…8891` | 2026-11-02 | `go-1.27@1.27.3-r0`, bash, git 2.56, glibc 2.44, `GOTOOLCHAIN=local+auto`, user 0 |
| `chainguard/node` | `4ad730197590…f252` | 2026-11-02 | `nodejs-26@26.13.0-r0`, `npm-12@12.2.1-r1`, busybox 1.38, dumb-init, `ca-certificates-bundle@20261020-r0`; user `node` uid/gid 65532, home `/home/node`; entrypoint `/usr/bin/node`, workdir `/app`. Layer listing confirmed `/usr/bin/sh`, `/usr/bin/npm`, `/usr/lib/node_modules/npm/bin/npm-cli.js`, `/etc/ssl/certs/ca-certificates.crt`. Cosign certificate SAN: `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com` |
| `chainguard/postgres` | `c976eb2e1f77…e202` | 2026-11-02 | `postgresql-18@18.6-r7` with client, contrib and oci-entrypoint packages, bash, busybox; entrypoint `docker-entrypoint.sh postgres`; `PGDATA=/var/lib/postgresql/data`; README documents `POSTGRES_PASSWORD`/`POSTGRES_USER`/`POSTGRES_DB` |
| `chainguard/mysql` | — | — | token endpoint: `{"errors":[{"code":"FORBIDDEN"}]}` on three attempts → not in the free catalog; `chainguard/mariadb` is pullable but not used |
| `chainguard/wolfi-base` | `771146c2dfc8…db61` | 2026-11-03 | apk-tools, busybox, CA bundle (not used: `node:latest` already ships Node 26; the Wolfi APKINDEX was fetched and lists `nodejs-26`) |

## Not run here (and therefore not claimed)

- `docker build` of the new Dockerfile and `docker run … version`: no
  Docker daemon (`dial unix /var/run/docker.sock: no such file`). Parsed and
  linted only (hadolint, exit 0). First real exercise: the next release dry
  run (`sbom` job builds the gate image) or a local `docker build`.
- Starting `cgr.dev/chainguard/postgres` as a CI service or through
  `scripts/test-sql.sh`: unverified in this environment. The README
  documents the same environment variables and `pg_isready` is in the
  image; PostgreSQL moves from 17 to 18.6.
- The `examples/testing/compose.yaml` smoke runner with the Chainguard node
  image (`command: ["/tests/smoke.mjs"]`).
- Both workflows on GitHub Actions: `anchore/sbom-action/download-syft@v0`
  and `anchore/scan-action/download-grype@v7` outputs (`cmd`) and
  `actions/attest-sbom@v2` inputs were checked against the actions'
  `action.yml` files; `load: true` for the single-platform gate build,
  `push-to-registry` for the image SBOM attestation and the extended
  `subject-path` list run for the first time in the next dry run / release.
- `gh attestation verify` and the cosign commands in `docs/supply-chain.md`
  against a real release (none exists with these assets yet).
- A scan of the image SBOM: `scripts/sbom.sh image` needs a daemon or a
  registry image; the script path is the same as for archives except for
  the source reference.

## Open for the maintainer

1. **GHSA-mgcc-cww5-fp2q** (go-jose v4.1.5 → 4.1.6): bump the dependency
   before the next release, or the `sbom` gate stops it. (`govulncheck` in
   CI should report the same if the vulnerable function is reachable; not
   run here.)
2. **Scheduled re-scan** of the latest release's SBOMs (spec §9): needs a
   ruling against the manual-CI rule.
3. **cosign keyless signing** of the image and archives (spec §9).
4. **`chainguard/mysql`** when it becomes pullable.
5. The workflow-only commit needs a push with the `workflow` scope.
