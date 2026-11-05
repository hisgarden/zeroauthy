# Supply chain: SBOMs, attestations and verification

Every zeroauthy release carries a software bill of materials (SBOM) for
each artefact, signed build provenance, and the result of a vulnerability
gate. This page says what is published, how to verify it with tools you
already have, how to feed the SBOMs to your own scanner, what the gate
blocks, and what the build is pinned to. The design is in
[Plan 49](superpowers/specs/2026-11-05-zeroauthy-sbom-supply-chain-design.md);
how a release is cut is in [RELEASING.md](../RELEASING.md).

## What is published

A release `vX.Y.Z` on the [Releases](https://github.com/occupysaas/zeroauthy/releases)
page carries:

| Asset | What it is |
| --- | --- |
| `zeroauthy_X.Y.Z_<os>_<arch>.tar.gz` (linux/amd64, linux/arm64, darwin/arm64) | the static binary with `LICENSE`, `NOTICE`, `README.md`, `CHANGELOG.md` |
| `SHA256SUMS` | checksums of the three archives |
| `zeroauthy_X.Y.Z_<os>_<arch>.cdx.json` | CycloneDX 1.6 SBOM of that archive |
| `zeroauthy_X.Y.Z_<os>_<arch>.spdx.json` | SPDX 2.3 SBOM of that archive |
| `zeroauthy_X.Y.Z_image.cdx.json`, `zeroauthy_X.Y.Z_image.spdx.json` | SBOMs of the multi-arch container image `ghcr.io/occupysaas/zeroauthy:X.Y.Z` |
| `SBOM_SHA256SUMS` | checksums of the SBOM files |

And, as GitHub [artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
(Sigstore bundles signed with the repository's GitHub Actions identity):

- **Build provenance** (SLSA v1) for every archive, every SBOM file,
  `SBOM_SHA256SUMS` and the image: which workflow run, on which commit,
  produced the bytes.
- **SBOM attestations** (predicate type `https://cyclonedx.org/bom`) binding
  each archive's CycloneDX SBOM to that archive, and the image's to its
  digest (pushed to the registry beside the image).
- **BuildKit attestations** on the image index: an SPDX SBOM and SLSA
  provenance of the image build itself (`sbom: true`, `provenance: mode=max`).

### What an SBOM covers

- **Archives:** the Go modules linked into that platform's binary (read from
  the binary's build information, so versions and `h1:` sums are the ones
  that were linked) and the admin console's production npm dependencies.
  The console is compiled into the binary (`console/dist`, `go:embed`); its
  lockfile (`console/package-lock.json`, or `bun.lock` once the console
  moves to Bun) is cataloged without development-only tools such as Vite,
  ESLint or Vitest.
- **Image:** the Wolfi `apk` packages of the Chainguard base (Node.js, npm,
  busybox, glibc, OpenSSL, CA bundle) and the Go modules of the binary. The
  console's npm packages are not visible inside the image; the archive SBOM
  for the same version lists them.
- Each document names its artefact (`metadata.component` in CycloneDX, the
  document `name` in SPDX) and the version. The tool and its version are in
  `metadata.tools`.

## Verify a download

```sh
V=1.2.3
gh release download "v$V" --repo occupysaas/zeroauthy
sha256sum -c SHA256SUMS                       # archives
sha256sum -c SBOM_SHA256SUMS                  # SBOM files

# Provenance: the file was built by the release workflow of this repository.
gh attestation verify "zeroauthy_${V}_linux_amd64.tar.gz" --repo occupysaas/zeroauthy
gh attestation verify "zeroauthy_${V}_linux_amd64.cdx.json" --repo occupysaas/zeroauthy

# The SBOM attestation of an archive (the predicate is the CycloneDX document).
gh attestation verify "zeroauthy_${V}_linux_amd64.tar.gz" --repo occupysaas/zeroauthy \
  --predicate-type https://cyclonedx.org/bom --format json | jq '.[0].verificationResult.statement.predicate.metadata'
```

`gh attestation verify` checks the Sigstore signature, that the signing
identity is a workflow of `occupysaas/zeroauthy`, and that the subject
digest matches the file. Add `--signer-workflow occupysaas/zeroauthy/.github/workflows/release.yml`
to also require the release workflow specifically.

## Verify the image

```sh
IMG=ghcr.io/occupysaas/zeroauthy:1.2.3

# Build provenance attestation (GitHub) by tag or digest.
gh attestation verify "oci://$IMG" --repo occupysaas/zeroauthy
# The image SBOM attestation.
gh attestation verify "oci://$IMG" --repo occupysaas/zeroauthy --predicate-type https://cyclonedx.org/bom

# BuildKit's own SBOM and provenance, stored on the image index.
docker buildx imagetools inspect "$IMG" --format '{{json .SBOM}}'
docker buildx imagetools inspect "$IMG" --format '{{json .Provenance}}'
```

**cosign.** GitHub's attestations are Sigstore bundles, so cosign can verify
them too; this form was not exercised by the Plan 49 acceptance run and is
given as a starting point:

```sh
cosign verify-attestation "$IMG" --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/occupysaas/zeroauthy/\.github/workflows/release\.yml@'
```

zeroauthy does not add a separate cosign signature; a keyless `cosign sign`
of the image is a recorded follow-up (Plan 49 §9).

## Use the SBOM in your own scanner

```sh
grype sbom:zeroauthy_${V}_linux_amd64.cdx.json          # https://github.com/anchore/grype
osv-scanner --sbom zeroauthy_${V}_linux_amd64.cdx.json   # https://google.github.io/osv-scanner/
trivy sbom zeroauthy_${V}_linux_amd64.cdx.json           # https://trivy.dev/

# Dependency-Track: upload the CycloneDX document to a project.
curl -X POST "https://dtrack.example.com/api/v1/bom" \
  -H "X-Api-Key: $DT_API_KEY" \
  -F "projectName=zeroauthy" -F "projectVersion=$V" -F "autoCreate=true" \
  -F "bom=@zeroauthy_${V}_linux_amd64.cdx.json"
```

Scan the archive SBOM for the platform you run and the image SBOM if you
run the container; between them they cover everything that ships.

## Policy: what blocks a release

- **Go:** `govulncheck ./...` (`golang/govulncheck-action`) runs in the `ci`
  workflow, which the release runs as its first gate. Any finding reachable
  from zeroauthy's code fails the gate.
- **SBOM scan:** grype runs over every release SBOM (the three archives and
  a locally built image) before the maintainer can approve the release, and
  again over the pushed image before the release is created. A finding of
  severity **high or critical** fails the gate, whether or not a fix exists.
  Medium and lower are reported in the job log and do not block. The
  policy file is [`.grype.yaml`](../.grype.yaml) (`fail-on-severity: high`).
- **Accepting a finding** is a reviewed change to the repository, never a
  flag on the command line:
  - an `ignore` rule in `.grype.yaml` for a scanner false positive, naming
    the vulnerability and package with a comment giving the reason and the
    date;
  - an [OpenVEX](https://github.com/openvex/spec) statement in
    `openvex.json` at the repository root when zeroauthy does not reach the
    vulnerable code (`status: not_affected` with a `justification`) or the
    fix is in (`status: fixed`). The file does not exist until the first
    statement is needed; create it with
    [`vexctl`](https://github.com/openvex/vexctl):

    ```sh
    vexctl create --product "pkg:golang/github.com/zeroauthy/zeroauthy" \
      --vuln GHSA-xxxx-xxxx-xxxx --subcomponents "pkg:golang/example.com/module@v1.2.3" \
      --status not_affected --justification vulnerable_code_not_in_execute_path \
      --impact-statement "zeroauthy never calls the affected parser" > openvex.json
    ```

    `scripts/scan-sbom.sh` passes the file to grype (`--vex`), which drops
    matches the document marks `not_affected` or `fixed`.
- Found a vulnerability in zeroauthy or in a dependency it exposes? See the
  [security policy](../SECURITY.md).

## Reproduce the SBOMs locally

```sh
make sbom          # builds dist/zeroauthy_<version>_*.tar.gz if missing, then dist/sbom/
make sbom-check    # the contract check CI runs (internal/sbomcheck, strict)
make sbom-scan     # grype with .grype.yaml (and openvex.json when present)
```

`VERSION` defaults to `0.0.0-dev.<commit>`; `make sbom VERSION=1.2.3` on
the tagged commit reproduces a release's SBOMs (the `serialNumber`,
timestamps and tool version differ; the package lists do not). The scripts
are the ones CI runs: [`scripts/sbom.sh`](../scripts/sbom.sh),
[`scripts/check-sbom.sh`](../scripts/check-sbom.sh),
[`scripts/scan-sbom.sh`](../scripts/scan-sbom.sh). They need
[syft](https://github.com/anchore/syft) (1.46.0 or later when the console
uses `bun.lock`) and [grype](https://github.com/anchore/grype) on `PATH`
(or `SYFT=`/`GRYPE=`). Without syft, `scripts/sbom.sh` falls back to a
pinned `cyclonedx-gomod` (installed into a temporary `GOBIN`; `go.mod` is
never touched): CycloneDX only, Go modules only, no console coverage, and
it needs a normal clone rather than a `git worktree`. The strict check then
fails on purpose.

`scripts/sbom.sh` also writes `<name>.syft.json` beside each SBOM: syft's
own format with the Go function symbols of the binary. It is not published;
`scripts/scan-sbom.sh` scans it instead of the CycloneDX file when present,
so grype can tell whether a vulnerable Go function is linked at all.

## What is pinned and how to bump it

Chainguard's free tier publishes only `latest`, so every `cgr.dev` reference
is pinned by digest, with the tag, the image's creation date and what it
ships in a comment beside it. Read on 2026-11-05:

| Where | Image | Digest (`latest`, created) | Ships |
| --- | --- | --- | --- |
| `Dockerfile` build stage | `cgr.dev/chainguard/go` | `sha256:575572885e29c3c3bac6622d8db116e983436c546cb2987b001747ce6c278891` (2026-11-02) | Go 1.27.3, bash, git, glibc; the build forces the `go.mod` toolchain |
| `Dockerfile` runtime stage | `cgr.dev/chainguard/node` | `sha256:4ad7301975908b87d321af8b9ed41630dc69015976269965ee459c27541df252` (2026-11-02) | Node.js 26.13.0, npm 12.2.1, busybox, dumb-init, CA bundle; user `node` 65532 |
| `.github/workflows/ci.yml`, `scripts/test-sql.sh` | `cgr.dev/chainguard/postgres` | `sha256:c976eb2e1f7702a9ec38acb3f44c3976b449db7f10181f20b74c53b212a0e202` (2026-11-02) | PostgreSQL 18.6, client and contrib, bash |
| `examples/testing/compose.yaml` | `cgr.dev/chainguard/node` | as the runtime stage | the smoke-test runner |

MySQL stays on `mysql:8.4` from Docker Hub: `cgr.dev/chainguard/mysql` was
not pullable anonymously on 2026-11-05, and MariaDB is not a substitute for
the MySQL 8.0.17+ collations the driver needs.

The build stage sets `GOTOOLCHAIN` to the `go` line of `go.mod`, so the
image binary is built with the same Go as the release archives
(`actions/setup-go` with `go-version-file: go.mod`) whatever Go the base
ships; the toolchain download is verified by the Go checksum database.

**To bump a base image:**

1. Read the new index digest and creation date without a Docker daemon:

   ```sh
   img=chainguard/node
   tok=$(curl -s "https://cgr.dev/token?scope=repository:$img:pull" | jq -r .token)
   curl -sI -H "Authorization: Bearer $tok" \
     -H "Accept: application/vnd.oci.image.index.v1+json" \
     "https://cgr.dev/v2/$img/manifests/latest" | grep -i docker-content-digest
   ```

   (`crane digest cgr.dev/$img:latest` does the same.) The image's SBOM
   attestation, `sha256-<platform manifest digest>.att`, lists the package
   versions; `cosign download sbom cgr.dev/$img@sha256:<digest>` fetches it.
2. Replace the digest and update the comment (tag, date, versions) in every
   file in the table; the digests in this page and in the files must stay
   equal.
3. `docker build --build-arg VERSION=dev -t zeroauthy .` and
   `docker run --rm zeroauthy version`; `make sbom sbom-check sbom-scan`
   for the archive SBOMs; a release dry run (push `main` to `release`
   untagged) for the image gate.
4. Commit with the old and new Node, Go or PostgreSQL versions in the
   message.

Tool versions: the CI jobs install syft and grype through
`anchore/sbom-action/download-syft@v0` and `anchore/scan-action/download-grype@v7`
(the versions those majors bundle); attestations use
`actions/attest-build-provenance@v2` and `actions/attest-sbom@v2`; the Go
fallback is `cyclonedx-gomod` v1.12.0 (`scripts/sbom.sh`). The CycloneDX
schemas used by the contract check are vendored in
`internal/sbomcheck/schema/` (see `NOTICE`).

### Base-image SBOMs

Chainguard publishes an SPDX SBOM and SLSA provenance for every image as
cosign attestations on the registry. zeroauthy's image SBOM lists the base's
packages by cataloging the image; for how those packages were built, the
base's own SBOM is the authority:

```sh
cosign download sbom cgr.dev/chainguard/node@sha256:4ad7301975908b87d321af8b9ed41630dc69015976269965ee459c27541df252
cosign verify-attestation --type spdxjson \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main \
  cgr.dev/chainguard/node@sha256:4ad7301975908b87d321af8b9ed41630dc69015976269965ee459c27541df252
```

(The identity is the one Chainguard documents for its public images; check
their [verification page](https://edu.chainguard.dev/chainguard/chainguard-images/how-to-use/retrieve-image-sboms/)
if it changes.)
