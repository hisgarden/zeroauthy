# Security policy

zeroauthy is an identity server, so we take vulnerability reports seriously
and are grateful for them.

## Supported versions

zeroauthy 1.0 is an early preview. Security fixes are released for the
latest 1.0 preview release (`1.0.0-rc.N` and, once published, `1.0.x`).
Older prereleases and builds from `main` are not patched separately: upgrade
to the latest release ([upgrading](docs/upgrading.md)).

| Version | Supported |
|---|---|
| Latest 1.0 preview release | Yes |
| Earlier prereleases, unreleased `main` | No |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a
security problem.**

Report it privately through GitHub's private vulnerability reporting:
open <https://github.com/occupysaas/zeroauthy/security/advisories/new>
(the **Security** tab of the repository, then **Report a vulnerability**).

If you cannot use GitHub, email **security@occupysaas.com** instead.

Please include:

- the zeroauthy version or commit, storage driver and relevant configuration
  (with secrets removed);
- the steps to reproduce, and what an attacker gains;
- whether you believe it is being exploited.

Never include real users' data, live tokens or the master key.

## What to expect

- We aim to acknowledge your report within 3 working days.
- We aim to send an initial assessment (confirmed or not, and a severity) within
  10 working days.
- We aim to release a fix for critical and high-severity issues within
  30 days of confirmation, and keep you informed until then.
- We publish a GitHub security advisory with the fix and credit you, unless
  you prefer otherwise. Please keep the issue confidential until the advisory
  is published.

This is a volunteer-maintained preview, so these are targets, not contractual
guarantees.

## Scope

In scope:

- the zeroauthy server (`cmd/zeroauthy`, `internal/...`): the Authentication
  and Management APIs, hosted login, token issuance, tenant isolation, secret
  storage and the Actions and custom-database runners;
- the admin console served at `/admin/`;
- the storage plugin protocol and `pkg/` libraries;
- the release artefacts: binaries, the container image and their build
  pipeline.

Out of scope:

- vulnerabilities in third-party dependencies that zeroauthy does not expose
  (report them upstream; tell us if zeroauthy is affected);
- issues that need a malicious operator or someone who already holds the
  master key or database access;
- deployments that ignore the documented requirements (for example trusting
  proxy headers from every peer, or running untrusted tenants' Actions without
  the isolation in [Actions](docs/actions.md) and
  [custom databases](docs/custom-db.md));
- features listed as stored only or not supported on the
  [compatibility page](docs/compatibility.md);
- denial of service by sheer traffic volume.

Behaviour that differs from Auth0's documentation but is not a security
problem is a normal bug: please open a public issue.

## Supply chain

Every release publishes, beside the archives and the container image, a
CycloneDX 1.6 and an SPDX 2.3 SBOM per artefact, GitHub artifact
attestations (build provenance for every file and the image, and an SBOM
attestation per artefact), and checksums. Before a release can be approved,
`govulncheck` and a grype scan of every SBOM must pass: a finding of
severity high or critical blocks the release unless it is accepted by a
reviewed `ignore` rule in `.grype.yaml` or an OpenVEX statement in
`openvex.json`, each with its reason. The container image is built on
Chainguard base images pinned by digest.

How to verify a download or the image, how to feed the SBOMs to your own
scanner, and the full policy are in [docs/supply-chain.md](docs/supply-chain.md).
A vulnerability in a dependency that zeroauthy exposes is in scope: report
it as above and name the package and advisory.
