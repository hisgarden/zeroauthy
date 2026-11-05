#!/usr/bin/env bash
# scripts/check-sbom.sh [--strict] [DIR]: check the SBOMs in DIR (default
# dist/sbom) against the release contract (internal/sbomcheck): every
# *.cdx.json validates against the CycloneDX 1.6 schema and every
# *.spdx.json carries the SPDX 2.3 fields. With --strict (CI), each artefact
# must have both formats, archive SBOMs must list Go modules and the
# console's production npm packages, and the image SBOM must list Go
# modules and OS packages. See docs/supply-chain.md.
set -euo pipefail
cd "$(dirname "$0")/.."

strict=0
if [ "${1:-}" = "--strict" ]; then strict=1; shift; fi
dir="${1:-dist/sbom}"
[ -d "$dir" ] || { echo "check-sbom.sh: $dir does not exist (run make sbom first)" >&2; exit 1; }

ZA_SBOM_DIR="$(cd "$dir" && pwd)" ZA_SBOM_STRICT="$strict" \
  go test -count=1 -run '^TestGeneratedSBOMs$' -v ./internal/sbomcheck
