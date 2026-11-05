#!/usr/bin/env bash
# scripts/scan-sbom.sh [DIR...]: the vulnerability gate (Plan 49,
# docs/supply-chain.md). Runs grype over every SBOM scripts/sbom.sh wrote
# in each DIR (default dist/sbom), with the repository policy in
# .grype.yaml (fail on high and critical; accepted findings are `ignore`
# rules there) and, when openvex.json exists, its OpenVEX statements. For
# an artefact that has <name>.syft.json (syft's format with Go function
# symbols) that file is scanned instead of <name>.cdx.json, so grype can
# tell whether a vulnerable Go function is linked at all; the published
# CycloneDX document lists the same packages.
#
# grype is taken from $GRYPE or PATH. Exit status is grype's: 0 clean,
# 1 on an error, 2 when findings at or above the cutoff remain.
set -euo pipefail
cd "$(dirname "$0")/.."

grype="${GRYPE:-$(command -v grype || true)}"
[ -n "$grype" ] && [ -x "$grype" ] || { echo "scan-sbom.sh: grype not found (https://github.com/anchore/grype); set GRYPE or add it to PATH" >&2; exit 1; }
[ -f .grype.yaml ] || { echo "scan-sbom.sh: .grype.yaml is missing" >&2; exit 1; }

args=(-c .grype.yaml)
if [ -f openvex.json ]; then args+=(--vex openvex.json); echo "scan-sbom.sh: applying openvex.json"; fi

dirs=("${@:-dist/sbom}")
status=0
scanned=0
for dir in "${dirs[@]}"; do
  [ -d "$dir" ] || { echo "scan-sbom.sh: $dir does not exist (run make sbom first)" >&2; exit 1; }
  for cdx in "$dir"/*.cdx.json; do
    [ -e "$cdx" ] || continue
    name="$(basename "$cdx" .cdx.json)"
    input="$cdx"
    [ -f "$dir/$name.syft.json" ] && input="$dir/$name.syft.json"
    echo "scan-sbom.sh: $name ($(basename "$input"))"
    scanned=$((scanned + 1))
    "$grype" "${args[@]}" "sbom:$input" -o table || { rc=$?; [ "$rc" -gt "$status" ] && status=$rc; }
  done
done
[ "$scanned" -gt 0 ] || { echo "scan-sbom.sh: nothing to scan in ${dirs[*]}" >&2; exit 1; }
[ "$status" -eq 0 ] && echo "scan-sbom.sh: no unaccepted findings at or above the cutoff in $scanned SBOM(s)"
exit "$status"
