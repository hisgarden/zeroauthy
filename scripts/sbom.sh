#!/usr/bin/env bash
# scripts/sbom.sh VERSION [DISTDIR]
# scripts/sbom.sh image REF VERSION [DISTDIR]
#
# Software bills of materials for a release (Plan 49, docs/supply-chain.md).
#
# The first form takes the archives scripts/dist.sh built in DISTDIR
# (default dist) and writes, into DISTDIR/sbom, for each
# zeroauthy_<version>_<os>_<arch>.tar.gz:
#   <name>.cdx.json   CycloneDX 1.6
#   <name>.spdx.json  SPDX 2.3
#   <name>.syft.json  syft's own format with Go function symbols; only an
#                     input for scripts/scan-sbom.sh, never published
# plus SBOM_SHA256SUMS over the published files. Each SBOM is one syft scan
# of a staging directory holding the binary extracted from the archive (the
# Go modules actually linked for that platform, from the binary's build
# information) and console/package.json with the console's lockfile (the
# admin console's production npm dependencies, embedded in the binary).
#
# The second form scans a container image (REF as syft spells it:
# registry:ghcr.io/owner/zeroauthy@sha256:..., docker:zeroauthy:tag) into
# DISTDIR/sbom/zeroauthy_<version>_image.{cdx,spdx}.json.
#
# syft is taken from $SYFT or PATH. Without syft, the archive form falls
# back to a pinned cyclonedx-gomod installed into a temporary GOBIN (never
# touching go.mod):
# CycloneDX only, Go modules only, and it needs a normal clone (it reads the
# module version from git; a `git worktree` is not enough). The strict
# contract check (scripts/check-sbom.sh --strict) then fails on purpose.
set -euo pipefail
cd "$(dirname "$0")/.."

cyclonedx_gomod="github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0"
min_syft_for_bun="1.46.0"

work=""
usage() { echo "usage: scripts/sbom.sh VERSION [DISTDIR] | scripts/sbom.sh image REF VERSION [DISTDIR]" >&2; exit 2; }

find_syft() {
  if [ -n "${SYFT:-}" ]; then
    [ -x "$SYFT" ] && { echo "$SYFT"; return 0; }
    return 1
  fi
  command -v syft 2>/dev/null || return 1
}

# syft_version PATH: the version number, for example 1.56.0.
syft_version() { "$1" version 2>/dev/null | awk '/^Version:/ {print $2; exit}'; }

# version_ge A B: true when semver A >= B.
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# console_manifest DIR: copy console/package.json and every lockfile into DIR.
# Returns the lockfiles found, one per line.
console_manifest() {
  mkdir -p "$1"
  cp console/package.json "$1/"
  local found=()
  for lock in package-lock.json bun.lock yarn.lock pnpm-lock.yaml; do
    if [ -f "console/$lock" ]; then cp "console/$lock" "$1/"; found+=("$lock"); fi
  done
  printf '%s\n' "${found[@]:-}"
}

sums() { # DIR: write SBOM_SHA256SUMS over the published SBOM files
  (
    cd "$1"
    files=()
    for f in *.cdx.json *.spdx.json; do [ -e "$f" ] && files+=("$f"); done
    sha256sum "${files[@]}" > SBOM_SHA256SUMS
  )
  cat "$1/SBOM_SHA256SUMS"
}

scan_archives() {
  local version="${1#v}" out="$2/sbom"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "sbom.sh: version must be semver (got $version)" >&2; exit 1; }
  local archives=("$2"/zeroauthy_"${version}"_*.tar.gz)
  [ -e "${archives[0]}" ] || { echo "sbom.sh: no $2/zeroauthy_${version}_*.tar.gz (run scripts/dist.sh $version $2 first)" >&2; exit 1; }
  mkdir -p "$out"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  local syft
  if syft="$(find_syft)"; then
    local sv; sv="$(syft_version "$syft")"
    echo "sbom.sh: syft $sv ($syft)"
    local locks; locks="$(console_manifest "$work/console")"
    [ -n "$locks" ] || { echo "sbom.sh: console/ has no lockfile; the console dependency tree would be missing" >&2; exit 1; }
    if ! grep -q -E '^(package-lock.json|yarn.lock|pnpm-lock.yaml)$' <<<"$locks" && ! version_ge "$sv" "$min_syft_for_bun"; then
      echo "sbom.sh: console/bun.lock needs syft >= $min_syft_for_bun (have $sv); refusing to write an SBOM without the console" >&2; exit 1
    fi
    for archive in "${archives[@]}"; do
      local name; name="$(basename "$archive" .tar.gz)"
      local stage="$work/$name"
      mkdir -p "$stage"
      tar -xzf "$archive" -C "$stage" --strip-components=1 "$name/zeroauthy"
      cp -r "$work/console" "$stage/console"
      echo "sbom.sh: $name"
      SYFT_GOLANG_CAPTURE_SYMBOLS="${SYFT_GOLANG_CAPTURE_SYMBOLS:-all}" "$syft" scan "dir:$stage" \
        --source-name "$name" --source-version "$version" -q \
        -o "cyclonedx-json@1.6=$out/$name.cdx.json" \
        -o "spdx-json@2.3=$out/$name.spdx.json" \
        -o "syft-json=$out/$name.syft.json"
    done
  else
    echo "sbom.sh: syft not found; falling back to $cyclonedx_gomod (Go modules only, CycloneDX only, no SPDX, no console dependencies)" >&2
    # Built for the host into a throwaway GOBIN (go.mod is not touched), then
    # run with GOOS/GOARCH set so it resolves each platform's module graph.
    GOBIN="$work/bin" go install "$cyclonedx_gomod"
    for archive in "${archives[@]}"; do
      local name; name="$(basename "$archive" .tar.gz)"
      local plat="${name#zeroauthy_${version}_}" os arch
      os="${plat%_*}" arch="${plat#*_}"
      echo "sbom.sh: $name ($os/$arch)"
      GOOS="$os" GOARCH="$arch" "$work/bin/cyclonedx-gomod" app -json -main cmd/zeroauthy -output "$out/$name.cdx.json" . \
        || { echo "sbom.sh: cyclonedx-gomod failed; it reads the module version from git and does not work in a git worktree. Install syft instead." >&2; exit 1; }
      rm -f "$out/$name.spdx.json" "$out/$name.syft.json"
    done
    echo "sbom.sh: install syft (https://github.com/anchore/syft) for SPDX output and console coverage; scripts/check-sbom.sh --strict will fail on this output" >&2
  fi
  sums "$out"
}

scan_image() {
  local ref="$1" version="${2#v}" out="$3/sbom"
  local syft
  syft="$(find_syft)" || { echo "sbom.sh: syft is required to scan an image" >&2; exit 1; }
  mkdir -p "$out"
  local name="zeroauthy_${version}_image"
  echo "sbom.sh: $name from $ref (syft $(syft_version "$syft"))"
  SYFT_GOLANG_CAPTURE_SYMBOLS="${SYFT_GOLANG_CAPTURE_SYMBOLS:-all}" "$syft" scan "$ref" \
    --source-name "$name" --source-version "$version" -q \
    -o "cyclonedx-json@1.6=$out/$name.cdx.json" \
    -o "spdx-json@2.3=$out/$name.spdx.json" \
    -o "syft-json=$out/$name.syft.json"
  sums "$out"
}

case "${1:-}" in
  "" | -h | --help) usage ;;
  image) [ $# -ge 3 ] || usage; scan_image "$2" "$3" "${4:-dist}" ;;
  *) scan_archives "$1" "${2:-dist}" ;;
esac
