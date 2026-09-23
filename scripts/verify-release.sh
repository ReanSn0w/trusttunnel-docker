#!/bin/sh
set -eu
ref="${1:?usage: verify-release.sh image@sha256:digest}"
case "$ref" in *@sha256:*) ;; *) echo "an immutable manifest digest is required" >&2; exit 2;; esac
command -v cosign >/dev/null
repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required for signature identity verification}"
identity="^https://github.com/${repository}/.github/workflows/release.yml@refs/tags/"
cosign verify \
  --certificate-identity-regexp "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$ref" >/dev/null
for platform in linux/amd64 linux/arm64; do
  image="$(docker buildx imagetools inspect "$ref" --format "{{json (index .Image \"$platform\")}}")"
  sbom="$(docker buildx imagetools inspect "$ref" --format "{{json (index .SBOM \"$platform\").SPDX}}")"
  provenance="$(docker buildx imagetools inspect "$ref" --format "{{json (index .Provenance \"$platform\").SLSA}}")"
  printf '%s' "$image" | grep -q 'io.trusttunnel.controller.version'
  printf '%s' "$image" | grep -q 'io.trusttunnel.endpoint.version'
  printf '%s' "$image" | grep -q 'io.trusttunnel.endpoint.sha256'
  printf '%s' "$image" | grep -q 'org.opencontainers.image.revision'
  printf '%s' "$sbom" | grep -q 'SPDXRef-DOCUMENT'
  printf '%s' "$provenance" | grep -q 'mobyproject.org/buildkit'
  docker run --rm --platform "$platform" "$ref" --version
done
