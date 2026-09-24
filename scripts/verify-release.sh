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
  # Do not use grep -q here. These JSON documents can be large; grep -q exits
  # after the first match and leaves printf writing to a closed pipe (EPIPE).
  printf '%s' "$image" | grep -F 'io.trusttunnel.controller.version' >/dev/null
  printf '%s' "$image" | grep -F 'io.trusttunnel.endpoint.version' >/dev/null
  printf '%s' "$image" | grep -F 'io.trusttunnel.endpoint.sha256' >/dev/null
  printf '%s' "$image" | grep -F 'org.opencontainers.image.revision' >/dev/null
  printf '%s' "$sbom" | grep -F 'SPDXRef-DOCUMENT' >/dev/null
  printf '%s' "$provenance" | grep -F 'mobyproject.org/buildkit' >/dev/null
  docker run --rm --platform "$platform" "$ref" --version
done
