#!/bin/sh
set -eu

ref="${1:?usage: verify-release.sh image@sha256:digest}"
case "$ref" in *@sha256:*) ;; *) echo "an immutable image digest is required" >&2; exit 2;; esac

command -v cosign >/dev/null
repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required for signature identity verification}"
identity="^https://github.com/${repository}/.github/workflows/release.yml@refs/(heads/master|tags/v[0-9]+\\.[0-9]+\\.[0-9]+)$"
cosign verify \
  --certificate-identity-regexp "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$ref" >/dev/null

platform=linux/amd64
image="$(docker buildx imagetools inspect "$ref" --format '{{json .Image}}')"
sbom="$(docker buildx imagetools inspect "$ref" --format '{{json .SBOM.SPDX}}')"
provenance="$(docker buildx imagetools inspect "$ref" --format '{{json .Provenance.SLSA}}')"
printf '%s' "$image" | grep -F 'io.trusttunnel.controller.version' >/dev/null
printf '%s' "$image" | grep -F 'io.trusttunnel.endpoint.version' >/dev/null
printf '%s' "$image" | grep -F 'io.trusttunnel.endpoint.sha256.amd64' >/dev/null
printf '%s' "$image" | grep -F 'org.opencontainers.image.revision' >/dev/null
printf '%s' "$sbom" | grep -F 'SPDXRef-DOCUMENT' >/dev/null
printf '%s' "$provenance" | grep -F 'github.com/moby/buildkit' >/dev/null
docker run --rm --platform "$platform" "$ref" --version
