# Release contract

The production image is `ghcr.io/reansn0w/trusttunnel-controller` and is
published as one OCI manifest containing `linux/amd64` and `linux/arm64`.

Release tags are immutable:

- `vMAJOR.MINOR.PATCH` identifies the controller release;
- `sha-<12 lowercase commit characters>` identifies the exact source commit.

Published tags are never moved or overwritten. Production Compose examples pin
the manifest digest (`image@sha256:...`); `latest` is neither published by the
release workflow nor accepted in production documentation.

Every platform image carries OCI source, version and revision labels plus these
TrustTunnel-specific labels:

- `io.trusttunnel.endpoint.version`;
- `io.trusttunnel.endpoint.sha256` (the official archive for that platform);
- `io.trusttunnel.controller.version`.

The release manifest, SBOM, provenance and signature must all refer to the same
manifest digest. A release is invalid if the embedded controller version,
commit, endpoint version or per-architecture archive digest differs from the
release manifest metadata.
