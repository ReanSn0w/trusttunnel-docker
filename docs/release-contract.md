# Release contract

The production image is `ghcr.io/reansn0w/trusttunnel-controller` and is
published for `linux/amd64`.

This is a **server image** release. It does not ship a mobile TrustTunnel app.
The inspected Flutter client drops `antiDpi` during deeplink import, so a
profile exported by the controller does not activate Anti-DPI in that build.
The official native CLI v1.1.7 accepts the transport, Anti-DPI and
post-quantum settings, but lacks `tls_profile`; that field needs a compatible
source build. See [connection profiles](connection-dpi.md) for the inspected
commits, tested exports, local connection results and remaining mobile limits.

Release tags are immutable:

- `master` identifies the latest successful build of the default branch;
- `vMAJOR.MINOR.PATCH` identifies a controller release.

Published tags are never moved or overwritten. Production Compose examples pin
the image digest (`image@sha256:...`); `latest` is neither published by the
release workflow nor accepted in production documentation.

Every platform image carries OCI source, version and revision labels plus these
TrustTunnel-specific labels:

- `io.trusttunnel.endpoint.version`;
- `io.trusttunnel.endpoint.sha256` (the official archive for that platform);
- `io.trusttunnel.controller.version`.

The workflow runs the Dockerfile test stage and a blocking HIGH/CRITICAL image
scan before publishing. The amd64 image is published with SBOM and provenance,
then its immutable digest is signed and verified. A release is invalid if the
embedded controller version, commit, endpoint version or amd64 archive digest
differs from its source revision.
