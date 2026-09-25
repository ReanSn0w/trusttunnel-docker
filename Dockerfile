# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS controller-build
ARG TARGETOS TARGETARCH
ARG CONTROLLER_VERSION=dev
ARG VCS_REF=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X main.version=$CONTROLLER_VERSION -X main.commit=$VCS_REF" \
    -o /out/trusttunnel-controller ./cmd/trusttunnel-controller
RUN install -d -m 0700 -o 65532 -g 65532 /out/data

FROM --platform=$TARGETPLATFORM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS test
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go test ./...

FROM --platform=$TARGETPLATFORM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS endpoint-fetch
ARG TARGETARCH
ARG TT_VERSION=1.1.0
ARG TT_SHA256_AMD64=91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7
ARG TT_SHA256_ARM64=c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
         amd64) TT_ARCH=x86_64; TT_SHA256="$TT_SHA256_AMD64" ;; \
         arm64) TT_ARCH=aarch64; TT_SHA256="$TT_SHA256_ARM64" ;; \
         *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && FILE="trusttunnel-v${TT_VERSION}-linux-${TT_ARCH}.tar.gz" \
    && curl -fsSL --retry 3 "https://github.com/TrustTunnel/TrustTunnel/releases/download/v${TT_VERSION}/${FILE}" -o /tmp/endpoint.tar.gz \
    && echo "${TT_SHA256}  /tmp/endpoint.tar.gz" | sha256sum -c - \
    && mkdir /tmp/endpoint \
    && tar -xzf /tmp/endpoint.tar.gz -C /tmp/endpoint \
    && find /tmp/endpoint -type f -name trusttunnel_endpoint -exec cp {} /trusttunnel_endpoint \; \
    && chmod 0755 /trusttunnel_endpoint \
    && test -x /trusttunnel_endpoint

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG CONTROLLER_VERSION=dev
ARG VCS_REF=unknown
ARG TT_VERSION=1.1.0
ARG TT_SHA256_AMD64=91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7
ARG TT_SHA256_ARM64=c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686
LABEL org.opencontainers.image.title="TrustTunnel Controller" \
      org.opencontainers.image.version="$CONTROLLER_VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.source="https://github.com/ReanSn0w/trusttunnel-docker" \
      io.trusttunnel.controller.version="$CONTROLLER_VERSION" \
      io.trusttunnel.endpoint.version="$TT_VERSION" \
      io.trusttunnel.endpoint.sha256.amd64="$TT_SHA256_AMD64" \
      io.trusttunnel.endpoint.sha256.arm64="$TT_SHA256_ARM64"
COPY --from=controller-build --chown=65532:65532 /out/trusttunnel-controller /usr/local/bin/trusttunnel-controller
COPY --from=controller-build --chown=65532:65532 /out/data /var/lib/trusttunnel
COPY --from=endpoint-fetch --chown=65532:65532 /trusttunnel_endpoint /usr/local/bin/trusttunnel_endpoint
COPY --chown=65532:65532 LICENSES /licenses
USER 65532:65532
VOLUME ["/var/lib/trusttunnel"]
EXPOSE 8444/tcp 8081/tcp 8443/tcp 8443/udp 80/tcp
ENTRYPOINT ["/usr/local/bin/trusttunnel-controller"]
