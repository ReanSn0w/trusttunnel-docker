#!/bin/sh
set -eu

image="ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
container="trusttunnel-pebble-$$"
workspace="$(mktemp -d)"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$workspace"
}
trap cleanup EXIT INT TERM

docker run --detach --name "$container" \
  --publish 127.0.0.1:14000:14000 \
  --env PEBBLE_VA_ALWAYS_VALID=1 \
  "$image" >/dev/null
docker cp "$container:/test/certs/pebble.minica.pem" "$workspace/pebble.minica.pem"

attempt=0
until curl --insecure --fail --silent --show-error https://localhost:14000/dir >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    docker logs "$container"
    exit 1
  fi
  sleep 1
done

PEBBLE_DIRECTORY=https://localhost:14000/dir \
LEGO_CA_CERTIFICATES="$workspace/pebble.minica.pem" \
GOCACHE=/tmp/trusttunnel-go-build \
GOMODCACHE=/tmp/trusttunnel-go-mod \
go test -tags=integration ./internal/certificate -run TestPebbleIssueAndRenew -count=1
