#!/bin/sh
set -eu
destination="${1:-./backups}"
mkdir -p "$destination"
destination="$(cd "$destination" && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="trusttunnel-$stamp.tar.gz"
docker compose run --rm --no-deps \
  --volume "$destination:/backups" \
  trusttunnel --backup "/backups/$archive"
docker compose run --rm --no-deps \
  --volume "$destination:/backups:ro" \
  trusttunnel --verify-backup "/backups/$archive"
chmod 600 "$destination/$archive"
printf '%s\n' "$destination/$archive"
