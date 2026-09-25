#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
run_id="tt-smoke-$$"
work="$(mktemp -d)"
legacy="$work/legacy"
mkdir -p "$legacy/certs" "$work/backups"
volumes=""
containers=""

cleanup() {
  for container in $containers; do docker rm -f "$container" >/dev/null 2>&1 || true; done
  for volume in $volumes; do docker volume rm "$volume" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$legacy/certs/key.pem" -out "$legacy/certs/cert.pem" -days 2 \
  -subj '/CN=vpn.example.net' -addext 'subjectAltName=DNS:vpn.example.net' >/dev/null 2>&1
cat >"$legacy/vpn.toml" <<'EOF'
listen_address = "0.0.0.0:8443"
EOF
cat >"$legacy/hosts.toml" <<'EOF'
[[main_hosts]]
hostname = "vpn.example.net"
cert_chain_path = "certs/cert.pem"
private_key_path = "certs/key.pem"
EOF
cat >"$legacy/credentials.toml" <<'EOF'
[[client]]
username = "alice"
password = "Client-Secret-9!"
EOF
chmod -R a+rX "$legacy"

wait_exec() {
  container="$1"
  command="$2"
  attempt=0
  until docker exec "$container" /usr/local/bin/trusttunnel-controller "$command" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then docker logs "$container"; return 1; fi
    sleep 1
  done
}

ui_login_and_export() {
  ui_port="$1"
  bootstrap="${2:-yes}"
  ui_url="https://vpn.example.net:$ui_port"
  headers="$work/headers"
  body="$work/body"
  seed=""
  if [ "$bootstrap" = yes ]; then
    curl_ui -D "$headers" "$ui_url/bootstrap" -o "$body"
    seed="$(sed -n 's/^Set-Cookie: __Host-tt_csrf_seed=\([^;]*\).*/\1/p' "$headers" | tr -d '\r' | tail -1)"
    csrf="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$body" | tail -1)"
    curl_ui -o /dev/null -H "Cookie: __Host-tt_csrf_seed=$seed" \
      --data-urlencode "_csrf=$csrf" --data-urlencode 'username=admin' \
      --data-urlencode 'password=Admin-Smoke-9!' "$ui_url/bootstrap"
  fi
  curl_ui -D "$headers" -H "Cookie: __Host-tt_csrf_seed=$seed" "$ui_url/login" -o "$body"
  if [ -z "$seed" ]; then seed="$(sed -n 's/^Set-Cookie: __Host-tt_csrf_seed=\([^;]*\).*/\1/p' "$headers" | tr -d '\r' | tail -1)"; fi
  csrf="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$body" | tail -1)"
  curl_ui -D "$headers" -o /dev/null -H "Cookie: __Host-tt_csrf_seed=$seed" \
    --data-urlencode "_csrf=$csrf" --data-urlencode 'username=admin' \
    --data-urlencode 'password=Admin-Smoke-9!' "$ui_url/login"
  session="$(sed -n 's/^Set-Cookie: __Host-tt_session=\([^;]*\).*/\1/p' "$headers" | tr -d '\r' | tail -1)"
  curl_ui -H "Cookie: __Host-tt_session=$session" "$ui_url/" -o "$body"
  grep -q 'ready' "$body"
  csrf="$(sed -n 's/.*name="csrf-token" content="\([^"]*\)".*/\1/p' "$body" | tail -1)"
  if ! curl_ui -H "Cookie: __Host-tt_session=$session" -H "X-CSRF-Token: $csrf" \
    -X POST "$ui_url/users/1/client/deeplink" >"$work/deeplink"; then
    docker logs "$container"
    return 1
  fi
  grep -q 'tt://' "$work/deeplink"
}

curl_ui() {
  curl -kfsS --noproxy '*' --resolve "vpn.example.net:$ui_port:127.0.0.1" "$@"
}

run_platform() {
  arch="$1"
  ui_port="$2"
  vpn_port="$3"
  image="$run_id-$arch"
  volume="$run_id-$arch-data"
  container="$run_id-$arch"
  volumes="$volumes $volume"
  containers="$containers $container"
  docker buildx build --platform "linux/$arch" --load \
    --build-arg CONTROLLER_VERSION="smoke-$arch" --build-arg VCS_REF=smoke \
    --tag "$image" "$root" >/dev/null
  docker volume create "$volume" >/dev/null
  docker run --rm --platform "linux/$arch" -v "$volume:/var/lib/trusttunnel" \
    -v "$legacy:/legacy:ro" "$image" --migrate-legacy /legacy >/dev/null
  docker run -d --name "$container" --platform "linux/$arch" --read-only \
    --tmpfs /tmp:size=16m --cap-drop ALL \
    -p "127.0.0.1:$ui_port:8444/tcp" -p "127.0.0.1:$vpn_port:8443/tcp" \
    -p "127.0.0.1:$vpn_port:8443/udp" -v "$volume:/var/lib/trusttunnel" \
    "$image" --ui-listen 0.0.0.0:8444 >/dev/null
  wait_exec "$container" --healthcheck
  wait_exec "$container" --readycheck
  test "$(docker inspect -f '{{.Path}}' "$container")" = "/usr/local/bin/trusttunnel-controller"
  docker top "$container" -eo pid,stat,comm,args >"$work/top"
  grep -q trusttunnel_endpoint "$work/top"
  if awk 'NR > 1 && $2 ~ /^Z/ { found = 1 } END { exit !found }' "$work/top"; then return 1; fi
  docker port "$container" 8443/udp | grep -q "127.0.0.1:$vpn_port"
  nc -z 127.0.0.1 "$vpn_port"
  ui_login_and_export "$ui_port"
  docker stop -t 20 "$container" >/dev/null
  test "$(docker inspect -f '{{.State.ExitCode}}' "$container")" = 0
  docker rm "$container" >/dev/null
  containers=""
}

docker compose -f "$root/docker-compose.yml" config >/dev/null
docker compose -f "$root/docker-compose.yml" -f "$root/docker-compose.local.yml" config >/dev/null
run_platform amd64 19080 19443
run_platform arm64 19081 19444

# Upgrade the migrated amd64 data, then restore its verified backup under the old image.
old_image="$run_id-amd64"
new_image="$run_id-amd64-new"
data_volume="$run_id-amd64-data"
restore_volume="$run_id-restore-data"
volumes="$volumes $restore_volume"
chmod 777 "$work/backups"
docker run --rm --platform linux/amd64 -v "$data_volume:/var/lib/trusttunnel" \
  -v "$work/backups:/backups" "$old_image" --backup /backups/pre-upgrade.tar.gz >/dev/null
docker run --rm --platform linux/amd64 -v "$work/backups:/backups:ro" \
  "$old_image" --verify-backup /backups/pre-upgrade.tar.gz >/dev/null
docker buildx build --platform linux/amd64 --load \
  --build-arg CONTROLLER_VERSION=smoke-new --build-arg VCS_REF=smoke-new \
  --tag "$new_image" "$root" >/dev/null
upgrade_container="$run_id-upgrade"
containers="$upgrade_container"
docker run -d --name "$upgrade_container" --platform linux/amd64 --read-only --tmpfs /tmp:size=16m \
  --cap-drop ALL -p 127.0.0.1:19082:8444/tcp -p 127.0.0.1:19445:8443/tcp \
  -p 127.0.0.1:19445:8443/udp -v "$data_volume:/var/lib/trusttunnel" \
  "$new_image" --ui-listen 0.0.0.0:8444 >/dev/null
wait_exec "$upgrade_container" --readycheck
ui_login_and_export 19082 no
docker stop -t 20 "$upgrade_container" >/dev/null
docker rm "$upgrade_container" >/dev/null
containers=""

docker volume create "$restore_volume" >/dev/null
docker run --rm --platform linux/amd64 -v "$restore_volume:/var/lib/trusttunnel" \
  -v "$work/backups:/backups:ro" "$old_image" --restore-backup /backups/pre-upgrade.tar.gz >/dev/null
rollback_container="$run_id-rollback"
containers="$rollback_container"
docker run -d --name "$rollback_container" --platform linux/amd64 --read-only --tmpfs /tmp:size=16m \
  --cap-drop ALL -p 127.0.0.1:19083:8444/tcp -p 127.0.0.1:19446:8443/tcp \
  -p 127.0.0.1:19446:8443/udp -v "$restore_volume:/var/lib/trusttunnel" \
  "$old_image" --ui-listen 0.0.0.0:8444 >/dev/null
wait_exec "$rollback_container" --readycheck
ui_login_and_export 19083 no
docker stop -t 20 "$rollback_container" >/dev/null
docker rm "$rollback_container" >/dev/null
containers=""

printf '%s\n' "release smoke, migration, upgrade and rollback passed"
