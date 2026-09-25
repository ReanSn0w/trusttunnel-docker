#!/bin/sh
set -eu

image="${IMAGE:?set IMAGE to a locally built controller image}"
platform="${PLATFORM:-linux/amd64}"
work="$(mktemp -d)"
name="tt-tls-smoke-$$"
volume="$name-data"
container="$name"
source=""

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

make_pair() {
  destination="$1"
  mkdir -p "$destination"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 2 -subj '/CN=vpn.example.net' \
    -addext 'subjectAltName=DNS:vpn.example.net' \
    -keyout "$destination/key.new" -out "$destination/cert.new" >/dev/null 2>&1
  chmod 644 "$destination/key.new" "$destination/cert.new"
  mv "$destination/key.new" "$destination/key.pem"
  mv "$destination/cert.new" "$destination/cert.pem"
}

start_controller() {
  source="$1"
  set -- -e TT_TLS_SOURCE="$source" -e TT_TLS_HOSTNAME=vpn.example.net
  if [ "$source" = provided ]; then
    set -- "$@" -e TT_TLS_CERTIFICATE_FILE=/provided/cert.pem \
      -e TT_TLS_KEY_FILE=/provided/key.pem
  fi
  docker run -d --name "$container" --platform "$platform" --network none \
    --read-only --tmpfs /tmp:size=16m --cap-drop ALL \
    "$@" \
    -v "$volume:/var/lib/trusttunnel" -v "$work/provided:/provided:ro" \
    "$image" --ui-listen 0.0.0.0:8444 >/dev/null
  attempt=0
  until curl_ui -o /dev/null https://vpn.example.net:8444/bootstrap 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then docker logs "$container" >&2; return 1; fi
    sleep 1
  done
}

curl_ui() {
  docker run --rm --platform "$platform" --network "container:$container" \
    -v "$work:/work" --entrypoint curl nicolaka/netshoot:v0.15 \
    -kfsS --noproxy '*' --resolve vpn.example.net:8444:127.0.0.1 "$@"
}

fingerprint() {
  port="$1"
  docker run --rm --platform "$platform" --network "container:$container" \
    --entrypoint sh nicolaka/netshoot:v0.15 -c \
    "echo | openssl s_client -connect 127.0.0.1:$port -servername vpn.example.net 2>/dev/null | openssl x509 -noout -fingerprint -sha256" \
    | sed 's/^sha256 Fingerprint=//; s/^SHA2-256 Fingerprint=//'
}

bootstrap_and_create_user() {
  if docker run --rm --platform "$platform" --network "container:$container" \
      --entrypoint curl nicolaka/netshoot:v0.15 -fsS --max-time 3 \
      http://127.0.0.1:8444/bootstrap >/dev/null 2>&1; then
    echo 'AdminUI accepted plaintext HTTP' >&2
    return 1
  fi
  curl_ui -D /work/headers -o /work/body https://vpn.example.net:8444/bootstrap
  seed="$(sed -n 's/^Set-Cookie: __Host-tt_csrf_seed=\([^;]*\).*/\1/p' "$work/headers" | tr -d '\r' | tail -1)"
  csrf="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$work/body" | tail -1)"
  test -n "$seed" && test -n "$csrf"
  curl_ui -o /dev/null -H "Cookie: __Host-tt_csrf_seed=$seed" \
    --data-urlencode "_csrf=$csrf" --data-urlencode 'username=admin' \
    --data-urlencode 'password=Admin-Smoke-9!' https://vpn.example.net:8444/bootstrap
  curl_ui -D /work/headers -o /work/body \
    -H "Cookie: __Host-tt_csrf_seed=$seed" https://vpn.example.net:8444/login
  csrf="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$work/body" | tail -1)"
  curl_ui -D /work/headers -o /dev/null -H "Cookie: __Host-tt_csrf_seed=$seed" \
    --data-urlencode "_csrf=$csrf" --data-urlencode 'username=admin' \
    --data-urlencode 'password=Admin-Smoke-9!' https://vpn.example.net:8444/login
  session="$(sed -n 's/^Set-Cookie: __Host-tt_session=\([^;]*\).*/\1/p' "$work/headers" | tr -d '\r' | tail -1)"
  test -n "$session"
  curl_ui -D /work/headers -o /dev/null \
    -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 127.0.0.1' \
    https://vpn.example.net:8444/users
  grep -qi '^Location: /login' "$work/headers"
  curl_ui -o /work/body -H "Cookie: __Host-tt_session=$session" \
    https://vpn.example.net:8444/users
  csrf="$(sed -n 's/.*name="csrf-token" content="\([^"]*\)".*/\1/p' "$work/body" | tail -1)"
  test -n "$csrf"
  curl_ui -o /work/body -H "Cookie: __Host-tt_session=$session" \
    -H "X-CSRF-Token: $csrf" --data-urlencode 'username=alice' \
    https://vpn.example.net:8444/users
  grep -q 'alice' "$work/body"
  attempt=0
  until docker exec "$container" /usr/local/bin/trusttunnel-controller --readycheck >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then docker logs "$container" >&2; return 1; fi
    sleep 1
  done
}

check_pair() {
  admin="$(fingerprint 8444)"
  vpn="$(fingerprint 8443)"
  test -n "$admin" && test "$admin" = "$vpn"
  printf '%s\n' "$admin"
}

mkdir -p "$work/provided"
make_pair "$work/provided"

for source in self-signed provided; do
  docker volume create "$volume" >/dev/null
  start_controller "$source"
  bootstrap_and_create_user
  first="$(check_pair)"
  docker stop -t 20 "$container" >/dev/null
  docker rm "$container" >/dev/null
  start_controller "$source"
  test "$first" = "$(check_pair)"
  printf '%s first start, bootstrap, shared TLS and restart passed\n' "$source"

  if [ "$source" = provided ]; then
    printf 'checking invalid provided replacement\n'
    printf 'invalid replacement\n' >"$work/provided/cert.pem"
    sleep 32
    after_invalid="$(check_pair)"
    if [ "$first" != "$after_invalid" ]; then
      docker logs "$container" >&2
      echo 'invalid provided pair changed active certificate' >&2
      exit 1
    fi
    make_pair "$work/provided"
    printf 'waiting for valid provided replacement\n'
    attempt=0
    while :; do
      next_admin="$(fingerprint 8444)"
      next_vpn="$(fingerprint 8443)"
      if [ -n "$next_admin" ] && [ "$next_admin" != "$first" ] && [ "$next_admin" = "$next_vpn" ]; then
        break
      fi
      attempt=$((attempt + 1))
      if [ "$attempt" -ge 90 ]; then
        printf 'first=%s admin=%s vpn=%s\n' "$first" "$next_admin" "$next_vpn" >&2
        docker logs "$container" >&2
        exit 1
      fi
      sleep 1
    done
    printf 'provided invalid-pair guard and live replacement passed\n'
  fi
  docker rm -f "$container" >/dev/null
  docker volume rm "$volume" >/dev/null
done
