#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
image="${IMAGE:?set IMAGE to a locally built controller image}"
client_binary="${CLIENT_BINARY:?set CLIENT_BINARY to the official Linux x86_64 v1.1.7 binary}"
platform="${PLATFORM:-linux/amd64}"
work="$(mktemp -d)"
network="tt-connection-$$"
endpoint="tt-connection-endpoint-$$"
target="tt-connection-target-$$"
client="tt-connection-client-$$"
capture="tt-connection-capture-$$"

cleanup() {
  docker rm -f "$capture" "$client" "$endpoint" "$target" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=vpn.example.com' -addext 'subjectAltName=DNS:vpn.example.com' \
  -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
chmod 600 "$work/key.pem"
cat >"$work/vpn.toml" <<'EOF'
listen_address = "0.0.0.0:8443"
allow_private_network_connections = true
credentials_file = "/work/credentials.toml"
rules_file = "/work/rules.toml"
[listen_protocols]
http1 = {}
http2 = {}
quic = {}
[forward_protocol]
direct = {}
EOF
cat >"$work/hosts.toml" <<'EOF'
[[main_hosts]]
hostname = "vpn.example.com"
cert_chain_path = "/work/cert.pem"
private_key_path = "/work/key.pem"
EOF
cat >"$work/credentials.toml" <<'EOF'
[[client]]
username = "alice"
password = "integration-test-password"
EOF
: >"$work/rules.toml"

docker run --rm --platform "$platform" -v "$work:/work:ro" \
  --entrypoint /usr/local/bin/trusttunnel_endpoint "$image" \
  /work/vpn.toml /work/hosts.toml -c alice -a vpn.example.com:8443 --format deeplink >"$work/deeplink.out"
docker run --rm --platform "$platform" -v "$work:/work:ro" \
  --entrypoint /usr/local/bin/trusttunnel_endpoint "$image" \
  /work/vpn.toml /work/hosts.toml -c alice -a vpn.example.com:8443 --format toml >"$work/endpoint.toml"
for variant in baseline anti-dpi pq-off quic; do
  (cd "$root" && GOCACHE="${GOCACHE:-/tmp/trusttunnel-go-build}" go run ./scripts/write-connection-smoke.go "$work/deeplink.out" "$work/endpoint.toml" "$variant" "$work/client-$variant.toml")
done

docker network create "$network" >/dev/null
docker run -d --name "$target" --network "$network" --network-alias target \
  busybox:1.36 sh -c 'mkdir -p /www && echo trusttunnel-smoke-ok >/www/index.html && httpd -f -p 8080 -h /www' >/dev/null
target_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$target")"
docker run --rm --platform "$platform" --network "$network" curlimages/curl:8.12.1 \
  -fsS "http://$target_ip:8080/" | grep -q '^trusttunnel-smoke-ok$'
docker run -d --name "$endpoint" --platform "$platform" --network "$network" \
  --network-alias vpn.example.com -v "$work:/work:ro" \
  --entrypoint /usr/local/bin/trusttunnel_endpoint "$image" \
  /work/vpn.toml /work/hosts.toml >/dev/null

for variant in baseline anti-dpi pq-off quic; do
  docker run -d --name "$capture" --network "container:$endpoint" \
    --cap-add NET_RAW -v "$work:/work" --entrypoint tcpdump \
    nicolaka/netshoot:v0.15 -i eth0 --immediate-mode -s 0 -U -w "/work/capture-$variant.pcap" port 8443 >/dev/null
  sleep 1
  if [ "$(docker inspect -f '{{.State.Status}}' "$capture")" != running ]; then
    docker logs "$capture" >&2
    exit 1
  fi
  docker run -d --name "$client" --platform "$platform" --network "$network" \
    -v "$client_binary:/usr/local/bin/trusttunnel_client:ro" \
    -v "$work:/work:ro" --entrypoint /usr/local/bin/trusttunnel_client \
    debian:bookworm-slim --config "/work/client-$variant.toml" >/dev/null
  if ! docker run --rm --platform "$platform" --network "container:$client" \
      curlimages/curl:8.12.1 -fsS --socks5-hostname 127.0.0.1:1080 \
      --retry 10 --retry-connrefused --retry-delay 1 --max-time 15 \
      "http://$target_ip:8080/" >"$work/response"; then
    docker logs "$client" 2>&1 | tail -25
    docker logs "$endpoint" 2>&1 | tail -25
    exit 1
  fi
  grep -q '^trusttunnel-smoke-ok$' "$work/response"
  docker rm -f "$client" >/dev/null
  docker stop -t 2 "$capture" >/dev/null
  docker rm "$capture" >/dev/null
  first_tcp_header="$(docker run --rm -v "$work:/work:ro" --entrypoint tshark nicolaka/netshoot:v0.15 \
    -r "/work/capture-$variant.pcap" -Y 'tcp.dstport == 8443 && tcp.len > 0' \
    -T fields -e tcp.payload 2>/dev/null | head -2 | tr -d '\n' | cut -c1-10)"
  record_length=none
  case "$first_tcp_header" in
    16????????)
      record_hex="${first_tcp_header#??????}"
      record_length="$(printf '%d' "0x$record_hex")" ;;
  esac
  udp_packets="$(docker run --rm -v "$work:/work:ro" --entrypoint tshark nicolaka/netshoot:v0.15 \
    -r "/work/capture-$variant.pcap" -Y 'udp.dstport == 8443' \
    -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  frames="$(docker run --rm -v "$work:/work:ro" --entrypoint tshark nicolaka/netshoot:v0.15 \
    -r "/work/capture-$variant.pcap" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
  [ "$frames" -gt 0 ]
  case "$variant" in
    quic) [ "$udp_packets" -gt 0 ] ;;
    *) [ "$record_length" != none ] && [ "$udp_packets" -eq 0 ] ;;
  esac
  printf 'isolated %s connection passed; frames=%s; ClientHello TLS record=%s; UDP packets=%s\n' \
    "$variant" "$frames" "$record_length" "$udp_packets"
done
