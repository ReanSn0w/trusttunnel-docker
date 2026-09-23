#!/bin/sh
set -eu

image="${IMAGE:?set IMAGE to a locally built controller image}"
platform="${PLATFORM:-linux/arm64}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=vpn.example.com' \
  -addext 'subjectAltName=DNS:vpn.example.com' \
  -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
chmod 600 "$work/key.pem"

cat >"$work/vpn.toml" <<'EOF'
listen_address = "0.0.0.0:8443"
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

deeplink="$(docker run --rm --platform "$platform" -v "$work:/work:ro" \
  --entrypoint /usr/local/bin/trusttunnel_endpoint "$image" \
  /work/vpn.toml /work/hosts.toml -c alice -a vpn.example.com --format deeplink)"
case "$deeplink" in tt://*) ;; *) echo "invalid deeplink output" >&2; exit 1 ;; esac

toml="$(docker run --rm --platform "$platform" -v "$work:/work:ro" \
  --entrypoint /usr/local/bin/trusttunnel_endpoint "$image" \
  /work/vpn.toml /work/hosts.toml -c alice -a vpn.example.com --format toml)"
printf '%s' "$toml" | grep -q 'username = "alice"'
printf 'official endpoint export passed for %s\n' "$platform"
