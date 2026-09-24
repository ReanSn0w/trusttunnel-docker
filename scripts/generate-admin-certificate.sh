#!/bin/sh
set -eu

name=${1:?Usage: scripts/generate-admin-certificate.sh <dns-name-or-ip>}
out_dir=${2:-secrets}

mkdir -p "$out_dir"
umask 077

case "$name" in
  *[!0-9.]*|'') san="DNS:$name" ;;
  *) san="IP:$name" ;;
esac

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
  -keyout "$out_dir/admin-ca.key" \
  -out "$out_dir/admin-ca.crt" \
  -subj "/CN=TrustTunnel Admin Local CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -keyout "$out_dir/admin.key" \
  -out "$out_dir/admin.csr" \
  -subj "/CN=$name"

ext_file=$(mktemp)
trap 'rm -f "$ext_file" "$out_dir/admin.csr"' EXIT HUP INT TERM
{
  printf '%s\n' "subjectAltName=$san"
  printf '%s\n' 'basicConstraints=critical,CA:FALSE'
  printf '%s\n' 'keyUsage=critical,digitalSignature,keyEncipherment'
  printf '%s\n' 'extendedKeyUsage=serverAuth'
} >"$ext_file"

openssl x509 -req -sha256 -days 825 \
  -in "$out_dir/admin.csr" \
  -CA "$out_dir/admin-ca.crt" \
  -CAkey "$out_dir/admin-ca.key" \
  -CAcreateserial \
  -out "$out_dir/admin.crt" \
  -extfile "$ext_file"

chmod 600 "$out_dir/admin.key" "$out_dir/admin-ca.key"
chmod 644 "$out_dir/admin.crt" "$out_dir/admin-ca.crt"

printf '%s\n' "Created server certificate for $name in $out_dir."
printf '%s\n' "Install $out_dir/admin-ca.crt as a trusted root CA on each client."
