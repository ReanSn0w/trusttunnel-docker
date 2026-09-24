# Admin UI reverse proxy boundary

Production access to the administrator UI goes through a TLS reverse proxy. The
example deliberately does **not** proxy TrustTunnel VPN traffic. Because the VPN
already owns host TCP 443, the UI uses host TCP 8444 by default and is reachable
from any client address at `https://<server-name>:8444`. Set `TT_ADMIN_PORT` to
use another free host port. No source-IP allowlist is applied.

Place the certificate chain and private key at `secrets/admin.crt` and
`secrets/admin.key`. A publicly trusted certificate for the server DNS name is
preferred. For a private deployment, a self-signed certificate works after its
CA is installed as trusted on every phone/browser that will use the panel. Merely
clicking through a browser certificate warning is not a sound permanent setup.

For a private CA and a correctly constrained server certificate:

```sh
./scripts/generate-admin-certificate.sh admin.example.net
```

Replace `admin.example.net` with the real DNS name or server IP. The script puts
the correct DNS or IP SAN in the leaf certificate. Install
`secrets/admin-ca.crt` as a trusted root CA on the mobile device before logging
in; do not copy `admin-ca.key` off the server.

```sh
docker compose -f docker-compose.yml \
  -f docker-compose.reverse-proxy.yml config
docker compose -f docker-compose.yml \
  -f docker-compose.reverse-proxy.yml up -d
```

Open `https://<server-name>:8444/bootstrap` for the first account, then use
`https://<server-name>:8444/login`. HTTPS allows the controller's Secure session
and CSRF cookies to work correctly.

The proxy has the fixed address `172.31.250.2` on the dedicated `/29` bridge,
and the controller trusts exactly `172.31.250.2/32`. Nginx overwrites, rather
than appends, `X-Forwarded-For` and sets `X-Forwarded-Proto: https`; requests
from every other peer have forwarded headers ignored. The proxy receives static
certificate/key bind mounts and no Docker socket, service-discovery privilege,
host network, or access to the controller data volume.

The override explicitly sets `internal: false`. Podman disables bridge IP
forwarding for an internal network, which also prevents the published HTTPS port
from reaching Nginx. Only the declared host port is published; the controller's
port 8080 remains unbound on the host.
