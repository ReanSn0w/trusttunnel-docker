# TrustTunnel Controller

Self-hosted single-container controller for the official TrustTunnel endpoint.
It owns configuration, TLS renewal, process supervision and a server-rendered
administrator UI; the official endpoint binary remains the VPN data plane.

The checked-in `docker-compose.yml` runs one service and one persistent volume:
VPN TCP/UDP on 443, built-in HTTPS AdminUI on 8444, and TCP 80 only for ACME
HTTP-01. There is no Nginx service. Its essential layout is:

```yaml
services:
  trusttunnel:
    image: ${TRUSTTUNNEL_IMAGE}
    ports:
      - "443:8443/tcp"
      - "443:8443/udp"
      - "8444:8444/tcp"
      - "80:80/tcp"
    volumes:
      - trusttunnel_data:/var/lib/trusttunnel
volumes:
  trusttunnel_data:
```

Use the checked-in file for the complete security and healthcheck settings.

## Minimal production start

1. Point the VPN hostname's public A/AAAA record at the server. Make TCP 443,
   UDP 443 and TCP 8444 reachable. TCP 80 is needed for Let's Encrypt HTTP-01.
2. Copy `.env.example` to `.env`. Set `TRUSTTUNNEL_IMAGE` to the verified
   immutable release digest and choose exactly one TLS source before starting:

   | Source | Required `.env` values | Additional setup |
   | --- | --- | --- |
   | Let's Encrypt | `TT_TLS_SOURCE=letsencrypt`, `TT_TLS_HOSTNAME`, `TT_ACME_EMAIL` | Public DNS and inbound TCP 80 for HTTP-01 |
   | Self-signed | `TT_TLS_SOURCE=self-signed`, `TT_TLS_HOSTNAME` | Trust the generated certificate on clients |
   | Provided PEM | `TT_TLS_SOURCE=provided`, `TT_TLS_HOSTNAME`, `TT_PROVIDED_TLS_DIR` | Read-only PEM mount and container paths from `docker-compose.provided.yml` |

3. Validate and start. For the provided source, replace `docker compose` in
   each command with
   `docker compose -f docker-compose.yml -f docker-compose.provided.yml`:

   ```sh
   docker compose config
   docker compose pull
   docker compose up -d
   ```

4. The panel becomes reachable after the first valid pair is published. Check
   container logs and `/healthz` while Let's Encrypt is issuing. Later source
   changes can be saved in **TLS**; see `docs/tls-lifecycle.md`.
5. Open the built-in AdminUI at `https://<TT_TLS_HOSTNAME>:8444/bootstrap`.
   Use the DNS name covered by the VPN certificate, not the server IP. The base
   Compose publishes this HTTPS port separately from VPN TCP 443.
6. Create a strong administrator password. There are no default credentials and
   the password is not accepted through environment variables or logs.
   In **Users**, create the first VPN user and copy its generated
   password once. Confirm health/readiness and TCP/UDP listeners before sharing
   the generated official client config.

## Safe local smoke

The override builds locally, uses a separate volume and a self-signed certificate,
does not publish TCP 80, and binds every host port to loopback:

```sh
docker compose -f docker-compose.yml -f docker-compose.local.yml config
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
open https://vpn.localhost:18444/bootstrap
```

VPN TCP/UDP is available only at `127.0.0.1:18443`. Do not use production DNS,
certificates or volumes for this smoke run. Stop it with the same two `-f`
arguments and `down`; add `--volumes` only when you intentionally want to erase
the disposable local state.

## Operations

- Client transport, Anti-DPI exports and mobile limitations: `docs/connection-dpi.md`.
- Migration from the old Nginx deployment: `docs/reverse-proxy.md`.
- Persistent layout and one-time legacy import: `docs/data-layout.md`.
- Backup, restore, upgrade and rollback: `docs/upgrade-rollback.md`.
- Local release checks and deployment boundary: `docs/release-validation.md`.
- Release tags, digests and attestations: `docs/release-contract.md`.

Rotate the administrator password from **Account** in the UI. Rotation creates
a new session ID and invalidates every old session. Removing or recreating the
container leaves `trusttunnel_data` intact. Removing the named volume is a
separate destructive action and must never be part of routine `down`, upgrade
or rollback commands.
