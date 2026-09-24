# TrustTunnel Controller

Self-hosted single-container controller for the official TrustTunnel endpoint.
It owns configuration, TLS renewal, process supervision and a server-rendered
administrator UI; the official endpoint binary remains the VPN data plane.

## Minimal production start

1. Point the VPN hostname's public A/AAAA record at the server. Make TCP 80,
   TCP 443 and UDP 443 reachable; the reverse-proxy example publishes the admin
   UI over HTTPS on TCP 8444 by default.
2. Copy `.env.example` to `.env` and replace `TRUSTTUNNEL_IMAGE` with the
   verified immutable manifest digest from the release.
3. Validate and start:

   ```sh
   docker compose config
   docker compose pull
   docker compose up -d
   ```

4. Connect the UI only through the TLS reverse proxy described in
   `docs/reverse-proxy.md`. The base Compose does not publish it.
5. Open `/bootstrap` and create a strong administrator password. There are no
   default credentials and the password is not accepted through environment
   variables or logs.
6. In **TLS**, save the VPN hostname and ACME email, then explicitly issue the
   certificate. In **Users**, create the first VPN user and copy its generated
   password once. Confirm health/readiness and TCP/UDP listeners before sharing
   the generated official client config.

## Safe local smoke

The override builds locally, uses a separate volume, defaults ACME to staging,
does not publish TCP 80, and binds every host port to loopback:

```sh
docker compose -f docker-compose.yml -f docker-compose.local.yml config
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
open http://127.0.0.1:18080/bootstrap
```

VPN TCP/UDP is available only at `127.0.0.1:18443`. Do not use production DNS,
certificates or volumes for this smoke run. Stop it with the same two `-f`
arguments and `down`; add `--volumes` only when you intentionally want to erase
the disposable local state.

## Operations

- Reverse proxy and trusted-forwarding boundary: `docs/reverse-proxy.md`.
- Persistent layout and one-time legacy import: `docs/data-layout.md`.
- Backup, restore, upgrade and rollback: `docs/upgrade-rollback.md`.
- Release tags, digests and attestations: `docs/release-contract.md`.

Rotate the administrator password from **Account** in the UI. Rotation creates
a new session ID and invalidates every old session. Removing or recreating the
container leaves `trusttunnel_data` intact. Removing the named volume is a
separate destructive action and must never be part of routine `down`, upgrade
or rollback commands.
