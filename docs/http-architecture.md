# HTTP architecture

The controller exposes two deliberately separate listeners.

- `TT_UI_LISTEN` defaults to `127.0.0.1:8080` and serves the administrator UI.
  Compose may bind it to an internal network, but it is never public by default.
- `TT_PROBE_LISTEN` serves unauthenticated machine-readable `/healthz` and
  `/readyz` responses. It contains no administrator or credential data.

The UI is server-rendered with `html/template`. Mutations are HTML form POSTs;
htmx requests receive HTML fragments from the same routes. There is no parallel
JSON administration API and no state-changing GET endpoint.

## Routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET, POST | `/bootstrap` | create the first administrator |
| GET, POST | `/login` | establish an administrator session |
| POST | `/logout` | revoke the current session |
| GET | `/` | endpoint dashboard |
| GET | `/fragments/status` | bounded dashboard refresh fragment |
| GET, POST | `/users` | list and create VPN users |
| POST | `/users/{id}/enable` | enable a disabled VPN user |
| POST | `/users/{id}/disable` | disable a VPN user |
| POST | `/users/{id}/rotate` | rotate VPN credentials |
| POST | `/users/{id}/revoke` | irreversibly revoke a VPN user |
| POST | `/users/{id}/client/deeplink` | render the official `tt://` config |
| POST | `/users/{id}/client/toml` | download official client TOML |
| POST | `/users/{id}/client/qr` | render a local QR image |
| GET, POST | `/tls` | view and save domain/ACME settings |
| POST | `/tls/issue`, `/tls/renew` | explicit certificate operations |
| GET | `/events` | bounded apply history and redacted logs |
| GET | `/assets/{name}` | embedded immutable frontend assets |

## Layer boundary

Handlers depend on narrow service interfaces. They may validate input, enforce
authentication/CSRF policy and select a template, but must not execute SQL,
write TOML/PEM files, or signal the endpoint process directly. The existing
controller services remain the only mutation boundary and retain apply locking,
atomic file publication and rollback responsibilities.

Reverse-proxy headers are ignored unless the peer address matches an explicit
trusted-proxy allowlist. External TLS mode is therefore configuration, not an
inference from attacker-controlled `X-Forwarded-*` values.
