# Server release validation (2026-09-25)

The release candidate combines the automatic TLS, shared AdminUI/VPN TLS and
connection profile plans. The next free controller version after `v0.2.1` is
reserved for this feature release as `v0.3.0`; the tag and image digest are not
published by these local checks.

## Automated checks

| Check | Result |
| --- | --- |
| `git diff --check` | pass |
| `go test ./...` | pass |
| `go test -race ./...` | pass |
| `go vet ./...` | pass |
| `scripts/test-web-browser.sh` | pass |
| Base, local and provided Compose config | pass |
| Dockerfile `test` stage, `linux/amd64` | pass |
| Final local image, `linux/amd64` | built |
| `scripts/release-smoke.sh` | migration, upgrade, rollback and UI export pass on disposable volumes |
| `scripts/test-pebble.sh` | local ACME issue/renew integration pass |
| `scripts/test-official-endpoint.sh` | self-signed and provided trust export pass |
| `scripts/test-local-connection.sh` | official CLI v1.1.7 connected over HTTP/2, Anti-DPI, smaller ClientHello preset and QUIC |
| `scripts/test-release-tls-sources.sh` | isolated self-signed/provided first start, bootstrap, user creation, shared certificate, restart and provided replacement pass |

The TLS source container smoke runs with `--network none`; it does not contact
Let's Encrypt. ACME was exercised against Pebble by the integration test, not
by a full controller container. The endpoint and AdminUI certificate were
compared by actual TLS handshakes in the source smoke. Plain HTTP on the UI
port and unauthenticated access with forged `X-Forwarded-*` headers were
rejected. An invalid provided PEM pair retained the previous active pair, and
a later valid pair reached both listeners.

## Deployment boundary

The local repository contains no copy of the production SQLite database, and
no production TrustTunnel container is running on this host. The v3→v5 fixture
migration preserved a user and TLS metadata; it does not establish compatibility
with the actual deployment database. Before deployment, restore a verified
backup of that database into a separate volume and run the candidate image
against it. Keep the old image digest, original `.env`/Compose files and the
pre-upgrade backup for rollback. See [upgrade and rollback](upgrade-rollback.md).

Mobile compatibility remains separate. The inspected Flutter client discards
Anti-DPI on deeplink import, and no patched mobile binary was validated here.
See [connection profiles](connection-dpi.md).
