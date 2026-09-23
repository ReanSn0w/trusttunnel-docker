# Persistent data and legacy migration

The controller owns `/var/lib/trusttunnel` exclusively. A non-blocking flock on
`.controller.lock` prevents two controller/endpoint pairs from sharing it.

Stable paths are:

- `controller.db` plus SQLite WAL files — administrators, hashed sessions, VPN
  users, settings, TLS metadata and apply history;
- `config/revisions/<digest>/` with `config/current` and `config/previous`
  symlinks — rendered endpoint TOML revisions;
- `tls/revisions/<id>/` with `tls/current` and `tls/previous` symlinks — PEM
  revisions (`0700` directory, `0600` key, `0644` chain);
- `acme/account.key` — ACME account key (`0600`);
- `migration/legacy-v1.json` — non-secret one-time import manifest;
- controller and endpoint logs are bounded in memory and are not persistent.

## Legacy volume mapping

Stop the legacy container first, mount its `trusttunnel_endpoint_data` volume
read-only at `/legacy`, mount the new volume at `/var/lib/trusttunnel`, then run:

```sh
trusttunnel-controller --data-dir /var/lib/trusttunnel --migrate-legacy /legacy
```

The importer maps `vpn.toml`, `hosts.toml`, `credentials.toml`, optional
`rules.toml`, and the PEM paths referenced by `hosts.toml`. Credentials are read
directly into SQLite and never printed. It renders a fresh content-addressed
configuration revision and imports the certificate through the same validation
and atomic TLS store used by the controller.

The operation is idempotent. A completion manifest is atomically published only
after the database, TLS and rendered configuration are valid; a rerun after a
partial attempt safely upserts the same logical data. The source is never
modified or deleted. Keep the old volume until backup, smoke and rollback tests
have succeeded.
