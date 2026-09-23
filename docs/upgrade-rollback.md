# Backup, upgrade and rollback

Backups contain VPN credentials, administrator password hashes, TLS private
keys and the ACME account key. Store them as secrets with mode `0600`, encrypted
at rest, and never attach them to an issue or CI log.

## Backup and restore drill

`./scripts/backup.sh ./backups` performs SQLite `VACUUM INTO` online backup,
adds config/TLS/ACME data and a version/checksum manifest, then verifies the
archive. A failed verification is a hard stop: do not upgrade.

Restore only into an empty, separate volume:

```sh
docker run --rm \
  -v "$PWD/backups:/backups:ro" \
  -v trusttunnel_restore_test:/var/lib/trusttunnel \
  ghcr.io/reansnow/trusttunnel-controller@sha256:NEW_DIGEST \
  --restore-backup /backups/trusttunnel-TIMESTAMP.tar.gz
```

Start the restored volume on loopback ports and complete health, readiness, UI
login and client-export smoke tests before trusting the backup.

## Upgrade

1. Record the current manifest digest (`PREVIOUS_DIGEST`) and keep it until all
   smoke checks pass.
2. Create and verify a backup. Stop if either operation fails.
3. Set `TRUSTTUNNEL_IMAGE` to the new manifest digest, run `docker compose pull`,
   inspect `docker compose config`, then run `docker compose up -d`.
4. Verify `/healthz`, `/readyz`, UI login, endpoint listeners and one freshly
   generated official client config.

## Rollback

If the database schema is still supported by the old image, set
`TRUSTTUNNEL_IMAGE` back to `PREVIOUS_DIGEST` and recreate the service. If a
migration is not backward compatible, **do not** run the old image on the new
database. Stop the service, restore the pre-upgrade backup into a new volume,
attach that volume to the previous digest, and smoke-test it before switching
traffic. Deleting a container never deletes its named volume; volume deletion is
a separate, explicit and irreversible operation.
