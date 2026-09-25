# Backup, upgrade and rollback

Backups contain VPN credentials, administrator password hashes, TLS private
keys and the ACME account key. Store them as secrets with mode `0600`, encrypted
at rest, and never attach them to an issue or CI log.

## Backup and restore drill

`./scripts/backup.sh ./backups` performs SQLite `VACUUM INTO` online backup,
adds config/TLS/ACME data (including the ACME account key) and a
version/checksum manifest, then verifies the archive. Keep this one archive
together with the previous image digest for rollback. A failed verification is
a hard stop: do not upgrade.

Restore only into an empty, separate volume. Use the **previous** image for a
rollback rehearsal, or the candidate image to rehearse forward migration:

```sh
docker run --rm \
  -v "$PWD/backups:/backups:ro" \
  -v trusttunnel_restore_test:/var/lib/trusttunnel \
  ghcr.io/reansn0w/trusttunnel-controller@sha256:PREVIOUS_OR_NEW_DIGEST \
  --restore-backup /backups/trusttunnel-TIMESTAMP.tar.gz
```

Start the restored volume on loopback ports and complete health, readiness, UI
login and client-export smoke tests before trusting the backup. Rehearse the
candidate's SQLite migration on a **copy of the actual pre-upgrade volume**
before changing production. Record its schema version, users and TLS metadata
before and after. Never mount the production volume in this rehearsal.

## Upgrade

1. Record the current manifest digest (`PREVIOUS_DIGEST`) and save the current
   `.env` and Compose files. Keep them until all smoke checks pass.
2. Create and verify a backup, then rehearse restoration and migration on a
   separate volume. Stop if any check fails.
3. Set `TRUSTTUNNEL_IMAGE` to the new manifest digest, run `docker compose pull`,
   inspect `docker compose config`, then run `docker compose up -d`.
4. Verify `/healthz`, `/readyz`, UI login, endpoint listeners and one freshly
   generated official client config.

## Rollback

Do **not** assume SQLite v4/v5 migrations can be reversed by changing the image
tag. Stop the service, restore the verified pre-upgrade archive into a new
volume, attach that volume to `PREVIOUS_DIGEST`, and smoke-test it on loopback
ports before switching traffic. Restore the saved `.env` and Compose files as
well, including the old Nginx override if that version needed it. Keep the
upgraded volume untouched for diagnosis. Deleting a container never deletes its
named volume; volume deletion is a separate, explicit and irreversible action.
