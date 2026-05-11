#!/usr/bin/env bash
# PyGrove Chain — state-volume snapshot.
#
# Tarballs the `pygrove-data` Docker volume to a timestamped file under
# /var/backups/pygrove. Suitable for cron — quiet on success, exits
# non-zero on failure so `cron` mails the operator.
#
# Schedule:
#   sudo crontab -e
#   # Daily at 03:15 UTC:
#   15 3 * * * /opt/pygrove/ops/backup.sh
#
# Restore: see docs/runbook.md § Recovery.

set -euo pipefail

VOLUME="${PYGROVE_VOLUME:-pygrove-data}"
BACKUP_DIR="${PYGROVE_BACKUP_DIR:-/var/backups/pygrove}"
RETAIN_DAYS="${PYGROVE_BACKUP_RETAIN_DAYS:-14}"
TS="$(date -u +%Y%m%d-%H%M%S)"
OUT="${BACKUP_DIR}/pygrove-data-${TS}.tar.gz"

mkdir -p "$BACKUP_DIR"

# Snapshot the volume by spinning a one-shot alpine container that
# bind-mounts both the volume and the backup dir. Avoids needing to
# stop pygrove-node — the chain.log is append-only so a concurrent read
# is safe even mid-write.
docker run --rm \
    -v "${VOLUME}:/data:ro" \
    -v "${BACKUP_DIR}:/backup" \
    alpine \
    sh -c "tar czf /backup/pygrove-data-${TS}.tar.gz -C /data . && chmod 0640 /backup/pygrove-data-${TS}.tar.gz"

# Prune old backups beyond the retention window.
find "$BACKUP_DIR" -maxdepth 1 -name 'pygrove-data-*.tar.gz' -mtime "+${RETAIN_DAYS}" -delete

# Print a one-line summary on success — cron will mail it.
SIZE_HUMAN="$(du -h "$OUT" | cut -f1)"
echo "pygrove-backup OK: ${OUT} (${SIZE_HUMAN})"
