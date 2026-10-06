#!/bin/sh
set -eu

stack_dir=${STACK_DIR:-/opt/stumpfworks-observability}
backup_root=${BACKUP_ROOT:-/var/backups/stumpfworks-observability}
stamp=${1:-$(date -u +%Y%m%dT%H%M%SZ)}
backup_dir="$backup_root/$stamp"
archive_image=${ARCHIVE_IMAGE:-nginx@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94}

umask 077
test -d "$stack_dir"
test ! -e "$backup_dir"
mkdir -p "$backup_dir/volumes"

cd "$stack_dir"
docker compose config -q
tar -C "$stack_dir" -czf "$backup_dir/configuration.tgz" .

restart_stack() {
  docker compose up -d
}
trap restart_stack EXIT INT TERM
docker compose stop

for volume in prometheus-data grafana-data alertmanager-data loki-data alloy-data; do
  full_volume="stumpfworks-observability_${volume}"
  docker volume inspect "$full_volume" >/dev/null
  docker run --rm --entrypoint tar \
    -v "$full_volume:/source:ro" \
    -v "$backup_dir/volumes:/backup" \
    "$archive_image" -C /source -czf "/backup/${volume}.tgz" .
done

(cd "$backup_dir" && sha256sum configuration.tgz volumes/*.tgz > SHA256SUMS)
restart_stack
trap - EXIT INT TERM
chmod -R go-rwx "$backup_dir"
printf '%s\n' "$backup_dir"
