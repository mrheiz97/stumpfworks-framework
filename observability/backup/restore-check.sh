#!/bin/sh
set -eu

backup_dir=${1:?usage: restore-check.sh BACKUP_DIR}
archive_image=${ARCHIVE_IMAGE:-nginx@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94}
prefix=sw-observability-restore-check

test -f "$backup_dir/SHA256SUMS"
(cd "$backup_dir" && sha256sum -c SHA256SUMS)

cleanup() {
  docker rm -f "${prefix}-grafana" >/dev/null 2>&1 || true
  for volume in prometheus-data grafana-data alertmanager-data loki-data alloy-data; do
    docker volume rm "${prefix}-${volume}" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT INT TERM
cleanup

for volume in prometheus-data grafana-data alertmanager-data loki-data alloy-data; do
  restored="${prefix}-${volume}"
  docker volume create "$restored" >/dev/null
  docker run --rm --entrypoint tar \
    -v "$restored:/restore" \
    -v "$backup_dir/volumes:/backup:ro" \
    "$archive_image" -C /restore -xzf "/backup/${volume}.tgz"
done

prometheus_mount=$(docker volume inspect -f '{{.Mountpoint}}' "${prefix}-prometheus-data")
grafana_mount=$(docker volume inspect -f '{{.Mountpoint}}' "${prefix}-grafana-data")
loki_mount=$(docker volume inspect -f '{{.Mountpoint}}' "${prefix}-loki-data")

test -d "$prometheus_mount"
test -f "$grafana_mount/grafana.db"
test -n "$(find "$loki_mount" -type f -print -quit)"
python3 - "$grafana_mount/grafana.db" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
result = connection.execute("PRAGMA integrity_check").fetchone()[0]
connection.close()
if result != "ok":
    raise SystemExit(f"Grafana database integrity check failed: {result}")
PY

docker run --rm --entrypoint=promtool \
  -v "${prefix}-prometheus-data:/prometheus" \
  prom/prometheus:v3.15.0 tsdb analyze /prometheus >/dev/null

printf '%s\n' "restore check passed"
