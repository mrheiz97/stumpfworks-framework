# Observability backup and restore check

These scripts back up the single-node observability deployment and prove that
the archives can be restored into isolated Docker volumes. The backup includes
runtime configuration and secrets, so its directory must remain root-only and
must be copied only to encrypted, access-controlled storage.

Run on the Docker host:

```sh
sudo ./backup.sh
sudo ./restore-check.sh /var/backups/stumpfworks-observability/<timestamp>
```

`backup.sh` briefly stops only the observability Compose stack to produce a
consistent archive and uses a trap to restart it after success or failure.
`restore-check.sh` validates checksums, restores all five named volumes into
temporary isolated volumes, runs SQLite integrity checking for Grafana and
Prometheus TSDB analysis, checks Loki data, and removes the test volumes.

Keep at least one encrypted copy outside the Docker host. Test a full recovery
on a separate host before treating this as a disaster-recovery guarantee.
