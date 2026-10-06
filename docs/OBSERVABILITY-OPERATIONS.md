# Observability operations baseline

Status: validated single-node baseline for Homelab use and a bounded starting
point for small-business deployments.

## Retention

- Prometheus keeps 15 days of metrics.
- Loki keeps 14 days of logs and rejects queries beyond that period.
- Application audit records remain application-owned database records and are
  not replaced by Loki retention.
- Retention changes require a free-space check and a new backup/restore test.

These periods limit local disk and privacy exposure. An SMB operator may choose
longer periods only after documenting capacity, legal requirements and deletion
expectations.

## Access boundary

- Prometheus, Loki and Alertmanager bind only to loopback on the Docker host.
- Remote log ingestion uses a dedicated mTLS gateway that accepts only Loki's
  push endpoint and separate client certificates per host.
- Access and Identity metrics use separate bearer credentials and verified TLS.
- Grafana disables anonymous access and self-registration. The current Homelab
  instance is LAN-only; an SMB deployment must place it behind an authenticated
  TLS reverse proxy or VPN and issue named least-privilege viewer accounts.
- Metrics and log labels must remain bounded. Do not add usernames, subjects,
  badge IDs, request IDs, tokens, raw paths or free-form errors as labels.

## Backup and recovery

Use `observability/backup/backup.sh` on the Docker host for a consistent backup
of configuration and all five named volumes. It briefly stops only the
observability stack and always attempts to restart it through a shell trap.
Because the configuration archive contains credentials, the backup directory is
root-only and copies must use encrypted, access-controlled storage.

Run `observability/backup/restore-check.sh BACKUP_DIR` after every material
configuration change and periodically thereafter. It verifies checksums,
restores into isolated temporary volumes, checks Grafana SQLite integrity,
analyzes the Prometheus TSDB, confirms Loki data and removes the test volumes.

On 2026-10-06, backup `20261006T174000Z` passed this complete restore check. The
live stack returned with all six scrape targets healthy. The on-host copy is not
a disaster-recovery copy; at least one encrypted copy must also be kept outside
the Docker host.

## Alerts and review

Alertmanager delivers to the operator-owned ntfy topic over verified internal
TLS. Rules cover application availability/error rate/latency plus Prometheus,
Alertmanager, Loki and Alloy health, notification failures, Loki server errors
and dropped log entries. Review active targets, alert rules, disk use, retention
and the latest restore result after upgrades and at least quarterly for an SMB
deployment.
