# Grafana starter dashboard

Import `stumpfworks-overview.json` and choose a Prometheus datasource and job.
The dashboard shows target availability, HTTP rate/p95 latency, directory
lookup rate/p95 latency by bounded outcome/stage, and PostgreSQL pool pressure.

It intentionally contains no username, DN, request ID, client ID, raw route, or
free-form error labels. Protect each application's `/metrics` endpoint with a
private network and the framework's `metrics.ProtectBearer` wrapper; do not
expose it publicly. Store the random token only in protected runtime
configuration and configure the same value in Prometheus scrape authorization.

The dashboard is a starter for Homelab and small-business installations. Alert
destinations, retention, Loki log collection, tenant separation, and backups
remain deployment-owned and are not configured by this file.

`stumpfworks-logs.json` is the matching Loki dashboard. Choose the provisioned
Loki datasource and one or more bounded container labels. It deliberately does
not extract arbitrary JSON fields into labels.

`stumpfworks-identity.json` is the focused Identity dashboard. It is pinned to
the `stumpfworks-identity` scrape job and presents availability, bounded HTTP
status rates, server-error ratio and latency without exposing identities or
authentication material.
