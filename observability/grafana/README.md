# Grafana starter dashboard

Import `stumpfworks-overview.json` and choose a Prometheus datasource and job.
The dashboard shows target availability, HTTP rate/p95 latency, and directory
lookup rate/p95 latency by bounded outcome and protocol stage.

It intentionally contains no username, DN, request ID, client ID, raw route, or
free-form error labels. Protect each application's `/metrics` endpoint with a
private network or authenticated collector path; do not expose it publicly.

The dashboard is a starter for Homelab and small-business installations. Alert
destinations, retention, Loki log collection, tenant separation, and backups
remain deployment-owned and are not configured by this file.
