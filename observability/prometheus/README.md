# Prometheus alert rules

`stumpfworks-alerts.rules.json` is JSON and therefore valid YAML for Prometheus.
Add its absolute path under `rule_files` in `prometheus.yml`, then validate the
complete Prometheus configuration before reload:

```yaml
rule_files:
  - /etc/prometheus/rules/stumpfworks-alerts.rules.json
```

```bash
promtool check config /etc/prometheus/prometheus.yml
```

The starter thresholds intentionally require sustained or repeated failures:

- target down for five minutes;
- HTTP 5xx ratio over 5% for ten minutes with active traffic;
- at least three directory failures or two timeouts in ten minutes;
- directory p95 above two seconds for ten minutes with active lookups.

Tune them from observed baselines. Alertmanager owns delivery to ntfy or another
operator channel. Do not put ntfy tokens, directory identities, raw errors, or
private URLs into these rules or Git.
