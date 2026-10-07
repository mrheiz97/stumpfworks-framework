# StumpfWorks Framework

StumpfWorks Framework (SWF) is the shared, self-hostable foundation for
independent StumpfWorks applications. It targets Homelabs and small businesses
without requiring a StumpfWorks cloud service.

The current candidate is `v0.9.0-rc.2`. Its public API is frozen, and the
framework-backed Identity and Access paths have passed controlled production
acceptance. It is not yet a stable `1.0` platform release.

The current Go module path is `github.com/mrheiz97/stumpfworks-framework`.
It matches the current repository owner. The repository is public, so downstream
builds do not need `GOPRIVATE` for this module.

## Current capabilities

- application lifecycle, typed configuration and structured redacted logging;
- safe HTTP defaults, health checks, Problem Details and strict JSON decoding;
- PostgreSQL pooling, transactions, migrations and an append-only audit store;
- pinned-issuer OIDC Discovery, JWKS refresh, PKCE login and ID-token validation;
- encrypted, browser-bound OIDC transaction persistence for consumer storage;
- bounded, policy-neutral exact-match permission sets;
- bounded read-only LDAPS user lookup with privacy-safe observations;
- Prometheus-compatible HTTP, PostgreSQL and directory metrics;
- a Grafana starter dashboard and Prometheus starter alert rules.

Access is the first real OIDC consumer. Identity now uses the framework's
read-only LDAPS adapter for individual user reads while retaining its existing
authentication, listing and application policy. Its PostgreSQL migration remains
staged and inactive. RBAC/audit and the Access device protocol are validated;
events/outbox remain deliberately excluded until a consumer needs them.

## Quick start

Requirements: Go 1.26.8 or a newer patched release. Older toolchains contain known vulnerabilities
in standard-library paths used by SWF.

```bash
go test ./...
go run ./examples/minimal-app
```

Non-secret command-line overrides have highest precedence:

```bash
go run ./examples/minimal-app --config ./examples/minimal-app/config.example.json --http-address 127.0.0.1:9090
```

Secrets such as the PostgreSQL URL are deliberately not accepted as command-line
flags; use environment injection or a protected configuration file.

The example listens on `127.0.0.1:8080` by default and exposes:

- `GET /health/live` — the process is alive;
- `GET /health/ready` — all registered readiness checks pass.

The minimal application intentionally demonstrates only the foundation. OIDC,
LDAP and metrics are opt-in library components that consuming applications wire
with their own policy, storage and secrets.

Configuration is read from environment variables:

Set `SWF_CONFIG_FILE` to load a JSON file. Environment variables override file
values; omitted values retain safe defaults. Unknown JSON fields fail startup.

| Variable | Default | Meaning |
|---|---:|---|
| `SWF_HTTP_ADDRESS` | `127.0.0.1:8080` | HTTP listen address |
| `SWF_CONFIG_FILE` | empty | optional JSON configuration file |
| `SWF_HTTP_READ_TIMEOUT` | `5s` | request read timeout |
| `SWF_HTTP_READ_HEADER_TIMEOUT` | `5s` | request-header deadline |
| `SWF_HTTP_WRITE_TIMEOUT` | `10s` | response write timeout |
| `SWF_HTTP_IDLE_TIMEOUT` | `60s` | keep-alive idle timeout |
| `SWF_HTTP_MAX_HEADER_BYTES` | `1048576` | maximum request-header size |
| `SWF_HTTP_MAX_CONCURRENT_REQUESTS` | `128` | simultaneous request limit |
| `SWF_HTTP_QUEUE_TIMEOUT` | `100ms` | bounded wait for request capacity |
| `SWF_SHUTDOWN_TIMEOUT` | `10s` | graceful shutdown deadline |
| `SWF_POSTGRES_URL` | empty | optional PostgreSQL connection URL |
| `SWF_POSTGRES_CONNECT_TIMEOUT` | `5s` | initial connection deadline |
| `SWF_POSTGRES_MAX_CONNECTIONS` | `10` | maximum pool size |
| `SWF_POSTGRES_MIN_CONNECTIONS` | `1` | minimum pool size |
| `SWF_POSTGRES_MAX_MESSAGE_BYTES` | `16777216` | PostgreSQL protocol message limit |
| `SWF_POSTGRES_ALLOW_INSECURE` | `false` | explicitly permit plaintext for trusted local development |

See [the architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md),
[development guide](docs/DEVELOPMENT.md), [release procedure](docs/RELEASES.md),
and [security policy](docs/SECURITY.md). The candidate public API and
compatibility rules are recorded in
[`docs/API-STABILITY.md`](docs/API-STABILITY.md).
The validated consumer boundary for permissions and audit is recorded in
[`docs/AUTHORIZATION-AUDIT-CONTRACT.md`](docs/AUTHORIZATION-AUDIT-CONTRACT.md).
The first OIDC verifier and its integration boundary are documented in
[`docs/OIDC.md`](docs/OIDC.md).
The current acceptance evidence and remaining release gates are tracked in
[`docs/STATUS.md`](docs/STATUS.md).
An importable, privacy-safe starter dashboard is available at
[`observability/grafana/stumpfworks-overview.json`](observability/grafana/stumpfworks-overview.json).
Starter Prometheus alert rules live in
[`observability/prometheus`](observability/prometheus).
Consumers can protect their metrics handler with `metrics.ProtectBearer`; use a
random runtime secret of at least 32 bytes and never commit it.

## Project status

The `develop` branch contains the current integration work. Stable releases are
prepared through reviewed changes and version tags; no `1.0` release exists yet.
See the roadmap and implementation status for completed checks, current
limitations and the acceptance evidence from Identity and Access.

## License

Licensed under the Apache License, Version 2.0.
