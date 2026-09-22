# StumpfWorks Framework

StumpfWorks Framework (SWF) is the shared, self-hostable foundation for
independent StumpfWorks applications. The project is at an early `0.x` stage;
its public APIs may still change as Identity and Access validate them.

The Go module path is `github.com/TheRealHZL/stumpfworks-framework`. The
repository is public; downstream builds do not need `GOPRIVATE` for this
module.

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
[development guide](docs/DEVELOPMENT.md), and [security policy](docs/SECURITY.md).
The first OIDC verifier and its integration boundary are documented in
[`docs/OIDC.md`](docs/OIDC.md).
The current acceptance evidence and remaining release gates are tracked in
[`docs/STATUS.md`](docs/STATUS.md).
An importable, privacy-safe starter dashboard is available at
[`observability/grafana/stumpfworks-overview.json`](observability/grafana/stumpfworks-overview.json).
Starter Prometheus alert rules live in
[`observability/prometheus`](observability/prometheus).

## Status

The current vertical slice provides typed configuration, structured JSON
logging, build information, health endpoints, safe HTTP defaults, request IDs,
panic recovery, graceful shutdown, and optional PostgreSQL connectivity.

## License

Licensed under the Apache License, Version 2.0.
