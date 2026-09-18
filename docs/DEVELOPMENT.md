# Development

## Quality checks

Use Go 1.26.8 or a newer patched release:

```bash
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

Release builds can inject version metadata:

```bash
go build -ldflags "-X github.com/TheRealHZL/stumpfworks-framework/core/version.Version=0.1.0 -X github.com/TheRealHZL/stumpfworks-framework/core/version.Commit=$GIT_COMMIT -X github.com/TheRealHZL/stumpfworks-framework/core/version.BuildTime=$BUILD_TIME" ./examples/minimal-app
```

The race detector needs CGO locally. Linux CI runs it on every change.

## PostgreSQL integration test

The Compose service is bound to localhost and uses development-only credentials:

```bash
docker compose up -d postgres
SWF_TEST_POSTGRES_URL='postgres://swf:swf-local-only@127.0.0.1:5432/swf?sslmode=disable' go test -tags=integration ./test/integration
docker compose down
```

PowerShell uses this environment-variable syntax:

```powershell
$env:SWF_TEST_POSTGRES_URL='postgres://swf:swf-local-only@127.0.0.1:5432/swf?sslmode=disable'
go test -tags=integration ./test/integration
```

The integration test drops only the framework-owned tables in the explicitly
provided test database. Never point it at a production database.

## Minimal application

Without PostgreSQL:

```bash
go run ./examples/minimal-app
```

With the local database, set `SWF_POSTGRES_URL` to the URL above. Configuration
file values can be loaded with `SWF_CONFIG_FILE`; also set
`SWF_POSTGRES_ALLOW_INSECURE=true` for this local plaintext-only service. Environment variables take
precedence.
