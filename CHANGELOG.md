# Changelog

All notable changes to StumpfWorks Framework are documented here. The project
follows Semantic Versioning; APIs may change during `0.x` development.

## [Unreleased]

## [0.9.0-rc.2] - 2026-10-07

### Fixed

- Accept a unique local LDAP search result when Samba AD also returns referral
  responses, while continuing to reject referral-only and ambiguous results
  and never following referrals.

### Verified

- Identity and Access consume and run `v0.9.0-rc.2` in production with tested
  rollback paths.
- A real OIDC login exercised Identity's framework LDAP lookup successfully;
  an unlinked Identity subject was denied by Access.
- During a controlled Identity outage, Access stayed ready, local login
  remained available, new OIDC login failed closed, and recovery succeeded.
- Access delivered dedicated OIDC outage and recovery notifications to the
  protected operator-owned ntfy topic.
- Release checksums, CycloneDX SBOM, keyless provenance and SBOM attestations
  were published and independently verified.

## [0.9.0-rc.1] - 2026-10-06

### Added

- Consumer-validated OIDC login, key refresh, permission and audit contracts.
- Bounded read-only LDAPS lookup with live Identity activation over verified TLS.
- PostgreSQL pool observations and privacy-bounded HTTP/directory metrics.
- Access, Identity and central-log Grafana dashboards plus Prometheus alerts.
- Tested single-node observability backup and isolated restore verification.
- Release-candidate public API and compatibility policy.

### Changed

- Re-scoped events, outbox, webhooks, AI and device SDK abstractions out of 1.0
  until a real consumer justifies their public contracts.
- Standardized the public module path as
  `github.com/mrheiz97/stumpfworks-framework`.

### Security

- Added bearer-protected metrics, mTLS log ingestion, bounded metric labels and
  centralized secret-safe logs.
- Validated OIDC signing-key overlap/removal, stale-key behavior and consumer
  recovery without transferring application authorization into Identity claims.

## [0.1.0-alpha.1] - 2026-09-14

### Added

- Application lifecycle with bounded HTTP shutdown and owned resources.
- Strict layered JSON/environment configuration.
- Structured logging with centralized secret-field redaction.
- Cryptographically random UUID generation and coded internal errors.
- Secure HTTP middleware, correlation IDs, privacy-safe request logs, health
  endpoints, RFC 9457 Problem Details, bounded JSON decoding, strict opt-in CORS,
  and concurrent-request overload protection.
- TLS-by-default PostgreSQL pooling and forward-only transactional migrations.
- Immutable audit-event envelope, PostgreSQL schema, and append-only store API.
- Unit, integration, race, build, vet, and vulnerability checks in CI.
- Pinned-issuer OIDC Discovery/JWKS, offline RS256 ID-token validation,
  Authorization Code with PKCE S256, browser-bound one-use transactions, and
  encrypted transaction persistence for consumer-owned storage.
- Bounded OIDC metadata cache, managed refresh loop, and freshness status.
- Opt-in Prometheus-compatible HTTP request metrics.

### Security

- Raised the minimum toolchain from the initial Go 1.24 assumption to Go 1.26
  after vulnerability scanning found reachable standard-library issues.
- Updated pgx to 5.11.0 and `golang.org/x/text` to a fixed release line.

### Fixed

- Serialized creation of the migration tracking table under the advisory lock,
  preventing concurrent first-start PostgreSQL catalog races.
