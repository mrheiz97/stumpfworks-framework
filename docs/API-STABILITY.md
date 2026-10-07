# Public API stability for 1.0

This document freezes the public surface for `v1.0.0`. The Framework-backed
Identity and Access paths passed production acceptance; application-specific
release gates remain outside this API freeze.

## Supported library packages

The exported identifiers and documented behavior in these packages form the
candidate public API:

- `audit` and `audit/postgres`
- `auth/oidc`
- `authz`
- `core/app`, `core/config`, `core/errors`, `core/id`, `core/logging` and
  `core/version`
- `data/migrate` and `data/postgres`
- `directory/ldap`
- `security`
- `web/health`, `web/metrics`, `web/middleware`, `web/problem` and
  `web/validation`

For these packages, exported Go documentation, validation rules, sentinel
errors and documented security defaults are part of the contract. Changes from
the RC to 1.0 should be backward-compatible unless acceptance finds a security
or correctness defect that cannot safely be fixed compatibly. Such a change
must be called out in the changelog with migration guidance.

## Deliberately excluded surfaces

- `internal` implementation details, test fixtures and unexported identifiers
- `examples/minimal-app` and `test/contract`
- Grafana dashboards, Prometheus rule files and operational scripts, which are
  versioned deployment artifacts rather than Go APIs
- application-specific Identity, Access, badge, gate, role and tenant policy
- events, outbox, webhooks, AI providers and device SDKs not justified by a
  current consumer

Configuration environment names and database migrations already documented as
consumer inputs remain supported for the 1.x line. Dashboard layout, log wording
and metric help text may improve, but metric names and bounded label sets should
not be removed or widened incompatibly without deprecation.

## Compatibility policy

- Additive functions, methods, fields and metrics are allowed when safe.
- Existing behavior may be tightened to reject insecure or previously invalid
  inputs; the security impact and migration must be documented.
- Deprecations remain available for at least one compatible minor release before
  removal, except for an actively exploitable security issue.
- Breaking API changes after `v1.0.0` require a new major version.
- Consumers should pin a tagged version and run their own integration tests
  before upgrading.

The Go module path is permanently
`github.com/mrheiz97/stumpfworks-framework` for this major version.
