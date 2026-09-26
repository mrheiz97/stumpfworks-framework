# Roadmap

## 0.1 — Foundation

- [x] Typed environment configuration and validation
- [x] Structured JSON logging
- [x] Build metadata
- [x] HTTP lifecycle and graceful shutdown
- [x] Liveness and readiness endpoints
- [x] PostgreSQL pool and readiness check
- [x] Explicit PostgreSQL transaction helper
- [x] Forward-only transactional migration lifecycle
- [x] Audit event model and PostgreSQL adapter
- [x] Problem Details response model
- [x] Bounded strict JSON input validation

Later milestones remain defined in `ARCHITECTURE.md` and will be broken down as
real consumers validate the design.

## 0.2 — Conventions and hardening

- [x] Central secret-field classification
- [x] Privacy-safe request logging and security headers
- [x] Opt-in strict CORS policy
- [x] Concurrent-request overload protection
- [x] Standard coded errors and RFC 9457 mapping
- [x] Opt-in Prometheus-compatible HTTP metrics
- [x] Constant-time bearer protection for consumer metrics endpoints
- [x] Initial Core and HTTP threat model
- [x] Initial Auth/OIDC client threat model and 0.3 contract boundary
- [x] First Identity consumer integration in Access (see `ACCESS-OIDC-INTEGRATION.md`)

## 0.3 — OIDC client

- [x] Offline, pinned-issuer RS256 ID-token verifier with bounded JWKS and claims
- [x] Pinned-issuer Discovery and JWKS fetch with bounded responses, same-origin endpoints, no redirects, and TLS verification
- [x] One-use browser transaction, PKCE S256, confidential code exchange, and ID-token handoff
- [x] Optional bounded browser-bound transaction store for single-process consumers
- [x] Encrypted transaction codec for consumer-owned, one-use PostgreSQL storage
- [x] Age-bounded, atomic Discovery/JWKS refresh helper with fail-closed stale keys
- [x] Consumer-owned cookie/session wiring in Access
- [x] Contract test against the real Identity provider and first consumer
- [x] Optional managed metadata refresh loop and freshness status in the framework
- [x] Access refresh-loop wiring and result logging
- [x] Access isolated issuer-outage/recovery tests and live Identity key-rotation acceptance
- [ ] Deploy and verify Access ntfy alert delivery (notifier prepared locally)
- [ ] Live issuer-outage acceptance (no planned production shutdown)

## Next integration — Identity directory and PostgreSQL

Identity directory and PostgreSQL migration preparation is tracked in
`IDENTITY-INTEGRATION.md`. A read-only LDAPS lookup prototype is local work,
not yet consumer-integrated or accepted against Samba AD.

## 0.4 — Identity backend and authorization contracts

Work in this milestone is validated in Identity before an API is treated as
stable framework surface.

- [x] Stage the read-only framework LDAPS bridge behind a default-off switch
- [x] Stage Identity's PostgreSQL schema, importer and backend contract tests
- [x] Run PostgreSQL, backup/restore and framework integration checks in CI
- [x] Define explicit audit-failure policy for authentication, denials and
  security-sensitive state changes
- [x] Replace Identity's concrete SQLite server dependency with the smallest
  backend interface shared by SQLite and PostgreSQL
- [x] Wire a fail-closed, default-SQLite PostgreSQL runtime selection without
  running migrations under runtime credentials
- [x] Rehearse backup, import, verification and rollback using synthetic data
  through the real Identity startup path
- [ ] Replace the Samba AD certificate with a trusted certificate containing
  the required DNS SAN, then accept the read-only LDAPS adapter live
- [ ] Derive the first RBAC/permission contract from real Identity and Access
  requirements; keep application-specific roles outside the framework

No production database or directory cutover is part of the framework milestone.
Those changes require a separate Identity deployment gate and rollback record.

## Path to 1.0

- [ ] Resolve and document the mismatch between the public repository owner
  and the existing Go module path before freezing imports
- [ ] Validate RBAC and audit contracts with Identity and Access
- [ ] Add events/outbox and webhooks only from a real consumer requirement
- [ ] Validate the device protocol with real Access nodes
- [ ] Complete protected metrics collection, logs, dashboards and alert delivery
- [ ] Produce an SBOM and signed, traceable release artifacts
- [ ] Freeze and document public APIs in a release candidate
- [ ] Test upgrades, migrations, backups and rollback for both consumers
- [ ] Confirm Identity and Access are production-capable on the release candidate

## Future candidate — optional AI integration

When a real application needs AI, evaluate a small provider-neutral text
generation interface in the framework. Applications should choose a provider
and model through configuration, without depending on provider-specific APIs.
Potential adapters are OpenAI, an OpenAI-compatible local Ollama endpoint, and
Claude. Provider-specific features should remain explicit capabilities, not be
forced into a lowest-common-denominator interface. Streaming, tools, images,
embeddings, and fallback routing are out of scope until a consumer needs them.
Any implementation must bound time, request/response size, and spending; keep
API keys out of logs; and make external data transfer opt-in. Do not build this
module before a concrete consumer validates the interface (Architecture 5.6).

## Future milestone — self-hosted observability (Homelab and SMB)

Keep three concerns separate: Prometheus-compatible metrics for rates, latency,
errors, and service health; structured JSON logs collected centrally (candidate:
Grafana Alloy/journald -> Loki) for investigating individual failures; and
durable security audit events in PostgreSQL. Grafana should present these
together in useful dashboards for both Homelab operators and small businesses.
InfluxDB remains an optional additional
source for sensor, energy, or other existing time-series data; it is not the
default store for detailed application logs.

The framework already provides JSON logging, opt-in HTTP request metrics, and an
importable Grafana starter dashboard for service, HTTP, and directory health.
Versioned Prometheus starter rules cover sustained service, HTTP, and directory
failures; delivery remains deployment-owned.
Credential-free PostgreSQL pool metrics and dashboard/alert coverage include
connection utilization, waits, cancellations, and cumulative acquire duration.
The staged LDAPS reader now also exposes bounded lookup outcomes, protocol stage
and duration;
the metrics registry exports them as Prometheus counters and histograms without
usernames, DNs, arbitrary errors, or other high-cardinality labels.
Still open: a protected metrics endpoint in consuming applications, consistent
log fields and per-component levels, additional health/DB/auth metrics, a
collector/deployment example, retention and access rules, and validated live
dashboard provisioning. Start with a low-maintenance single-node setup; document a path to
multiple services and sites, role-based dashboard access, backups, configurable
retention, and alerting for SMB use without making those requirements mandatory
for Homelabs. Keep tokens, passwords, PINs, raw OIDC URLs, and other secrets out
of logs; avoid user IDs, request IDs, and raw paths as metric labels. Add these
incrementally as Identity and Access integrations provide real use cases.
