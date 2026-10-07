# Implementation Status

## Candidate: 0.1.0-alpha.1

The initial vertical slice is implemented and builds on Go 1.26. It covers Core,
configuration, logging, HTTP lifecycle, health, PostgreSQL, migrations, strict
request decoding, and the audit foundation.

## Verified locally on 2026-09-12

- `gofmt`, `go vet`, `go test ./...`, and `go build ./...` pass.
- Ten shuffled repetitions of all unit tests pass.
- The minimal app returns 200 for liveness and readiness, with correlation and
  security headers.
- Invalid configuration exits non-zero with a structured error.
- `govulncheck` 1.8.0 reports no reachable vulnerabilities after the Go 1.26
  and dependency upgrade.

## Verified in GitHub CI

- The first private-repository workflow on `main` completed successfully.
- Linux race detection passed.
- PostgreSQL 17 integration passed, including migration application, audit
  insert/read-back, idempotency, concurrent migration runners, and transaction
  rollback.
- The Linux build and current pinned `govulncheck` scan passed.

The initial PostgreSQL integration was CI-only because the local Docker daemon
was unavailable. A disposable native PostgreSQL 17 cluster was subsequently
used on Windows for the local Identity rehearsals below.

## Local integration preparation, 2026-09-17

- Read-only AD/Samba-AD LDAPS prototype: verified TLS, deadlines, no referrals,
  escaped filters, 1 MiB wire budget, 16-message cap, 32 nesting levels and 4096
  BER nodes per message. Config/reader formatting and JSON logging are redacted.
  Unit/protocol tests pass; a 20-second fuzz run tested about 345,000 inputs.
- Identity has an inactive PostgreSQL adapter, bounded all-table importer,
  shared backend contracts, atomic badge-plus-audit operation, pg_dump/restore
  probe and real OIDC-handler/framework-client contract over trusted local TLS.
  See `IDENTITY-INTEGRATION.md`. No production cutover or live LDAP acceptance.
- Go 1.26.8 is now enforced. With matching build/scanner toolchains, scans report
  no reachable or imported-package findings; one unused OpenPGP module advisory
  remains. This is not a blanket vulnerability-free dependency claim.
- Framework PR #32 passed fresh GitHub CI on 2026-09-18, including Linux race
  detection and PostgreSQL integration. Windows has CGO disabled and no local
  GCC for race testing. Identity's separate CI changes are still local.

## Identity bridge preparation, 2026-09-18

Identity now has an inactive bridge from its read-only user lookups to a pinned
framework LDAPS revision. Authentication, admin policy and listing remain
consumer-owned. Its local full test suite, vet, module verification and repeated
synthetic PostgreSQL/OIDC/TLS-LDAP contracts pass. No production adapter switch,
live LDAP acceptance or database migration occurred.

On 2026-09-22, read-only inspection confirmed that DC01 still presents a
temporary Samba certificate without a DNS SAN. Secure live framework lookup is
therefore blocked on certificate replacement, not on an application fallback.
The staged reader now emits bounded, privacy-safe outcomes and durations, and
the framework registry exports corresponding Prometheus counter/histogram data.
An importable Grafana starter dashboard now shows target availability, HTTP
rate/p95 latency, and directory rate/p95 latency by bounded outcome and stage.
Its JSON and privacy-label contract are tested, and the live Access, Identity
and logs dashboards are provisioned and API-validated in Grafana.
PostgreSQL pool snapshots now expose only bounded connection state and aggregate
acquire counters/duration. Dashboard panels and starter alerts cover pool usage,
waiting and cancellations. A real disposable PostgreSQL 17 pool exposition test
passed three shuffled repetitions; no database identity, URL or SQL is exported.

## OIDC client progress on 2026-09-13

The framework now has pinned-issuer Discovery and JWKS retrieval, an offline
RS256 ID-token verifier, confidential Authorization Code + PKCE S256 login,
one-use browser-bound transactions, and bounded Discovery/JWKS freshness.
Pending transactions can now be sealed for consumer-owned PostgreSQL storage;
an integration test verifies browser binding and atomic one-use retrieval.
`ACCESS-OIDC-INTEGRATION.md` records the next consumer steps. A provider-neutral
AI interface is noted only as a future candidate in the roadmap.
The latest merges passed the full GitHub CI workflow on both `main` and
`develop`, including race tests, PostgreSQL integration, build, vet, and the
vulnerability scan.

This remains a client library, not a complete application login. Access now
wires the browser cookie, callback, account link, and local session. Scheduled
and monitored metadata refresh is still open. Identity itself was not changed
by the framework implementation.

## Live OIDC contract check on 2026-09-14

- The opt-in `test/contract` check passed against the deployed Identity issuer
  using normal TLS verification. It
  covered Discovery, JWKS, and framework PKCE S256 login initialization; no
  client secret, user login, code exchange, or application session was used.
- This framework-side check made no production changes. It was only the first
  stage of the consumer acceptance test.

## Access consumer status on 2026-09-14

The Access project's validation record reports that its framework-backed OIDC
consumer is deployed and that a real browser login with an explicitly linked
Identity account succeeded. Its PostgreSQL integration tests cover successful
and negative flows; its deployment record describes a restricted backup and
rollback procedure. These are Access-project results, not tests independently
rerun by this framework repository. A controlled live issuer-outage acceptance
was completed on 2026-10-07.
Do not put deployment hostnames, IP addresses, or secrets in this public status
document.

The framework's local cache test covers overlapping old/new JWKS keys. Access
also passed isolated issuer-outage/recovery and overlapping-key integration tests
against a disposable PostgreSQL database. In a controlled live Identity rotation,
the operator confirmed a fresh Access browser login after the new key became the
only advertised key. The OIDC contract test, Identity and Access service checks,
and Identity token-issuance audit passed. The consumer's refresh loop runs every
ten minutes and logs each result. During a controlled Identity outage, Access
remained ready, local login and logout worked, and new OIDC login failed closed.
After Identity restarted, OIDC initialization recovered successfully.

Access now uses its optional ntfy notifier for refresh failure, stale-key
escalation, and recovery. Its dedicated token and the operator-owned protected
topic were deployed without committing or exposing the credential. Direct test
delivery and automatic outage/recovery publications were verified. Central
Alertmanager delivery to the same operator-owned destination also remains active.

## Before tagging alpha.1

- [x] The maintainer confirmed Apache-2.0 on 2026-09-14.
- [x] The canonical module path now matches the `mrheiz97` repository owner.
  Framework CI passed at `86400d1`; Access CI passed at `8823384` and Identity
  CI passed at `4d1d042` after both consumers migrated (ADR 0009).
- [x] Add a permanent private vulnerability-reporting address:
  `hello@stumpfworks.de`.
- [x] Perform the documented quick start in a clean local checkout. On
  2026-09-14, `go test ./...` and the minimal-app build passed; both liveness
  and readiness returned HTTP 200. No PostgreSQL service was required.

## Release pipeline preparation, 2026-10-03

- A tag-only workflow now requires a GitHub-verified signed annotated tag whose
  commit belongs to `main`.
- The workflow produces a source archive, CycloneDX SBOM and SHA-256 checksums,
  then creates keyless provenance and SBOM attestations before publishing.
- The `v0.9.0-rc.2` release completed the pipeline successfully. Downloaded
  checksums, the CycloneDX SBOM, keyless provenance and SBOM attestations were
  independently verified; GitHub marks the release as a prerelease.

## Authorization and audit acceptance, 2026-10-03

- Access consumes the exact-match framework permission set while retaining its
  own administrative override and physical-action policy. Negative tests prove
  that `access.admin` does not grant `access.action.execute`.
- Identity retains separate administrator and self-service audiences rather than
  inventing shared roles. Both consumers keep OIDC claims separate from local
  authorization.
- The framework audit envelope now bounds every text field and metadata size in
  addition to nesting depth and sensitive-key rejection.
- Access provides transactional audit rollback tests. Identity provides atomic
  tests for its migrated critical badge flows; its remaining best-effort legacy
  mutations stay an explicit production-cutover blocker.

## Device and event-boundary acceptance, 2026-10-03

- Access records real enrollment, authenticated polling, stable command IDs,
  acknowledgement and revocation with the ESP8266 reference node. The operator
  confirmed both `FULL_OPEN` and `PEDESTRIAN_OPEN` on the real gate.
- Electrical measurements plus crash/journal fault injection remain Access
  release gates; they do not invalidate the accepted protocol flow.
- No current consumer requires an outbox, broker or webhook contract. Those
  components are deliberately excluded from 1.0 until an application provides
  delivery, ordering and retry requirements.

## Live observability acceptance, 2026-10-04

- The single-node Prometheus, Grafana, Loki, Alloy and Alertmanager deployment
  collects protected Access metrics and bounded-label journald logs from the
  Docker, Access and Identity hosts.
- The operator confirmed authenticated alert delivery through Alertmanager to
  ntfy over separately trusted internal TLS.
- Prometheus now monitors itself, Alertmanager, Loki and Alloy. Validated rules
  cover target outages, Prometheus-to-Alertmanager failures, notification
  delivery failures, Loki server errors and dropped Alloy log entries. All five
  initial scrape targets, including Access, were healthy after activation.
- Identity's prepared bearer-protected framework metrics were then deployed with
  a systemd credential, verified Homelab TLS and dedicated availability,
  error-rate and latency alerts. Unauthorized access returns HTTP 401 and all
  six current scrape targets were healthy after activation.
- A focused Identity Grafana dashboard was provisioned and verified through the
  Grafana API. It presents availability, bounded status rates, server-error
  ratio and latency without identity or authentication labels.
- This validates the observability path, but does not by itself establish
  overall application production readiness.

## Observability recovery acceptance, 2026-10-06

- A root-only consistent backup captured deployment configuration and the
  Prometheus, Grafana, Alertmanager, Loki and Alloy volumes during a short,
  monitoring-only maintenance window.
- Every archive checksum passed. An isolated restore verified Grafana's SQLite
  integrity, Prometheus TSDB analysis and restored Loki content, then removed
  all temporary volumes.
- The live stack restarted automatically and all six scrape targets were
  healthy. Prometheus retains 15 days and Loki 14 days. Access and SMB-specific
  boundaries are recorded in `OBSERVABILITY-OPERATIONS.md`.
- The validated copy currently resides on the Docker host. An encrypted
  off-host copy remains an operator responsibility and is required for actual
  host-loss disaster recovery.

## Live Identity directory activation, 2026-10-06

- DC01 now presents a Homelab-CA-signed LDAPS certificate for
  `dc01.ad.stumpfworks.de` with DNS, IPv4 and IPv6 SANs. The private key was
  generated and retained on DC01. Samba, verified LDAPS and the AD database
  check passed after restart; the previous TLS directory remains a rollback.
- Identity enables the framework adapter only for `GetUser` and `UserExists`.
  Existing password authentication, user listing, writes and SQLite persistence
  remain unchanged. Health, OIDC Discovery and runtime selection passed with an
  automatic rollback rehearsal.
- On 2026-10-07, a fresh Access browser login exercised the live framework
  lookup and token issuance successfully. The directory success metric confirmed
  the adapter path. Both applications ran `v0.9.0-rc.2` with prepared rollback,
  and an unlinked Identity subject was denied by Access as designed.

## Stable 1.0 acceptance, 2026-10-07

- Framework, Access and Identity full Go tests and vet passed with clean diffs.
- Access remained active with no failed systemd units. Its rollback contains a
  distinct previous binary, unit and protected configuration; the PostgreSQL
  custom-format dump is readable by `pg_restore`.
- Identity remained active with no failed systemd units. Its rollback contains
  a distinct previous binary, configuration and SQLite snapshot. Both the live
  SQLite database and the latest separate daily backup pass integrity checks.
- These results close the Framework consumer upgrade, migration, backup and
  rollback gate. They do not replace Access's separate electrical measurement
  and physical crash testing or Identity's future PostgreSQL cutover and legacy
  mutation-audit migration.
- The accepted public surface is released as `v1.0.0`; later 1.x changes follow
  the compatibility policy in `API-STABILITY.md`.
- Identity and Access were then pinned to `v1.0.0`, passed their full Go test and
  vet suites, and were deployed with new root-only binary/configuration
  rollbacks. Both services restarted cleanly; Access readiness, Identity health,
  Discovery and the Access-to-Identity OIDC authorization redirect returned
  successfully over verified TLS.
