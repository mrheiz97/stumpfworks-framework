# ADR 0011: Read-only directory adapter before Identity cutover

- Status: Proposed (local prototype, not deployed)
- Date: 2026-09-17

## Context

Identity currently owns LDAP/Samba-AD queries and a SQLite-specific store.
Framework integration should reuse infrastructure without moving identity
policy into the framework or coupling multiple risky production changes.

## Decision

Prototype a read-only `directory/ldap` adapter for enabled AD user lookup.
Require verified LDAPS, least-privilege service credentials, escaped filters,
bounded responses and deadlines. Do not follow referrals or add an implicit
certificate-verification bypass. Keep authentication/authorization, directory
writes, OIDC issuance, badges, PKINIT and Kerberos in Identity.

PostgreSQL is the intended standard, but Identity owns its schema and migration.
Reuse framework transaction/migration/pool primitives; rehearse a loss-aware
data transfer before a separate consumer cutover. LDAP and PostgreSQL rollouts
are separate changes. The existing certificate-pin exception requires an
explicit consumer compatibility decision, not silent import into framework.

## Consequences

The prototype is not a general Samba administration API and not yet a full
replacement for Identity's Directory interface. Successful local protocol
fixtures are not a live AD compatibility claim. Existing product behavior and
production infrastructure remain unchanged until consumer integration and
recovery tests are complete. See `../IDENTITY-INTEGRATION.md` for evidence.

Lookup telemetry is limited to fixed outcome/protocol-stage vocabularies and
duration. This
supports Prometheus/Grafana without treating usernames, DNs, error strings, or
other identity data as metric labels. The observer is diagnostic only and may
not influence lookup results or authorization decisions.
