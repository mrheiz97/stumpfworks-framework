# ADR 0013: Pure certificate verification boundaries

- Status: Accepted for implementation
- Date: 2026-11-01

## Context

Identity's prepared certificate contracts identified reusable verified-peer and
issued-leaf checks. Device namespaces, CA bootstrap/rotation, credential state,
token modes, issuance, PKINIT and audit are consumer policy, not framework policy.

## Decision

Add opt-in `security/certificates` using standard Go TLS/X509. Require explicit
time and client/server EKU; issued-leaf verification additionally requires explicit
trust roots and expected PUBLIC key DER. Support an optional verified-root pin.
Return detached public metadata and bounded sentinel errors. Do not perform IO,
signing, revocation lookups or implicit application/transport activation.

## Consequences

No Identity imports or dependency changes are needed. No existing framework
consumer changes behavior. Policy-specific single-URI rules stay in adapters.
Identity migration, HTTP-client consolidation and CSR/signing extraction remain
separate. Compatibility and rollout guidance is in `docs/certificates.md`.
