# Authorization and audit consumer contract

This record fixes the shared boundary validated against Access and Identity.
It does not move either application's business policy into the framework.

## Authorization

- Framework permissions are bounded, case-sensitive, exact-match keys. There
  are no wildcards, hierarchy, deny rules or implicit administrator grants.
- Access validates stored permissions through `authz.Set`. Its local
  `access.admin` override applies only to administrative HTTP handlers and does
  not grant `access.action.execute` or a physical-access policy binding.
- Identity currently has two separate signed session audiences: administrator
  and self-service. Directory group membership and self-service ownership checks
  remain Identity policy; manufacturing framework permissions for them would add
  no shared contract.
- OIDC identity claims never create local roles or permissions in either
  consumer. Account linking and authorization remain explicit consumer actions.

## Audit

- The framework audit envelope rejects missing, invalid, oversized or
  secret-labelled data before persistence. Metadata is limited to 16 KiB and 16
  levels of nesting.
- Access commits security-sensitive mutations and their audit records in one
  PostgreSQL transaction. Its integration tests inject audit failures and prove
  rollback for login, enrollment and administrative mutations. Physical command
  denial and execution are audited separately.
- Identity defines the same fail-closed policy for successful credential
  issuance and security-sensitive mutation. Lost-badge revocation and pending
  replacement activation are atomic on SQLite and PostgreSQL, and backend
  contract tests inject audit failures.
- Identity still has legacy successful mutations with visible best-effort audit
  writes. They are an explicit production-cutover blocker and must move to
  transaction-owned store methods before PostgreSQL becomes the production
  backend.

## Acceptance

The shared authorization and audit contracts are validated for their current
consumer use. This does not claim that Identity is production-ready, that every
legacy mutation is atomic, or that application-specific roles are stable public
framework API. Those gates remain tracked separately in the roadmap.
