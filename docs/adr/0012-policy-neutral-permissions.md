# ADR 0012: Policy-neutral permission sets

- Status: Accepted
- Date: 2026-10-02

## Context

Access owns namespaced permissions such as `access.user.manage` and deliberately
keeps `access.action.execute` separate from administrative control. Identity
currently separates administrator and self-service session audiences. Their
roles, directory groups and object scopes are application policy and do not
have shared semantics.

## Decision

SWF provides only validated permission keys and bounded exact-match sets.
Permission keys are application-owned, case-sensitive lowercase ASCII segments.
The framework implements no roles, wildcard matching, deny rules, hierarchy,
administrator override, directory-group mapping or tenant scope.

Consumers explicitly decide whether a permission such as `access.admin` may
override another administrative permission. They must never infer physical
access, credential issuance or another application's rights from it.

## Consequences

The shared contract is small enough for sessions and middleware without moving
business policy into SWF. Consumers retain their existing database models and
last-administrator protections. Scoped grants and role mapping require a later
consumer-driven design rather than a backward-compatible assumption.
