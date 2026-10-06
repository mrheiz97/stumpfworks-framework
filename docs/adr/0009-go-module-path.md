# ADR 0009: Go module path follows the repository

- Status: Accepted
- Date: 2026-09-13
- Amended: 2026-10-03

## Context

The initial module path was `github.com/stumpfworks/framework`, followed by the
historical owner path `github.com/TheRealHZL/stumpfworks-framework`. GitHub now
hosts the public repository under `github.com/mrheiz97/stumpfworks-framework`.
Keeping the redirected historical path would make ownership and long-term import
stability unclear before version 1.0.

## Decision

Use `github.com/mrheiz97/stumpfworks-framework` as the canonical Go module
path. Package imports, examples, tests, and build metadata use that path.

## Consequences

The pre-1.0 migration is intentionally breaking. Identity and Access must update
their imports and module requirements in the same integration cycle. Historical
pseudo-versions remain addressable through GitHub's redirect, but new releases
and consumer updates use only the canonical `mrheiz97` path. A future repository
transfer must preserve that path or use a deliberate vanity import migration.
