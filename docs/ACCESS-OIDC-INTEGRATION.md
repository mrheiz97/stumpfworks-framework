# Access OIDC consumer integration plan

Status: Access reports the framework-backed consumer deployed and a successful
real browser login on 2026-09-14. A controlled live Identity signing-key rotation
and isolated issuer-outage/recovery tests also passed. This document retains the
original design and acceptance checklist; see `STATUS.md` for the current summary.
Live issuer-outage acceptance and a dedicated refresh alert remain open. Access
runs the framework refresh loop and logs each result.

## Existing consumer boundary

Access already has an OIDC login in `internal/auth/oidc.go`. It stores hashed
state and browser binding in PostgreSQL, atomically deletes an attempt on
callback, links only `(issuer, subject)` to an existing user, and owns its
session, rate limits, audit, and local fallback login. Preserve those behaviours.
Its Go 1.26 baseline matches SWF. Identity currently advertises Authorization
Code, PKCE S256, RS256, and `client_secret_basic`, which match `auth/oidc`.

## Proposed replacement boundary

1. At startup, configure one pinned issuer, exact callback URI, trusted Homelab
   CA, and `ConfigurationCache`. Refresh before accepting new OIDC logins,
   publish a new `LoginClient` after each successful refresh, and schedule
   monitored refreshes before the configured maximum age.
2. At login start, call `LoginClient.Begin` and `NewBrowserBinding`. Seal the
   transaction with `TransactionCodec` using a separate persistent random
   32-byte key. Store ciphertext and hashed state/browser binding in Access's
   PostgreSQL attempts table. Access keeps its own rate limiting and redirect.
3. At callback, read and clear the host-only browser cookie. Atomically delete
   the matching unexpired row using both digests. Call `codec.Open` and then
   `transaction.Complete`. Pass only the verified `(issuer, subject)` to Access's
   existing account-link and session transaction. Never grant roles from claims.
4. Keep the old login implementation available for rollback until the new path
   passes tests. Do not use the process-local `TransactionStore` for Access.

The original attempts table stored plaintext nonce and PKCE verifier. Access's
framework adapter now stores the sealed transaction encoded in the existing
verifier column, avoiding an immediate schema change. Pending attempts can
expire after five minutes during cutover. The codec key must survive restarts and be shared by
replicas; rotation must overlap pending attempts or intentionally invalidate
them. It must not be logged or committed.

## Acceptance before rollout

An opt-in first-stage live contract check is available in
`test/contract/identity_test.go`. Set `SWF_TEST_IDENTITY_ISSUER` and
`SWF_TEST_IDENTITY_CLIENT_ID`, plus `SWF_TEST_IDENTITY_CA_FILE` for a private
Homelab CA, then run `go test ./test/contract -v`. It verifies Identity's
Discovery/JWKS and that the framework can start a PKCE S256 login. It does not
authenticate a user, exchange a code, test browser cookie behaviour, or prove
Access account/session integration. Do not put real client secrets in test
configuration or the repository.

- Browser test with Identity's cross-site 303-to-GET callback and the
  `SameSite=Lax` binding cookie. Access currently uses `SameSite=None`; do not
  change it without this test.
- Live Development contract test against Identity with verified Homelab TLS:
  discovery, JWKS, login, PKCE, nonce, callback, and explicit account linking.
- Negative tests for wrong browser, state, code replay, expired/tampered sealed
  record, wrong issuer/key, unlinked or inactive user, and issuer outage.
- Confirm existing Access sessions, roles, physical grants, local login,
  audit, and rate limits are unchanged. No production credentials in tests.

## Production change gate and rollback

The framework-based Access replacement was deployed on 2026-09-14 according to
Access's validation and rollout records. Its restricted pre-change backup and
rollback script live on the Access host; this framework repository does not
contain them. The current Access checkout has no Git commits, so its local
source tree alone is not a sufficient rollback artifact. For any further binary
or schema change:

1. Identify the exact active binary and configuration paths from the local
   deployment documentation and validate them on the host without printing
   environment-file contents or secrets.
2. Record checksums of the active binary and relevant non-secret artifacts.
   Create a new, restricted, change-specific backup of the binary, service
   configuration, and environment file on the host. Verify the backup files
   exist and their checksums match. Do not copy secrets into the repository.
3. Confirm a recent restorable PostgreSQL backup. A migration that replaces
   plaintext transaction columns needs an explicit database rollback plan;
   existing pending OIDC attempts may be allowed to expire before cutover.
4. Build and test the new Access binary locally, including negative OIDC,
   session, role, grant, local-login, audit, and rate-limit cases. Keep the old
   path available until the new one is proven.
5. Deploy in a maintenance window; check service readiness and complete a real
   browser login with the operator. On failure, stop the new path, restore the
   exact backed-up binary/configuration (and database state if changed), then
   verify readiness and the local recovery login.

The Access rollout record reports a change-specific backup and successful
post-deployment login. Verify a fresh backup and rollback for each later update;
do not treat the first deployment's backup as current indefinitely.
