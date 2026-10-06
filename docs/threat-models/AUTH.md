# Auth and OIDC Client Threat Model

- Status: OIDC client primitives implemented; consumer wiring and live contract
  test still pending
- Date: 2026-09-13
- Scope: future SWF OIDC client, ID-token verification, callback/session handoff,
  and the boundary between Identity and an application such as Access

## Boundary and assets

Identity is the external authority for authentication and stable subjects. The
consumer owns its local account link, roles, policies, and session. SWF must not
copy Identity's badge, PIN, PKINIT, AD, or user-management logic. A successful
Identity login is not an authorization decision for an application's resources.

Assets are authorization codes, PKCE verifier, state and nonce, client
credentials, ID tokens, signing keys, local sessions, and the `(issuer, subject)`
account link. These values must not appear in URLs beyond the protocol-required
code/state callback, logs, metrics, audit free text, or diagnostic packages.

## Trust boundaries

1. The browser crosses into the application's login and callback endpoints.
2. The application crosses a TLS-authenticated boundary to Identity's discovery,
   token, and JWKS endpoints.
3. A signed ID token crosses into the verifier; its claims are untrusted until
   signature and all required claims are checked.
4. The verified `(issuer, subject)` crosses into application-owned account
   linking and authorization. Identity claims must not grant local roles.
5. The callback crosses into a new application-owned browser session.

## Threats, intended controls, and required tests

| Threat | Intended SWF/client control | Required test |
|---|---|---|
| Login CSRF or swapped browser transaction | unpredictable one-use state bound to the initiating browser, nonce, and PKCE S256; clear transaction after use | missing, altered, replayed, or cross-browser state and nonce fail |
| Pending-login database disclosure or tampering | encrypt and authenticate persisted transaction contents, protect the codec key separately, store only state/browser digests, expire after five minutes, and atomically delete on callback | wrong key, changed ciphertext, wrong client, expired record, and replay fail |
| Code interception or injection | exact registered redirect URI, PKCE S256, short-lived one-use code; reject unexpected callback parameters | wrong verifier, redirect, replay, and duplicate parameters fail |
| Mix-up between issuers | pin one configured issuer per client configuration; verify discovery issuer exactly; if multiple issuers are later supported, add an explicit mix-up defense | metadata or response from a different issuer fails |
| SSRF through discovery or JWKS | issuer is operator-configured, exact HTTPS origin; reject discovery-supplied non-HTTPS or foreign-host endpoints unless separately approved | attacker-supplied metadata cannot redirect fetches to local/private hosts |
| Forged or confused JWT | allowlist the expected signing algorithm; select only suitable issuer JWKS keys; reject `none`, mismatched algorithm/key use, unknown `kid`, and ambiguous keys | algorithm confusion, wrong key, malformed JWT, and signature failures |
| Token substitution across clients or issuers | verify `iss`, `aud`, `exp`, `iat`, required `nonce`, and `azp` where applicable; bound clock skew; never accept an access token as an ID token | wrong audience/issuer/nonce, expired and future tokens fail |
| Stale or malicious JWKS | bounded size, timeout, cache lifetime and refresh; key rotation overlap; fail closed when no valid key is available | rotated key succeeds during overlap; unknown key fails without bypass |
| Automatic account takeover | link only an explicitly approved `(issuer, subject)` pair to a local account; never auto-link by email, display name, or username | unlinked subject is denied; local roles remain unchanged |
| Session fixation or leakage | rotate/create local session after callback; secure, HttpOnly cookie; bounded lifetime and logout; never log cookie or token | old session cannot become authenticated; logout invalidates session |
| Open redirect or sensitive callback logging | fixed post-login destination or allowlisted relative path; no raw query or token in logs/metrics | hostile return URL rejected; logs contain no code/state/token |
| Identity outage | fail new logins closed while preserving an explicitly configured local recovery path; define behaviour of existing local sessions separately | outage cannot authenticate a new user or bypass authorization |

## Initial contract for 0.3

The first SWF module should be a small relying-party client that accepts an
operator-pinned issuer, client ID, redirect URI, TLS trust configuration and
explicitly approved signing algorithms. It returns a verified subject and
minimal claims, **not** an application user or permissions. State, nonce, PKCE,
session storage, account linking and local authorization have clear interfaces
owned by the consumer; they must not be hidden behind a global singleton.

The Go module path follows the repository (ADR 0009). Before
importing SWF into Identity or Access, confirm the supported Go baseline.
The staged Identity integration and SWF now require Go 1.26.8; compatibility
and patch-security reasons are recorded in Identity's migration preparation and
ADR 0007. Production upgrades remain separate from local preparation. Identity
currently persists to SQLite and Access to PostgreSQL. Neither database is
migrated merely to consume the OIDC client.

## Current evidence and limits

Identity's `development` branch already contains an OIDC provider and tests for
PKCE, redirect validation, disabled users, key overlap, and stable subjects.
This model does not assert a fresh production end-to-end result, nor does it
declare the provider standards-complete. The first consumer must run contract
tests against the actual Identity provider and separately verify local linking,
authorization, and fallback behaviour. No production configuration is changed
by this document.

## References

- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html)
- [JWT Best Current Practices (RFC 8725)](https://www.rfc-editor.org/rfc/rfc8725.html)
- [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://www.rfc-editor.org/rfc/rfc8414.html)
- [OpenID Connect Core 1.0, ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
