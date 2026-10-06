# OIDC ID-token verification

`auth/oidc` is a narrow confidential OIDC relying-party client for one
operator-pinned HTTPS issuer. It retrieves Discovery and JWKS without redirects,
checks the advertised issuer and same-origin endpoints, performs Authorization
Code + PKCE S256, and verifies the ID token. It returns only `(issuer, subject)`;
it neither creates an application account nor grants roles or permissions.

```go
configuration, err := oidc.Discover(ctx, expectedIssuer, clientID, httpClient)
if err != nil { /* reject discovery */ }
client, err := oidc.NewLoginClient(configuration, clientID, clientSecret, exactRedirectURI, httpClient)
if err != nil { /* reject configuration */ }
authorizationURL, transaction, err := client.Begin()
if err != nil { /* reject login start */ }
binding, err := oidc.NewBrowserBinding()
if err != nil { /* reject login start */ }
if err := store.Put(transaction, binding); err != nil { /* reject login start */ }
cookie, err := oidc.BindingCookie("__Host-swf_oidc", binding)
if err != nil { /* reject login start */ }
http.SetCookie(w, cookie)
// Redirect to authorizationURL. At the fixed callback, read that cookie and:
clearingCookie, err := oidc.ClearBindingCookie("__Host-swf_oidc")
if err != nil { /* reject callback */ }
http.SetCookie(w, clearingCookie) // Do this on every callback path, including errors.
transaction, err = store.Take(callbackQuery.Get("state"), bindingFromCookie)
if err != nil { /* reject callback */ }
identity, err := transaction.Complete(ctx, callbackQuery)
if err != nil { /* reject login without exposing token contents */ }
// Look up identity.Issuer + identity.Subject in the application's explicit
// account-link table, then create a new application-owned session.
```

`Discover` uses a five-second total deadline, bounds both JSON responses, and
rejects redirects or cross-origin metadata endpoints. The default HTTP client
verifies TLS. If a custom client is supplied for a private CA, its transport
must retain certificate and hostname verification. `ConfigurationCache` is an
optional helper for a one-minute to one-hour maximum key age. Call `Refresh`
at startup and on an application-owned schedule; `Current` fails closed when
the snapshot expires. A failed refresh does not extend its deadline. There is
no automatic background refresh, and the application must monitor failures.
Even a previously constructed `LoginClient` refuses to start a new transaction
after its configuration expires. Direct `Discover` snapshots expire after one
hour; applications that need a shorter limit should use the cache. Transactions
already started may complete within their separate five-minute lifetime. After
each successful refresh, construct and publish a new `LoginClient` for new
logins. Process-local pending transactions retain their original client
snapshot and should call `transaction.Complete` at callback.
`ConfigurationCache.Status()` reports the last successful refresh, expiry time,
and whether the snapshot is currently fresh without making a network request.
Consumers can expose those values in protected health/metrics endpoints and
alert before expiry. A failed refresh leaves the last-success and expiry values
unchanged. Applications may run `ConfigurationCache.Run(ctx, interval, observe)`
in their own managed goroutine. It refreshes immediately, then at an interval
between one second and half the configured maximum age; the observer receives
every result and the new status. A failed refresh is retried on the next tick,
but the snapshot still expires on its original deadline. Cancel the context on
shutdown. The application remains responsible for exposing alerts and keeping
local/recovery login available when the issuer is down.
Unknown keys fail closed until a trusted refresh completes. Tokens cannot
redirect key fetching via `jku`, `x5u`, or embedded keys. Only RS256 public
signing keys with unique `kid`,
`alg=RS256`, and `use=sig` are accepted.

For signing-key rotation, first publish both old and new public keys in JWKS.
Allow consumers to refresh successfully before signing with the new key. Keep
the old public key available until all old-signed pending logins and tokens can
expire, including refresh propagation and clock skew; then remove it and
verify that fresh snapshots reject it. Do not rotate by replacing the sole key
in one step. The local cache test covers the overlap and removal behaviour;
rotation against a deployed provider remains a separate acceptance check.

`Begin` generates unpredictable state, nonce, and PKCE verifier.
`TransactionStore` is an optional bounded, process-local helper that stores the
transaction against a hash of an independent random browser binding. The
binding belongs in a `Secure`, `HttpOnly`, `SameSite=Lax`, host-only cookie with
path `/` and a five-minute lifetime; use a `__Host-` cookie name. A cluster
needs shared atomic storage instead. For PostgreSQL-backed consumers,
`TransactionCodec` can encrypt a transaction for a server-side record. Use a
persistent random 32-byte key shared across replicas. Store the sealed bytes
with hashes of state and browser binding. On callback, atomically delete the
matching unexpired row using both hashes, then call `codec.Open(client, sealed)`
and `transaction.Complete(...)`. The sealed bytes must never enter a cookie, URL, or
log. Retain an old codec key for at least the five-minute transaction lifetime
during rotation, or explicitly invalidate pending logins. The codec protects
confidentiality and integrity, but the database must enforce one-use retrieval.
This boundary is recorded in [ADR 0010](adr/0010-oidc-transaction-persistence.md).
With `TransactionStore`, a failed binding does not consume the transaction,
while a successful `Take` does. `Complete` consumes the returned
transaction even on failure and validates the state before exchanging the code.
Using state alone as the lookup key is not browser binding. The application
owns its local session,
account link, roles, logout, and recovery login. Never pass an access token to
the ID-token verifier. Never log tokens, codes, state, nonce, client secrets, or
raw callback URLs. The verifier requires an ID-token lifetime of at most ten
minutes and accepts at most one minute of future clock skew for `iat`/`nbf`.

Identity's current provider issues RS256 ID tokens with a five-minute lifetime
and a nonce, so its output is compatible by design. A live consumer contract
test and application-owned session integration are still required before
production use. Identity remains on Go 1.24 and is not changed by this module.
