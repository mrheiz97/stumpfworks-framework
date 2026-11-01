# Certificate verification

`security/certificates` provides two pure, opt-in boundaries built on Go X509.
No existing LDAP, OIDC, HTTP or application verifier is automatically switched.

`VerifiedPeer(state, PeerOptions)` consumes a verified Go TLS connection state.
It requires a peer leaf matching the first verified-chain leaf, explicit time
and explicit ClientAuth or ServerAuth EKU. It does not establish CA trust from
a caller-constructed state, reverify the chain at a new time or check revocation.
Only use states originating in your correctly configured verified TLS handshake.

`VerifyIssued(leaf, IssuedOptions)` builds a chain using explicit Roots, optional
Intermediates, explicit clock/EKU, expected PKIX PUBLIC key DER and optional root
certificate pin. Nil roots never use system trust. An empty pool fails closed.
The pin must match the final certificate of an actually verified chain; it is
not an alternative to roots. ServerAuth requires an explicit hostname.

Both functions require the requested EKU explicitly in the leaf. Missing/Any-only
EKU is rejected; mixed EKUs remain supported. The first API slice intentionally
supports ClientAuth and ServerAuth only. Validity includes the exact NotBefore
and NotAfter instants, matching Go X509. Applications may impose stricter expiry
or usage policy. Positive serials are required. Leaves are reparsed from signed
DER so mutable parsed fields cannot override certificate contents. Metadata owns
all returned slices. Limits: 1 MiB leaf/public-key DER and 128 total SAN entries.

Inputs are already parsed certificates and PKIX DER. PEM parsing, size limits
before parsing, secure files and key generation belong to the caller. Private
keys, PKCS8 DER and PEM cannot be used as ExpectedPublicKeyDER. No private keys
are required or returned. Sentinel errors are bounded and omit raw input and
X509 error details. Certificate identifiers must not become metric labels.

The package performs no network requests, AIA/CRL/OCSP fetches, signing, database
lookups, logging, file mutation or token fallback. URI namespaces, allowed SAN
sets, device IDs, authorization, revocation, enrollment, audit and rollback stay
with consumers. Additional DNS/mail/IP identities are not globally forbidden;
a strict device consumer must enforce its own single-URI profile after verifying.

Example (all trust material is explicitly supplied by the application):

```go
publicDER, err := x509.MarshalPKIXPublicKey(expectedPublicKey)
if err != nil { return err }
metadata, err := certificates.VerifyIssued(leaf, certificates.IssuedOptions{
    PeerOptions: certificates.PeerOptions{Now: now, Usage: x509.ExtKeyUsageClientAuth},
    Roots: trustedRoots,
    ExpectedPublicKeyDER: publicDER,
    PinnedRoot: installedDeviceCA,
})
if err != nil { return err }
// Enforce your own exact URI/SAN and active-credential policy here.
_ = metadata
```

An enrollment response's CA is not inherently trusted. A consumer may establish
bootstrap trust over a separately verified transport; that decision is never
inferred here. Renewal must keep its installed pin unless rotation was approved.

This addition does not migrate Identity or alter production. A consumer rollout
requires its own pinned framework version, old/new contract parity, complete
application tests, verified binary/config rollback and maintenance approval.
