# Identity integration: bounded first steps

Status: local preparation, not deployed. Identity's current LDAP adapter and
SQLite store remain unchanged. Do not couple directory and database cutovers.

## Framework boundary

`directory/ldap` initially provides only an enabled AD/Samba-AD user lookup.
It uses a least-privilege service bind over verified LDAPS, escaped search
filters, a two-entry search limit, a whole-operation deadline, and connection
closure on cancellation. It does not follow referrals or return raw transport
errors that may expose infrastructure details. Consumers own PII handling.

No directory writes, password authentication, role mapping, Kerberos, PKINIT,
badge policy, or OIDC issuer implementation are included. A certificate-pin
exception in the existing Identity adapter is not carried into the framework:
use a valid SAN and trusted CA before replacing that adapter.

Local TLS/LDAP protocol fixture tests cover successful lookup, missing and
duplicate users, and rejection of referrals. The connection has a 1 MiB inbound
budget, at most 16 response messages, 32 BER nesting levels and 4096 nodes per
message. Common config/reader formatting and JSON logging are redacted. Before
consumer cutover: settle group lookup requirements, run the prepared opt-in
read-only contract test, and wire an Identity adapter behind its existing Directory interface.
Do not claim production LDAP compatibility from unit tests alone.

Identity now has a tested, inactive `WithUserLookup` overlay behind its existing
Directory interface. It delegates GetUser/UserExists to a consumer callback;
ListUsers and both authentication methods remain with the existing adapter.
The bridge must project framework User fields to Identity User and translate
framework ErrNotFound to Identity ErrUserNotFound. Transport/cancellation errors
must not become "user missing" or trigger automatic insecure fallback.
This overlay is preparation only: no directory bridge or startup switch
has been added to Identity yet. The staged PostgreSQL adapter now imports a
pinned framework revision, independently of directory wiring. Decide whether mixed read/auth adapters are
acceptable before enabling it, and ensure both use the exact same directory.

## PostgreSQL migration inventory

Identity owns users, badges, audit_log, clients, self_service_sessions,
oidc_clients, oidc_codes and later schema additions such as activation_pending.
The existing store contains many SQLite-specific statements; changing only the
driver is insufficient. Inventory all migrations and direct database callers.

Preserve user/badge numeric IDs, OIDC subjects, hashes, client registration,
enabled/revoked states and historical audit timestamps. Never reissue subjects
or hashes during migration. Convert AUTOINCREMENT to identity sequences and
reset sequences after copying IDs; convert placeholders and LastInsertId to
RETURNING, SQLite booleans/datetimes to BOOLEAN/TIMESTAMPTZ, and define explicit
case-normalization semantics instead of silently dropping COLLATE NOCASE.

Implement schema and application-specific queries in Identity. Reuse framework
PostgreSQL pools, transactions and migration lifecycle; do not move Identity
tables or business rules into the framework. Give runtime and migration users
separate privileges. Consumer audit integration must preserve atomicity and
historical records, not force a lossy envelope conversion.

## Rehearsal and acceptance

1. Use synthetic SQLite fixtures only; no production secret export to the repo.
2. Import to a disposable PostgreSQL database in a bounded transaction.
3. Compare counts, foreign keys, original subjects/hashes and timestamp values;
   output only aggregate results. Rehearse repeated/import-failure behavior.
4. Test badge activation/revocation, session revocation, code one-use/replay,
   PKCE, audit rollback and concurrent mutations against PostgreSQL.
5. Before production, verify fresh SQLite/config/binary backup and restoration.
   Stop writes, migrate, verify, switch one consumer and run real login tests.
6. Before accepting new writes, rollback restores the previous binary/config
   and original SQLite snapshot. After new PostgreSQL writes, a simple snapshot
   rollback loses data: require an explicit reconciliation or reverse-transfer
   procedure. Do not promise zero-loss rollback without testing it.

## Local evidence on 2026-09-17

- Framework unit tests and vet pass with the new LDAP reader.
- `govulncheck` found no reachable vulnerabilities; four module-level findings
  outside the imported package paths remain dependency review items, not a
  blanket claim that every dependency is vulnerability-free.
- TLS/LDAP fixtures verify successful lookup, missing/duplicate results,
  referral rejection, filter escaping, pre-cancellation and untrusted TLS.
- An ignored synthetic-only rehearsal created the initial Identity tables in
  a disposable local PostgreSQL 17 cluster, copied two artificial SQLite rows,
  and checked numeric IDs, subject/hash preservation, pending/disabled badge
  state and identity-sequence advancement. The transaction was rolled back and
  the local cluster stopped. No production records or credentials were used.
- This is not an implementation or acceptance of the full migration. All-table
  transfer, timestamp/case edge cases, real Identity queries, concurrency,
  privileges, failure recovery and full auth flows remain to implement.
- Extended rehearsal copied synthetic records for all seven tables and checked
  row counts, audit timestamps, nulls, session revocation state, client
  credentials/registration, foreign-key rejection, subject uniqueness and
  sequential code replay rejection. Repeat runs and an injected duplicate-key
  import failure left no schema residue. The reusable synthetic-only tool is
  in Identity at `scripts/rehearse-postgres-synthetic.py`; it requires explicit
  opt-in and a disposable loopback PostgreSQL cluster on port 55441.
- The LDAP deadline-during-bind test passes. An opt-in `TestLDAPReadOnly`
  contract test is prepared but has not run against an actual directory.

### Staged application adapter, evening update

Identity has an inactive `PostgresStore` using the framework pool, transaction
helper and checksum-checked migrations. User/PIN reads and writes, stable
subjects, OIDC client administration, atomic code consumption, badge lifecycle,
self-service sessions and greeter client management have local PostgreSQL tests.
Shared SQLite/PostgreSQL contracts cover badge ownership and pending activation,
session ownership/expiry/revocation, client rotation and retained update metadata.
Eight competing consumers yield one code winner; eight badge replacements yield
one replacement; concurrent badge creation uses distinct sequence-derived codes.

The bounded importer refuses nonempty targets and unknown source columns/tables,
streams all seven tables under one transaction, compares every normalized field
using private in-memory digests, preserves IDs/subjects/hashes/nulls, and resets
sequences. Row-budget failures and a field-changing test trigger roll back.
Generated or hidden source columns are refused. SQLite AUTOINCREMENT high-water
marks are retained so deleted historical IDs are not reused after import.
Timestamps normalize to UTC at PostgreSQL's microsecond precision; naive SQLite
timestamps are interpreted as UTC. Source nanoseconds below that precision are
not retained. The importer has a two-minute cap and one-million-row maximum,
a 256 KiB SQLite row/cell limit and a 128 MiB aggregate payload budget. Limits
are connection-local and restored; existing tighter limits are not raised.
Lost commit responses require reconciliation, not a blind retry/rollback claim.

Audit writing and counters deliberately expose failures rather than repeating
legacy silent-error behavior. A staged SQLite/PostgreSQL badge-revocation API
commits state plus security audit atomically; audit failures roll back the badge,
and eight competitors produce one state change and one event. Both backends
pass actual Identity-handler/framework-login-client contracts over verified
local TLS (Discovery/JWKS, browser binding, PKCE, signature/claims and replay).
pg_dump/restore preserves full synthetic contents of all seven tables.
Application-wide audit policy and runtime wiring remain open. No runtime switch,
production migration or full native badge/PKINIT acceptance has occurred.
Go 1.26.8 is enforced after checking a build/scanner mismatch; scans with that
toolchain report no reachable/imported-package findings, with one unused OpenPGP
module advisory remaining. Full unit tests and vet pass locally.
