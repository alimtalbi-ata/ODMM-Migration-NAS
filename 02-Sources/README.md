# ODMM V178.5 / Compact V2.9.5 — Resource-limited ACL collectors
Auteur : Abdelhalim Talbi

Cumulative prototype based on V178.4. Linux collector execution adds RLIMIT_FSIZE (kernel-enforced stdout/stderr temporary-file size), RLIMIT_CPU, RLIMIT_NOFILE and disabled core dumps. Process group is killed on wall-clock timeout. All inherited SQLite, ACL evidence and recovery modules remain.

Run: `python3 -m unittest discover -s . -p 'test_*.py'`

Limits: Linux only for resource-limited execution; not a namespace/seccomp sandbox. RLIMIT_FSIZE is per file, not a combined output quota. Child can still consume memory and spawn processes. ACL commands require trusted executable paths. No real NAS qualification, no effective-access certification, and no integrated Full/Compact product release.

## V178.6 / Compact V2.9.6 — Mount capability evidence
Added `capability_probe.py` and five fail-closed tests. Reports are deterministic,
read-only, and NEVER assert production qualification or effective ACL equivalence.
This is NOT a Linux sandbox and has not been tested on real NAS equipment.
Author: Abdelhalim Talbi.

## V178.7 / Compact V2.9.7 — Qualification matrix and SQLite lifecycle
Author: Abdelhalim Talbi. Added 12 offline vendor/protocol profiles (NetApp, Dell, Pure, IBM, HPE, Hitachi × NFSv4/SMB). All remain NOT production qualified regardless of submitted evidence; manual review and real NAS tests required. Added context manager lifecycle to Registry and ProvenanceRegistry to explicitly close SQLite handles. This is a cumulative prototype, not a complete ODMM distribution.

## V178.8 / Compact V2.9.8 — Offline qualification bench
Author: Abdelhalim Talbi. Added deterministic, fail-closed offline fixture harness (`qualification_bench.py`) for the six vendor-neutral checks and multi-vendor matrix reports. Fixture comparisons are explicitly SIMULATED_PASS/FAIL; even passing all checks NEVER certifies actual NAS capabilities, ACL semantics or effective access. No real NAS connections or writes. Run `python3 -m unittest discover -s . -p 'test_*.py'`.

## V178.9 / Compact V2.9.9 — Evidence Bench
Auteur : Abdelhalim Talbi.

`evidence_bench.py` adds SHA-256 consistency-checked envelopes for all six
qualification checks, profile/endpoint binding, duplicate/missing/tamper
rejection, deterministic report hashes, and explicit provenance limitations.
`operator-import` is untrusted offline data, not a live NAS probe. Hashes are
not signatures. No live NFS/SMB effective-access tests, vendor qualification,
or production approval are asserted. Native ODMM engine remains primary.

## V179.0 / Compact V3.0 — Collector evidence bridge
Auteur : Abdelhalim Talbi.

`collector_evidence_bridge.py` converts **previously collected** attested NFSv4/SMB
ACL metadata into a deterministic, SHA-256 checked, privacy-minimized **partial**
qualification artifact (`acl_capture` only). It deliberately omits raw ACLs,
mount paths, remote sources and identities. It does not run collectors, perform
remote access, attest provenance, or fill in the other five qualification checks.
Hashes prove only consistency, not authenticity. No NAS was tested; no production
qualification is asserted. ODMM native migration remains the preferred engine.

## V179.1 / Compact V3.0.1 — Offline effective-access comparison
Auteur : Abdelhalim Talbi.

`effective_access_compare.py` compares explicitly provided, aliased source/target
access observations for read, write, delete, traverse, ACL read and ACL write.
Missing and UNKNOWN decisions are INDETERMINATE, not equivalent. Duplicate
observations are rejected; deterministic SHA-256 report checks integrity only.
This does not perform live access tests, resolve AD/LDAP identities, establish
provenance, or qualify a NAS for production. Native ODMM engine stays primary.

## V179.2 / Compact V3.0.2 — Read-only access probe
Auteur : Abdelhalim Talbi. `readonly_access_probe.py` tests read-only open under the current local effective UID/GID, with expected identity validation, no symlink traversal, FD identity comparison, no content read or write. It does NOT impersonate AD/LDAP users, authenticate NAS servers, prove NFS/SMB ACL semantics or production readiness. Linux/POSIX-only; Windows compact remains unqualified for this probe. Native migration engine remains primary.


## V179.3 / Compact V3.0.3 — Read-only probe evidence bridge
Auteur : Abdelhalim Talbi. `access_probe_bridge.py` converts hashed local read-only
probe reports to aliased ALLOW/DENY observations and compares source/target with
the existing offline engine. Rejects tampered evidence, invalid identities, unsafe
qualification flags and unsupported outcomes. Missing observations remain
INDETERMINATE. No AD/LDAP mapping, remote NAS verification, live NAS test, or
production certification is claimed. The native ODMM migration engine stays primary.

## V179.4 / Compact V3.0.4 — Offline identity mapping matrix
Auteur : Abdelhalim Talbi. `identity_mapping_matrix.py` validates offline AD SID, LDAP DN/UID/GID and POSIX UID/GID mapping proposals. Rejects duplicates, incompatible kinds and invalid IDs; detects one-to-many and many-to-one ambiguity. Reports remain PENDING_DIRECTORY_VERIFICATION or BLOCKED; no directory bind, identity impersonation, effective-access certification or production approval. SHA-256 proves consistency only. Native ODMM migration engine remains primary.

## V179.5 / Compact V3.0.5 — Offline directory snapshot review
Auteur : Abdelhalim Talbi. `directory_snapshot_review.py` cross-checks operator-supplied AD/LDAP/POSIX identity snapshots against the V179.4 mapping matrix. It rejects duplicate snapshots and malformed group references; missing snapshots and group memberships remain explicitly unverified. SHA-256 reports are deterministic, but do not authenticate snapshots. No live LDAP/AD bind, nested group expansion, access impersonation, or production qualification. ODMM native migration engine remains primary.

## V179.6 / Compact V3.0.6 — Nested group review
Auteur : Abdelhalim Talbi.
`nested_group_review.py` expands operator-supplied offline group memberships with bounded depth/node count, cycle and missing-group detection, deterministic SHA-256 reports, and fail-closed status. No live AD/LDAP verification, no effective-access certification. Run `python3 -m unittest discover -s . -p 'test_*.py'`.

## V179.7 / Compact V3.0.7 — Offline group membership comparison
Auteur : Abdelhalim Talbi. `group_membership_compare.py` compares expanded group memberships between operator-supplied source/target directory snapshots through one-to-one identity mappings. Flags missing/extra groups as BLOCKED_PRIVILEGE_DRIFT, missing identity mappings as indeterminate, and unexpected target users as blocked. Input report integrity is checked against snapshots. Even matching groups are DECLARED_MATCH_ONLY: no directory authentication, live NAS verification, or effective access certification. Native ODMM engine remains primary.

## V179.8 / Compact V3.0.8 — Privilege Evidence Gate
Auteur : Abdelhalim Talbi. `privilege_evidence_gate.py` correlates verified offline group-membership, effective-access and collector metadata evidence. Fail-closed: drift blocks, missing observations remain indeterminate, and matching observations remain PENDING_LIVE_VERIFICATION. Never authorizes cutover or certifies ACL equivalence. SHA-256 is consistency only, not proof of provenance. No NAS or AD/LDAP live tests. Native ODMM engine remains primary.

## V179.9 / Compact V3.0.9 — Offline ACE structural comparison
Auteur : Abdelhalim Talbi. `acl_ace_compare.py` compares explicit ordered ACE snapshots
for a single NFSv4 or SMB protocol. It detects positional drift, inheritance, rights,
flags, principals and ALLOW/DENY differences. It does NOT parse vendor ACL formats,
translate NFSv4/SMB semantics, authenticate identities, or prove effective access.
Even structural matches NEVER authorize cutover or qualify production.
Native ODMM migration remains primary; external utilities require explicit selection.

## V180.0 / Compact V3.1 — Native ACL subset parsing
Auteur : Abdelhalim Talbi. Added `native_acl_normalize.py` and 11 tests.
Strict subset parser for nfs4_getfacl ACE lines and getcifsacl SID ACE lines, preserving order, opaque native permissions and inheritance markers. Rejects unsupported syntax rather than silently discarding data. Does NOT establish NFS/SMB semantic equivalence or cover full vendor ACL formats; no NAS qualification or cutover approval.

## V180.1 / Compact V3.1.1 — ACL metadata fidelity review
Auteur : Abdelhalim Talbi. `acl_fidelity_review.py` adds fail-closed offline SMB OWNER/GROUP SID and REVISION metadata drift detection alongside ordered ACE comparison. Duplicate/malformed metadata rejected. Missing SMB metadata and unparsed NFSv4 owner/group metadata are explicitly INDETERMINATE, not certified. No live NAS access, vendor-specific parser support, semantic cross-protocol translation, or automatic cutover authorization. Native ODMM engine remains primary.

## V180.2 / Compact V3.1.2 — ACL portability and inheritance review
Auteur : Abdelhalim Talbi. Added `acl_portability_review.py` and 11 tests.
Conservatively records inheritance flags for supported native ACL subsets, detects
source/target drift and unrecognized flags, and produces deterministic SHA-256
reports. Opaque/unknown flags cause INDETERMINATE, not silent translation.
No cross-protocol semantic translation, live NAS verification, or automatic cutover.

## V180.3 / Compact V3.1.3 — Potential ACL loss inventory
Auteur : Abdelhalim Talbi. `acl_loss_inventory.py` adds conservative, offline, per-ACE potential-loss findings and metadata-drift flags, using vendor names solely as unverified profile labels. Never authorizes cutover. No vendor certification, real NAS testing, effective access equivalence, or cross-protocol ACL translation. ODMM native migration engine remains primary.

## V180.4 / Compact V3.1.4 — Consolidated migration ACL risk
Auteur : Abdelhalim Talbi. `migration_acl_risk_report.py` aggregates offline ACL loss inventories by dataset, reports conservative worst-case risk, issue codes, deterministic SHA-256 and human-review recommendations. Raw ACL content is excluded from report. Missing/unrecognized evidence is never considered safe. No automatic cutover; no real NAS or AD/LDAP verification; hashes are not signatures. Native ODMM engine remains primary.

## V180.5 / Compact V3.1.5 — Conservative cutover readiness gate
Auteur : Abdelhalim Talbi. `cutover_readiness_gate.py` combines verified offline ACL risk and privilege-evidence bundles with operator-declared recovery status. Fail-closed BLOCKED/INDETERMINATE/PENDING_HUMAN_AND_LIVE_VERIFICATION outcomes; **never** authorizes cutover. SHA-256 provides consistency, not authenticated provenance. No live NAS tests, directory verification, recovery execution, or production qualification. Native ODMM engine remains primary; external tools require explicit selection.

## V180.6 / Compact V3.1.6 — Transactional human review ledger
Auteur : Abdelhalim Talbi. Added `human_approval_registry.py` with SQLite WAL, durable review records bound to exact readiness-report SHA-256, expiry, revocation, duplicate rejection and fail-closed check. **A recorded review never authorizes cutover**. No reviewer authentication or cryptographic signatures; offline operator assertions only. Full/Compact product integration and real NAS qualification remain outstanding.

## V180.7 / Compact V3.1.7 — Dual-role human review ledger
Auteur : Abdelhalim Talbi. `dual_review_ledger.py` requires separate security and operations reviewers, each bound to the same readiness SHA-256 and migration ID. SQLite BEGIN IMMEDIATE enforces atomic review insertions; duplicate role and same reviewer are rejected. Expiration, revocation, changed evidence and restart are handled fail-closed. All states explicitly deny production cutover; reviewers are identifiers only, not authenticated principals. No live NAS or directory qualification.

## V180.8 / Compact V3.1.8 — Review Event Journal
Auteur : Abdelhalim Talbi.

Nouveau module `review_event_journal.py` : journal SQLite WAL append-only au niveau API, chaînage SHA-256, vérification des altérations et sérialisation des écritures concurrentes par `BEGIN IMMEDIATE`. Les événements autorisés sont REVIEW_RECORDED, REVIEW_REVOKED et REVIEW_REJECTED. Les données d'identité restent déclaratives et aucune autorisation de cutover n'est émise.

**Limites** : pas de signature, pas d'authentification des acteurs, pas de stockage WORM, pas de protection contre un attaquant ayant accès en écriture à la base et capable de recalculer toute la chaîne ; le journal n'est pas encore intégré transactionnellement au registre de double revue. Prototype hors production.


## V180.9 / Compact V3.1.9 — Atomic Dual Review Journal
Auteur : Abdelhalim Talbi. New `atomic_review_ledger.py` stores review changes and hash-chain events in the SAME SQLite transaction (`BEGIN IMMEDIATE`), rolling back both on journal failure. Use `AtomicReviewLedger` for new installations; legacy independent ledgers are not automatically migrated. This does NOT authenticate reviewers, guarantee immutable audit, authorize cutover, or qualify a real NAS. Native ODMM engine remains primary.

## V181.0 / Compact V3.2 — Attested reviewer assertions
Auteur : Abdelhalim Talbi. `authenticated_review_ledger.py` verifies bounded HMAC-SHA256 assertions from a **trusted external issuer**, binds role, reviewer, migration ID, readiness evidence SHA-256, nonce and expiry; consumes nonce and writes review + audit event atomically in SQLite. Rejects replay, stale evidence, invalid signature and tampered existing journal. **Not AD/LDAP authentication**, no live directory connection, no issuer key management, no nonrepudiation, no WORM, no production cutover authorization. Issuer secrets must be provisioned separately and never embedded in client bundles. ODMM native engine remains default.

## V181.1 / Compact V3.2.1 — Offline reviewer RBAC and issuer-key lifecycle
Auteur : Abdelhalim Talbi. `review_identity_policy.py` introduces provisioned reviewer roles, directory snapshot version checks, issuer key validity windows and revocation, plus HMAC attestation verification and nonce protection inherited from V181.0. This is **offline provisioned policy**, NOT an AD/LDAP connector or login. Key/reviewer policy precheck and final attested write are **not one atomic transaction**: a concurrent revocation between the checks is not fully prevented. No automatic cutover; no real NAS qualification. Native engine remains primary.

## V181.2 / Compact V3.2.2 — Atomic reviewer policy enforcement

Author: Abdelhalim Talbi.

`review_identity_policy.py` now holds one `BEGIN IMMEDIATE` transaction throughout issuer-key validity, RBAC directory status, HMAC assertion verification, evidence binding, nonce consumption, review insert, and hash-chain audit append. No intermediate rollback/release of the lock is permitted. `authenticated_review_ledger.py` exposes `_record_verified_in_transaction` to share the audited persistence path with the base attested review API. On any error the transaction rolls back, including nonce consumption. Seven regression tests cover atomic success, invalid signatures, simulated audit failure, revocation, directory change, replay, and competing writer lock. Offline SQLite tests only; no real AD/LDAP authentication, production-grade secret custody, WORM journal or live NAS qualification. No automatic cutover authorization.

## V181.3 / Compact V3.2.3 — Offline directory snapshot RBAC synchronization
Author: Abdelhalim Talbi. `directory_snapshot_adapter.py` validates operator-supplied AD/LDAP **exports** in read-only offline mode, normalizes reviewer/group membership, rejects conflicting roles and malformed exports, and atomically applies a full snapshot to SQLite with digest compare-and-swap. Omitted or disabled accounts become inactive. It is **not** a live LDAP connector or directory authentication; snapshot provenance is not verified. The native ODMM engine remains primary; no automatic cutover.

## V181.4 / Compact V3.2.4 — Directory freshness gate
Auteur : Abdelhalim Talbi. `directory_freshness_gate.py` assesses offline snapshot age, digest consistency and reviewer membership drift; returns deterministic SHA-256 evidence and fails closed to REVIEW_REQUIRED. This is a read-only assessment, not an automatic revocation or live AD/LDAP connector. No production cutover authorization.

## V181.5 / Compact V3.2.5 — Transactional reviewer quarantine
Auteur : Abdelhalim Talbi. `review_quarantine.py` introduces `QuarantinedReviewLedger`, an opt-in SQLite transactional quarantine of both human approvals when an offline directory freshness report indicates review-required drift. The quarantine marker, review revocations and hash-chain audit event are written in one BEGIN IMMEDIATE transaction. It fails closed for modified evidence, duplicate quarantine and tampered journal, and never authorizes cutover. This is not an automatic AD/LDAP revocation, nor a live directory connection. The caller must explicitly invoke quarantine after assessing drift. No real NAS production qualification.

## V181.6 / Compact V3.2.6 — Atomic Directory Quarantine
Auteur : Abdelhalim Talbi.

`atomic_directory_quarantine.py` links offline directory snapshot application,
reviewer RBAC changes, review revocation, quarantine and SHA-256 audit journal
within a single SQLite `BEGIN IMMEDIATE` transaction. Optimistic snapshot
compare-and-swap prevents stale writers; journal failures roll back all writes.
A changed reviewer quarantines every migration they reviewed; quarantine cannot
be cleared by a subsequent import. This is a conservative offline prototype,
NOT a live AD/LDAP connector, trusted snapshot attestation, or cutover authority.

## V181.7 / Compact V3.2.7 — Read-only LDAP connector contract
Auteur : Abdelhalim Talbi. `ldap_readonly_adapter.py` implements a fail-closed, injectable read-only LDAP paging contract with LDAPS-only endpoint validation, strict completion, duplicate detection, account-disabled and privileged group mapping. The injected client MUST independently enforce TLS certificate and hostname validation and read-only binds: this prototype DOES NOT implement network TLS, real AD/LDAP connection, or authenticate snapshots. Never production-qualified, never cutover-authorizing. Native ODMM engine remains primary.

## V181.8 / Compact V3.2.8 — Optional LDAPS transport
Auteur : Abdelhalim Talbi. `ldap_tls_client.py` adds an optional ldap3-based LDAPS-only read-only transport, certificate validation against a supplied CA bundle, no referrals, bind/search timeouts and paged reads. Install optional `ldap3` separately. Fake-transport unit tests are NOT a real AD/LDAP integration test. No automatic directory import/quarantine, no live server qualification, no cutover authorization. Keep credentials out of logs and archives. Native ODMM engine remains primary.

## V181.9 / Compact V3.2.9 — Explicit LDAPS to atomic RBAC/quarantine pipeline
Auteur : Abdelhalim Talbi. `ldaps_directory_pipeline.py` explicitly connects a fully collected LDAPS snapshot to the existing SQLite atomic identity synchronization, review quarantine, and SHA-256 journal. Rejects incomplete/untrusted transport claims, digest tampering, and stale compare-and-swap. No partial SQLite writes on collection failure. Optional `ldap3` for live transport; no AD/LDAP server qualification. The transport claim is **not** cryptographic provenance attestation; `collector` injection is for offline tests. No automatic cutover. Native ODMM migration engine remains primary.

## V182.0 / Compact V3.3 — Directory synchronization health (offline)
Auteur : Abdelhalim Talbi. `directory_sync_health.py` assesses a read-only directory baseline and caller-supplied chronological synchronization observations. It fails closed on missing or mismatched baseline, stale sync, latest-attempt network/TLS/pagination/import failure, invalid observations and tampered report. Recovery after an outage can restore only `OFFLINE_HEALTHY_NOT_AUTHORIZED`; it NEVER authorizes cutover. Observations are unauthenticated, not persisted by this module; no live AD/LDAP or NAS qualification. Native ODMM engine remains primary.

## V182.1 / Compact V3.3.1 — Persistent directory synchronization journal
Auteur : Abdelhalim Talbi. `directory_sync_journal.py` persists LDAPS synchronization observations in SQLite, with unique event identifiers, monotonic timestamps, SHA-256 hash chaining, transaction rollback, restart recovery and direct read-only evaluation via `directory_sync_health.py`. These are **caller-supplied observations**, not automatically collected, authenticated or signed; a database administrator can rewrite the chain. The journal is not automatically wired to the network collector. No production cutover authorization or real directory/NAS qualification. Native ODMM migration engine remains primary.

## V182.2 / Compact V3.3.2 — Journaled LDAPS attempt pipeline
Auteur : Abdelhalim Talbi. `ldaps_journaled_pipeline.py` wires the explicit
LDAPS import pipeline to the persistent sync journal. It prechecks the journal,
rejects reused IDs and nonmonotonic timestamps before collection, records
successes and classifies collection/import failures, and feeds the existing
read-only directory health assessment. The **directory import transaction and
journal append are NOT atomic together**: an import may commit before a journal
write fails. In that case the API fails closed with
`IMPORT_COMMITTED_JOURNAL_FAILED_RECONCILIATION_REQUIRED`; manual reconciliation
is mandatory. No automatic retry or cutover; mock collector tests do not
qualify real LDAP/TLS or NAS production. Native ODMM migration engine remains primary.

## V182.3 / Compact V3.3.3 — Atomic LDAPS success journal
Auteur : Abdelhalim Talbi. Added `ldaps_atomic_journal_pipeline.py`: after LDAPS collection, RBAC synchronization, quarantine/revocation, and success journal entry share one `BEGIN IMMEDIATE` transaction. On journal or directory failure, the entire database change rolls back. Network failures are recorded separately and cannot be atomic with a nonexistent successful import. Existing `sync_and_record` remains available as legacy non-atomic API; use `sync_atomically` for the stronger guarantee. No live AD/NAS qualification, no automatic cutover.

## V182.4 / Compact V3.3.4 — Durable crash recovery intents
Auteur : Abdelhalim Talbi. `ldaps_crash_recovery.py` persists an attempt intent
before network collection, reconciles STARTED intents after a process restart
against the SHA-256 journal, and classifies COMMITTED / FAILED / INTERRUPTED.
Recovery never replays an interrupted import or grants cutover authority.
The RBAC/quarantine/SUCCESS journal transaction remains atomic in
`sync_atomically`. An intent is a separate durable transaction by design;
interruption before import commit leaves no successful directory import.
Limitations: simulated collectors, no real AD/LDAP/NAS qualification; local
SQLite journal hashes are not immutable against privileged rewriting.

## V182.5 / Compact V3.3.5 — Read-only LDAPS operational recovery plan
Auteur : Abdelhalim Talbi. `ldaps_recovery_plan.py` builds a deterministic SHA-256 recovery assessment from durable attempt intents and verified sync journal, flags missing/contradictory/future/stale evidence, and prescribes manual review. It does not mutate state, replay imports, attest AD/LDAP or authorize cutover. Offline unit tests only; native ODMM engine remains primary.

## V182.6 / Compact V3.3.6 — Supervised LDAPS recovery reviews
Auteur : Abdelhalim Talbi. `ldaps_supervised_recovery.py` records operator-declared decisions in SQLite transactions bound to a verified SHA-256 recovery plan, prevents duplicate decisions and reused new-attempt identifiers, and detects locally tampered review rows. Approving only RESERVES a new attempt ID; it does not create an intent, perform a network retry, authenticate the reviewer, or authorize cutover. A fresh plan must match exactly at decision time. Local hashes are not signatures and privileged database rewrites are out of scope. Native ODMM migration remains primary.

## V182.7 / Compact V3.3.7 — Fenced supervised recovery dispatch
Auteur : Abdelhalim Talbi. `ldaps_recovery_dispatch.py` consumes each reviewed recovery reservation once under `BEGIN IMMEDIATE`, binds it to an owner and fencing epoch, and atomically journals CLAIM/FINISH/ABORT transitions with a SHA-256 chain. A claimed reservation does **not** start an LDAP attempt or network I/O; execution is external and must independently enforce ownership/fencing. Claims are never automatically retried or reclaimed, including after a crash; manual reconciliation is required. Hashes are local and not immutable against privileged DB rewriting. No real AD/NAS qualification or automatic cutover. Native ODMM migration engine remains primary.


## V182.8 / Compact V3.3.8 — LDAPS recovery leases
Author: Abdelhalim Talbi. `ldaps_recovery_lease.py` provides START, RENEW and TRANSFER leases with strictly increasing fencing epochs, SQLite `BEGIN IMMEDIATE`, local SHA-256 event chaining, and expiry checks. Leases do not execute LDAPS or cutover. **Important:** SQLite lease checks alone cannot prevent a stale external worker from performing side effects; the external effect target MUST enforce the epoch and ownership, and trusted time is required. Existing dispatcher `finish` is not lease-aware and must not be used as a lease-fenced completion API. Tests are offline only.

## V182.9 / Compact V3.3.9 — Lease-gated local finalization

Auteur : Abdelhalim Talbi.

`ldaps_lease_finalization.py` adds `LeasedFinalizer.finish()` and `verify()`.
Finalization is permitted only while the current SQLite lease is active and the
owner and fencing epoch match. One SQLite transaction inserts the finalization
state and hash-chained journal event; any failure rolls back both. A finalized
lease cannot be renewed or transferred. This is **local bookkeeping only**:
external LDAP effects are not executed or fenced by this module, and neither
cutover nor automatic retries are authorized. The earlier dispatcher finish API
is retained for backward compatibility and does not enforce leases; callers
requiring lease gating must use `LeasedFinalizer`.

## V183.0 / Compact V3.4.0 — Pre-effect fencing (local)

`ldaps_effect_fence.EffectFence.authorize` performs a fresh SQLite `BEGIN IMMEDIATE` check of dispatch claim, lease owner, epoch, expiry, and finalization, then atomically records a hash-chained pre-effect permit. It does **not** call LDAP or authorize cutover. The permit is only a local observation: a remote LDAP/NAS target cannot be fenced by this SQLite transaction. Production-grade effect fencing requires the effect executor/target to enforce the epoch atomically at the actual effect boundary, with trusted time and authenticated identities. No automatic retries.

Auteur : Abdelhalim Talbi.

## V183.1 / Compact V3.4.1 — Simulated target-side fenced execution
Auteur : Abdelhalim Talbi.
`ldaps_fenced_executor.py` provides a **simulation-only** adapter that requests a
fresh local permit and passes its epoch to a simulated target that atomically
checks the current target epoch under a lock. It stores SHA-256 receipt records,
rejects duplicate request IDs, and requires manual reconciliation if receipt
persistence fails after an effect. **Not production LDAPS/NAS integration**:
no network I/O, authenticated worker identities, real target-side fencing,
external effects, automatic retry or cutover. Production requires target-native
atomic fencing and durable idempotency across restarts; this in-memory simulator
is not a substitute. The native ODMM engine remains primary.

## V183.2 / Compact V3.4.2 — Cible simulée durable

- `ldaps_durable_target.py` : cible **simulée uniquement**, avec base SQLite indépendante du coordinateur, epochs persistants, effets idempotents par `(event_id, request_id)`, conflits détectés et reçus SHA-256.
- `DurableEffectReconciler.inspect()` : rapprochement **en lecture seule** de la cible et des reçus du coordinateur (`NOT_APPLIED`, `TARGET_COMMITTED_RECEIPT_MISSING`, `RECEIPT_WITHOUT_TARGET`, `EVIDENCE_MISMATCH`, `CONSISTENT`).
- Aucune relance automatique, aucune authentification réelle LDAP/NAS, aucun cutover.
- Les deux bases SQLite **ne forment pas une transaction distribuée** : une écriture cible sans reçu doit être examinée par un opérateur.
- Auteur : Abdelhalim Talbi.

## V183.3 / Compact V3.4.3 — Crash reconciliation evidence
Auteur : Abdelhalim Talbi.

`ldaps_crash_reconciliation.py` records read-only reconciliation observations
in a transactionally appended SHA-256 hash chain. States: NOT_APPLIED,
TARGET_COMMITTED_RECEIPT_MISSING, RECEIPT_WITHOUT_TARGET, EVIDENCE_MISMATCH,
CONSISTENT. Contradictions require manual review. No retries, real LDAP/NAS
operations or automatic cutover. Coordinator and simulated target remain
separate SQLite databases; cross-database observations are not atomic snapshots.


## V183.4 / Compact V3.4.4 — Supervised uncertain-effect review
Auteur : Abdelhalim Talbi. `ldaps_uncertain_review.py` records human investigation/acknowledgment/block decisions against the latest fresh crash reconciliation evidence in a SQLite transaction. It rechecks evidence and chained journals; changes, tampering, duplicates and stale observations fail closed. No automatic retry, migration, real LDAPS effect or cutover is authorized. Local simulation only; coordinator/target are not a distributed atomic snapshot.


## V183.5 / Compact V3.4.5 — RBAC uncertain reconciliation
`ldaps_rbac_reconciliation.py`: local SECURITY/OPERATIONS reviewer grants, independent dual approval for critical uncertainty, freshness and evidence verification, SHA-256 decision journal, fail-closed; decisions never execute operations or authorize cutover. Identity grants are local and not externally authenticated. Auteur : Abdelhalim Talbi.

## V183.6 / Compact V3.4.6 — Directory-backed reconciliation RBAC
Auteur : Abdelhalim Talbi.
`ldaps_directory_rbac_bridge.py` synchronizes **validated offline** AD/LDAP exports
into local reconciliation SECURITY/OPERATIONS reviewer grants in one SQLite transaction.
Missing/disabled identities are revoked, changed reviewers' prior decisions are
invalidated without erasing historical audit, and a SHA-256 chain records grant
changes. `ReconciliationRBAC.decide()` fails closed on grant-audit tampering or
invalidated reviews. Offline exports are **not authenticated**: this is not a live
AD/LDAP connection, not instantaneous external revocation and not production
identity assurance. No execution, migration, retry or cutover authorization.


## V183.7 / Compact V3.4.7 — Directory freshness fail-closed
New `ldaps_directory_freshness.py` configures a persisted maximum offline directory snapshot age. When enabled, reviewer decisions are rejected if the snapshot is older than the configured limit or has a future timestamp. A successful offline directory sync refreshes the timestamp within the existing RBAC transaction. Freshness is based on a supplied timestamp, not authenticated directory presence. No automatic retry, production cutover or external authorization. Legacy installations without the policy retain old decision behavior; configure the policy to enable strict freshness enforcement.

## V183.8 / Compact V3.4.8 — Audited freshness policy changes
Author: Abdelhalim Talbi.

`ldaps_freshness_policy_audit.py` introduces opt-in, dual-role (SECURITY +
OPERATIONS) policy changes, SQLite atomic audit chain, monotonic change timestamps,
local integrity verification and fail-closed reviewer decision checks when this
module has been initialized. Policy reconfiguration does not refresh the directory
observation timestamp. No disable operation is exposed. Legacy configuration
APIs are retained and are NOT prevented from bypassing the new audit: production
integrations must restrict access to the database and use the audited API only.
Directory identities are locally asserted, not externally authenticated. This is
not a production AD/LDAP security attestation or migration/cutover authorization.

## V183.9 / Compact V3.4.9 — Audited freshness policy bypass guard

Auteur : Abdelhalim Talbi.

- The legacy `DirectoryFreshnessPolicy.configure` refuses configuration when the audited-policy journal table exists, preventing bypass of dual-review audited changes.
- `DirectoryFreshnessPolicy.assess` verifies the audited policy chain before returning freshness status.
- Four regression tests cover legacy bypass, installed journal, invalid parameters and restart.
- Existing `ReconciliationRBAC.decide` already checks the audited chain before each decision; this remains unchanged.
- Limitation: older direct database writers or privileged SQLite access can bypass application-level controls. An externally anchored signed audit and authenticated identity remain outstanding.
- No automatic migration, external LDAPS effects or production cutover is authorized.

## V184.0 / Compact V3.5.0 — Startup security gate
Auteur : Abdelhalim Talbi.

`ldaps_security_startup.verify_startup(rbac, now=..., require_audited_policy=True)`
performs a read-only SQLite integrity check, verifies the directory RBAC and
freshness audit chains, requires an initialized audited policy and a fresh
snapshot, and fails closed on anomalies. It does not prevent direct SQLite
writes by a privileged administrator or provide real AD/LDAP authentication.
Call it at service startup AND before sensitive reviews; it is not automatically
wired into every possible entry point. No automatic migration or cutover.


## V184.1 / Compact V3.5.1 — Audited decision entrypoint guard
The audited RBAC decision entrypoint now invokes `verify_startup` within its
SQLite `BEGIN IMMEDIATE` transaction, before recording a human review. It
checks the SQLite integrity, audited policy chain and directory freshness
when an audited policy event exists. Legacy installations without an initialized audited policy remain compatible;
they are NOT automatically upgraded to production-grade enforcement.
No external anchor or independently authenticated reviewer is implemented.
This gate cannot protect against direct privileged SQLite writes, and other
entrypoints must be audited separately. No automatic migration/cutover.
Auteur : Abdelhalim Talbi.

## V184.2 / Compact V3.5.2 — Persistent strict security mode
Auteur : Abdelhalim Talbi.

`StrictSecurityMode(rbac).enable(now=timestamp)` activates an opt-in, persistent,
fail-closed mode, only after the audited directory freshness policy passes the
startup gate. Once enabled through this API, it cannot be disabled through the
API. Every `ReconciliationRBAC.decide` checks the gate in strict mode, including
when the policy audit table is missing. Legacy mode is preserved for upgrades.

Migration: synchronize a validated directory export, configure an audited
freshness policy with two independent reviewers, verify startup, enable strict
mode, then restart and verify it remains enabled. Before production deployment,
configure database file permissions and independent audit anchors; a privileged
SQLite administrator can modify the flag and audit data. No external LDAP/NAS
qualification, automated retry, migration execution or cutover authorization.

## V184.3 / Compact V3.5.3 — External policy HMAC anchor
Auteur : Abdelhalim Talbi.

`ldaps_external_anchor.py` introduces an explicit external HMAC-SHA256 checkpoint of the audited policy head, policy count, freshness state and strict-mode bit. Use a 32+ byte secret stored outside SQLite and an anchor file protected from database administrators. `checkpoint()` writes via fsync + atomic rename; `verify()` fails closed on missing, tampered, or drifted evidence. **Checkpoint is manual and must be performed after an authorized policy change**; verification rejects legitimate changes until re-anchored. A privileged actor with both secret and anchor can forge the checkpoint, and restoring both SQLite and an old anchor together cannot be detected without an independent monotonic store. SQLite and anchor file are NOT one atomic transaction. This is a local library API, not automatically wired into all service entrypoints. No real LDAP/NAS qualification or automatic cutover.

## V184.4 / Compact V3.5.4 — Opt-in anchored review gate

`ldaps_anchored_gate.py` provides `verify_anchored_startup`, `AnchoredReviewGate`,
 and explicit `rotate_anchor_key`. The facade enforces the external HMAC anchor
 inside the RBAC decision transaction, before writing the decision. It never
 automatically refreshes a mismatched checkpoint. Rotation requires verification
 with the old key first. These are **opt-in** interfaces: direct access to the
 legacy `ReconciliationRBAC.decide()` bypasses the external anchor, so restrict
 direct access before production. Policy changes also require a separately
 controlled anchor checkpoint workflow. Keys and anchors must be independently
 protected; file replacement and SQLite are not a distributed transaction.
 No real AD/LDAP/NAS certification and no automatic cutover.

## V184.5 / Compact V3.5.5 — Supervised policy transition

`ldaps_policy_transition.SupervisedPolicyTransition` records a durable external
intent **before** changing the audited SQLite freshness policy. After SQLite
commit it publishes and verifies the external HMAC anchor. Any interruption
leaves the intent for explicit operator reconciliation. `inspect()` distinguishes
intent-only, uncertain anchor, conflicting evidence and published-but-unacknowledged
states. `acknowledge(operator_confirmed=True)` only clears an independently
verified completed transition. **Never** automatically repairs or retries.

**Deployment restriction:** the transition API is opt-in and does not disable
legacy direct policy configuration methods. Deployments must restrict access
to those methods, protect anchor/key/intent with separate privileges, and
serialize policy writers externally. No distributed atomicity, AD/LDAP/NAS
qualification, or automatic cutover is claimed.

Auteur : Abdelhalim Talbi.

## V184.6 / Compact V3.5.6 — Supervised transition reconciliation

`ldaps_transition_reconciliation.py` introduces a cooperating-administrator filesystem
lock, deterministic SHA-256 reconciliation evidence, age/future-clock checks,
explicit operator acknowledgement and rechecking before acknowledgement.
No anchor repair, no automatic retry, no LDAP or NAS side effects. The lock
only serializes cooperating callers using the same lock path; direct SQLite
writers and legacy APIs are not fenced. The SHA-256 evidence is not a signature.
Auteur : Abdelhalim Talbi.

## V184.7 / Compact V3.5.7 — Acquittement durable anti-rejeu

`ldaps_durable_ack.py` ajoute `DurableAcknowledgement`, une interface supervisée qui
valide la preuve et la fraîcheur sous verrou coopératif, persiste un reçu SQLite
chaîné SHA-256 (unicité de l'empreinte de preuve et de l'intention), puis acquitte
l'intention. Une interruption entre ces étapes est signalée pour réconciliation
manuelle ; aucun rejeu, aucune réparation silencieuse ni cutover automatique.
L'ancienne API d'acquittement reste disponible pour compatibilité et peut
contourner ce nouveau registre : ne pas l'exposer en production. La chaîne
SHA-256 n'est pas une signature externe, et le verrou n'arrête pas les écrivains
non coopératifs. Auteur : Abdelhalim Talbi.

## V184.8 / Compact V3.5.8 — Interrupted acknowledgement recovery

`ldaps_ack_recovery.py` introduces `InterruptedAckRecovery` for supervised
resolution of a durable acknowledgement receipt left behind after an intent
unlink crash. It requires a second, distinct reviewer identity, explicit
confirmation, fresh receipt, valid receipt chain, and a currently verified
policy/anchor. A new SQLite recovery audit is committed before intent unlink.
Replay and tampering are blocked. If unlink fails again, manual investigation
remains mandatory. This is **not** atomic across SQLite and filesystem.
Reviewer identity is declarative (not externally authenticated); the legacy
acknowledgement API remains available. No automatic migration or cutover.
Author: Abdelhalim Talbi.

## V184.9 / Compact V3.5.9 — Authenticated acknowledgement recovery
Auteur : Abdelhalim Talbi.

`ldaps_authenticated_ack_recovery.py` provides an **opt-in** wrapper around interrupted acknowledgement recovery. It validates HMAC-SHA256 signed, expiring identity assertions from explicitly trusted issuers, enforces a SECURITY reviewer grant, a different original operator, explicit confirmation, a durable one-use token identifier and a SHA-256-chained review ledger. It refuses tampered audit chains, stale receipts and failed policy verification. All outcomes keep execution and cutover authorization false.

**Security boundaries:** The HMAC assertion is NOT an AD/LDAP login, the issuer must independently authenticate the human and protect its signing key, and grants are locally provisioned. The original operator's identity is supplied by the caller rather than cryptographically bound to the original receipt. The wrapper is opt-in and legacy recovery APIs remain available. SQLite and filesystem intent removal remain non-atomic; an interrupted unlink after review is left for manual investigation, not replayed. Do not expose the legacy APIs to untrusted operators. No production qualification.

Run `python -m unittest discover -p 'test_*.py' -q`.


## V185.0 / Compact V3.6.0 — Révocation persistante des assertions

Auteur : Abdelhalim Talbi. Nouveau module `ldaps_identity_revocation.py` : registre SQLite des révocations d’émetteurs, sujets et identifiants de jeton ; chaînage SHA-256, transactions, garde optionnelle des récupérations HMAC. Les révocations sont définitives dans ce prototype ; aucune connexion OIDC/LDAP réelle. **L’API historique reste accessible : ne pas exposer directement en production.** Aucun cutover automatique.


## V185.1 / Compact V3.6.1 — OIDC offline verifier
Auteur : Abdelhalim Talbi. `ldaps_oidc_identity.py` verifies pinned RS256 JWKS JWT signatures, issuer, audience, expiry, not-before, issued-at and local revocations. No network or discovery, no login, no role authorization, no migration/cutover. Requires cryptography. Production requires trusted JWKS distribution, key rotation and enforcement at service boundaries.

## V185.2 / Compact V3.6.2 — OIDC RBAC decision gate

`ldaps_oidc_rbac.py` adds a fail-closed local role-mapping decision gate
for already-verified RS256 JWT identities, checks the persistent revocation
registry, consumes a token once per role, and writes a SHA-256 chained audit
record. Grants are provisioned via `provision()`; callers MUST independently
authenticate and authorize grant administrators. Authorization decisions do
NOT execute recovery, migrations, or cutovers. Legacy entry points are NOT
blocked in this release; isolate them before production use. No live OIDC,
LDAP, AD, or NAS integration is claimed.

Auteur : Abdelhalim Talbi.

## V185.3 / Compact V3.6.3 — Authenticated role administration
Auteur : Abdelhalim Talbi.
`ldaps_oidc_admin.py` supplies an opt-in OIDC SECURITY-role administration facade,
with revocation checks, one-use token digest, serialized SQLite role updates and
hash-chained audit. SECURITY bootstrap is out-of-band. This does NOT disable the
legacy `OIDCRBACGate.provision()` method or legacy recovery endpoints: deployers
MUST isolate those APIs and enforce this facade at the service boundary. No live
OIDC/AD/NAS qualification and no automatic cutover.

## V185.4 / Compact V3.6.4 — Dual-control OIDC administration
Auteur : Abdelhalim Talbi.

`ldaps_dual_control_admin.py` introduces an opt-in dual-review facade for
local OIDC RBAC grants: independent SECURITY and OPERATIONS subjects, signature
verification, revocation checks, SQLite BEGIN IMMEDIATE serialization, SHA-256
chained event audit, token replay rejection, and no migration/cutover effects.
The facade does NOT remove or intercept legacy provisioning and administrative
APIs; service boundary enforcement remains required. No external OIDC/AD/NAS
integration is claimed. `test_ldaps_dual_control_admin.py` covers the facade.


## V185.5 / Compact V3.6.5 — Secure role service boundary

Auteur : Abdelhalim Talbi. `ldaps_secure_service.py` exposes only two-person OIDC role administration and read-only audit status; direct legacy provisioning/recovery is not forwarded. Concurrent same-token calls through one service instance are serialized and replay is rejected. **Deployment limitation:** callers with direct access to underlying Python objects or SQLite can bypass this facade. It is not a network authentication boundary and does not globally disable legacy APIs. No real directory/NAS qualification; no migration or cutover authorized.


## V185.6 / Compact V3.6.6 — Cooperative interprocess service gate
- `ldaps_service_concurrency.py`: optional SQLite-backed interprocess exclusive lock for the sensitive role-service facade. Lock released by SQLite after process crash.
- `SecureRoleService(..., gate_path=...)` serializes cooperating processes using the same local lock-file path.
- Tests cover contention with spawned processes, crash recovery, rollback and fail-closed timeout.
- **Limitations:** optional opt-in gate; direct legacy Python/SQLite APIs bypass it; not a distributed lock, no remote identity provider/NAS integration; avoid NFS-hosted lock databases. No cutover is authorized.
- Auteur : Abdelhalim Talbi.

## V185.7 / Compact V3.6.7 — strict secure service (Auteur : Abdelhalim Talbi)
`SecureRoleService(..., strict=True, gate_path=...)` exige un verrou SQLite
interprocessus pour toutes les opérations exposées, y compris la lecture d'audit.
Le service vérifie les journaux RBAC et de révocation avant mutation et refuse
l'initialisation stricte sans verrou. L'option reste volontairement explicite
pour préserver la compatibilité. Ce n'est pas une isolation globale : les
anciennes API et l'accès direct SQLite doivent être bloqués par le déploiement.
Aucune migration ni bascule automatique.

## V185.8 / Compact V3.6.8 — Secure startup attestation

`ldaps_secure_startup.SecureStartupAttestation` performs a fail-closed local
startup preflight: strict mode, cooperative interprocess gate, SQLite
`integrity_check`, role/revocation/dual-control audit checks, and **explicit**
deployment declarations that legacy routes and direct database access are not
exposed. Exposure declarations are supplied by the deployer, NOT automatically
verified by OS isolation. This does not close legacy Python APIs or protect
against a privileged local attacker. No migration or cutover is authorized.
Auteur : Abdelhalim Talbi.


## V185.9 / Compact V3.6.9 — Legacy boundary inventory

Module `ldaps_boundary_inventory.py`: deterministic AST inventory of sensitive legacy
Python entrypoints, file-mode inspection for declared SQLite files, SHA-256
fingerprint, and explicit human review tied to the current fingerprint.
This is **not** a proof of runtime isolation, not a signature, and not a global
interceptor of direct SQLite or legacy calls. Existing services are unchanged.
A deployment must still enforce OS/container permissions and a private API boundary.
No automatic migration or cutover is authorized. Auteur : Abdelhalim Talbi.

## V186.0 / Compact V3.7.0 — POSIX service filesystem boundary
Auteur : Abdelhalim Talbi.
`ldaps_os_boundary.POSIXBoundaryAttestation` refuses root, unexpected UID,
symlinks, unsafe ownership/modes on the RBAC SQLite database, interprocess gate,
private directories and existing SQLite sidecars. It does not chmod or mutate
production state. Deploy under a dedicated unprivileged UID in a private 0700
folder with 0600 files. POSIX-only; Windows needs a separate ACL-aware verifier.
This is a filesystem attestation, NOT process sandboxing, direct API isolation,
or proof of production safety. Native ODMM engine remains default; no cutover.

## V186.1 / Compact V3.7.1 — Linux local audit IPC (auteur : Abdelhalim Talbi)
`ldaps_ipc_boundary.py` adds a deliberately **read-only** AF_UNIX IPC facade
for `audit_status` only. Requires an unprivileged Linux service account,
private 0700 socket directory, socket mode 0600, and peer UID allowlisting
via SO_PEERCRED. Strict JSON operation allowlist and bounded requests; errors
fail closed. **No role mutations or migration operations are exposed over IPC.**
Windows named pipes / DACL support, an authenticated write endpoint, lifecycle
management and deployment-level isolation are not implemented. Legacy direct
Python and SQLite APIs remain accessible to callers with filesystem access.

## V186.2 / Compact V3.7.2 — Lifecycle of Linux read-only audit IPC
Auteur : Abdelhalim Talbi.
`ldaps_ipc_lifecycle.py` provides explicit start, bounded serve and stop for the
read-only Unix socket. It checks socket identity (device/inode) before unlink,
refuses stale paths on restart and never automatically repairs interrupted
service state. Mutation operations remain unavailable. POSIX/Linux only;
Windows DACL/named-pipe support and authenticated administrative writes are
not implemented. Existing direct Python/SQLite APIs remain outside this IPC
boundary. No migration or cutover is authorized.

## V186.3 / Compact V3.7.3 — Supervision IPC locale (Abdelhalim Talbi)

`ldaps_ipc_supervisor.py` fournit une inspection non destructive des sockets Unix,
une preuve SHA-256 reproductible, le contrôle de remplacement entre inspection et
revue humaine, et des statuts explicites pour les anomalies de permissions,
d'horloge et d'ancienneté. L'âge d'un socket n'établit **pas** la vivacité du
processus; un socket récent ne garantit pas qu'un serveur écoute. Le module ne
supprime aucun socket et ne redémarre aucun service automatiquement. La preuve
SHA-256 est une empreinte non authentifiée, pas une signature ni un anti-rejeu
cryptographique. Pas encore d'implémentation Windows named pipes / DACL.

## V186.4 / Compact V3.7.4 — Active read-only IPC probe

`ldaps_ipc_active_probe.py` adds an opt-in, bounded Unix-domain-socket
availability probe with SO_PEERCRED UID validation, socket inode checks before
and after the request, strict response framing, and fail-closed reporting.
The probe never deletes sockets, restarts services, modifies roles, or authorizes
migration/cutover. It does **not** attest the actual service binary, and is
not a Windows named-pipe implementation. Author: Abdelhalim Talbi.


## V186.5 / Compact V3.7.5 — IPC process identity guard
Read-only Linux /proc process birth-time and pinned executable SHA-256 checks; explicit operator reset after PID restart. No automatic socket cleanup, service restart, migration or cutover. The pin is configured locally, not remote attestation; no Windows implementation yet. Author: Abdelhalim Talbi.


## V186.6 / Compact V3.7.6 — Persistent IPC process identity pin

`ldaps_ipc_persistent_identity.py` stores a locally authenticated HMAC-SHA256
process identity pin (PID, /proc start ticks, expected executable digest) using
atomic file replacement and fsync. Enrollment and rotation require explicit
operator confirmation and exact observed identity. Missing, corrupt or changed
pins fail closed. Never auto-delete sockets, restart services or authorize cutover.

**Limits:** local key management is external; HMAC is not remote attestation.
Pin rotation has no two-person approval; concurrent enrollments are not serialized
across processes. This Linux-only add-on does not block legacy APIs.
Auteur : Abdelhalim Talbi.

### V186.7 / Compact V3.7.7 — Dual-reviewed IPC pin rotation
`ldaps_ipc_dual_pin.py` adds a cooperating-process SQLite `BEGIN IMMEDIATE` lock,
separate declared SECURITY and OPERATIONS reviewers, an HMAC chained audit and
fail-closed handling of incomplete pin publication. No automatic reconciliation.
**Security boundaries:** reviewer names are not authenticated; the legacy direct
`PersistentProcessIdentity.rotate()` remains callable; the audit DB is not
externally anchored against complete rollback; SQLite and pin file do not share
an atomic commit. This is not production-grade dual authorization.
Auteur : Abdelhalim Talbi.

## V186.8 / Compact V3.7.8 — Authenticated IPC pin rotation

New `ldaps_ipc_authenticated_rotation.py` adds a strictly opt-in dual OIDC reviewer
facade for the existing SQLite-coordinated pin rotation. It requires separate
SECURITY and OPERATIONS identities, an external trusted RBAC `assert_role`
authority, explicit operator confirmation and a local HMAC checkpoint of the
SQLite audit head and process pin. It detects rollback or interrupted publication
and refuses further rotation pending manual investigation. No automatic recovery.

Security limitations: The checkpoint is not an independent tamper-proof counter:
a simultaneous rollback of all files can still evade detection. Checkpoint updates
are not serialized with the SQLite gate; concurrent facade users need deployment
isolation. Existing `DualPinController.rotate` and `pin.rotate` remain callable,
so service/OS isolation is mandatory. This does not implement a complete OIDC
login or actual LDAP/AD integration. The verifier's `assert_role` must be a trusted
RBAC implementation, not an unverified JWT claim. No production cutover permitted.

## V186.9 / Compact V3.7.9 — Serialized authenticated IPC rotation

`ldaps_ipc_serialized_rotation.py` provides an optional SQLite `BEGIN IMMEDIATE`
cooperating-process lock around authenticated checkpoint enrollment, inspection,
rotation, and read-only reconciliation reporting. A failed or ambiguous rotation
remains blocked until manually investigated; no automatic re-anchor or cutover.

**Security boundaries:** the lock is not a distributed lock, does not stop direct
legacy API or filesystem/SQLite writes, and is not atomic across checkpoint and
pin files. All instances must use the same lock path; deployments must isolate
legacy entry points. Reviewer roles rely on a trusted verifier. No real NAS,
AD/LDAP, or Windows named-pipe qualification is claimed.

Auteur : Abdelhalim Talbi.

### V187.0 / Compact V3.8.0 — IPC rotation reconciliation evidence

Auteur : Abdelhalim Talbi. `ldaps_ipc_reconciliation.py` provides a read-only
snapshot of checkpoint, journal and pinned-process identity under the cooperative
SQLite lock, followed by OIDC-authenticated SECURITY and OPERATIONS review of the
exact snapshot digest. It issues an HMAC-authenticated review receipt requiring
manual investigation. The receipt is **not durably archived**, does not clear
pending transitions, and never authorizes automatic recovery, migration or cutover.
Legacy direct APIs are still accessible. An external trusted evidence archive and
production identity/role integration remain necessary.

### V187.1 / Compact V3.8.1 — Durable IPC review ledger
Auteur : Abdelhalim Talbi. `ldaps_ipc_durable_review.py` persists HMAC-chained
review receipts in SQLite under the cooperative rotation lock. Replaying the same
evidence digest is rejected, and the ledger is reverified on restart. Neither
review nor receipt authorizes recovery or cutover. Historical direct APIs remain
accessible; database snapshot rollback and external tampering of all resources
are outside the protection of this local ledger.

## V187.2 / Compact V3.8.2 — Independent IPC review ledger anchor

`ldaps_ipc_review_anchor.py` adds an external HMAC-SHA256 checkpoint of the
review ledger's verified count and chain head. Enrollment and advancement are
explicit human-confirmed operations under the cooperative interprocess SQLite
lock. Verification is read-only and fails closed on tampering, rollback, or
unpublished ledger changes. After a new review, the ledger intentionally remains
in a pending-checkpoint state until an operator verifies the evidence and
explicitly publishes the new checkpoint. No automatic repair or cutover.

Limits: a coordinated rollback of both the SQLite ledger and anchor is not
prevented; HMAC keys need independent protection. Direct legacy APIs remain
accessible, and there is no live AD/LDAP/NAS qualification.

## V187.3 / Compact V3.8.3 — External review witness
Auteur : Abdelhalim Talbi.
`ldaps_ipc_external_witness.py` provides a separately placed HMAC-SHA256
monotonic witness history for the IPC review ledger checkpoint. Explicit
operator enrollment/publication only, cooperative SQLite interprocess gate,
read-only restoration report, replay and divergence detection. Deploy witness
in an independently administered storage/failure domain; local placement does
NOT protect against simultaneous rollback of every copy. No automatic repair,
recovery authorization, migration or cutover. No live AD/LDAP/NAS qualification.

## V187.4 / Compact V3.8.4 — Remote read-only witness verification

`ldaps_remote_witness.py` implements an optional mutually authenticated TLS
client for an independently operated witness endpoint. Each read request has a
fresh 256-bit nonce; the reply must include the same nonce and a keyed HMAC of
its version, nonce, count and last ledger MAC. Divergence or network errors
fail closed. No remote write, publication, repair or cutover method is provided.

The test transport is injected for deterministic protocol tests. **There is no
production witness server in this package and no end-to-end mTLS qualification.**
The remote operator must implement the documented newline-delimited JSON
protocol, secure HMAC keys independently, and enforce append-only witness state.
This does not protect against compromise of the independent witness itself.

Auteur : Abdelhalim Talbi.

### V187.5 / Compact V3.8.5 — Remote witness reference server

`ldaps_remote_witness_server.py` adds an operator-managed SQLite append-only
HMAC ledger, optimistic CAS publications with explicit human confirmation,
read-only nonce-bound responses compatible with V187.4, and an mTLS TCP
listener requiring client certificates. Only `read` is exposed over the
network: publication is an **out-of-band** operator operation. SQLite is not
immutable/WORM and cannot resist an attacker restoring both DB and key.
Deploy on an independently administered host; restrict access to DB and key.
No production NAS/AD/LDAP qualification or automatic cutover.

## V187.6 / Compact V3.8.6 — boucle mTLS réelle (2026-10-14)
Auteur : Abdelhalim Talbi.

`test_ldaps_remote_witness_mtls_e2e.py` démarre un serveur TLS sur loopback avec
certificats éphémères générés par OpenSSL et valide réellement la connexion
mutuellement authentifiée entre `RemoteWitnessVerifier` et `RemoteWitnessStore`.
Scénarios : lecture, publication hors bande suivie de lecture, mauvaise CA,
nom DNS invalide, absence de certificat client, divergence du témoin,
clé HMAC incorrecte, indisponibilité après arrêt. Les certificats de test
sont éphémères et ne sont pas livrés dans l'archive.

**Limites :** ce sont des tests d'intégration loopback, pas un déploiement Debian
sur deux hôtes indépendants. La configuration PKI, le renouvellement des
certificats, les permissions systemd, la révocation CRL/OCSP, le réseau réel
et les reprises après panne restent à qualifier. Aucune publication réseau,
auto-réparation, migration ni bascule n'est exposée. L'absence d'OpenSSL
entraîne l'ignorance explicite de ces tests.

## V187.7 / Compact V3.8.7 — Déploiement témoin Debian 13

Ajout de `ldaps_witness_daemon.py` : démarrage non-root, configuration stricte,
rejet des liens symboliques et secrets trop accessibles, listener mTLS en
lecture seule. Modèle systemd et guide sous `deploy/debian13/`.
Ce modèle n'a pas été installé ni testé sur une machine Debian 13 indépendante.
La révocation des certificats, le renouvellement et les tests réseau inter-hôtes
restent à qualifier. Auteur : Abdelhalim Talbi.

## V187.8 / Compact V3.8.8 — Rotation supervisée des certificats
Auteur : Abdelhalim Talbi.

`ldaps_witness_cert_rotation.py` vérifie les certificats mTLS candidats avant
rotation : dates de validité, seuil d'expiration, SAN DNS, EKU serverAuth,
correspondance certificat/clé, permissions et présence d'une CA PEM. Le plan
exige deux confirmations déclaratives, sans authentification des approbateurs.
Aucun fichier en production n'est modifié et aucun service n'est redémarré.

Limites : le précontrôle ne vérifie **pas** la chaîne de confiance CA, la
révocation CRL/OCSP ou une connexion mTLS active. Ces contrôles doivent être
réalisés avant tout déploiement supervisé. Pas de test Debian inter-hôtes.

## V187.9 / Compact V3.8.9 — Vérification de confiance et retour arrière supervisé
Auteur : Abdelhalim Talbi.

`ldaps_witness_trust_validation.py` ajoute la vérification OpenSSL de la chaîne
CA, du nom DNS et de l'usage TLS serveur. Si un fichier CRL est fourni,
`-crl_check_all` est imposé et une CRL invalide ou absente bloque la vérification.
Sans CRL, le résultat indique explicitement `REVOCATION_UNKNOWN` et ne donne
aucune autorisation de déploiement. OCSP n'est pas implémenté. Le plan de retour
arrière exige deux confirmations déclaratives et ne modifie aucun fichier.
Aucun redémarrage systemd réel ni validation sur deux hôtes n'est revendiqué.

## V188.0 / Compact V3.9.0 — Witness recovery gate

`ldaps_witness_recovery_gate.py` provides a read-only post-restore qualification
that checks a locally verified durable review anchor against a separately
administered remote witness. It refuses changed local heads, remote divergence,
invalid evidence and outages. Bounded retries apply **only** to temporary remote
unavailability, never to mismatches. All reports explicitly deny recovery,
publication and cutover authorization. This is an evidence gate, not a recovery
executor. Run `python -m unittest test_ldaps_witness_recovery_gate -v`.

No remote-host deployment or OCSP qualification is claimed. Witness storage
must be outside the restore domain; legacy direct APIs remain a bypass risk.

## V188.1 / Compact V3.9.1 — Témoin distant : redémarrage et panne réseau

Ajout de `test_ldaps_witness_restart_network.py` : tests d'intégration mTLS sur socket loopback du redémarrage du service témoin, de la persistance SQLite (0, 1 et 2 publications), de la divergence après redémarrage, du refus de consultation pendant une panne, du rétablissement manuel du service, de la clé HMAC incorrecte et du refus d'une publication par l'API réseau en lecture seule. Aucun redémarrage systemd, hôte Debian indépendant ou panne réseau physique n'est qualifié. Les opérations de publication restent explicitement confirmées par l'opérateur, hors API réseau ; aucune migration/cutover automatique.

Auteur : Abdelhalim Talbi.

## V188.2 / Compact V3.9.2 — qualification multiprocessus

`test_ldaps_witness_multiprocess.py` exercises separate Python OS processes for
SQLite witness publication (including six concurrent contenders), persistent
HMAC state across process exits, database corruption refusal, and an independent
TLS server process killed/restarted while an authenticated client verifies the
witness. No publication, migration, recovery or cutover is automated.

Limits: local loopback and shared host only, not two physical Debian hosts;
no real network partition, systemd restart, immutable witness storage or
end-to-end certificate revocation qualification. Tests are not production certification.
Author: Abdelhalim Talbi.

## V188.3 / Compact V3.9.3 — Préqualification de deux hôtes

`ldaps_two_host_qualification.py` fournit un précontrôle explicite d'une cible témoin
non-loopback, la vérification des fichiers mTLS et une sonde de lecture distante
avec confirmation humaine. Les résultats ne donnent jamais d'autorisation de
restauration, publication ou cutover. Les tests `test_ldaps_two_host_qualification.py`
couvrent les échecs DNS, les adresses locales, les certificats absents, les
refus de confirmation et les divergences. Les tests simulés ne prouvent pas
que le témoin est réellement sur un autre hôte ou domaine d'administration.

Auteur : Abdelhalim Talbi.

## V188.4 / Compact V3.9.4 — kit de qualification sur deux hôtes

- `ldaps_two_host_runbook.py`: CLI de vérification mTLS en lecture seule, avec rapport HMAC signé et écriture exclusive mode 0600.
- `qualification/TWO-HOST-DEBIAN13.md`: procédures manuelles de coupure réseau, redémarrage systemd, restauration et audit.
- `test_ldaps_two_host_runbook.py`: tests de refus, intégrité du rapport et absence d'autorisation de cutover.
- Le kit ne simule pas une qualification réelle sur deux machines ; les opérations perturbatrices restent manuelles et explicitement approuvées.

## V188.5 / Compact V3.9.5 — Consolidation de preuves deux hôtes

- `ldaps_two_host_evidence_bundle.py` : enregistrements de scénarios signés HMAC,
  consolidation déterministe, refus des doublons et des incidents divergents,
  publication atomique sans écrasement d'un rapport signé.
- `test_ldaps_two_host_evidence_bundle.py` : tests de sécurité et de non-régression.
- Les scénarios réseau, redémarrage systemd et restauration sont **déclaratifs** :
  aucune action distante ou perturbatrice n'est exécutée par le collecteur.
- Le statut `REPORTED_COMPLETE` ne constitue **pas** une preuve indépendante
  d'exécution ; revue humaine obligatoire et aucune autorisation de cutover.
- Auteur : Abdelhalim Talbi.

## V188.6 / Compact V3.9.6 — Preuves techniques signées par deux hôtes

- `ldaps_two_host_attested_evidence.py` : déclarations horodatées distinctes
  par hôte et identifiant d'exécution, HMAC par hôte, fenêtre temporelle,
  contrôle de schéma strict, registre SQLite anti-rejeu transactionnel.
- `test_ldaps_two_host_attested_evidence.py` : tests de divergence, rejeu,
  expiration, signature, nonce et interdiction d'autorisation automatique.
- Les attestations prouvent la possession des clés, **pas** l'exécution
  technique indépendante ni la séparation administrative des hôtes.
- Aucune migration, réparation, publication, restauration ou bascule automatique.
- Auteur : Abdelhalim Talbi.

## V188.7 / Compact V3.9.7 — Read-only technical observation and multiprocess replay

- `ldaps_two_host_observation.py`: bounded TCP reachability and local file digest probes, strictly read-only, no remote disruption or cutover.
- `ObservationRegistry`: SQLite atomic uniqueness by run/host/probe/target, fail-closed on replay across independent processes.
- `test_ldaps_two_host_observation.py`: technical probe and multiprocessing regression tests.
- Observations are **not** proof of independent execution, TLS authentication, physical host independence, or operational authorization.
- Author: Abdelhalim Talbi.

## V188.8 / Compact V3.9.8 — Robustesse des observations de fichiers

- Nouveau `ldaps_observation_hardened.py` : lecture bornée via descripteur avec `O_NOFOLLOW`, rejet des fichiers non réguliers, contrôle `fstat` avant/après et empreinte SHA-256.
- Tests de symlink, FIFO, dépassement de taille, modification concurrente et remplacement atomique.
- Collecte en lecture seule, aucune autorisation automatique de migration, restauration, publication ou cutover.
- Limites : la collecte ne garantit pas un snapshot atomique contre un adversaire capable de restaurer les métadonnées ; les anciennes API de collecte restent accessibles. La qualification sur deux machines Debian indépendantes n'est pas réalisée.
- Auteur : Abdelhalim Talbi.

## Audit V188.9 — Correctif de collecte et revue de maturité
Auteur : Abdelhalim Talbi. `ldaps_two_host_observation` délègue désormais le hachage de fichiers à `ldaps_observation_hardened.observe_file` afin de supprimer le chemin `stat/read_bytes` vulnérable aux remplacements entre vérification et lecture. Rapport : `AUDIT-ARCHITECTURE-ET-PLAN-INDUSTRIALISATION.md`. 26 tests ciblés réussis. **Suite complète non confirmée sur cette branche.** Prototype non qualifié production.


## V189.0 / Compact V4.0.0 — R0 quality gate
Isolation de chaque module de test dans un processus, timeout par module, rapport JSON non-écrasant avec SHA-256 des sources, refus de qualification automatique. Usage : `python quality_gate.py --pattern "test_ldaps_*.py" --timeout 60 --report /tmp/odmm-quality.json`. Ne constitue pas une qualification NAS/ACL réelle. Auteur : Abdelhalim Talbi.

## V189.1 / Compact V4.0.1 — Native POSIX migration prototype
Auteur : Abdelhalim Talbi. `native_posix_migration.py` adds a limited regular-file native copy with SHA-256, atomic no-clobber publication, SQLite journal, explicit verification and conservative restart. Source and target must be separate non-overlapping local trees; directory structure must pre-exist. Rejects symlinks, non-regular files, existing unjournaled targets and drift. No NFS/SMB ACL, xattrs, ownership, sparse-file, hardlink semantics, directory tree migration, concurrent job fencing or real NAS qualification. A crash after atomic publication but before SQLite commit requires manual reconciliation; the engine refuses overwriting the orphan target. Never authorizes cutover. The source must be quiescent; timestamp/ctime checks cannot guarantee a stable source under adversarial concurrent writes.

## V189.2 / Compact V4.0.2 — Native POSIX recovery
- Durable SQLite intent before atomic publication; operator-confirmed reconciliation after interruption.
- Interprocess cooperative flock on the registry; duplicate operations serialize.
- Fail-closed on source/destination mismatch, missing file, or pending intent.
- POSIX regular-file prototype only; no ACL/xattr/UID/GID preservation or full tree traversal; no production NAS qualification.
- Targeted native tests: 20 passed. Full regression attempted, did not complete within execution budget.

## V189.3 / Compact V4.0.3 — Native tree orchestration

Added `native_tree_migration.py` and `test_native_tree_migration.py`. Deterministic
POSIX regular-file inventory, conservative batch copy via V189.2 transactional
engine, verification, no overwrite, no implicit directory creation, no cutover.
Not production NAS migration: TOCTOU directory replacement, ACL/xattr/owner
fidelity, distributed fencing, source mutations and filesystem crash durability
require further qualification. Author: Abdelhalim Talbi.

## V189.4 / Compact V4.0.4 — Crash durability qualification
- SQLite native migration ledger uses `PRAGMA synchronous=FULL` with WAL for stronger durability of intent and commit transactions.
- `test_native_crash_durability.py` exercises real subprocess `os._exit(77)` after temp fsync and after publication, verifies persisted intent, requires explicit human reconciliation, rejects changed targets, and confirms no overwrite on retry.
- Tested 37 focused tests across native POSIX, reconciliation, tree and crash modules. This does not qualify remote NAS fsync semantics, distributed fencing, or directory replacement races. Full regression suite is not claimed.

## V189.5 / Compact V4.0.5 — primitives dir_fd (14 octobre 2026)
Auteur : Abdelhalim Talbi.
Ajout `native_dirfd_guard.py` : ouverture des composants de chemins par descripteurs de répertoires avec `O_NOFOLLOW`, lecture bornée de fixtures régulières, publication atomique sans écrasement dans un répertoire épinglé. Tests : `test_native_dirfd_guard.py`.
**Important : primitives préparatoires non encore raccordées au parcours `NativePosixMigration.copy` / `NativeTreeMigration.inventory`. Les anciens chemins restent sujets à des courses TOCTOU ; cette livraison ne prétend pas les corriger.**
Les tests ciblés du nouveau composant et du moteur existant sont réussis ; suite complète non exécutée. Aucun support ACL/NFSv4/SMB ni fencing distribué qualifié.

## V189.6 / Compact V4.0.6 — Descriptor-pinned native engine

- Connects `native_dirfd_guard.parent_fd` and `publish_noreplace` to the native copy, verify and manual reconciliation paths.
- Opens regular files with `O_NOFOLLOW` relative to pinned parent directory descriptors; rejects unsafe parent traversal.
- Revalidates parent directory inode identity before publication and before committing the journal. An unexpected replacement fails closed and may leave a pending intent requiring manual reconciliation.
- Maintains durable SQLite intent, SHA-256 verification, no-overwrite semantics and no automatic cutover.
- New tests cover parent replacement before/after publication, symlink replacement and explicit crash reconciliation.
- Limits: cooperative local locking, no distributed fencing, no NFSv4/SMB ACL preservation, root path replacement not fully protected, full regression not confirmed.

## V189.7 / Compact V4.0.7 — Root identity pinning
Auteur : Abdelhalim Talbi.
- Le moteur natif conserve les descripteurs des racines source/destination et vérifie leur identité avant les opérations critiques.
- Refus des racines symboliques directes, des remplacements de racines et des modifications source après publication.
- `fsync` du répertoire après suppression du temporaire publié.
- Voir `ARCHITECTURE-QUALITY-ROADMAP-V189.7.md` pour l'analyse P0/P1/P2 et les limites restantes.

## V189.8 / Compact V4.0.8 — Root descriptor anchoring and inode identity
- Native POSIX copy/verify/reconcile traverses from pinned root descriptors, not fresh root pathname opens.
- Checks the source directory entry still names the pinned source inode before publication and commit.
- Adds regression tests for renamed root descriptors and same-content source replacement after publication.
- 65 targeted tests passed; full-suite results reported separately.
- Limitations: path-based root identity checks still have sampling windows; no distributed fencing, NAS ACL fidelity, or vendor qualification; no automatic cutover.

## V189.9 / Compact V4.0.9 — Consistent file verification
Auteur : Abdelhalim Talbi.
- `_verified_hash` verifies pinned inode/device/size/mtime/ctime before and after hashing, refusing observable concurrent mutations.
- `verify`, `reconcile` and already-committed `copy` now check directory entries still refer to the verified inode, preventing same-content replacement acceptance.
- Added regression tests for in-place modification during hashing and destination entry replacement during verify/reconcile.
- Native test suite: 79 tests passed. Full repository regression not claimed.
- Limitations: POSIX only; no atomic snapshot, malicious writers with metadata restoration or writes between checks may evade detection; no SMB/NFSv4 ACL or distributed fencing qualification.

## V190.0 / Compact V4.1.0 — Durable incremental POSIX inventory
Auteur : Abdelhalim Talbi.

Added `native_incremental_inventory.py` and `test_native_incremental_inventory.py`.
Captures durable SQLite inventory passes and compares added/deleted/modified regular files by dev/inode/size/mtime/ctime/mode. Read-only, pinned-root traversal, fail-closed for symlinks and special entries. No implicit deletion, copying, ACL validation, snapshot guarantee or cutover. Full regression not executed; targeted suite: 76 tests passed.

Design caveat: inventories are sequential observations, not consistent filesystem snapshots; a concurrent change can escape detection. A complete inventory is not a guarantee of migration completeness or metadata fidelity. Next steps: change journal / incremental copy gate, persistent job states, metadata and ACL capability matrix, full regression.

## V190.1 / Compact V4.1.1 — Transactional incremental planner
Auteur : Abdelhalim Talbi

- `native_incremental_planner.py`: deterministic durable plans from two COMPLETE inventories; SHA-256 plan and inventory integrity checks; SQLite transactional plan creation and idempotence.
- COPY claims with durable unique tokens; interrupted claims are blocked pending explicit operator reset; native intent/committed records prevent blind reset.
- DELETE_REVIEW tasks are never executable or auto-approved; no migration, cutover or deletion is triggered by this planner.
- `record_verified` only acknowledges an existing native committed record and marks `COMMITTED_REVERIFY_REQUIRED`; it does NOT certify final source/target re-hash or ACL fidelity.
- No leases or distributed fencing, no snapshot isolation, no actual incremental execution scheduler, no SMB/NFSv4 ACL preservation. Human approval arguments are declarative, not identity-authenticated.
- Targeted validation: 47 tests passed including 15 new planner tests. Full suite not run for this release.

## V190.2 / Compact V4.1.2 — Native incremental executor
Auteur : Abdelhalim Talbi.

`native_incremental_executor.py` links a previously claimed COPY task to the native
POSIX engine, validates source identity against the persistent inventory, performs
non-overwriting native copy, re-verifies source and destination while holding the
cooperative lock, and commits a `VERIFIED_POSIX_SUBSET` task state. An interruption
after publication leaves the claim blocked. `acknowledge_reconciled()` requires
explicit operator confirmation, a reconciled native intent and fresh verification.
No automatic claim, deletion, fallback, rollback or cutover.

Limitations: POSIX regular files only; source inventory is not a coherent snapshot;
no NFSv4/SMB ACL fidelity; no distributed fencing; no production NAS qualification.

## V190.3 / Compact V4.1.3 — Crash boundaries et acquittement atomique
Auteur : Abdelhalim Talbi.
- Cinq tests de processus indépendants avec arrêt brutal (`os._exit`) : avant exécution, après fsync temporaire, après publication, après commit natif, et modification de destination après crash.
- L'acquittement après réconciliation contrôle désormais `rowcount == 1` et annule la transaction en cas de divergence.
- 108 tests ciblés du moteur natif réussis ; suite complète non exécutée.
- Limites : POSIX fichiers réguliers, absence de fencing distribué, ACL NFSv4/SMB non qualifiées, pas de cutover automatique.

## V190.4 / Compact V4.1.4 — inventaire conservateur des fichiers temporaires
- `native_orphan_inventory.py` : inventaire en lecture seule des fichiers `.odmm-<uuid>.part` dans un répertoire cible épinglé, refus des liens symboliques, des chemins traversants et des racines remplacées.
- Aucune suppression automatique : le caractère réellement orphelin ne peut pas être prouvé sans protocole d'ownership et de liveness. Une revue humaine est obligatoire.
- `test_native_orphan_inventory.py` : sept tests dédiés ; 99 tests natifs ciblés réussis.
- Limites : l'inventaire n'est pas un garbage collector et n'est pas une preuve d'absence de worker actif. La suite complète ODMM n'a pas été exécutée.

## V190.5 / Compact V4.1.5 — Revue des fichiers temporaires
Auteur : Abdelhalim Talbi. Le module `native_orphan_review.py` conserve les décisions de revue en SQLite, revérifie l'identité POSIX, refuse les intentions de copie en attente dans le répertoire et n'autorise **que l'investigation manuelle**. Aucune suppression, quarantaine ou bascule automatique. Tests : `python -m unittest discover -p 'test_native_*.py' -q` (158 réussis sur la suite native disponible).

## V190.6 / Compact V4.1.6 — Audit HMAC des revues
Auteur : Abdelhalim Talbi. `native_orphan_audit.py` ajoute une chaîne HMAC-SHA256 pour les décisions de revue. `approve_for_manual_investigation` exige désormais `audit_key` (secret externe >=32 octets) et écrit décision et preuve dans une seule transaction SQLite. Aucune autorisation de suppression ni de cutover. Voir `ARCHITECTURE-QUALITY-ROADMAP-V190.6.md`.

## V190.7 / Compact V4.1.7 — Export d'audit
Auteur : Abdelhalim Talbi. `native_audit_export.py` fournit `build_bundle`, `verify_bundle`, `checkpoint`, `verify_checkpoint`, `export_file` pour les événements de revue des fichiers temporaires. L'ancrage externe est une opération manuelle indispensable à la détection d'une réécriture privilégiée. 185 tests natifs validés; aucune suppression ni bascule automatique. Voir `ARCHITECTURE-QUALITY-ROADMAP-V190.7.md`.

## V190.8 / Compact V4.1.8 — 2026-10-14

Auteur : Abdelhalim Talbi. Export HMAC sous instantané SQLite cohérent (SAVEPOINT), vérification sous concurrence WAL, attestation de rotation à deux signatures HMAC **sans changement de clé actif**. Voir `ARCHITECTURE-QUALITY-ROADMAP-V190.8.md`. Aucun cutover ni nettoyage automatique autorisé. Tests natifs : 193 OK.

## V190.9 / Compact V4.1.9 — Audit segmenté
Auteur : Abdelhalim Talbi. Nouveau module autonome `native_segmented_audit.py` et tests `test_native_segmented_audit.py`. Rotation explicite dual-HMAC avec conservation de l'historique ; aucune migration silencieuse de l'ancien journal. Voir `ARCHITECTURE-QUALITY-ROADMAP-V190.9.md`.

## V191.0 / Compact V4.2.0 — Pont d'audit transactionnel
Auteur : Abdelhalim Talbi. `native_audit_bridge.py` introduit l'activation supervisée du pont legacy → audit segmenté, avec checkpoint HMAC et double écriture atomique pour les nouvelles revues. Tests natifs : 226 OK. Pas de cutover ni de nettoyage automatique. Voir `ARCHITECTURE-QUALITY-ROADMAP-V191.0.md`.

## V191.1 / Compact V4.2.1 — Cohérence inter-journaux
Auteur : Abdelhalim Talbi. Ajout de `native_bridge_consistency.py` et
`test_native_bridge_consistency.py`. Le vérificateur rapproche les événements
historiques et segmentés, valide le checkpoint et accepte des ancrages externes.
Lecture seule, sans nettoyage automatique ni autorisation de cutover.
Voir `ARCHITECTURE-QUALITY-ROADMAP-V191.1.md`.

## V191.2 / Compact V4.2.2 — vérification sous instantané SQLite
Auteur : Abdelhalim Talbi. Nouvelle API `native_bridge_consistency.verify_bridge_snapshot(database_path, legacy_key=..., segment_keys=...)` : connexion indépendante en lecture seule, transaction de lecture garantissant la cohérence des deux journaux, fermeture systématique. Tests dans `test_native_bridge_snapshot.py`. Aucun cutover automatique.

## V191.3 / Compact V4.2.3 — contrôle multiprocessus
Auteur : Abdelhalim Talbi. Vérification d'audit sur instantané SQLite sous écriture non validée depuis un processus distinct ; encodage sécurisé des URI de bases SQLite. 286 tests natifs réussis ; voir `ARCHITECTURE-QUALITY-ROADMAP-V191.3.md`.

## V191.4 / Compact V4.2.4 — Concurrence des journaux d'audit
Auteur : Abdelhalim Talbi. Nouveau test multiprocessus `test_native_bridge_contention.py` : trois lecteurs concurrents, deux rotations HMAC successives, vérification finale croisée. 301 tests natifs réussis ; avertissements de nettoyage des fixtures encore présents. Voir `ARCHITECTURE-QUALITY-ROADMAP-V191.4.md`.

## V191.5 / Compact V4.2.5 — Benchmark audit lecture seule
Auteur : Abdelhalim Talbi. `native_audit_benchmark.py` mesure p50/p95/p99, débit et erreurs des vérifications croisées multiprocessus SQLite. Exemple : `ODMM_LEGACY_HMAC_KEY_HEX=<hex> ODMM_SEGMENT_KEYS_JSON='{"k1":"<hex>"}' python native_audit_benchmark.py /chemin/registre.sqlite --workers 3 --repetitions 20 --output /chemin/rapport.json`. Les clés sont requises via l'environnement ; le rapport ne les contient pas. Aucun cutover autorisé. Voir `ARCHITECTURE-QUALITY-ROADMAP-V191.5.md`.

## V191.6 / Compact V4.2.6 — contention SQLite sur copie isolée
Auteur : Abdelhalim Talbi. Module `native_mixed_audit_benchmark.py` : banc multiprocessus de lecture d'audit et écritures artificielles sur clone SQLite transactionnel. Latences p50/p95/p99, conflits BUSY, erreurs et débit. La base source n'est pas modifiée ; aucun cutover. Tests natifs : 337 réussis. Voir `ARCHITECTURE-QUALITY-ROADMAP-V191.6.md`.

### V191.7 / Compact V4.2.7 — Benchmark reliability
Fermeture explicite des connexions de sauvegarde, budget de délai multiprocessus,
rapport manquant traité sans exception non contrôlée et taux de conflits SQLite.
Auteur : Abdelhalim Talbi. Tests natifs : 337 réussis. Non qualifié NAS production.


## V191.8 / Compact V4.2.8 — Historique des benchmarks
Module `native_benchmark_history.py` : archivage JSONL local, rendu HTML statique du cockpit, 9 nouveaux tests. Auteur : Abdelhalim Talbi. Aucun cutover.

## V191.9 / Compact V4.2.9 — Historique chaîné des benchmarks
Voir `ARCHITECTURE-QUALITY-ROADMAP-V191.9.md`. Fonctions `append_verified` et `read_verified` de `native_benchmark_integrity.py`. SHA-256 détecte des altérations sans constituer une preuve authentifiée; pas de raccordement au portail déployé.

## V192.0 / Compact V4.3.0 — Authenticated benchmark campaigns
New `native_benchmark_authenticated.py` offers HMAC-SHA256 journal records, explicit dual-key authenticated rotation, full-chain validation, optional external trusted head and safe report redaction. It is independent from the previous SHA-only history; it does not authorize cutover. See `ARCHITECTURE-QUALITY-ROADMAP-V192.0.md`. Auteur : Abdelhalim Talbi.

### V192.1 / Compact V4.3.1
Authenticated history initialization writes the `start` and initial `report` records in one prepared batch and fsyncs on success. Crash/failure injection tests exercise pre-write and partial-write boundaries; partial/corrupted histories fail closed. See `ARCHITECTURE-QUALITY-ROADMAP-V192.1.md`. Auteur : Abdelhalim Talbi.

## V192.2 / Compact V4.3.2
Diagnostic read-only de récupération HMAC: `native_benchmark_recovery.diagnose_authenticated`.
État VERIFIED/EMPTY/BLOCKED, conservation des preuves et aucune réparation automatique.
Voir `ARCHITECTURE-QUALITY-ROADMAP-V192.2.md`.

## V192.3 / Compact V4.3.3
Evidence-first supervised HMAC journal recovery proposal in `native_benchmark_recovery_plan.py`. Read-only SHA-256 evidence fingerprint and explicit review acknowledgement. This does not authenticate the operator or authorize repair/cutover. See `ARCHITECTURE-QUALITY-ROADMAP-V192.3.md`.

## V192.4 / Compact V4.3.4
`native_benchmark_evidence.py` fournit un diagnostic HMAC et une sauvegarde facultative sur le même instantané verrouillé. Aucune réparation automatique ni cutover. Voir `ARCHITECTURE-QUALITY-ROADMAP-V192.4.md`.

## V192.5 / Compact V4.3.5
Evidence backups: symlink-safe destination traversal, inode verification, private mode and fsync of file + directory. See ARCHITECTURE-QUALITY-ROADMAP-V192.5.md.

## V192.6 / Compact V4.3.6 — Publication des sauvegardes de preuves

Voir `ARCHITECTURE-QUALITY-ROADMAP-V192.6.md`. Les copies HMAC sont préparées et vérifiées dans un fichier privé avant publication exclusive, avec test de concurrence. Aucun cutover ni réparation automatique. Auteur : Abdelhalim Talbi.

## V192.7 / Compact V4.3.7 — Forensic stage inventory
Auteur : Abdelhalim Talbi. `native_benchmark_stage_inventory.py` exposes read-only
`inventory_stages(directory)` and `cockpit_evidence_payload(journal, directory, keys=...)`.
This is an integration-ready payload, not a deployed portal endpoint. No cleanup,
repair, fallback, or cutover authorization is performed.

## V192.8 / Compact V4.3.8 — Manifeste HMAC des preuves
Auteur : Abdelhalim Talbi. Le module `native_benchmark_evidence_manifest.py` signe les diagnostics cockpit en HMAC-SHA256 (clé externe >=32 octets) et vérifie le manifeste en lecture seule. L'empreinte externe facultative protège contre la substitution/retour arrière si elle est conservée hors de la machine. Pas de nettoyage, réparation, cutover ni identité humaine implicite. Voir `ARCHITECTURE-QUALITY-ROADMAP-V192.8.md`.

## V192.9 / Compact V4.3.9 — Evidence cockpit panel

`native_benchmark_cockpit_panel.cockpit_panel()` renders an escaped, HMAC-verified read-only HTML fragment for the **existing** ODMM portal. `cockpit_status()` returns a read-only status object. These are integration contracts, not deployed routes. No cleanup, repair or cutover capability is introduced. Author: Abdelhalim Talbi.

## V193.0 / Compact V4.4.0 — accès serveur au panneau des preuves
Auteur : Abdelhalim Talbi. `native_benchmark_cockpit_adapter.serve_evidence` vérifie le rôle et le manifeste HMAC, journalise la consultation dans SQLite puis retourne JSON ou fragment HTML en lecture seule. Ce composant doit être monté dans le portail existant derrière son middleware d'identité fiable; aucun déploiement n'est revendiqué. Voir `ARCHITECTURE-QUALITY-ROADMAP-V193.0.md`.

### V193.1 / Compact V4.4.1 — Audit des consultations
Le module `native_benchmark_cockpit_adapter.py` impose `audit_key` (clé secrète externe de 32 octets minimum), authentifie les lignes SQLite par HMAC-SHA256, vérifie la chaîne avant chaque nouvelle consultation et refuse la divulgation si l'audit échoue. L'ancienne base V193.0 exige une migration explicite. Voir `ARCHITECTURE-QUALITY-ROADMAP-V193.1.md` pour les limites et les prérequis d'intégration.

## V193.2 / Compact V4.4.2 — Audit operations
Auteur : Abdelhalim Talbi. `native_cockpit_audit_operations.py` provides `verify_access_audit`, `export_anchor`, and `inspect_legacy_audit`. Legacy audits remain untrusted/quarantined; an exported anchor must be stored and attested externally. No deployed SSO integration.

## V193.3 / Compact V4.4.3 — Server-verified identity bridge
Auteur : Abdelhalim Talbi. `native_cockpit_identity_bridge.py` maps trusted middleware claims to evidence-view roles, requires issuer/audience match and checks an out-of-band trusted audit anchor. It does not validate OIDC tokens, does not deploy to the existing portal, and deliberately blocks stale anchors. See `ARCHITECTURE-QUALITY-ROADMAP-V193.3.md`.

## V193.4 / Compact V4.4.4
Historical trusted audit checkpoints are now validated at their exact chain prefix; subsequent access entries can be appended transactionally without refreshing the anchor after every read. See `ARCHITECTURE-QUALITY-ROADMAP-V193.4.md`.

## V193.5 / Compact V4.4.5
Proposition de rotation supervisée HMAC double signature, liée à un checkpoint externe et à la tête courante, avec tests anti-altération et anti-rejeu. Aucune rotation effective de clé ni opération NAS automatique.

## V193.6 / Compact V4.4.6 — Multi-epoch audit (Auteur : Abdelhalim Talbi)
See `native_cockpit_audit_epochs.py` and `ARCHITECTURE-QUALITY-ROADMAP-V193.6.md`. Standalone transactional START/EVENT/ROTATE, old-key verification, external historical checkpoint. Not deployed or wired to SSO middleware; no automatic migration of legacy audit.

## V193.7 / Compact V4.4.7
Approbation de rotation HMAC côté passerelle, séparation demandeur/approbateur et transaction atomique de rotation/rejeu. Voir ARCHITECTURE-QUALITY-ROADMAP-V193.7.md.

## V193.8 / Compact V4.4.8
Décisions APPROVE/DENY signées, expiration, journal HMAC transactionnel; voir ARCHITECTURE-QUALITY-ROADMAP-V193.8.md. Auteur : Abdelhalim Talbi.

### V193.9 / Compact V4.4.9 — Review gate
Voir `ARCHITECTURE-QUALITY-ROADMAP-V193.9.md`. Nouveau module `native_cockpit_review_gate.py` : rotation conditionnée par une approbation valide, non expirée et non révoquée ; les anciennes API restent contournables et ne doivent pas être exposées en production.

## V194.0 / Compact V4.5.0
Deployment admission policy for rotation routes; see ARCHITECTURE-QUALITY-ROADMAP-V194.0.md.

## V194.1 / Compact V4.5.1
Voir ARCHITECTURE-QUALITY-ROADMAP-V194.1.md pour les limites de la nouvelle approbation liée à la clé cible.

## V194.2 / Compact V4.5.2
Voir `ARCHITECTURE-QUALITY-ROADMAP-V194.2.md` pour la passerelle de gouvernance unifiée et ses limites de sécurité.

## V194.3 / Compact V4.5.3
Voir `ARCHITECTURE-QUALITY-ROADMAP-V194.3.md`. Registre de révocation requis (fail-closed) avant rotation. Auteur : Abdelhalim Talbi.

V194.4 / Compact V4.5.4 : chaîne de révocation HMAC avec ancrage externe obligatoire dans le point d’entrée unifié. Voir ARCHITECTURE-QUALITY-ROADMAP-V194.4.md.

## V194.5 / Compact V4.5.5 — Historical revocation reconciliation
See `ARCHITECTURE-QUALITY-ROADMAP-V194.5.md`. Preview before explicit transactional import; independently anchor the returned head. Unreconciled historical revocations fail closed in unified rotation gate. Auteur : Abdelhalim Talbi.

V194.6 / Compact V4.5.6: live ASGI route introspection gate and 10 tests. See ARCHITECTURE-QUALITY-ROADMAP-V194.6.md.

## V194.7 / Compact V4.5.7
Outermost ASGI startup and request-time route admission wrapper. See `ARCHITECTURE-QUALITY-ROADMAP-V194.7.md`. Auteur : Abdelhalim Talbi.

## V194.8 / Compact V4.5.8
Persistent opt-in SQLite rotation seal and a sealed-only governance entrypoint. See `ARCHITECTURE-QUALITY-ROADMAP-V194.8.md`. Auteur : Abdelhalim Talbi.


## V194.9 — Portal binding
Voir ARCHITECTURE-QUALITY-ROADMAP-V194.9.md. Auteur : Abdelhalim Talbi.

## V195.0 / Compact V4.6.0
Protection du cycle de vie ASGI (révocation de l’admission après arrêt) et tests de régression. Auteur : Abdelhalim Talbi.

V195.2 / Compact V4.6.2: validation OIDC/JWT RS256 (voir ARCHITECTURE-QUALITY-ROADMAP-V195.2.md).

### V195.3 / Compact V4.6.3
Journal transactionnel d'autorisation `native_rotation_access_audit.py` : chaînage HMAC, déduplication, vérification et export, avec 10 tests nouveaux. Voir `ARCHITECTURE-QUALITY-ROADMAP-V195.3.md`.

V195.7 / Compact V4.6.7: voir ARCHITECTURE-QUALITY-ROADMAP-V195.7.md.

V196.0 / Compact V4.7.0: strict HTTPS GET vendor transport; see ARCHITECTURE-QUALITY-ROADMAP-V196.0.md.

V197.8: see README-V197.8.md.
