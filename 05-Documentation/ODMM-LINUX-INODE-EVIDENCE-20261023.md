# ODMM — durable inode evidence for Linux laboratory copies (2026-10-23)

**Author: Abdelhalim Talbi.** Scope: Linux Full and Linux Compact **local POSIX laboratory** only. No production NAS, NFS/SMB or Windows claim.

## Failure mode

A local copy may finish data and metadata verification and then crash before the SQLite intent transitions from IN_FLIGHT to VERIFIED. Recovery correctly quarantines it as UNCERTAIN, but until this change there was no durable record of the source and target inode identities observed at verification. A subsequent read-only comparison could report identical bytes and modes for a *different* target inode.

## Implementation

- New `odmm_lab_identity_evidence` SQLite table keyed by `intent_id`, with task/fence/payload binding, immutable canonical JSON observation and SHA-256 checksum. It records `st_dev`/`st_ino` for the source, target and their immediate parent directories, plus verified byte count and content SHA-256.
- `run_lab_copy` persists the observation **after** independent local SHA-256/mode verification and pathname inode checks, but **before** `record_verification` sets VERIFIED. An injected `after_identity_evidence` fault reproduces the dangerous crash window.
- `inspect_uncertain` returns `identity_evidence`: recorded/identity_matches/reason. It reads only; it does **not** change intent state, approve a retry, delete, or overwrite data. An absent observation reports `identity_matches: null`; a mismatch or invalid checksum fails closed.
- The journal's SQLite transaction checks the current lease and IN_FLIGHT state, verifies the intent payload digest, and refuses duplicate evidence. A committed observation is advisory; matching inode numbers are not cryptographic proof of ownership.

## Local qualification commands

```bash
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_identity_journal.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_pipeline.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_parent_fencing.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_reconciliation.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_process_crash.py' -v
```

The Full/Compact GitHub Actions preflight matrix executes the new test file. The eight new deterministic tests cover success, crash after durable observation, same-content inode substitutions for source and target, crash before observation, duplicate rejection, tampering and target removal. Do not report PASS unless the CI logs confirm it.

## Operational contract and limitations

1. Keep `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=FULL` for durability; test behavior under power loss separately.
2. `UNCERTAIN` remains quarantined even when `identity_matches=true` and content matches. A human must inspect; there is no automatic promotion or resume.
3. Device/inode values may be reused, filesystem remounts can change identities, and pathname checks cannot eliminate all races. The table is not an anti-TOCTOU proof, nor a distributed fencing token.
4. Source/target ancestors above the immediate parent are not pinned. SQLite and filesystem writes cannot form one atomic transaction. A crash between the evidence commit and VERIFIED is deliberately ambiguous.
5. No xattrs, POSIX/NFSv4/NTFS ACL, UID/GID/SID, SMB alternate streams, symlink traversal, NFS durability, multiserver performance, real NAS or Windows GUI qualification is claimed.
6. No UI screenshots or new compiled executable are provided by this source-only change. Any future cumulative release must report this explicitly.

## Next engineering gates

- Replace pathname-based verification with descriptor-relative `openat`/Linux `openat2` where available, with explicit filesystem and kernel compatibility tests.
- Make the evidence journal append-only and add independent consistency verification and a signed audit export; model inode reuse and journal tampering separately.
- Add a controlled two-host lab for NFSv3/v4 and SMB metadata fidelity; production migrations require explicit authorization.
