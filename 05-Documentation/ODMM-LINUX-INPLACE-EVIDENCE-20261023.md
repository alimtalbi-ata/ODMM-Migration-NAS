# ODMM Linux Full / Compact — R96 same-inode content verification

**Date:** 2026-10-23  
**Author:** Abdelhalim Talbi  
**Scope:** local POSIX Linux laboratory only; **not** NFSv3/v4, SMB, production NAS, or distributed fencing qualification.

## Failure mode and correction

The durable observation introduced in V228.95 recorded source/target device and inode, parent identities, content size and SHA-256. The read-only `inspect_identity` implementation previously compared **only** the device/inode tuples. A file modified **in place** (unchanged inode and size) could be reported as an identity match despite having different bytes.

The new inspector opens each immediate parent directory with `O_DIRECTORY | O_NOFOLLOW`, then the regular file with `dir_fd` and `O_NOFOLLOW`. It verifies pinned parent/file identities, observed byte count and streaming SHA-256 against the SQLite observation. It checks `st_mtime_ns` and `st_ctime_ns` before/after reading, and checks path identity again before reporting a match. It returns distinct fail-closed reasons: `CONTENT_DIGEST_MISMATCH`, `CONTENT_SIZE_CHANGED`, `CONTENT_CHANGED_DURING_INSPECTION`, `PATH_IDENTITY_CHANGED`, or `IDENTITY_UNAVAILABLE_OR_UNSAFE`.

**No recovery is authorized by a match.** `UNCERTAIN` remains quarantined; `inspect_uncertain` retains `MANUAL_REVIEW_REQUIRED` and performs no filesystem mutations. SHA-256 comparison is read-only; it is not a filesystem snapshot.

## Verification

```bash
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_inplace_evidence.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_identity_journal.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_reconciliation.py' -v
```

Four new tests: unchanged evidence remains advisory, target same-size in-place mutation, source same-size in-place mutation, and truncation without inode change. The Full/Compact GitHub Actions preflight matrix runs the new suite. CI success must be independently checked at the exact branch SHA before qualification is claimed.

## Residual risks and release limits

- Only immediate parents are pinned; higher ancestors can change. Path checks before/after cannot make the filesystem and SQLite atomic.
- A hostile actor with write access to SQLite can recompute an unauthenticated observation checksum. Independent signed/HMAC anchors are a separate future gate.
- Inode reuse, timestamp manipulation, changes after inspection, remote NAS semantics and consistency remain unqualified.
- The inspector streams each file and may incur additional I/O on large datasets; measure on a dedicated lab before performance claims.
- No real NAS migration, ACL/xattr fidelity, UID/GID/SID translation, Windows build, standalone Linux binary, UI screenshot, or cumulative release ZIP was performed by this source-only change.

## Next engineering gate

Add immutable externally anchored evidence and a two-host controlled NFS/SMB qualification matrix. Never enable automatic replay based solely on advisory evidence.
