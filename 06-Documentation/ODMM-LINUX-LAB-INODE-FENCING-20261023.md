# ODMM — Linux POSIX lab inode-fencing qualification (2026-10-23)

Author: **Abdelhalim Talbi**. Applies to **Linux Full and Linux Compact laboratory pipeline only**.

## Defect and impact

The former `run_lab_copy` closed its exclusive-create target descriptor before calling `os.chmod(target, ...)`. A concurrent actor could replace the pathname with a symlink after the close; pathname-based chmod would then alter an unrelated victim's permissions. Additionally, a different regular file with identical content and mode could replace either pathname, allowing independent content comparison to pass without establishing that the verified inode was the one opened for the intent.

## Mitigation

* Apply POSIX permissions through `os.fchmod` on the **original still-open output descriptor**, followed by `os.fsync`. Never chmod the destination pathname.
* Compare `(st_dev, st_ino)` from the original open file descriptors with `lstat` on the source and target pathnames. Refuse non-regular or replaced entries.
* Recheck source and target pathname identity **after** the independent SHA-256/mode verifier, before recording `VERIFIED`. If a check fails, leave the intent `IN_FLIGHT` and require crash-recovery quarantine to `UNCERTAIN`.
* Preserve the existing injected `after_copy_fsync` fault before mode restoration, retaining prior recovery semantics.

## Deterministic regression tests

`python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_inode_fencing.py' -v`

Four scenarios: target replaced with a symlink to a mode-protected unrelated victim; target replaced with a byte-for-byte and mode-identical regular file; source replaced with a byte-for-byte and mode-identical regular file; original inodes complete successfully. The first three **must fail closed** and remain recoverable as `UNCERTAIN`. Existing `test_linux_lab_pipeline.py`, `test_linux_lab_process_crash.py` and `test_linux_lab_reconciliation.py` remain mandatory regression gates.

## Evidence classification

This is a **local POSIX filesystem injection test**. It does **not** establish NFSv3/v4 or SMB behavior, server-side atomicity, distributed fencing, ACL fidelity, xattrs, UID/GID/SID mapping, cross-host durability, Windows compatibility, UI qualification, or production NAS readiness. `nas_migration_qualified` remains false.

## Residual risks and next engineering gate

Path-based `lstat` checks do not eliminate swaps **between** the final check and the durable `VERIFIED` update; the journal is not an atomic filesystem transaction. Parent-directory symlink traversal, hard links, filesystem mounts, hostile remote servers, and multi-node lease expiry also require separate controls. Next: pin parent directories using dirfd/openat2 or equivalent where available, introduce a durable inode/metadata evidence record and require a server-enforced lease/fence before any remote NAS write. Until then, **no production NAS migration**.

No screenshot or binary is claimed for this change. Release ZIP and Word/PDF are not produced by this code-only PR; GitHub Actions CI artifacts are the available qualification evidence.
