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


## R95 — Parent directory pinning (2026-10-23)

**Author: Abdelhalim Talbi.** Applies to the isolated Linux Full/Compact POSIX laboratory pipeline only.

### Failure mode and mitigation
A concurrent actor could rename the parent directory after the initial pathname check, then replace it with another directory or a symlink. An exclusive file create via a re-resolved target pathname could then write outside the intended directory. The pipeline now opens the immediate source and target parent directories with `O_DIRECTORY|O_NOFOLLOW`, pins their `(st_dev, st_ino)` identities, and opens source and target basenames relative to those directory descriptors (`dir_fd`). It also fsyncs the **pinned** target directory rather than reopening a pathname after the copy.

The pipeline checks the original parent identities before target creation, after copying, and again after independent verification before updating the SQLite intent to `VERIFIED`. A changed parent fails closed, leaving the intent `IN_FLIGHT` for quarantine to `UNCERTAIN`. No automatic cleanup or replay is performed.

### Reproduce local tests
```bash
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_parent_fencing.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_inode_fencing.py' -v
python3 -m unittest discover -s 09-Tools -p 'test_linux_lab_pipeline.py' -v
```

The five new deterministic scenarios exercise a successful pinned-parent copy; target-parent replacement with a directory; target-parent replacement with a symlink to an unrelated directory; source-parent replacement with byte-identical content; and initial symlink-parent rejection without an intent. Both Linux edition CI matrix jobs execute the new tests.

### Scope and residual risks
This is **not** a complete openat2 `RESOLVE_BENEATH` / `RESOLVE_NO_SYMLINKS` path policy: ancestors above the immediate parent may still be symlinks or change, and the final verification still uses pathnames. An attacker can race the last check and SQLite commit. Filesystem writes and SQLite journal updates are not atomic. There is no remote-server fencing, NAS protocol, NFSv3/v4 or SMB ACL proof, xattr/UID/GID/SID preservation, distributed durability or production NAS qualification. Do not enable unattended real NAS migration based on these tests. The next engineering step is durable inode evidence tied to the intent and a server-enforced fencing strategy.
