"""Read-only crash-window inventory for dual-HMAC receipt publication.

POSIX laboratory only. This is NOT a receipt authenticator, a cleanup
routine, or an authorization to resume migration.
Author: Abdelhalim Talbi.
"""
import os
import re
import stat
from pathlib import Path

from odmm_linux_datamover_intents import _id
from odmm_linux_lab_external_anchor import _KEY_ID
from odmm_linux_lab_anchor_rotation import _receipt_name, _MAX_RECEIPT
from odmm_linux_lab_path_fence import pin_parent_chain

_PENDING_SUFFIX = re.compile(r"^[0-9a-f]{32}$")
_MAX_PENDING = 32


def inspect_rotation_publication(anchor_dir, intent_id, to_key_id):
    """Inspect final/pending inode topology without reading keys or mutating files.

    A clean final merely permits a *separate* dual-HMAC verification. Even a
    valid receipt never authorizes replay, UNCERTAIN promotion or NAS cutover.
    """
    denied = {"status": "UNSAFE_OR_UNAVAILABLE", "pending_count": None,
              "ready_for_authentication": False, "authorizes_resume": False,
              "nas_migration_qualified": False}
    try:
        intent_id = _id(intent_id)
        if not isinstance(to_key_id, str) or not _KEY_ID.fullmatch(to_key_id):
            return denied
        path = Path(anchor_dir) / _receipt_name(intent_id, to_key_id)
        prefix = path.name + ".pending-"
        with pin_parent_chain(path) as (dirfd, check):
            check()
            before_dir = os.fstat(dirfd)

            def snapshot(name):
                try:
                    item = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                if (not stat.S_ISREG(item.st_mode) or item.st_mode & 0o077 or
                        item.st_size > _MAX_RECEIPT or item.st_nlink not in (1, 2)):
                    raise ValueError("unsafe rotation inode")
                return (item.st_dev, item.st_ino, item.st_nlink,
                        item.st_size, item.st_mtime_ns, item.st_ctime_ns)

            final = snapshot(path.name)
            pending = []
            with os.scandir(dirfd) as entries:
                for entry in entries:
                    if not entry.name.startswith(prefix):
                        continue
                    if not _PENDING_SUFFIX.fullmatch(entry.name[len(prefix):]):
                        raise ValueError("invalid pending filename")
                    pending.append((entry.name, snapshot(entry.name)))
                    if len(pending) > _MAX_PENDING:
                        raise ValueError("too many pending files")
            if any(item is None for _, item in pending):
                raise ValueError("pending disappeared")
            if snapshot(path.name) != final:
                raise ValueError("final inode changed")
            if any(snapshot(name) != item for name, item in pending):
                raise ValueError("pending inode changed")
            after_dir = os.fstat(dirfd)
            if ((before_dir.st_dev, before_dir.st_ino, before_dir.st_mtime_ns,
                 before_dir.st_ctime_ns) !=
                (after_dir.st_dev, after_dir.st_ino, after_dir.st_mtime_ns,
                 after_dir.st_ctime_ns)):
                raise ValueError("directory changed during inspection")
            check()

        if len(pending) > 1:
            status = "MULTIPLE_PENDING"
        elif pending and final is None:
            status = "PENDING_ONLY" if pending[0][1][2] == 1 else "UNSAFE_OR_UNAVAILABLE"
        elif pending and final is not None:
            same_inode = pending[0][1][:2] == final[:2]
            status = ("PUBLISHED_WITH_PENDING" if same_inode and final[2] == 2
                      else "UNRELATED_PENDING" if not same_inode
                      else "UNSAFE_OR_UNAVAILABLE")
        elif final is None:
            status = "ABSENT"
        else:
            status = "FINAL_PRESENT_UNVERIFIED" if final[2] == 1 else "UNSAFE_OR_UNAVAILABLE"
        return {"status": status, "pending_count": len(pending),
                "ready_for_authentication": status == "FINAL_PRESENT_UNVERIFIED",
                "authorizes_resume": False, "nas_migration_qualified": False}
    except Exception:
        return denied
