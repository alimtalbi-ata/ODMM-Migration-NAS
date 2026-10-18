"""V177.3 read-only ACL evidence; no claim of effective access fidelity."""
import hashlib
import json
import os
import stat
from pathlib import Path

ACL_NAMES = ("system.posix_acl_access", "system.posix_acl_default", "security.NTACL")

def acl_evidence(path):
    """Collect non-following metadata and ACL xattr fingerprints, fail closed on errors."""
    p = Path(path)
    st = os.lstat(p)
    out = {"kind": "symlink" if stat.S_ISLNK(st.st_mode) else "directory" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "other",
           "mode": stat.S_IMODE(st.st_mode), "uid": getattr(st, "st_uid", None), "gid": getattr(st, "st_gid", None),
           "acl_attributes": {}, "errors": [], "acl_complete": False, "effective_access_verified": False}
    if out["kind"] == "symlink":
        out["errors"].append("SYMLINK_UNSUPPORTED")
        return out
    if not hasattr(os, "listxattr") or not hasattr(os, "getxattr"):
        out["errors"].append("XATTR_API_UNAVAILABLE")
        return out
    try:
        names = set(os.listxattr(p, follow_symlinks=False))
        for name in ACL_NAMES:
            if name in names:
                value = os.getxattr(p, name, follow_symlinks=False)
                out["acl_attributes"][name] = {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
        out["acl_complete"] = True  # xattr enumeration only; not complete ACL semantics
    except (OSError, TypeError, NotImplementedError) as exc:
        out["errors"].append(type(exc).__name__)
    return out

def compare_acl_evidence(source, target):
    a, b = acl_evidence(source), acl_evidence(target)
    mismatch = {k: {"source": a[k], "target": b[k]} for k in ("kind", "mode", "uid", "gid", "acl_attributes") if a[k] != b[k]}
    status = "MISMATCH" if mismatch else "INDETERMINATE"
    return {"status": status, "mismatches": mismatch, "source": a, "target": b,
            "acl_fidelity_certified": False, "effective_access_verified": False,
            "requires_protocol_specific_acl_and_access_tests": True}

def evidence_digest(report):
    payload = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
