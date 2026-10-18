"""ODMM V201.4 - bounded, reproducible migration fidelity fixtures. Author: Abdelhalim Talbi.

Creates synthetic local fixtures only, NEVER writes to a NAS or migration target.
ACL records are expected evidence, not OS-applied ACLs or vendor certification.
"""
import hashlib
import json
import os
from pathlib import Path

SCHEMA = "odmm.fidelity.fixtures.v2014"
MAX_BYTES = 16 * 1024 * 1024

def _hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block: break
            h.update(block)
    return h.hexdigest()

def create_fixtures(root, *, max_bytes=MAX_BYTES):
    """Create small deterministic data in a NEW empty local directory; no ACL changes."""
    root = Path(root)
    if root.is_symlink() or root.exists() or not root.parent.is_dir() or root.parent.is_symlink():
        raise ValueError("DESTINATION_MUST_BE_NEW_LOCAL_DIRECTORY")
    if not isinstance(max_bytes, int) or not 4096 <= max_bytes <= MAX_BYTES:
        raise ValueError("INVALID_BYTE_BUDGET")
    root.mkdir(mode=0o700)
    try:
        (root / "empty").write_bytes(b"")
        (root / "unicode-échantillon.txt").write_bytes("ODMM\nUnicode\n".encode())
        (root / "binary.bin").write_bytes(bytes(range(256)) * 4)
        (root / "nested").mkdir()
        (root / "nested" / "data.txt").write_bytes(b"source target integrity\n")
        sparse = root / "sparse.dat"
        with sparse.open("wb") as f:
            f.write(b"HEAD")
            f.seek(max_bytes - 4)
            f.write(b"TAIL")
        os.symlink("nested/data.txt", root / "relative-link")
        entries = []
        for p in sorted(root.rglob("*")):
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                entries.append({"path":rel,"kind":"symlink","target":os.readlink(p)})
            elif p.is_file():
                entries.append({"path":rel,"kind":"file","size":p.stat().st_size,"sha256":_hash(p)})
            elif p.is_dir():
                entries.append({"path":rel,"kind":"directory"})
        manifest = {"schema":SCHEMA,"author":"Abdelhalim Talbi","entries":entries,
                    "expected_acl_cases":[
                        {"protocol":"NFS4","case":"allow_read","expected":"ALLOW","qualified":False},
                        {"protocol":"NFS4","case":"deny_write","expected":"DENY","qualified":False},
                        {"protocol":"SMB3","case":"inherited_read","expected":"ALLOW","qualified":False},
                        {"protocol":"SMB3","case":"explicit_deny","expected":"DENY","qualified":False}],
                    "xattr_fidelity_qualified":False,"acl_applied":False,"vendor_qualified":False,
                    "cutover_authorized":False}
        payload=json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        manifest["manifest_sha256"]=hashlib.sha256(payload).hexdigest()
        return manifest
    except BaseException:
        # Fail closed: do not erase a partially created dataset automatically.
        raise

def verify_fixtures(root, manifest):
    root=Path(root)
    if not isinstance(manifest,dict) or manifest.get("schema") != SCHEMA: return False
    if any(manifest.get(k) is not False for k in ("acl_applied","vendor_qualified","cutover_authorized","xattr_fidelity_qualified")): return False
    expected=manifest.get("manifest_sha256")
    raw={k:v for k,v in manifest.items() if k!="manifest_sha256"}
    if hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()!=expected: return False
    if root.is_symlink() or not root.is_dir(): return False
    try:
        expected_paths=set()
        for e in manifest["entries"]:
            rel=e["path"]
            if not rel or rel.startswith("/") or any(x in (".","..","") for x in rel.split("/")): return False
            expected_paths.add(rel)
            p=root/rel
            if e["kind"]=="symlink":
                if not p.is_symlink() or os.readlink(p)!=e["target"]: return False
            elif e["kind"]=="directory":
                if p.is_symlink() or not p.is_dir(): return False
            elif e["kind"]=="file":
                if p.is_symlink() or not p.is_file() or p.stat().st_size!=e["size"] or _hash(p)!=e["sha256"]: return False
            else: return False
        return {p.relative_to(root).as_posix() for p in root.rglob("*")}==expected_paths
    except (OSError,KeyError,TypeError,ValueError): return False
