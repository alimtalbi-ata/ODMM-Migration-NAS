"""Immutable per-file content/POSIX fingerprint manifest for ODMM V204.1.
Local POSIX prototype; does not certify NAS ACL/ADS or cutover.
"""
from __future__ import annotations
import hashlib, json, os, stat
from pathlib import Path
from native_tree_migration import NativeTreeMigration
from native_migration_errors import MigrationBlocked
SCHEMA = "odmm-native-fidelity-manifest-v2041"
def _canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def _fingerprint(path):
    p=Path(path)
    st=p.lstat()
    if not stat.S_ISREG(st.st_mode): raise MigrationBlocked("UNSUPPORTED_SOURCE_ENTRY")
    h=hashlib.sha256()
    flags=os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_CLOEXEC",0)
    fd=os.open(p,flags)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or (before.st_dev,before.st_ino)!=(st.st_dev,st.st_ino): raise MigrationBlocked("SOURCE_ENTRY_REPLACED")
        while True:
            block=os.read(fd,1024*1024)
            if not block: break
            h.update(block)
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): raise MigrationBlocked("SOURCE_CHANGED_DURING_HASH")
    finally: os.close(fd)
    return {"size":st.st_size,"sha256":h.hexdigest(),"mode":stat.S_IMODE(st.st_mode),"mtime_ns":st.st_mtime_ns,"uid":st.st_uid,"gid":st.st_gid}
def create_fidelity_manifest(source,target,database,manifest_path):
    out=Path(manifest_path)
    if out.exists() or out.is_symlink(): raise MigrationBlocked("MANIFEST_ALREADY_EXISTS")
    with NativeTreeMigration(source,target,database) as tree:
        files=tree.inventory(); records={rel:_fingerprint(tree.engine.source/rel) for rel in files}
        payload={"schema":SCHEMA,"source":str(tree.engine.source),"target":str(tree.engine.target),"files":files,"fingerprints":records,"count":len(files)}
    digest=hashlib.sha256(_canon(payload)).hexdigest(); envelope={"payload":payload,"sha256":digest}
    out.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        data=_canon(envelope)+b"\n"; view=memoryview(data)
        while view: view=view[os.write(fd,view):]
        os.fsync(fd)
    finally: os.close(fd)
    return {"status":"FIDELITY_MANIFEST_CREATED","count":len(files),"sha256":digest,"cutover_authorized":False,"acl_fidelity_verified":False}
def load_fidelity_manifest(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file(): raise MigrationBlocked("MANIFEST_MISSING_OR_UNSAFE")
    try: env=json.loads(p.read_text(encoding="utf-8")); payload=env["payload"]; digest=env["sha256"]
    except (OSError,ValueError,KeyError,TypeError) as e: raise MigrationBlocked("MANIFEST_INVALID") from e
    if not isinstance(payload,dict) or payload.get("schema")!=SCHEMA or hashlib.sha256(_canon(payload)).hexdigest()!=digest: raise MigrationBlocked("MANIFEST_INTEGRITY_FAILURE")
    files=payload.get("files"); fp=payload.get("fingerprints")
    if not isinstance(files,list) or payload.get("count")!=len(files) or files!=sorted(set(files)) or not isinstance(fp,dict) or set(fp)!=set(files): raise MigrationBlocked("MANIFEST_INVENTORY_INVALID")
    for rel in files:
        if not isinstance(rel,str) or not rel or rel.startswith("/") or "\\" in rel or any(x in ("",".","..") for x in rel.split("/")): raise MigrationBlocked("MANIFEST_INVENTORY_INVALID")
        r=fp[rel]
        if not isinstance(r,dict) or type(r.get("size")) is not int or r["size"]<0 or not isinstance(r.get("sha256"),str) or len(r["sha256"])!=64: raise MigrationBlocked("MANIFEST_FINGERPRINT_INVALID")
    return payload
def verify_fingerprint(path, expected, *, check_identity=False):
    actual=_fingerprint(path)
    keys=("size","sha256","mode","mtime_ns","uid","gid")
    mismatches=[k for k in keys if actual.get(k)!=expected.get(k)]
    return {"status":"MATCH" if not mismatches else "MISMATCH","mismatches":mismatches,"actual":actual}
