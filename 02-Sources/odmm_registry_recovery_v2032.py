"""ODMM V203.2 local SQLite backup rotation and verified recovery.
Author: Abdelhalim Talbi. No NAS writes, no automatic cutover.
"""
import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from odmm_registry_resilience_v2031 import export, verify_export, snapshot

SCHEMA='odmm.registry.recovery.v2032'
def _hash(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def _check_dir(folder):
    d=Path(folder)
    if not d.is_dir() or d.is_symlink(): raise ValueError('UNSAFE_BACKUP_DIRECTORY')
    return d.resolve()
def _valid_name(name):
    if not isinstance(name,str) or not name.startswith('odmm-') or not name.endswith('.sqlite') or len(name)>110 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. ' for c in name): raise ValueError('INVALID_BACKUP_NAME')
    return name

def backup(registry,folder,*,name,keep=5):
    d=_check_dir(folder); name=_valid_name(name)
    if not isinstance(keep,int) or isinstance(keep,bool) or keep<1: raise ValueError('INVALID_RETENTION')
    dest=d/name
    if dest.exists() or dest.is_symlink(): raise ValueError('BACKUP_EXISTS')
    if Path(registry).resolve().parent==d and Path(registry).name==name: raise ValueError('SOURCE_EQUALS_DESTINATION')
    report=snapshot(registry,dest)
    if not verify_export(report):
        dest.unlink(missing_ok=True); raise ValueError('BACKUP_VERIFICATION_FAILED')
    # SQLite backup can contain WAL-independent committed state; fsync file and directory.
    with open(dest,'rb') as f: os.fsync(f.fileno())
    result={'schema':SCHEMA,'author':'Abdelhalim Talbi','backup_name':name,'backup_sha256':_hash(dest),
            'audit_report_sha256':report['report_sha256'],'chain_head':report['chain_head'],
            'created_at':datetime.now(timezone.utc).isoformat(),'cutover_authorized':False,'writes_to_nas':False}
    # Rotation only known .sqlite backup files; never delete symlinks, manifest, or unrelated files.
    candidates=sorted((p for p in d.glob('odmm-*.sqlite') if p.is_file() and not p.is_symlink()),key=lambda p:(p.stat().st_mtime_ns,p.name),reverse=True)
    for old in candidates[keep:]:
        if old!=dest: old.unlink()
    return result

def restore(backup_path,destination,*,expected_sha256,expected_chain_head=None):
    src=Path(backup_path); dst=Path(destination)
    if not src.is_file() or src.is_symlink(): raise ValueError('UNSAFE_BACKUP')
    if dst.exists() or dst.is_symlink(): raise ValueError('RESTORE_DESTINATION_EXISTS')
    if not dst.parent.is_dir() or dst.parent.is_symlink(): raise ValueError('UNSAFE_RESTORE_PARENT')
    if not isinstance(expected_sha256,str) or len(expected_sha256)!=64 or _hash(src)!=expected_sha256: raise ValueError('BACKUP_DIGEST_MISMATCH')
    original=export(src)
    if not verify_export(original): raise ValueError('INVALID_BACKUP_AUDIT')
    if expected_chain_head is not None and original['chain_head']!=expected_chain_head: raise ValueError('CHAIN_HEAD_MISMATCH')
    # Create a private temporary destination, then atomically publish with hardlink (no overwrite).
    fd,tmp=tempfile.mkstemp(prefix='.odmm-restore-',suffix='.sqlite',dir=dst.parent)
    try:
        with os.fdopen(fd,'wb') as out, open(src,'rb') as inp:
            for b in iter(lambda:inp.read(1024*1024),b''): out.write(b)
            out.flush(); os.fsync(out.fileno())
        if _hash(tmp)!=expected_sha256 or not verify_export(export(tmp)): raise ValueError('RESTORE_VERIFICATION_FAILED')
        os.link(tmp,dst)  # atomic create-if-absent; never clobber an existing registry
        return {'schema':SCHEMA,'restored':True,'backup_sha256':expected_sha256,'chain_head':original['chain_head'],
                'cutover_authorized':False,'writes_to_nas':False}
    finally: Path(tmp).unlink(missing_ok=True)
