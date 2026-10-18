"""V203.3: encrypted local recovery with advisory interprocess locking.
Author: Abdelhalim Talbi. No NAS writes or cutover.
Requires cryptography; key must be provided by a secure external key manager.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from odmm_registry_resilience_v2031 import snapshot, export, verify_export

MAGIC=b'ODMM2033\x00'

def _sha(b): return hashlib.sha256(b).hexdigest()

def _key(key):
    if not isinstance(key,bytes) or len(key)!=32: raise ValueError('AES256_KEY_REQUIRED')
    return key

@contextlib.contextmanager
def _lock(directory):
    d=Path(directory)
    if not d.is_dir() or d.is_symlink(): raise ValueError('UNSAFE_DIRECTORY')
    p=d/'.odmm-recovery.lock'
    fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)

def _atomic_new(path,data):
    p=Path(path)
    if p.exists() or p.is_symlink(): raise ValueError('DESTINATION_EXISTS')
    fd,tmp=tempfile.mkstemp(prefix='.odmm-pending-',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.link(tmp,p)
        dirfd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)
    finally: Path(tmp).unlink(missing_ok=True)

def encrypted_backup(registry,folder,*,name,key,keep=5):
    _key(key)
    if not isinstance(name,str) or not name.startswith('odmm-') or not name.endswith('.aes') or len(name)>100 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. ' for c in name): raise ValueError('INVALID_NAME')
    if type(keep) is not int or keep<1: raise ValueError('INVALID_RETENTION')
    d=Path(folder)
    with _lock(d):
        target=d/name
        if target.exists() or target.is_symlink(): raise ValueError('DESTINATION_EXISTS')
        with tempfile.TemporaryDirectory(dir=d,prefix='.odmm-staging-') as stage:
            snap=Path(stage)/'snapshot.sqlite'
            report=snapshot(registry,snap)
            if not verify_export(report): raise ValueError('AUDIT_INVALID')
            plaintext=snap.read_bytes()
            nonce=os.urandom(12)
            ciphertext=MAGIC+nonce+AESGCM(key).encrypt(nonce,plaintext,MAGIC)
            _atomic_new(target,ciphertext)
        files=sorted((p for p in d.glob('odmm-*.aes') if p.is_file() and not p.is_symlink()),key=lambda p:(p.stat().st_mtime_ns,p.name),reverse=True)
        for p in files[keep:]:
            if p!=target: p.unlink()
        return {'schema':'odmm.recovery.v2033','author':'Abdelhalim Talbi','name':name,'ciphertext_sha256':_sha(ciphertext),'chain_head':report['chain_head'],'encrypted':True,'writes_to_nas':False,'cutover_authorized':False}

def encrypted_restore(archive,destination,*,key,expected_sha256,expected_chain_head=None):
    _key(key)
    src=Path(archive); dst=Path(destination)
    if not src.is_file() or src.is_symlink(): raise ValueError('UNSAFE_ARCHIVE')
    if not dst.parent.is_dir() or dst.parent.is_symlink(): raise ValueError('UNSAFE_DIRECTORY')
    with _lock(dst.parent):
        if dst.exists() or dst.is_symlink(): raise ValueError('DESTINATION_EXISTS')
        blob=src.read_bytes()
        if _sha(blob)!=expected_sha256: raise ValueError('DIGEST_MISMATCH')
        if not blob.startswith(MAGIC) or len(blob)<len(MAGIC)+12+16: raise ValueError('INVALID_ARCHIVE')
        nonce=blob[len(MAGIC):len(MAGIC)+12]
        plain=AESGCM(key).decrypt(nonce,blob[len(MAGIC)+12:],MAGIC)
        with tempfile.TemporaryDirectory(dir=dst.parent,prefix='.odmm-verify-') as stage:
            p=Path(stage)/'restore.sqlite';p.write_bytes(plain)
            report=export(p)
            if not verify_export(report): raise ValueError('AUDIT_INVALID')
            if expected_chain_head is not None and report['chain_head']!=expected_chain_head: raise ValueError('CHAIN_HEAD_MISMATCH')
            _atomic_new(dst,plain)
        return {'restored':True,'chain_head':report['chain_head'],'writes_to_nas':False,'cutover_authorized':False}
