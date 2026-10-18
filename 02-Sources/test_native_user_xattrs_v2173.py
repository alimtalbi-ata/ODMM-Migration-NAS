"""V217.3 user namespace fidelity tests. Author: Abdelhalim Talbi."""
import os
import tempfile
from pathlib import Path
import pytest
from native_posix_migration import NativePosixMigration
from native_migration_errors import MigrationBlocked


def _setup(tmp):
    src, dst = tmp/'source', tmp/'target'
    src.mkdir(); dst.mkdir()
    (src/'a').write_bytes(b'hello')
    try:
        os.setxattr(src/'a', 'user.odmm_test', b'proof')
    except OSError:
        pytest.skip('user xattrs not supported on this filesystem')
    return src,dst

def test_opt_in_copies_and_verifies_user_xattr(tmp_path):
    src,dst=_setup(tmp_path)
    with NativePosixMigration(src,dst,tmp_path/'db.sqlite',copy_user_xattrs=True) as engine:
        assert engine.copy('a')['status']=='COPIED_VERIFIED'
        assert os.getxattr(dst/'a','user.odmm_test')==b'proof'
        assert engine.verify('a')['cutover_authorized'] is False
        os.setxattr(dst/'a','user.odmm_test',b'tampered')
        with pytest.raises(MigrationBlocked, match='XATTR_DRIFT'):
            engine.verify('a')

def test_default_remains_fail_closed(tmp_path):
    src,dst=_setup(tmp_path)
    with NativePosixMigration(src,dst,tmp_path/'db.sqlite') as engine:
        with pytest.raises(MigrationBlocked, match='UNSUPPORTED_XATTR_OR_ACL'):
            engine.copy('a')

def test_source_xattr_drift_detected(tmp_path):
    src,dst=_setup(tmp_path)
    with NativePosixMigration(src,dst,tmp_path/'db.sqlite',copy_user_xattrs=True) as engine:
        engine.copy('a')
        os.setxattr(src/'a','user.odmm_test',b'changed')
        with pytest.raises(MigrationBlocked, match='XATTR_DRIFT'):
            engine.verify('a')

def test_non_user_namespace_rejected(tmp_path,monkeypatch):
    src,dst=_setup(tmp_path)
    import native_posix_migration as mod
    real=mod.os.listxattr
    monkeypatch.setattr(mod.os,'listxattr',lambda fd: ['system.posix_acl_access'] if isinstance(fd,int) else real(fd))
    with NativePosixMigration(src,dst,tmp_path/'db.sqlite',copy_user_xattrs=True) as engine:
        with pytest.raises(MigrationBlocked, match='UNSUPPORTED_XATTR_OR_ACL'):
            engine.copy('a')
