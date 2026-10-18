"""POSIX metadata fail-closed qualification. Author: Abdelhalim Talbi."""
import os
import tempfile
from pathlib import Path
import pytest
from native_posix_migration import NativePosixMigration, MigrationBlocked


def _setup(root):
    src=root/'source'; dst=root/'target'; src.mkdir(); dst.mkdir()
    (src/'file').write_bytes(b'ODMM metadata test')
    return src,dst,root/'audit.sqlite'


def test_regular_file_without_xattrs_remains_supported():
    with tempfile.TemporaryDirectory() as td:
        src,dst,db=_setup(Path(td))
        with NativePosixMigration(src,dst,db) as engine:
            assert engine.copy('file')['status']=='COPIED_VERIFIED'
            assert engine.verify('file')['status']=='VERIFIED_POSIX_SUBSET_ONLY'


def test_source_xattr_is_refused_without_publishing():
    with tempfile.TemporaryDirectory() as td:
        src,dst,db=_setup(Path(td))
        try:
            os.setxattr(src/'file','user.odmm_qualification',b'preserve-me')
        except (AttributeError, OSError):
            pytest.skip('Filesystem does not support user xattrs')
        with NativePosixMigration(src,dst,db) as engine:
            with pytest.raises(MigrationBlocked,match='UNSUPPORTED_XATTR_OR_ACL'):
                engine.copy('file')
            assert not (dst/'file').exists()
            assert engine.db.execute('SELECT count(*) FROM files').fetchone()[0]==0


def test_xattr_drift_invalidates_verified_file():
    with tempfile.TemporaryDirectory() as td:
        src,dst,db=_setup(Path(td))
        with NativePosixMigration(src,dst,db) as engine:
            engine.copy('file')
            try:
                os.setxattr(dst/'file','user.odmm_qualification',b'added')
            except (AttributeError, OSError):
                pytest.skip('Filesystem does not support user xattrs')
            with pytest.raises(MigrationBlocked,match='UNSUPPORTED_XATTR_OR_ACL'):
                engine.verify('file')
