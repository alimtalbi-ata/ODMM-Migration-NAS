"""POSIX metadata and guarded application startup qualification; Abdelhalim Talbi."""
from __future__ import annotations
import json, os, stat, tempfile, hashlib
from pathlib import Path
from odmm_runtime_qualification_v2249 import qualify as prior

def qualify():
    checks=[]
    def record(name,ok,detail=''):
        checks.append({'name':name,'status':'PASS' if ok else 'FAIL','detail':detail})
    base_result=prior()
    record('v2249-runtime-baseline',base_result['status']=='PASS_WITH_UNQUALIFIED_ITEMS')
    if os.name!='posix':
        checks.extend({'name':n,'status':'NOT_TESTED'} for n in ('posix-mode-mtime','posix-restart','posix-unsupported-symlink','posix-xattr-guard'))
    else:
        from native_tree_migration import NativeTreeMigration
        from native_migration_errors import MigrationBlocked
        with tempfile.TemporaryDirectory(prefix='odmm-v2250-') as tmp:
            root=Path(tmp); src=root/'src'; dst=root/'dst'; src.mkdir();dst.mkdir()
            p=src/'metadata.bin';p.write_bytes(b'odmm-v2250\x00data');p.chmod(0o640)
            mtime=1_700_000_000_123_456_789;os.utime(p,ns=(mtime,mtime))
            db=root/'journal.sqlite'
            try:
                with NativeTreeMigration(src,dst,db) as migration:
                    outcome=migration.run(limit=1)
                    record('posix-first-copy',outcome['processed_count']==1)
                q=dst/'metadata.bin'; s=q.stat()
                record('posix-mode-mtime',stat.S_IMODE(s.st_mode)==0o640 and s.st_mtime_ns==mtime)
                record('posix-sha256',hashlib.sha256(p.read_bytes()).digest()==hashlib.sha256(q.read_bytes()).digest())
                with NativeTreeMigration(src,dst,db) as migration:
                    result=migration.run(); verified=migration.verify_all()
                record('posix-restart',result['processed_count']==1 and verified['count']==1)
                (src/'unsafe-link').symlink_to(p)
                with NativeTreeMigration(src,dst,db) as migration:
                    try: migration.run();blocked=False
                    except MigrationBlocked: blocked=True
                record('posix-unsupported-symlink',blocked)
                (src/'unsafe-link').unlink()
                if hasattr(os,'setxattr'):
                    try:
                        os.setxattr(p,'user.odmm_v2250',b'guard')
                    except OSError:
                        checks.append({'name':'posix-xattr-guard','status':'NOT_TESTED','detail':'filesystem does not support user xattrs'})
                    else:
                        with NativeTreeMigration(src,dst,db) as migration:
                            try: migration.run();blocked=False
                            except MigrationBlocked: blocked=True
                        record('posix-xattr-guard',blocked)
                else:
                    checks.append({'name':'posix-xattr-guard','status':'NOT_TESTED'})
            except Exception as exc:
                record('posix-runtime',False,type(exc).__name__+': '+str(exc)[:150])
    from odmm_operations_app import create_operations_app
    from odmm_scoped_app import create_scoped_app
    try:
        create_operations_app(registry_path='unused.sqlite',resolve_verified_principal=None)
    except ValueError as exc:
        record('full-auth-required',str(exc)=='VERIFIED_PRINCIPAL_RESOLVER_REQUIRED')
    else:record('full-auth-required',False)
    try:
        create_scoped_app(registry_path='unused.sqlite',grants_path='unused.sqlite',resolve_verified_principal=None)
    except ValueError as exc:
        record('scoped-auth-required',str(exc)=='VERIFIED_PRINCIPAL_RESOLVER_REQUIRED')
    else:record('scoped-auth-required',False)
    checks.extend({'name':n,'status':'NOT_TESTED'} for n in ('windows-portable-runtime','nas-nfs-smb-acl-e2e','real-idp','full-compact-ui-launch'))
    return {'version':'225.0','compact_version':'7.6.0','author':'Abdelhalim Talbi','status':'FAIL' if any(c['status']=='FAIL' for c in checks) else 'PASS_WITH_UNQUALIFIED_ITEMS','checks':checks}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args()
    result=qualify();output=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    print(output)
    if a.output:a.output.write_text(output,encoding='utf-8')
    raise SystemExit(1 if result['status']=='FAIL' else 0)
