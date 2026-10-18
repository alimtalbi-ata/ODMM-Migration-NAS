"""Crash-after-publish reconciliation qualification; isolated POSIX fixtures only.
Author: Abdelhalim Talbi.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile


def qualify():
    checks = []
    def record(name, ok=None, detail=''):
        checks.append({'name': name, 'status': 'NOT_TESTED' if ok is None else ('PASS' if ok else 'FAIL'), 'detail': detail})
    if os.name != 'posix' or not hasattr(signal, 'SIGKILL'):
        record('post-publish-crash', None, 'Requires POSIX SIGKILL')
    else:
        from native_posix_migration import NativePosixMigration, MigrationBlocked
        with tempfile.TemporaryDirectory(prefix='odmm-v2254-') as tmp:
            root = Path(tmp); src=root/'src'; dst=root/'dst'; src.mkdir(); dst.mkdir(); db=root/'state.sqlite'
            payload=b'ODMM-POST-PUBLISH-'*16384
            (src/'data.bin').write_bytes(payload)
            script='''import os,signal,sys
from native_posix_migration import NativePosixMigration
with NativePosixMigration(sys.argv[1],sys.argv[2],sys.argv[3]) as engine:
    engine.copy('data.bin',after_publish=lambda: os.kill(os.getpid(),signal.SIGKILL))
'''
            env=os.environ.copy(); env['PYTHONPATH']=str(Path(__file__).resolve().parent)+os.pathsep+env.get('PYTHONPATH','')
            try:
                p=subprocess.run([sys.executable,'-c',script,str(src),str(dst),str(db)],capture_output=True,timeout=30,env=env)
                record('post-publish-crash',p.returncode == -signal.SIGKILL, f'returncode={p.returncode}')
                record('published-file-intact', (dst/'data.bin').is_file() and hashlib.sha256((dst/'data.bin').read_bytes()).digest()==hashlib.sha256(payload).digest())
                with sqlite3.connect(db) as conn:
                    record('intent-durable',conn.execute('SELECT count(*) FROM intents').fetchone()[0]==1)
                    record('commit-not-recorded',conn.execute('SELECT count(*) FROM files').fetchone()[0]==0)
                with NativePosixMigration(src,dst,db) as engine:
                    for operation in ('copy','reconcile'):
                        try:
                            if operation=='copy': engine.copy('data.bin')
                            else: engine.reconcile('data.bin')
                        except MigrationBlocked:
                            record(operation+'-blocked-without-recovery',True)
                        else:
                            record(operation+'-blocked-without-recovery',False)
                    recovered=engine.reconcile('data.bin',operator_confirmed=True)
                    record('explicit-reconcile',recovered['status']=='RECONCILED_VERIFIED' and not recovered['cutover_authorized'])
                    record('verified-after-reconcile',engine.verify('data.bin')['status']=='VERIFIED_POSIX_SUBSET_ONLY')
                with sqlite3.connect(db) as conn:
                    record('atomic-final-register',conn.execute('SELECT count(*) FROM intents').fetchone()[0]==0 and conn.execute('SELECT count(*) FROM files').fetchone()[0]==1)
            except Exception as exc:
                record('post-publish-execution',False,f'{type(exc).__name__}: {exc}')
        with tempfile.TemporaryDirectory(prefix='odmm-v2254-corrupt-') as tmp:
            root=Path(tmp); src=root/'src'; dst=root/'dst'; src.mkdir(); dst.mkdir(); db=root/'state.sqlite'
            (src/'data.bin').write_bytes(b'ORIGINAL'*8192)
            try:
                with NativePosixMigration(src,dst,db) as engine:
                    try: engine.copy('data.bin',after_publish=lambda: (_ for _ in ()).throw(RuntimeError('injected-after-publish')))
                    except RuntimeError: pass
                    else: record('injected-publish-failure',False)
                with sqlite3.connect(db) as conn:
                    record('corruption-intent-present',conn.execute('SELECT count(*) FROM intents').fetchone()[0]==1)
                (dst/'data.bin').write_bytes(b'TAMPERED')
                with NativePosixMigration(src,dst,db) as engine:
                    try: engine.reconcile('data.bin',operator_confirmed=True)
                    except MigrationBlocked: record('tampered-destination-rejected',True)
                    else: record('tampered-destination-rejected',False)
                    try: engine.copy('data.bin')
                    except MigrationBlocked: record('no-overwrite-of-corrupt-target',True)
                    else: record('no-overwrite-of-corrupt-target',False)
                with sqlite3.connect(db) as conn:
                    record('corrupt-intent-remains',conn.execute('SELECT count(*) FROM intents').fetchone()[0]==1 and conn.execute('SELECT count(*) FROM files').fetchone()[0]==0)
            except Exception as exc:
                record('corruption-execution',False,f'{type(exc).__name__}: {exc}')
    for name in ('windows-portable','real-nfs-smb','effective-acl','power-failure-durability'):
        record(name,None,'Not qualified in local POSIX fixture')
    return {'version':'225.4','compact_version':'7.6.4','author':'Abdelhalim Talbi','status':'FAIL' if any(x['status']=='FAIL' for x in checks) else 'PASS_WITH_UNQUALIFIED_ITEMS','checks':checks}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(); p.add_argument('--output',type=Path); args=p.parse_args()
    result=qualify(); content=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output: args.output.write_text(content,encoding='utf-8')
    print(content); sys.exit(1 if result['status']=='FAIL' else 0)
