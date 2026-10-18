"""Isolated crash consistency tests for the native POSIX engine. Author: Abdelhalim Talbi.
No production data, NAS or cutover. POSIX only.
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
    def record(name, condition=None, detail=''):
        checks.append({'name': name, 'status': 'NOT_TESTED' if condition is None else ('PASS' if condition else 'FAIL'), 'detail': detail})
    if os.name != 'posix' or not hasattr(signal, 'SIGKILL'):
        record('mid-write-process-kill', None, 'Requires POSIX')
    else:
        from native_posix_migration import NativePosixMigration, MigrationBlocked
        with tempfile.TemporaryDirectory(prefix='odmm-v2253-') as tmp:
            root = Path(tmp); src=root/'src'; dst=root/'dst'; src.mkdir(); dst.mkdir()
            payload = (b'ODMM-V2253-CRASH-' * 131072)  # > 2 MiB
            (src/'large.bin').write_bytes(payload)
            db = root/'state.sqlite'
            script = '''import os, signal, sys
from native_posix_migration import NativePosixMigration
real_write = os.write
calls = [0]
def crashing_write(fd, data):
    result = real_write(fd, data)
    calls[0] += 1
    if calls[0] == 1:
        os.kill(os.getpid(), signal.SIGKILL)
    return result
os.write = crashing_write
with NativePosixMigration(sys.argv[1],sys.argv[2],sys.argv[3]) as engine:
    engine.copy('large.bin')
'''
            env = os.environ.copy(); env['PYTHONPATH'] = str(Path(__file__).resolve().parent) + os.pathsep + env.get('PYTHONPATH','')
            try:
                p = subprocess.run([sys.executable,'-c',script,str(src),str(dst),str(db)], env=env, capture_output=True, timeout=30)
                record('mid-write-process-kill', p.returncode == -signal.SIGKILL, f'exit={p.returncode}; stderr={p.stderr.decode(errors="replace")[:120]}')
                record('no-partial-published-file', not (dst/'large.bin').exists())
                leftovers = list(dst.glob('.odmm-*.part'))
                record('orphan-partial-temp-exists', len(leftovers) == 1 and 0 < leftovers[0].stat().st_size < len(payload))
                with sqlite3.connect(db) as conn:
                    count = conn.execute("SELECT count(*) FROM files").fetchone()[0]
                    intents = conn.execute("SELECT count(*) FROM intents").fetchone()[0]
                record('sqlite-not-committed', count == 0 and intents == 0)
                with NativePosixMigration(src,dst,db) as engine:
                    try:
                        engine.cleanup_orphan_temps('large.bin')
                    except MigrationBlocked:
                        record('cleanup-requires-operator', True)
                    else:
                        record('cleanup-requires-operator', False)
                    cleanup = engine.cleanup_orphan_temps('large.bin', operator_confirmed=True)
                    record('explicit-orphan-cleanup', len(cleanup['removed']) == 1 and not list(dst.glob('.odmm-*.part')))
                    result = engine.copy('large.bin')
                    verified = engine.verify('large.bin')
                record('restart-copy-and-verify', result['status'] == 'COPIED_VERIFIED' and verified['status'] == 'VERIFIED_POSIX_SUBSET_ONLY' and hashlib.sha256((dst/'large.bin').read_bytes()).digest() == hashlib.sha256(payload).digest())
                record('cutover-blocked', result['cutover_authorized'] is False and verified['cutover_authorized'] is False)
            except Exception as exc:
                record('execution', False, f'{type(exc).__name__}: {exc}')
    for name in ('windows-native-portable','real-nfs-smb','effective-acl-preservation','power-loss-fsync-durability'):
        record(name, None, 'Outside local POSIX test scope')
    return {'version':'225.3','compact_version':'7.6.3','author':'Abdelhalim Talbi', 'status':'FAIL' if any(c['status']=='FAIL' for c in checks) else 'PASS_WITH_UNQUALIFIED_ITEMS','checks':checks}

if __name__ == '__main__':
    import argparse
    p=argparse.ArgumentParser(); p.add_argument('--output', type=Path); args=p.parse_args()
    result=qualify(); data=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if args.output: args.output.write_text(data,encoding='utf-8')
    print(data); sys.exit(result['status']=='FAIL')
