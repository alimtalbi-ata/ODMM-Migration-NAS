"""Isolated hard-process termination and SQLite recovery qualification.

Author: Abdelhalim Talbi. POSIX regular files only; never authorizes NAS cutover.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def qualify():
    checks = []
    def record(name, ok=None, detail=''):
        checks.append({'name': name, 'status': 'NOT_TESTED' if ok is None else ('PASS' if ok else 'FAIL'), 'detail': detail})
    if os.name != 'posix' or not hasattr(signal, 'SIGKILL'):
        record('hard-kill-child', None, 'Requires POSIX SIGKILL')
        record('sqlite-reopen-and-resume', None, 'Requires POSIX SIGKILL')
        record('metadata-and-hashes', None, 'Requires POSIX filesystem')
    else:
        from native_tree_migration import NativeTreeMigration
        with tempfile.TemporaryDirectory(prefix='odmm-v2252-') as directory:
            root = Path(directory)
            source, target = root/'source', root/'target'
            source.mkdir(); target.mkdir()
            originals = {}
            for i in range(4):
                p = source / f'file-{i:02d}.dat'
                p.write_bytes((f'ODMM-{i}-'.encode()) * (1000 + i))
                p.chmod(0o640)
                os.utime(p, ns=(1_700_000_000_000_000_000+i,)*2)
                originals[p.name] = (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode & 0o777, p.stat().st_mtime_ns)
            database = root/'journal.sqlite'
            child = '''import os, signal, sys
from native_tree_migration import NativeTreeMigration
with NativeTreeMigration(sys.argv[1], sys.argv[2], sys.argv[3]) as migration:
    migration.run(limit=1)
os.kill(os.getpid(), signal.SIGKILL)
'''
            env = os.environ.copy()
            env['PYTHONPATH'] = str(Path(__file__).resolve().parent) + os.pathsep + env.get('PYTHONPATH','')
            try:
                outcome = subprocess.run([sys.executable, '-c', child, str(source), str(target), str(database)],
                                         env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                record('hard-kill-child', outcome.returncode == -signal.SIGKILL,
                       f'returncode={outcome.returncode}; stderr={outcome.stderr.decode(errors="replace")[:180]}')
                record('partial-file-survives', (target/'file-00.dat').is_file() and not (target/'file-03.dat').exists())
                with NativeTreeMigration(source, target, database) as migration:
                    resumed = migration.run()
                    verified = migration.verify_all()
                record('sqlite-reopen-and-resume', resumed['processed_count'] == 4 and verified['count'] == 4)
                record('cutover-fail-closed', resumed['cutover_authorized'] is False and resumed['acl_fidelity_verified'] is False)
                metadata_ok = all((target/name).is_file() and hashlib.sha256((target/name).read_bytes()).hexdigest() == digest
                                  and ((target/name).stat().st_mode & 0o777) == mode and (target/name).stat().st_mtime_ns == mtime
                                  for name, (digest, mode, mtime) in originals.items())
                record('metadata-and-hashes', metadata_ok)
            except Exception as exc:
                record('qualification-execution', False, f'{type(exc).__name__}: {str(exc)[:180]}')
    for item in ('windows-portable-execution', 'nfs-smb-real-nas', 'effective-acl-identity', 'mid-file-crash-atomicity'):
        record(item, None, 'Outside this local POSIX qualification scope')
    return {'version': '225.2', 'compact_version': '7.6.2', 'author': 'Abdelhalim Talbi',
            'status': 'FAIL' if any(x['status']=='FAIL' for x in checks) else 'PASS_WITH_UNQUALIFIED_ITEMS', 'checks': checks}

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = qualify()
    rendered = json.dumps(result, indent=2, ensure_ascii=False)+'\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered)
    raise SystemExit(result['status']=='FAIL')
