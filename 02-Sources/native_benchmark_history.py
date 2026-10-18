"""V191.8: append-only benchmark history and read-only cockpit, local POSIX only."""
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path

FIELDS = ('schema','status','reader_operations','writer_attempts','writer_busy_conflicts',
          'writer_busy_conflict_rate','reader_latency','writer_latency','elapsed_s',
          'reader_throughput_ops_s','error_count','cutover_authorized','source_read_only','isolated_copy')

def _safe_report(report):
    if report.get('schema') != 'odmm.audit.mixed_benchmark.v1':
        raise ValueError('UNSUPPORTED_REPORT_SCHEMA')
    if report.get('cutover_authorized') is not False or report.get('source_read_only') is not True or report.get('isolated_copy') is not True:
        raise ValueError('UNSAFE_BENCHMARK_REPORT')
    if report.get('status') not in ('PASS','FAIL'):
        raise ValueError('INVALID_STATUS')
    return {key:report.get(key) for key in FIELDS}

def append_history(path, report):
    """Durable serialized append; refuses symlinks; never stores key material."""
    entry=_safe_report(report)
    target=Path(path)
    target.parent.mkdir(parents=True,exist_ok=True)
    flags=os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW
    fd=os.open(target,flags,0o600)
    try:
        with os.fdopen(fd,'ab',closefd=False) as stream:
            fcntl.flock(fd,fcntl.LOCK_EX)
            try:
                # Reject a truncated previous record instead of silently accepting corruption.
                if os.fstat(fd).st_size:
                    with open(target,'rb') as current:
                        current.seek(-1,os.SEEK_END)
                        if current.read(1)!=b'\n': raise ValueError('INCOMPLETE_HISTORY')
                payload=(json.dumps(entry,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
                stream.write(payload);stream.flush();os.fsync(fd)
            finally: fcntl.flock(fd,fcntl.LOCK_UN)
    finally: os.close(fd)
    return hashlib.sha256(payload).hexdigest()

def read_history(path, limit=100):
    if not 1<=limit<=10000: raise ValueError('INVALID_LIMIT')
    target=Path(path)
    if target.is_symlink(): raise ValueError('SYMLINK_HISTORY')
    if not target.exists(): return []
    with target.open('rb') as stream:
        fcntl.flock(stream.fileno(),fcntl.LOCK_SH)
        try:
            raw=stream.read(20_000_001)
        finally: fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
    if len(raw)>20_000_000: raise ValueError('HISTORY_TOO_LARGE')
    if raw and not raw.endswith(b'\n'): raise ValueError('INCOMPLETE_HISTORY')
    return [_safe_report(json.loads(line)) for line in raw.splitlines()[-limit:]]

def cockpit_html(records):
    """Standalone HTML dashboard, no external scripts, no active controls."""
    rows=[]
    for i,report in enumerate(records,1):
        r=_safe_report(report)
        def cell(value): return '<td>'+html.escape(str(value if value is not None else '—'))+'</td>'
        rows.append('<tr>'+''.join(map(cell,(i,r['status'],r['reader_operations'],r['writer_attempts'],r['writer_busy_conflict_rate'],r['elapsed_s'],r['error_count'])))+'</tr>')
    return ("""<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ODMM · Audits / Performances</title><style>body{font:16px system-ui;background:#101c30;color:#e9f3ff;margin:2rem}h1{color:#7bd7ff}table{border-collapse:collapse;width:100%;background:#1c3048}th,td{padding:.8rem;border-bottom:1px solid #40546a;text-align:left}th{color:#a9e3ff}.note{color:#b7c9d9}</style><h1>ODMM · Historique des benchmarks</h1><p class="note">Cockpit statique en lecture seule · tests sur copie isolée · aucun cutover autorisé</p><table><thead><tr><th>#</th><th>État</th><th>Lectures</th><th>Écritures</th><th>Conflits (%)</th><th>Durée (s)</th><th>Erreurs</th></tr></thead><tbody>"""+''.join(rows)+"""</tbody></table><p class="note">Auteur : Abdelhalim Talbi · V191.8 / Compact V4.2.8</p></html>""")
