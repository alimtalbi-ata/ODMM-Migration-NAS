"""Read-only history of Windows browser qualification reports (not a Windows certification).
Author: Abdelhalim Talbi.
"""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from qualification_windows_v2204 import consolidate

SCHEMA = '''CREATE TABLE IF NOT EXISTS runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 recorded_at TEXT NOT NULL,
 evidence_sha256 TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL,
 browser_status TEXT NOT NULL,
 checks_json TEXT NOT NULL,
 failures_json TEXT NOT NULL,
 screenshots_json TEXT NOT NULL,
 windows_qualified INTEGER NOT NULL CHECK(windows_qualified=0)
)'''


def _connect(db):
    con = sqlite3.connect(db, timeout=10)
    con.execute('PRAGMA busy_timeout=10000')
    con.execute(SCHEMA)
    return con


def ingest(db, evidence_dir):
    """Revalidate evidence on ingest; never trust a precomputed PASS or Windows qualification flag."""
    directory = Path(evidence_dir)
    raw_path = directory / 'recette-result.json'
    result = consolidate(directory)
    if not raw_path.is_file():
        raise ValueError('BROWSER_REPORT_MISSING')
    # Hash includes validated screenshot digests and consolidated assessment.
    raw_hash = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    canonical = json.dumps({'raw_sha256': raw_hash, 'result': result}, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    with _connect(db) as con:
        cur = con.execute('INSERT OR IGNORE INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',
            (datetime.now(timezone.utc).isoformat(), digest, result['status'], result['browser_status'],
             json.dumps(result['checks'], sort_keys=True), json.dumps(result['failures']), json.dumps(result['screenshots'])))
        row = con.execute('SELECT id FROM runs WHERE evidence_sha256=?', (digest,)).fetchone()
    return {'id': row[0], 'duplicate': cur.rowcount == 0, 'status': result['status'], 'evidence_sha256': digest, 'windows_qualified': False}


def history(db, limit=100):
    if not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError('INVALID_LIMIT')
    with _connect(db) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute('SELECT * FROM runs ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    return [{**dict(r), 'checks': json.loads(r['checks_json']), 'failures': json.loads(r['failures_json']),
             'screenshots': json.loads(r['screenshots_json']), 'windows_qualified': False}
            for r in rows]


def compare(db, older_id, newer_id):
    with _connect(db) as con:
        rows = con.execute('SELECT id,status,checks_json,failures_json FROM runs WHERE id IN (?,?)', (older_id, newer_id)).fetchall()
    by_id = {r[0]: r for r in rows}
    if older_id == newer_id or older_id not in by_id or newer_id not in by_id:
        raise ValueError('RUN_NOT_FOUND_OR_IDENTICAL')
    old, new = by_id[older_id], by_id[newer_id]
    a, b = json.loads(old[2]), json.loads(new[2])
    return {'older_id': older_id, 'newer_id': newer_id, 'older_status': old[1], 'newer_status': new[1],
            'regressions': sorted(k for k in set(a)|set(b) if a.get(k) is True and b.get(k) is not True),
            'improvements': sorted(k for k in set(a)|set(b) if a.get(k) is not True and b.get(k) is True),
            'new_failures': sorted(set(json.loads(new[3])) - set(json.loads(old[3]))),
            'windows_qualified': False}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', required=True)
    sub = p.add_subparsers(dest='action', required=True)
    add = sub.add_parser('ingest'); add.add_argument('--evidence', required=True)
    hist = sub.add_parser('history'); hist.add_argument('--limit', type=int, default=100)
    diff = sub.add_parser('compare'); diff.add_argument('--older', type=int, required=True); diff.add_argument('--newer', type=int, required=True)
    args = p.parse_args()
    result = ingest(args.db, args.evidence) if args.action == 'ingest' else history(args.db, args.limit) if args.action == 'history' else compare(args.db, args.older, args.newer)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
