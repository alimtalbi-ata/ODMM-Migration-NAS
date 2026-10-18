"""Isolated SQLite transaction experiment. NEVER touches ODMM production databases."""
import argparse, json, sqlite3, statistics, tempfile, time
from pathlib import Path

SCHEMA = '''CREATE TABLE tasks (id INTEGER PRIMARY KEY, status TEXT NOT NULL, token TEXT NOT NULL);
INSERT INTO tasks VALUES(1,'CLAIMED','t');'''

def trial(path, *, mode, repetitions=100):
    if mode not in ('baseline', 'returning'):
        raise ValueError('unsupported mode')
    if repetitions < 1: raise ValueError('repetitions must be positive')
    db=sqlite3.connect(str(path), isolation_level=None)
    try:
        db.executescript(SCHEMA)
        durations=[]
        for _ in range(repetitions):
            db.execute("UPDATE tasks SET status='CLAIMED' WHERE id=1")
            start=time.perf_counter_ns()
            db.execute('BEGIN IMMEDIATE')
            try:
                if mode=='baseline':
                    row=db.execute('SELECT status,token FROM tasks WHERE id=1').fetchone()
                    if row!=('CLAIMED','t'): raise RuntimeError('claim mismatch')
                    updated=db.execute("UPDATE tasks SET status='VERIFIED' WHERE id=1 AND status='CLAIMED' AND token='t'")
                    if updated.rowcount!=1: raise RuntimeError('claim update mismatch')
                else:
                    row=db.execute("UPDATE tasks SET status='VERIFIED' WHERE id=1 AND status='CLAIMED' AND token='t' RETURNING status,token").fetchone()
                    if row!=('VERIFIED','t'): raise RuntimeError('claim update mismatch')
                db.execute('COMMIT')
            except BaseException:
                if db.in_transaction: db.execute('ROLLBACK')
                raise
            durations.append(time.perf_counter_ns()-start)
            if db.execute('SELECT status,token FROM tasks WHERE id=1').fetchone()!=('VERIFIED','t'):
                raise RuntimeError('persisted state mismatch')
        return {'mode':mode,'iterations':repetitions,'median_ms':round(statistics.median(durations)/1e6,6),'p95_ms':round(sorted(durations)[int((len(durations)-1)*.95)]/1e6,6)}
    finally: db.close()

def run(repetitions=100):
    with tempfile.TemporaryDirectory(prefix='odmm-sqlite-isolated-') as d:
        results=[trial(Path(d)/(mode+'.db'),mode=mode,repetitions=repetitions) for mode in ('baseline','returning')]
    return {'experiment':'isolated sqlite claim validation', 'production_modified':False, 'caveat':'Synthetic SQLite workload, not an ODMM end-to-end migration benchmark', 'results':results}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--iterations',type=int,default=100);p.add_argument('--output');a=p.parse_args()
    result=run(a.iterations);payload=json.dumps(result,indent=2)
    if a.output:Path(a.output).write_text(payload+'\n',encoding='utf-8')
    print(payload)
