"""V191.6 opt-in mixed contention benchmark on an isolated SQLite backup.

Never writes to the supplied source database. Writers touch only a disposable
benchmark table in the isolated copy, not the cryptographic audit ledgers.
"""
import multiprocessing as mp
from contextlib import closing
from queue import Empty
import sqlite3
import tempfile
import time
from pathlib import Path
from native_audit_benchmark import percentiles, _worker


def _writer(database, repetitions, start, output):
    timings=[]; errors=[]; busy=0
    db=None
    try:
        db=sqlite3.connect(database,timeout=0.2,isolation_level=None)
        db.execute('PRAGMA busy_timeout=200')
        if not start.wait(30): raise RuntimeError('START_TIMEOUT')
        for i in range(repetitions):
            began=time.perf_counter_ns()
            try:
                db.execute('BEGIN IMMEDIATE')
                db.execute('INSERT INTO benchmark_write_probe(sequence) VALUES (?)',(i,))
                db.execute('COMMIT')
            except sqlite3.OperationalError as exc:
                if db.in_transaction: db.execute('ROLLBACK')
                if 'locked' in str(exc).lower() or 'busy' in str(exc).lower(): busy+=1
                else: errors.append(type(exc).__name__)
            except Exception as exc:
                if db.in_transaction: db.execute('ROLLBACK')
                errors.append(type(exc).__name__)
            timings.append((time.perf_counter_ns()-began)/1e6)
    except BaseException as exc:
        errors.append('WORKER:'+type(exc).__name__)
    finally:
        if db is not None: db.close()
        output.put({'timings':timings,'errors':errors,'busy':busy,'role':'writer'})


def mixed_benchmark(database, *, legacy_key, segment_keys, readers=2,
                    reader_repetitions=20, writer_repetitions=20, timeout=60):
    """Return latency/error report; source database remains unchanged.

    Only safe for SQLite databases supporting online backup; not a production
    workload qualification or a simulation of audit-event writer contention.
    """
    source=Path(database)
    if not source.is_file(): raise FileNotFoundError(database)
    if not (1<=readers<=16 and 1<=reader_repetitions<=10000 and 1<=writer_repetitions<=10000 and 1<=timeout<=600):
        raise ValueError('INVALID_BENCHMARK_BOUNDS')
    with tempfile.TemporaryDirectory(prefix='odmm-mixed-bench-') as td:
        clone=str(Path(td)/'isolated.sqlite3')
        uri=source.resolve().as_uri()+'?mode=ro'
        with closing(sqlite3.connect(uri,uri=True,timeout=5)) as original:
            with closing(sqlite3.connect(clone)) as copy:
                original.backup(copy)
        with closing(sqlite3.connect(clone)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE benchmark_write_probe (sequence INTEGER NOT NULL)')
            db.commit()
        ctx=mp.get_context('spawn'); event=ctx.Event(); output=ctx.Queue()
        workers=[ctx.Process(target=_worker,args=(clone,legacy_key,segment_keys,reader_repetitions,event,output)) for _ in range(readers)]
        writer=ctx.Process(target=_writer,args=(clone,writer_repetitions,event,output))
        processes=workers+[writer]
        started=time.perf_counter()
        try:
            for p in processes:p.start()
            event.set()
            results=[]
            deadline=time.monotonic()+timeout
            for _ in processes:
                remaining=deadline-time.monotonic()
                if remaining<=0: break
                try: results.append(output.get(timeout=remaining))
                except Empty: break
        finally:
            for p in processes:
                if p.pid is not None:
                    p.join(2)
                    if p.is_alive():p.terminate();p.join(2)
            output.close();output.join_thread()
        elapsed=time.perf_counter()-started
        reads=[r for r in results if r.get('role')!='writer']; write=next((r for r in results if r.get('role')=='writer'), {'timings':[], 'errors':['MISSING_WRITER_REPORT'], 'busy':0})
        latencies=[t for r in reads for t in r['timings']]
        failures=[e for r in reads for e in r['failures']]+write['errors']
        failures.extend('PROCESS_EXIT:'+str(p.exitcode) for p in processes if p.exitcode!=0)
        if len(results)!=len(processes): failures.append('MISSING_PROCESS_REPORT')
        return {'schema':'odmm.audit.mixed_benchmark.v1','isolated_copy':True,
                'source_read_only':True,'audit_ledgers_modified':False,
                'readers':readers,'reader_operations':len(latencies),
                'writer_attempts':len(write['timings']),'writer_busy_conflicts':write['busy'],
                'writer_busy_conflict_rate':round(write['busy']/len(write['timings']),4) if write['timings'] else None,
                'reader_latency':percentiles(latencies) if latencies else None,
                'writer_latency':percentiles(write['timings']) if write['timings'] else None,
                'elapsed_s':round(elapsed,3),
                'reader_throughput_ops_s':round(len(latencies)/elapsed,2) if elapsed else 0,
                'errors':failures[:20],'error_count':len(failures),
                'status':'PASS' if not failures and len(latencies)==readers*reader_repetitions and len(write['timings'])==writer_repetitions else 'FAIL',
                'cutover_authorized':False}
