"""V191.5 reproducible, read-only multiprocess audit verification benchmark.

Never performs cutover or data modification. The optional writer is deliberately
excluded: this measures reader contention, not mixed-write production capacity.
"""
import argparse
import json
import multiprocessing as mp
import os
import statistics
import time
from pathlib import Path


def percentiles(samples):
    if not samples:
        raise ValueError('EMPTY_SAMPLES')
    ordered = sorted(samples)
    def p(q):
        index = (len(ordered) - 1) * q
        lo = int(index)
        hi = min(lo + 1, len(ordered)-1)
        return round(ordered[lo] + (ordered[hi]-ordered[lo])*(index-lo), 3)
    return {'p50_ms':p(.50),'p95_ms':p(.95),'p99_ms':p(.99),
            'min_ms':round(ordered[0],3),'max_ms':round(ordered[-1],3)}


def _worker(database, old_key, keys, repetitions, start, out):
    from native_bridge_consistency import verify_bridge_snapshot
    timings=[]
    failures=[]
    try:
        if not start.wait(30):
            raise RuntimeError('START_TIMEOUT')
        for _ in range(repetitions):
            t=time.perf_counter_ns()
            try:
                result=verify_bridge_snapshot(database,legacy_key=old_key,segment_keys=keys)
                if result.get('status') != 'CONSISTENT':
                    raise RuntimeError('INCONSISTENT')
            except Exception as exc:
                failures.append(type(exc).__name__+':'+str(exc))
            timings.append((time.perf_counter_ns()-t)/1_000_000)
        out.put({'timings':timings,'failures':failures})
    except BaseException as exc:
        out.put({'timings':timings,'failures':['WORKER:'+repr(exc)]})


def benchmark(database, *, legacy_key, segment_keys, workers=3, repetitions=20, timeout=60):
    """Run bounded spawned readers. Keys are never included in returned report."""
    if not Path(database).is_file():
        raise FileNotFoundError(database)
    if not 1 <= workers <= 32 or not 1 <= repetitions <= 10000:
        raise ValueError('INVALID_BENCHMARK_BOUNDS')
    ctx=mp.get_context('spawn')
    start=ctx.Event()
    queue=ctx.Queue()
    processes=[ctx.Process(target=_worker,args=(str(database),legacy_key,segment_keys,repetitions,start,queue))
               for _ in range(workers)]
    started=time.perf_counter()
    for proc in processes: proc.start()
    start.set()
    reports=[]
    try:
        for _ in processes:
            reports.append(queue.get(timeout=timeout))
    finally:
        for proc in processes:
            proc.join(2)
            if proc.is_alive():
                proc.terminate();proc.join(2)
    elapsed=time.perf_counter()-started
    samples=[v for report in reports for v in report['timings']]
    errors=[error for report in reports for error in report['failures']]
    bad_exits=[p.exitcode for p in processes if p.exitcode != 0]
    if bad_exits: errors.extend('PROCESS_EXIT:'+str(code) for code in bad_exits)
    if len(reports) != workers: errors.append('MISSING_WORKER_REPORT')
    return {'schema':'odmm.audit.benchmark.v1','workers':workers,'repetitions_per_worker':repetitions,
            'operations':len(samples),'elapsed_s':round(elapsed,3),
            'throughput_ops_s':round(len(samples)/elapsed,2) if elapsed else 0,
            'latency':percentiles(samples) if samples else None,
            'error_count':len(errors),'errors':errors[:20],
            'status':'PASS' if not errors and len(samples)==workers*repetitions else 'FAIL',
            'read_only':True,'cutover_authorized':False}


def main():
    parser=argparse.ArgumentParser(description='ODMM read-only audit benchmark')
    parser.add_argument('database')
    parser.add_argument('--legacy-key-env',default='ODMM_LEGACY_HMAC_KEY_HEX')
    parser.add_argument('--segment-keys-env',default='ODMM_SEGMENT_KEYS_JSON')
    parser.add_argument('--workers',type=int,default=3)
    parser.add_argument('--repetitions',type=int,default=20)
    parser.add_argument('--output')
    args=parser.parse_args()
    legacy=bytes.fromhex(os.environ[args.legacy_key_env])
    keys={k:bytes.fromhex(v) for k,v in json.loads(os.environ[args.segment_keys_env]).items()}
    result=benchmark(args.database,legacy_key=legacy,segment_keys=keys,workers=args.workers,repetitions=args.repetitions)
    report=json.dumps(result,sort_keys=True,indent=2)+'\n'
    if args.output:
        output=Path(args.output)
        with output.open('x',encoding='utf-8') as f:
            f.write(report);f.flush();os.fsync(f.fileno())
    else:
        print(report,end='')
    raise SystemExit(0 if result['status']=='PASS' else 1)

if __name__=='__main__': main()
