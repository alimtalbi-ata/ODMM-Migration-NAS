"""Reproducible local end-to-end incremental executor benchmark (no NAS claims)."""
import argparse
import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path
from native_posix_migration import NativePosixMigration
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner
from native_incremental_executor import IncrementalExecutor
from exclusive_timing_v22842 import exclusive_timings


def run_case(size_bytes):
    with tempfile.TemporaryDirectory(prefix='odmm-bench-') as tmp:
        base=Path(tmp);src=base/'source';dst=base/'target';src.mkdir();dst.mkdir()
        engine=NativePosixMigration(src,dst,base/'registry.sqlite')
        try:
            inventory=IncrementalInventory(engine);planner=IncrementalPlanner(inventory)
            before=inventory.capture()['pass_id']
            with (src/'payload.bin').open('wb') as f:
                chunk=b'ODMM-v22839\0'*8192
                left=size_bytes
                while left:
                    part=chunk[:min(left,len(chunk))];f.write(part);left-=len(part)
            after=inventory.capture()['pass_id']
            plan=planner.create(before,after)['plan_id']
            token=planner.claim_copy(plan,'payload.bin')['claim_token']
            executor=IncrementalExecutor(planner)
            start=time.perf_counter_ns()
            result=executor.execute_claimed(plan,'payload.bin',claim_token=token)
            duration=time.perf_counter_ns()-start
            assert result['status']=='VERIFIED_POSIX_SUBSET'
            assert (dst/'payload.bin').stat().st_size==size_bytes
            stages={}
            for event in executor.last_timings:
                stages.setdefault(event['stage'],[]).append(event['elapsed_ns'])
            return {'total_ns':duration,'stages_ns':{k:sum(v) for k,v in stages.items()},'stage_counts':{k:len(v) for k,v in stages.items()},'exclusive_stages_ns':exclusive_timings(executor.last_timings)}
        finally:
            engine.close()


def benchmark(sizes=(1048576,4194304,16777216),repetitions=3):
    if repetitions<1 or any(n<1 for n in sizes):raise ValueError('sizes and repetitions must be positive')
    cases=[]
    for size in sizes:
        runs=[run_case(size) for _ in range(repetitions)]
        med=statistics.median(r['total_ns'] for r in runs)
        cases.append({'size_bytes':size,'repetitions':repetitions,'median_total_ms':round(med/1e6,3),
                      'median_throughput_mib_s':round(size/(1024**2)/(med/1e9),2),
                      'median_stage_ms':{k:round(statistics.median(r['stages_ns'].get(k,0) for r in runs)/1e6,3)
                                         for k in sorted(set().union(*(r['stages_ns'] for r in runs)))},
                      'median_exclusive_stage_ms':{k:round(statistics.median(r['exclusive_stages_ns'].get(k,0) for r in runs)/1e6,3) for k in sorted(set().union(*(r['exclusive_stages_ns'] for r in runs)))},'runs':runs})
    return {'benchmark':'ODMM V228.39 actual local executor path','environment':{'python':platform.python_version(),
            'platform':platform.platform(),'filesystem':'temporary local filesystem (not NAS)'},
            'scope':'inventory and claim excluded from timed section; copy, reverify, SQLite commit included',
            'limitations':['single worker','warm filesystem caches possible','inclusive stage totals overlap; use exclusive stage timings for non-overlapping attributed cost; uninstrumented time remains outside measured stages','no network or NAS','no ACL fidelity claim'],
            'cases':cases}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sizes-mib',type=int,nargs='+',default=[1,4,16]);p.add_argument('--repetitions',type=int,default=3)
    p.add_argument('--output',default='benchmark-executor-v22839.json')
    args=p.parse_args();data=benchmark([x*1048576 for x in args.sizes_mib],args.repetitions)
    Path(args.output).write_text(json.dumps(data,indent=2)+'\n',encoding='utf8')
    print(json.dumps([{'size_mib':x['size_bytes']//1048576,'median_ms':x['median_total_ms'],'throughput_mib_s':x['median_throughput_mib_s']} for x in data['cases']],indent=2))
