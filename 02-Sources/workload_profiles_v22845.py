"""Measured local executor workload profiles; no NAS throughput or ACL claims."""
import argparse
import json
import statistics
from pathlib import Path
from benchmark_executor_v22839 import run_case

PROFILES = {'tiny': (4096, 16384, 65536), 'small': (262144, 1048576), 'large': (4194304, 16777216)}

def measure_profile(name, repetitions=3):
    if name not in PROFILES or not isinstance(repetitions,int) or repetitions < 1:
        raise ValueError('unknown profile or invalid repetitions')
    cases=[]
    for size in PROFILES[name]:
        runs=[run_case(size) for _ in range(repetitions)]
        med=statistics.median(r['total_ns'] for r in runs)
        stages=sorted(set().union(*(r['exclusive_stages_ns'] for r in runs)))
        cases.append({'size_bytes':size,'repetitions':repetitions,'median_total_ms':round(med/1e6,4),
                      'median_throughput_mib_s':round((size/1048576)/(med/1e9),3),
                      'median_exclusive_ms':{s:round(statistics.median(r['exclusive_stages_ns'].get(s,0) for r in runs)/1e6,4) for s in stages},
                      'raw_runs':runs})
    return {'schema':'odmm.local.workload.v22845','profile':name,'scope':'real local IncrementalExecutor; inventory/claim excluded from timing',
            'limitations':['local filesystem only','warm caches possible','one worker','no NAS or ACL claims','small sample, descriptive only'], 'cases':cases}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile',choices=sorted(PROFILES),default='tiny')
    p.add_argument('--repetitions',type=int,default=3)
    p.add_argument('--output',required=True)
    args=p.parse_args()
    result=measure_profile(args.profile,args.repetitions)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps([{'bytes':c['size_bytes'],'median_ms':c['median_total_ms']} for c in result['cases']]))
if __name__=='__main__': main()
