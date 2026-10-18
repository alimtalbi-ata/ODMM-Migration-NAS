"""Evidence-based stage ranking for ODMM timing events (no synthetic timings)."""
import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from exclusive_timing_v22842 import exclusive_timings


def analyze(runs):
    if not isinstance(runs,list) or not runs:
        raise ValueError('at least one measured run is required')
    stages=defaultdict(list)
    for events in runs:
        if not isinstance(events,list) or not events:
            raise ValueError('each run must contain measured timing intervals')
        exclusive=exclusive_timings(events)
        if not exclusive or any(v<0 for v in exclusive.values()):
            raise ValueError('invalid exclusive timings')
        for stage,value in exclusive.items():
            stages[stage].append(value/1e6)
    ranking=sorted(({'stage':name,'samples':len(samples),'median_exclusive_ms':round(statistics.median(samples),6),'min_ms':round(min(samples),6),'max_ms':round(max(samples),6)} for name,samples in stages.items()),key=lambda x:(-x['median_exclusive_ms'],x['stage']))
    return {'schema':'odmm.bottlenecks.v1','runs':len(runs),'ranked_stages':ranking,'limitations':['Local timing evidence only; no NAS throughput inference','Nested intervals are not additive; compare exclusive medians','Different stage sample counts are not directly comparable']}


def main():
    p=argparse.ArgumentParser(description='Rank measured ODMM stages without inventing results')
    p.add_argument('input',help='JSON list of runs; each run is a list of interval events')
    p.add_argument('--output',help='optional output JSON path')
    args=p.parse_args()
    report=analyze(json.loads(Path(args.input).read_text(encoding='utf-8')))
    data=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
    if args.output:Path(args.output).write_text(data,encoding='utf-8')
    else:print(data,end='')
if __name__=='__main__':main()
