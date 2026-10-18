"""Diagnose measured ODMM executor runs; no fabricated timings or NAS claims."""
import argparse
import json
import statistics
from pathlib import Path


def diagnose(data):
    if not isinstance(data,dict) or not data.get('cases'):
        raise ValueError('benchmark cases required')
    output=[]
    for case in data['cases']:
        runs=case.get('runs')
        if not isinstance(runs,list) or not runs:
            raise ValueError('raw measured runs required')
        stages=set().union(*(r.get('exclusive_stages_ns',{}) for r in runs))
        if not stages:
            raise ValueError('exclusive timing events required')
        totals=[]; unexplained=[]; values={k:[] for k in stages}
        for run in runs:
            total=run.get('total_ns')
            measured=run.get('exclusive_stages_ns',{})
            if not isinstance(total,(int,float)) or total<=0 or any(not isinstance(v,(int,float)) or v<0 for v in measured.values()):
                raise ValueError('invalid duration')
            attributed=sum(measured.values())
            if attributed>total*1.01:
                raise ValueError('exclusive timing exceeds wall time')
            totals.append(total)
            unexplained.append(max(0,total-attributed))
            for k in stages: values[k].append(measured.get(k,0))
        median_total=statistics.median(totals)
        ranked=sorted(({'stage':k,'median_ms':round(statistics.median(v)/1e6,4),'median_fraction_of_total':round(statistics.median(v)/median_total,4)} for k,v in values.items()),key=lambda v:-v['median_ms'])
        output.append({'size_bytes':case['size_bytes'],'repetitions':len(runs),'median_wall_ms':round(median_total/1e6,4),'median_unattributed_ms':round(statistics.median(unexplained)/1e6,4),'ranked_exclusive_stages':ranked,'largest_instrumented_stage':ranked[0]['stage']})
    return {'schema':'odmm.benchmark.diagnosis.v22844','environment':data.get('environment',{}),'cases':output,'limitations':['Local filesystem only; no NAS inference','Median per-stage costs do not sum to median wall time','Unattributed time includes instrumentation gaps and overhead','No change to transfer or safety decisions']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input');p.add_argument('--output')
    args=p.parse_args()
    result=diagnose(json.loads(Path(args.input).read_text()))
    encoded=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if args.output:Path(args.output).write_text(encoded)
    else:print(encoded,end='')

if __name__=='__main__':main()
