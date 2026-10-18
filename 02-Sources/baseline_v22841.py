"""ODMM V228.41: statistical analysis of measured executor runs; no synthetic timings."""
import json, statistics, random, pathlib, sys

def summarize(payload, bootstrap=1000, seed=41):
    if bootstrap < 10: raise ValueError('bootstrap must be >= 10')
    out = {'benchmark': 'ODMM V228.41 statistical baseline', 'source': payload.get('benchmark'), 'cases': [], 'warnings': ['stage timings may overlap; do not sum stage durations', 'bootstrap confidence intervals describe observed local runs, not NAS performance', 'small samples and warm cache effects limit inference']}
    for case in payload['cases']:
        runs=case['runs']; values=[r['total_ns']/1e6 for r in runs]
        if not values or any(v <= 0 for v in values): raise ValueError('invalid timings')
        rng=random.Random(seed+int(case['size_bytes']))
        medians=sorted(statistics.median(rng.choices(values,k=len(values))) for _ in range(bootstrap))
        n=len(medians)
        stages={k:statistics.median([r.get('stages_ns',{}).get(k,0)/1e6 for r in runs]) for k in sorted(set().union(*(r.get('stages_ns',{}).keys() for r in runs)))}
        out['cases'].append({'size_bytes':case['size_bytes'],'repetitions':len(values),'median_ms':round(statistics.median(values),3),'min_ms':round(min(values),3),'max_ms':round(max(values),3),'bootstrap_median_95pct_ms':[round(medians[int(.025*(n-1))],3),round(medians[int(.975*(n-1))],3)],'stage_medians_ms_overlapping':stages,'additive_stage_costs':False})
    return out

def main():
    if len(sys.argv)!=3: raise SystemExit('usage: python baseline_v22841.py input.json output.json')
    result=summarize(json.loads(pathlib.Path(sys.argv[1]).read_text()))
    pathlib.Path(sys.argv[2]).write_text(json.dumps(result,indent=2)+'\n')
if __name__=='__main__':main()
