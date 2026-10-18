"""Analyse descriptive des coûts SQLite observés dans le moteur natif; aucune optimisation implicite."""
import argparse
import json
import statistics
from pathlib import Path

SQLITE_STAGES = ('verify.sqlite_lookup', 'commit.claim_lookup', 'commit.claim_update', 'commit.sqlite_commit')

def analyze(data):
    cases = data.get('cases')
    if not isinstance(cases, list) or not cases:
        raise ValueError('Benchmark cases missing')
    output = []
    for case in cases:
        runs = case.get('runs', [])
        if not runs:
            raise ValueError('Raw runs missing: cannot estimate SQLite cost')
        samples = []
        for run in runs:
            total = run.get('total_ns')
            exclusive = run.get('exclusive_stages_ns')
            if not isinstance(total, (int, float)) or total <= 0 or not isinstance(exclusive, dict):
                raise ValueError('Invalid timing record')
            if not all(k in exclusive for k in SQLITE_STAGES):
                raise ValueError('Missing SQLite stage instrumentation')
            values = [exclusive[k] for k in SQLITE_STAGES]
            if any(not isinstance(v, (int, float)) or v < 0 for v in values):
                raise ValueError('Invalid SQLite stage duration')
            sqlite_ns = sum(values)
            if sqlite_ns > total:
                raise ValueError('SQLite exclusive durations exceed wall time')
            samples.append({'sqlite_ns':sqlite_ns,'total_ns':total,'share_pct':sqlite_ns / total * 100})
        output.append({'size_bytes':case['size_bytes'],'runs':len(samples),
                       'median_sqlite_ms':round(statistics.median(x['sqlite_ns'] for x in samples)/1e6,4),
                       'median_sqlite_share_pct':round(statistics.median(x['share_pct'] for x in samples),2),
                       'median_total_ms':round(statistics.median(x['total_ns'] for x in samples)/1e6,4)})
    return {'analysis':'ODMM V228.47 SQLite exclusive-cost characterization',
            'scope':'instrumented SQLite substeps only, excludes uninstrumented SQLite operations',
            'optimization_applied':False,
            'cases':output}

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('benchmark_json');p.add_argument('--output',required=True)
    args=p.parse_args()
    result=analyze(json.loads(Path(args.benchmark_json).read_text(encoding='utf8')))
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result,indent=2))
