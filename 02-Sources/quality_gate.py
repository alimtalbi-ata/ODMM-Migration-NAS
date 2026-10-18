"""ODMM R0 quality gate: isolated test modules, bounded time and machine-readable evidence.
This tool executes tests; it never starts migrations or changes application data.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run_gate(root, *, pattern='test_*.py', timeout=60, report=None):
    root=Path(root).resolve()
    if not root.is_dir() or not isinstance(timeout,int) or isinstance(timeout,bool) or not 1<=timeout<=3600:
        raise ValueError('INVALID_QUALITY_GATE_ARGUMENTS')
    if '/' in pattern or '\\' in pattern or '..' in pattern or not pattern.startswith('test_') or not pattern.endswith('.py'):
        raise ValueError('INVALID_TEST_PATTERN')
    results=[]
    for file in sorted(root.glob(pattern)):
        if not file.is_file() or file.is_symlink():
            continue
        cmd=[sys.executable,'-m','unittest',file.stem,'-q']
        start=time.monotonic()
        try:
            completed=subprocess.run(cmd,cwd=root,capture_output=True,text=True,timeout=timeout,check=False,
                                     env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            output=(completed.stdout+'\n'+completed.stderr)[-16000:]
            status='PASS' if completed.returncode==0 else 'FAIL'
            code=completed.returncode
        except subprocess.TimeoutExpired as exc:
            output=((exc.stdout or b'').decode(errors='replace') if isinstance(exc.stdout,bytes) else (exc.stdout or ''))[-16000:]
            status='TIMEOUT';code=None
        results.append({'module':file.name,'status':status,'returncode':code,
                        'elapsed_seconds':round(time.monotonic()-start,3),
                        'source_sha256':hashlib.sha256(file.read_bytes()).hexdigest(),
                        'output_tail':output})
    summary={'schema':1,'status':'PASS' if results and all(r['status']=='PASS' for r in results) else 'FAIL',
             'modules':len(results),'passed':sum(r['status']=='PASS' for r in results),
             'failed':sum(r['status']=='FAIL' for r in results),
             'timed_out':sum(r['status']=='TIMEOUT' for r in results),
             'manual_review_required':True,'production_qualified':False,
             'cutover_authorized':False,'migration_authorized':False,'results':results}
    if report is not None:
        target=Path(report)
        if target.exists() or target.is_symlink(): raise FileExistsError('REPORT_EXISTS')
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('x',encoding='utf-8') as f:
            json.dump(summary,f,sort_keys=True,indent=2)
            f.write('\n')
    return summary


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',default=str(Path(__file__).resolve().parent))
    parser.add_argument('--pattern',default='test_*.py')
    parser.add_argument('--timeout',type=int,default=60)
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    summary=run_gate(args.root,pattern=args.pattern,timeout=args.timeout,report=args.report)
    print(json.dumps({k:v for k,v in summary.items() if k!='results'},sort_keys=True))
    return 0 if summary['status']=='PASS' else 1

if __name__=='__main__':sys.exit(main())
