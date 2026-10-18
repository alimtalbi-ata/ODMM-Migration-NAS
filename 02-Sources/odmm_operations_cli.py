"""Read-only CLI sharing the same contract as the optional API adapter."""
import argparse
import json
from odmm_operations import OperationsView

def main(argv=None):
    p=argparse.ArgumentParser(description='ODMM read-only operations CLI')
    p.add_argument('--db',required=True,help='Existing SQLite registry (never created)')
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('overview')
    jobs=sub.add_parser('jobs'); jobs.add_argument('--limit',type=int,default=50)
    ops=sub.add_parser('operations'); ops.add_argument('--job-id',required=True); ops.add_argument('--limit',type=int,default=50)
    a=p.parse_args(argv)
    try:
        v=OperationsView(a.db)
        data= v.overview() if a.command=='overview' else v.jobs(a.limit) if a.command=='jobs' else v.operations(a.job_id,a.limit)
    except (OSError,ValueError,LookupError) as exc:
        p.exit(2,'ODMM_ERROR: '+str(exc)+'\n')
    print(json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2))
    return 0

if __name__=='__main__': raise SystemExit(main())
