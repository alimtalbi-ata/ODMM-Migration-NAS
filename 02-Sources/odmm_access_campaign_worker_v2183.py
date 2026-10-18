"""Strict subprocess entrypoint for ODMM access campaigns. Author: Abdelhalim Talbi."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from odmm_live_access_v2182 import AccessCase,run_readonly_case

def main():
    raw=sys.stdin.buffer.read(1024*1024+1)
    if len(raw)>1024*1024:
        return 2
    try:
        data=json.loads(raw)
        if not isinstance(data,dict) or set(data)!=set(AccessCase.__dataclass_fields__):
            return 2
        result=run_readonly_case(AccessCase(**data))
        sys.stdout.write(json.dumps(result,sort_keys=True,separators=(',',':')))
        return 0
    except (Exception,):
        return 2
if __name__=='__main__':
    sys.exit(main())
