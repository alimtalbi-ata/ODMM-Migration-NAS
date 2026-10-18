"""Isolated runtime smoke tests. Author: Abdelhalim Talbi."""
from __future__ import annotations
import json, subprocess, sys, tempfile, hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def qualify():
    checks=[]
    def record(name,ok,detail=''):
        checks.append({'name':name,'status':'PASS' if ok else 'FAIL','detail':detail})
    with tempfile.TemporaryDirectory(prefix='odmm-v2249-') as tmp:
        base=Path(tmp)
        src=base/'source'; dst=base/'target'; src.mkdir();dst.mkdir()
        (src/'nested').mkdir();(dst/'nested').mkdir()
        (src/'sample.bin').write_bytes(b'ODMM\x00native\xff')
        (src/'nested'/'data.txt').write_text('reprise et integrite',encoding='utf-8')
        script='''from native_tree_migration import NativeTreeMigration\nfrom pathlib import Path\nimport sys,json\ns,d,db=map(Path,sys.argv[1:])\nwith NativeTreeMigration(s,d,db) as engine:\n a=engine.run(limit=1); b=engine.run(); c=engine.verify_all(); print(json.dumps({'first':a['processed_count'],'second':b['processed_count'],'verified':c['count'],'cutover':b['cutover_authorized'],'acl':b['acl_fidelity_verified']}))\n'''
        cmd=[sys.executable,'-c',script,str(src),str(dst),str(base/'ledger.sqlite')]
        try:
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=25)
            data=json.loads(p.stdout) if p.returncode==0 else {}
            record('native-copy-resume-subprocess',p.returncode==0 and data.get('first')==1 and data.get('second')==2 and data.get('verified')==2,p.stderr[-300:])
            record('sha256-integrity',all(hashlib.sha256(f.read_bytes()).digest()==hashlib.sha256((dst/f.relative_to(src)).read_bytes()).digest() for f in src.rglob('*') if f.is_file()))
            record('no-automatic-cutover-or-acl-claim',data.get('cutover') is False and data.get('acl') is False)
            p2=subprocess.run([sys.executable,'-m','odmm_operations_cli','--help'],cwd=ROOT,capture_output=True,text=True,timeout=15)
            record('operations-cli-help',p2.returncode==0 and '--db' in p2.stdout)
            p3=subprocess.run([sys.executable,'-m','odmm_scoped_cli','--help'],cwd=ROOT,capture_output=True,text=True,timeout=15)
            record('scoped-cli-fail-closed',p3.returncode!=0 and 'VERIFIED_IDENTITY_PROVIDER_REQUIRED' in p3.stderr)
        except (OSError,ValueError,subprocess.TimeoutExpired) as e:
            record('runtime-execution',False,type(e).__name__)
    checks.extend([{'name':n,'status':'NOT_TESTED'} for n in ('windows-native','real-nas-acl','real-nas-smb-nfs','production-idp')])
    return {'version':'224.9','author':'Abdelhalim Talbi','status':'FAIL' if any(x['status']=='FAIL' for x in checks) else 'PASS_WITH_UNQUALIFIED_ITEMS','checks':checks}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args();r=qualify();out=json.dumps(r,indent=2,ensure_ascii=False)+'\n';print(out)
    if a.output:a.output.write_text(out,encoding='utf-8')
    raise SystemExit(1 if r['status']=='FAIL' else 0)
