"""Bounded read-only NetApp NFS policy evidence, canonical ACL comparison and safe HTML report.
Author: Abdelhalim Talbi. Never authorizes cutover.
"""
import html,json
from urllib.parse import urlsplit

MAX_PAGES=20

def _local_api_path(path):
    if not isinstance(path,str) or len(path)>4096 or not path.startswith('/api/') or path.startswith('//') or '\\' in path or any(ord(c)<32 for c in path):
        return False
    u=urlsplit(path)
    return not u.scheme and not u.netloc and all(p not in ('.','..') for p in u.path.split('/'))

def collect_nfs_rules(fetch, path, *, max_pages=MAX_PAGES, max_rules=5000):
    if not callable(fetch) or not _local_api_path(path) or not 1<=max_pages<=100 or not 1<=max_rules<=100000:
        raise ValueError('INVALID_COLLECTOR_PARAMETERS')
    seen=set(); rules=[]; blockers=[]; current=path
    for _ in range(max_pages):
        if current in seen:
            blockers.append('PAGINATION_CYCLE');break
        seen.add(current)
        try:
            data=fetch(current)
            if not isinstance(data,dict) or not isinstance(data.get('records'),list):raise ValueError('INVALID_RESPONSE')
            if len(rules)+len(data['records'])>max_rules:
                blockers.append('RULE_LIMIT_EXCEEDED');break
            rules.extend(data['records'])
            link=data.get('_links',{}).get('next')
            if not link:
                return {'rules':rules,'complete':not blockers,'blockers':blockers,'pages':len(seen)}
            current=link.get('href') if isinstance(link,dict) else None
            if not _local_api_path(current):
                blockers.append('UNSAFE_NEXT_LINK');break
        except Exception:
            blockers.append('FETCH_OR_SCHEMA_ERROR');break
    else:
        blockers.append('PAGE_LIMIT_EXCEEDED')
    return {'rules':rules,'complete':False,'blockers':blockers,'pages':len(seen)}

def _canonical(records):
    if not isinstance(records,list):raise ValueError('INVALID_RULES')
    # Canonicalize dictionary field order, preserve rule order by explicit index.
    indexes=[r.get('index') for r in records if isinstance(r,dict)]
    if len(indexes)!=len(records) or any(not isinstance(i,int) or isinstance(i,bool) for i in indexes) or len(set(indexes))!=len(indexes):
        raise ValueError('AMBIGUOUS_RULE_INDEX')
    return [json.dumps(r,sort_keys=True,ensure_ascii=False,separators=(',',':')) for r in sorted(records,key=lambda x:x['index'])]

def compare_nfs_policies(source,target):
    blockers=list(source.get('blockers',[]))+list(target.get('blockers',[]));diffs=[]
    if not source.get('complete') or not target.get('complete'):blockers.append('INCOMPLETE_POLICY_EVIDENCE')
    try:
        a=_canonical(source.get('rules',[]));b=_canonical(target.get('rules',[]))
        if a!=b:diffs.append({'domain':'nfs_export_rules','issue':'RULE_DRIFT'});blockers.append('NFS_RULE_DRIFT')
    except (ValueError,TypeError):blockers.append('AMBIGUOUS_POLICY_EVIDENCE')
    blockers.append('EFFECTIVE_ACCESS_NOT_PROVEN')
    return {'status':'BLOCKED','cutover_authorized':False,'blockers':sorted(set(blockers)),'differences':diffs}

def render_policy_differences(result):
    lines=['<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM NetApp — écarts</title>',
           '<style>body{font:16px system-ui;margin:3rem;background:#f4f7fb;color:#132c44}main{max-width:1000px;margin:auto;background:white;padding:2rem;border-radius:16px}li{padding:.5rem}strong{color:#9c1b2d}</style>',
           '<main><h1>NetApp ONTAP — écarts source / cible</h1><p><strong>Bascule interdite — preuves à compléter</strong></p><h2>Blocages</h2><ul>']
    lines += ['<li>'+html.escape(str(b))+'</li>' for b in result.get('blockers',[])]
    lines += ['</ul><h2>Écarts</h2><ul>']
    lines += ['<li>'+html.escape(str(d.get('domain','?')))+' : '+html.escape(str(d.get('issue','?')))+'</li>' for d in result.get('differences',[]) if isinstance(d,dict)]
    return ''.join(lines)+'</ul><p>Inventaires en lecture seule ; aucune validation effective des ACL fichiers.</p></main></html>'
