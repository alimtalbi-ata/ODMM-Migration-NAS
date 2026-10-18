"""Optional real Chromium/Windows browser acceptance. Author: Abdelhalim Talbi.
Usage: python recette_navigateur_v2202.py --url http://127.0.0.1:8000/operations/campaign-audit --output snapshots/v2202
Requires: pip install playwright; python -m playwright install chromium
Never creates synthetic screenshots.
"""
import argparse
import json
from pathlib import Path

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--url',required=True)
    parser.add_argument('--output',default='snapshots/v2202')
    parser.add_argument('--header',action='append',default=[],help='Header Name: Value (do not persist secrets)')
    args=parser.parse_args()
    headers={}
    for item in args.header:
        key,sep,value=item.partition(':')
        if not sep or not key.strip(): parser.error('Invalid header')
        headers[key.strip()]=value.strip()
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    report={'url':args.url,'browser':'chromium','status':'FAIL','checks':{},'screenshots':[]}
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            try:
                page=browser.new_page(viewport={'width':1440,'height':900},extra_http_headers=headers)
                response=page.goto(args.url,wait_until='networkidle',timeout=15000)
                assert response and response.status==200,'HTTP_NOT_200'
                assert 'Content-Security-Policy' in response.headers,'CSP_HEADER_MISSING'
                page.locator('#cases tr').first.wait_for(timeout=5000)
                count=page.locator('#cases tr').count()
                assert count>0,'NO_SYNTHETIC_OR_REAL_CASES'
                page.screenshot(path=str(out/'dashboard-initial.png'),full_page=True)
                report['screenshots'].append('dashboard-initial.png')
                first=page.locator('#cases tr').first.get_attribute('data-identity')
                page.locator('#identity').fill('NON_EXISTENT_IDENTITY_V2202')
                assert page.locator('#cases tr:visible').count()==0,'SEARCH_FILTER_FAILED'
                assert page.locator('#empty').is_visible(),'EMPTY_STATE_FAILED'
                page.screenshot(path=str(out/'dashboard-empty-filter.png'),full_page=True)
                report['screenshots'].append('dashboard-empty-filter.png')
                page.locator('#identity').fill(first)
                assert page.locator('#cases tr:visible').count()>=1,'SEARCH_RESTORE_FAILED'
                page.locator('#severity').select_option('critical')
                assert all(row.get_attribute('data-severity')=='critical' for row in page.locator('#cases tr:visible').all()),'SEVERITY_FILTER_FAILED'
                page.locator('#severity').select_option('all')
                page.locator('#status').select_option('true')
                assert all(row.get_attribute('data-mismatch')=='true' for row in page.locator('#cases tr:visible').all()),'MISMATCH_FILTER_FAILED'
                report['checks']={'http':True,'csp':True,'search':True,'empty_state':True,'severity':True,'mismatch':True}
                report['status']='PASS'
            finally:browser.close()
    except Exception as exc:
        report['error']=type(exc).__name__+': '+str(exc).splitlines()[0][:240]
    (out/'recette-result.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
