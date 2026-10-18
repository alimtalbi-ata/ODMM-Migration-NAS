"""Consolidate ODMM browser acceptance evidence without treating absent runs as PASS.
Author: Abdelhalim Talbi.
"""
import argparse
import hashlib
import json
from pathlib import Path


def consolidate(directory):
    root = Path(directory)
    report_file = root / 'recette-result.json'
    output = {'schema': 'odmm-windows-qualification-v2204', 'status': 'NOT_EXECUTED',
              'browser_status': 'NOT_EXECUTED', 'checks': {}, 'screenshots': [],
              'failures': [], 'windows_qualified': False}
    if not report_file.is_file():
        output['failures'].append('BROWSER_REPORT_MISSING')
        return output
    try:
        raw = json.loads(report_file.read_text(encoding='utf-8'))
        if not isinstance(raw, dict) or raw.get('schema') != 'odmm-browser-acceptance-v2203':
            raise ValueError('INVALID_REPORT_SCHEMA')
        output['browser_status'] = raw.get('status') if raw.get('status') in ('PASS', 'FAIL') else 'INVALID'
        checks = raw.get('checks', {})
        if not isinstance(checks, dict) or not all(isinstance(v, bool) for v in checks.values()):
            raise ValueError('INVALID_CHECKS')
        output['checks'] = checks
        for item in raw.get('screenshots', []):
            if not isinstance(item, dict) or not isinstance(item.get('name'), str):
                raise ValueError('INVALID_SCREENSHOT')
            name = item['name']
            if name not in ('dashboard-initial.png', 'dashboard-empty-filter.png', 'dashboard-failure.png'):
                raise ValueError('UNEXPECTED_SCREENSHOT')
            path = root / name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item.get('sha256'):
                output['failures'].append('SCREENSHOT_HASH_MISMATCH')
            else:
                output['screenshots'].append({'name': name, 'sha256': item['sha256']})
        required = ('http', 'security_headers', 'filters')
        if not all(checks.get(k) is True for k in required):
            output['failures'].append('REQUIRED_CHECKS_NOT_PASSED')
        if raw.get('console_error_count') != 0 or raw.get('page_error_count') != 0:
            output['failures'].append('BROWSER_ERRORS')
        if output['browser_status'] != 'PASS':
            output['failures'].append('BROWSER_NOT_PASSED')
        if not output['screenshots']:
            output['failures'].append('NO_VERIFIED_SCREENSHOTS')
        output['status'] = 'PASS' if not output['failures'] else 'FAIL'
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError):
        output['status'] = 'FAIL'
        output['failures'].append('REPORT_INVALID')
    # A browser run alone is insufficient to claim a Windows-qualified product.
    return output


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--directory', required=True)
    args = p.parse_args(argv)
    result = consolidate(args.directory)
    dest = Path(args.directory) / 'qualification-v2204.json'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
