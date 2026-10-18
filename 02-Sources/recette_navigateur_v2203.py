"""ODMM V220.3 browser acceptance: safe evidence and deterministic failure reporting.
Author: Abdelhalim Talbi. Requires optional Playwright Chromium.
"""
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def safe_url(url):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('HTTP_URL_REQUIRED')
    if parts.username or parts.password:
        raise ValueError('URL_CREDENTIALS_FORBIDDEN')
    return urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))


def validate_header(raw):
    name, separator, value = raw.partition(':')
    name = name.strip()
    if not separator or not re.fullmatch(r'[A-Za-z0-9-]+', name) or '\r' in value or '\n' in value:
        raise ValueError('INVALID_HEADER')
    return name, value.strip()


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--output', default='snapshots/v2203')
    parser.add_argument('--header', action='append', default=[], help='Name: Value; never persisted')
    args = parser.parse_args(argv)
    try:
        redacted_url = safe_url(args.url)
        headers = dict(validate_header(h) for h in args.header)
    except ValueError as exc:
        parser.error(str(exc))
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'odmm-browser-acceptance-v2203', 'url': redacted_url,
              'timestamp_utc': datetime.now(timezone.utc).isoformat(),
              'browser': 'chromium', 'status': 'FAIL', 'checks': {}, 'screenshots': [],
              'console_error_count': 0, 'page_error_count': 0}
    page = None
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={'width': 1440, 'height': 900}, extra_http_headers=headers)
                console_errors, page_errors = [], []
                page.on('console', lambda msg: console_errors.append(msg.type) if msg.type == 'error' else None)
                page.on('pageerror', lambda exc: page_errors.append(type(exc).__name__))
                response = page.goto(args.url, wait_until='networkidle', timeout=15000)
                assert response and response.status == 200, 'HTTP_NOT_200'
                report['checks']['http'] = True
                policy = response.headers.get('content-security-policy', '')
                assert 'script-src' in policy and 'sha256-' in policy and "'unsafe-inline'" not in policy.split('style-src')[0], 'CSP_INVALID'
                assert response.headers.get('x-frame-options', '').upper() == 'DENY', 'FRAME_POLICY_MISSING'
                assert response.headers.get('cache-control', '').lower() == 'no-store', 'CACHE_POLICY_MISSING'
                report['checks']['security_headers'] = True
                page.locator('#cases tr').first.wait_for(timeout=5000)
                assert page.locator('#cases tr').count() > 0, 'NO_CASES'
                def capture(name):
                    path = out / name
                    page.screenshot(path=str(path), full_page=True)
                    report['screenshots'].append({'name': name, 'sha256': sha256(path)})
                capture('dashboard-initial.png')
                identity = page.locator('#cases tr').first.get_attribute('data-identity')
                page.locator('#identity').fill('NON_EXISTENT_IDENTITY_V2203')
                assert page.locator('#cases tr:visible').count() == 0 and page.locator('#empty').is_visible(), 'SEARCH_FILTER_FAILED'
                capture('dashboard-empty-filter.png')
                page.locator('#identity').fill(identity)
                assert page.locator('#cases tr:visible').count() >= 1, 'SEARCH_RESTORE_FAILED'
                page.locator('#severity').select_option('critical')
                assert all(r.get_attribute('data-severity') == 'critical' for r in page.locator('#cases tr:visible').all()), 'SEVERITY_FILTER_FAILED'
                page.locator('#severity').select_option('all')
                page.locator('#status').select_option('true')
                assert all(r.get_attribute('data-mismatch') == 'true' for r in page.locator('#cases tr:visible').all()), 'MISMATCH_FILTER_FAILED'
                report['checks']['filters'] = True
                report['console_error_count'] = len(console_errors)
                report['page_error_count'] = len(page_errors)
                assert not console_errors and not page_errors, 'BROWSER_SCRIPT_ERRORS'
                report['status'] = 'PASS'
            finally:
                if report['status'] != 'PASS' and page is not None:
                    try:
                        path = out / 'dashboard-failure.png'
                        page.screenshot(path=str(path), full_page=True, timeout=3000)
                        report['screenshots'].append({'name': path.name, 'sha256': sha256(path)})
                    except Exception:
                        report['failure_screenshot'] = 'UNAVAILABLE'
                browser.close()
    except Exception as exc:
        # Do not persist exception messages: browser exceptions may embed URL secrets or header values.
        report['error_type'] = type(exc).__name__
        report['error_code'] = str(exc) if str(exc) in {
            'HTTP_NOT_200', 'CSP_INVALID', 'FRAME_POLICY_MISSING', 'CACHE_POLICY_MISSING',
            'NO_CASES', 'SEARCH_FILTER_FAILED', 'SEARCH_RESTORE_FAILED',
            'SEVERITY_FILTER_FAILED', 'MISMATCH_FILTER_FAILED', 'BROWSER_SCRIPT_ERRORS'
        } else 'BROWSER_EXECUTION_FAILED'
    (out / 'recette-result.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['status'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
