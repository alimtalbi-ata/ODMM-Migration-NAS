"""Safe, read-only presentation model for ODMM Desktop V225.8."""
import json
from pathlib import Path

MAX_REPORT_BYTES = 5_000_000

def read_report(path):
    p = Path(path)
    if p.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError('Rapport trop volumineux (limite 5 Mo)')
    with p.open('r', encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, (dict, list)):
        raise ValueError('Rapport JSON : objet ou tableau attendu')
    return data

def report_summary(data):
    """Describe an unknown report without inventing status or quality metrics."""
    if isinstance(data, list):
        return {'format': 'liste', 'entries': len(data), 'status': 'non déclaré'}
    status = next((str(data[k]) for k in ('status', 'result', 'outcome') if k in data and isinstance(data[k], (str, bool))), 'non déclaré')
    return {'format': 'objet', 'entries': len(data), 'status': status}

def pretty_report(data, filter_text=''):
    rendered = json.dumps(data, ensure_ascii=False, indent=2)
    if not filter_text.strip():
        return rendered
    term = filter_text.casefold()
    return '\n'.join(line for line in rendered.splitlines() if term in line.casefold())
