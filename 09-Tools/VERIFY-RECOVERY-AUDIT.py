"""Verify a read-only ODMM recovery audit JSON; no database or NAS access.

Exit 0: valid self-consistent evidence; 2: invalid or unreadable evidence.
SHA-256 is NOT a signature and does NOT authenticate its origin.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '02-Sources'))
from native_incremental_planner import IncrementalPlanner


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('Duplicate JSON key')
        obj[key] = value
    return obj


def verify_file(path):
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 8 * 1024 * 1024:
            return False
        evidence = json.loads(raw, object_pairs_hook=_reject_duplicate_keys,\n                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON number')))
    except (OSError, UnicodeError, ValueError):
        return False
    return IncrementalPlanner.verify_recovery_audit(evidence)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', help='JSON recovery evidence file')
    args = parser.parse_args(argv)
    valid = verify_file(args.evidence)
    print('PASS: self-consistent recovery audit (unsigned; origin not authenticated)'
          if valid else 'FAIL: invalid or unreadable recovery audit')
    return 0 if valid else 2


if __name__ == '__main__':
    raise SystemExit(main())
