"""Isolated, reproducible cost benchmark for ODMM file verification.

No NAS claim, no production mutation. Compares one and two full SHA-256 passes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import tempfile
import time


def hash_file(path, block_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, 'rb', buffering=0) as stream:
        while True:
            chunk = stream.read(block_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def benchmark(sizes=(1024 * 1024, 8 * 1024 * 1024), repeats=3):
    if repeats < 1 or any(s < 1 or s > 128 * 1024 * 1024 for s in sizes):
        raise ValueError('Invalid benchmark parameters')
    rows = []
    with tempfile.TemporaryDirectory(prefix='odmm-verify-bench-') as temp:
        file = Path(temp) / 'payload.bin'
        for size in sizes:
            with file.open('wb') as output:
                block = bytes(range(256)) * 4096
                remaining = size
                while remaining:
                    chunk = block[:min(remaining, len(block))]
                    output.write(chunk)
                    remaining -= len(chunk)
            samples = {1: [], 2: []}
            for _ in range(repeats):
                for passes in (2, 1):
                    start = time.perf_counter_ns()
                    digests = [hash_file(file) for _ in range(passes)]
                    elapsed = time.perf_counter_ns() - start
                    assert len(set(digests)) == 1
                    samples[passes].append(elapsed / 1e6)
            one = statistics.median(samples[1])
            two = statistics.median(samples[2])
            rows.append({'bytes': size, 'repeats': repeats,
                         'single_pass_median_ms': round(one, 3),
                         'double_pass_median_ms': round(two, 3),
                         'observed_ratio': round(two / one, 3) if one else None})
    return {'scope': 'synthetic local file SHA256 only; no NAS, no SQLite or engine benchmark',
            'rows': rows, 'recommendation': 'Retain final re-verification; no unsafe cache or skipped hash.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sizes-mib', nargs='+', type=int, default=[1, 8])
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = benchmark([x * 1024 * 1024 for x in args.sizes_mib], args.repeats)
    payload = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(payload + '\n', encoding='utf-8')
    print(payload)


if __name__ == '__main__':
    main()
