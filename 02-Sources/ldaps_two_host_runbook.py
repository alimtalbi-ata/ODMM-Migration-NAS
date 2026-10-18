"""V188.4 read-only qualification runner: explicit remote probe and signed local report.

Never restarts services, changes firewall rules, publishes witnesses or authorizes cutover.
"""
import argparse
import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_qualification import TwoHostQualification


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def run_probe(qualifier, *, expected_count, expected_last_mac, incident_id, operator_confirmed):
    result = qualifier.probe(expected_count=expected_count, expected_last_mac=expected_last_mac,
                             incident_id=incident_id, operator_confirmed=operator_confirmed)
    if result.get('status') != 'TWO_HOST_REMOTE_PROBE_VERIFIED':
        raise IdentityPinError('TWO_HOST_PROBE_UNVERIFIED')
    return {'schema': 1, 'result': result, 'tests': {'dns_preflight': 'PASS',
            'mtls_read_only_probe': 'PASS', 'remote_independence': 'NOT_PROVEN',
            'systemd_restart': 'NOT_EXECUTED', 'network_partition': 'NOT_EXECUTED'},
            'manual_review_required': True, 'cutover_authorized': False,
            'recovery_authorized': False, 'publication_authorized': False}


def signed_report(report, *, key):
    if not isinstance(key, bytes) or len(key) < 32:
        raise IdentityPinError('REPORT_KEY_TOO_SHORT')
    if report.get('cutover_authorized') is not False:
        raise IdentityPinError('REPORT_UNSAFE')
    return {'report': report, 'hmac_sha256': hmac.new(key, canonical(report), hashlib.sha256).hexdigest()}


def verify_report(envelope, *, key):
    if not isinstance(envelope, dict) or set(envelope) != {'report', 'hmac_sha256'}:
        raise IdentityPinError('REPORT_FORMAT_INVALID')
    expected = signed_report(envelope['report'], key=key)['hmac_sha256']
    if not isinstance(envelope['hmac_sha256'], str) or not hmac.compare_digest(expected, envelope['hmac_sha256']):
        raise IdentityPinError('REPORT_SIGNATURE_INVALID')
    return envelope['report']


def write_report(path, envelope):
    p = Path(path)
    if p.is_symlink() or p.exists():
        raise IdentityPinError('REPORT_TARGET_EXISTS')
    if not p.parent.is_dir() or p.parent.is_symlink():
        raise IdentityPinError('REPORT_DIRECTORY_UNSAFE')
    fd, tmp = tempfile.mkstemp(prefix='.odmm-qualification-', dir=p.parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(envelope) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, p)  # atomic no-clobber publication
        directory_fd = os.open(p.parent, os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return str(p)


def main(argv=None):
    parser = argparse.ArgumentParser(description='ODMM two-host witness read-only qualification')
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--witness-hmac-key-file', required=True)
    parser.add_argument('--report-hmac-key-file', required=True)
    parser.add_argument('--expected-count', type=int, required=True)
    parser.add_argument('--expected-last-mac', required=True)
    parser.add_argument('--incident-id', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--operator-confirmed', action='store_true')
    args = parser.parse_args(argv)
    if not args.operator_confirmed:
        parser.error('explicit --operator-confirmed required')
    for path in (args.witness_hmac_key_file, args.report_hmac_key_file):
        p = Path(path)
        if p.is_symlink() or not p.is_file() or p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            parser.error('HMAC key files must be regular, non-symlink, mode 0600')
    qualifier = TwoHostQualification(host=args.host, port=args.port, cafile=args.ca,
        certfile=args.cert, keyfile=args.key, witness_key=Path(args.witness_hmac_key_file).read_bytes(), clock=time.time)
    report = run_probe(qualifier, expected_count=args.expected_count,
        expected_last_mac=args.expected_last_mac, incident_id=args.incident_id,
        operator_confirmed=True)
    envelope = signed_report(report, key=Path(args.report_hmac_key_file).read_bytes())
    print(write_report(args.output, envelope))


if __name__ == '__main__':
    main()
